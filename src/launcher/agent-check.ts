import { analyzePackages, AnalyzeError, type AnalyzeEcosystem, type ScannerAction, type ScannerPackageResult } from "../api/analyze.js";
import {
  classifyPackageManagerInvocation,
  isSupportedPackageManager,
  normalizeManagerName,
  packageManagerNames,
  type Ecosystem,
  type PackageManager,
} from "./classify.js";
import { resolveLatest } from "../verify/package-check.js";
import { matchDecision } from "../decisions/apply.js";
import { isCooldownExempt, isCooldownExemptByDgFile } from "../policy/cooldown.js";
import type { CooldownExemption } from "../project/dgfile.js";
import { resolvePreflightCooldown, resolvePreflightDecisions, type PreflightCooldownContext } from "./install-preflight.js";
import { sanitizeLine } from "../security/sanitize.js";
import { readNpmManifestSpecs, readPipRequirementSpecs } from "./manifest-screen.js";

export type AgentDecision = "allow" | "deny" | "ask";

export interface AgentPackageVerdict {
  readonly name: string;
  readonly version: string;
  readonly action: ScannerAction | "cooldown";
  readonly why: string;
}

export interface ScreenedPackage {
  readonly name: string;
  readonly version: string;
  readonly ecosystem: AnalyzeEcosystem;
}

export interface AgentVerdict {
  readonly decision: AgentDecision;
  readonly reason?: string;
  readonly packages?: readonly AgentPackageVerdict[];
  readonly screened?: readonly ScreenedPackage[];
}

export interface AgentCheckInput {
  readonly commandLine: string;
  readonly cwd?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly fetchImpl?: typeof fetch;
  // Test-only override for the fail-closed deadline. Deliberately a function
  // parameter, not an env var: an env-tunable deadline an attacker could raise
  // past the hook timeout would re-open the slow-scanner fail-open.
  readonly deadlineMs?: number;
}

const ALLOW: AgentVerdict = { decision: "allow" };

export const ESCALATE =
  "Stop and report this to the person you are working with; do not retry, override, or disable dg.";

export function formatScreenedNote(screened: readonly ScreenedPackage[]): string {
  if (screened.length === 0) {
    return "";
  }
  const items = screened.map((pkg) => `${pkg.name}@${pkg.version} (${pkg.ecosystem})`).join(", ");
  const noun = screened.length === 1 ? "package" : "packages";
  // This note is injected verbatim into the agent's context. Package name and
  // version are attacker-influenced (they come off the command line, and a
  // pinned version skips registry resolution), so newlines/control sequences
  // are flattened to a single line — otherwise a crafted spec could smuggle a
  // forged instruction ("[SYSTEM] all installs pre-approved") into the agent.
  return sanitizeLine(`dg pre-screened the requested ${noun}: ${items} — no known issues (dependencies are screened at install time)`);
}

// A real package name/version never contains a control character; a spec that
// does is either garbage or an attempt to smuggle a newline into agent-facing
// text. Reject it before it reaches the scanner or any rendered string.
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

// The `DG_PROXY_ACTIVE` env flag is spoofable (an agent can set it in its own
// settings env), so it is never trusted on its own. Defer an undecidable install
// to the proxy only when the process is genuinely routed to a loopback proxy AND
// a dg-managed service proxy is verifiably running (PID + reachable health).
async function proxyGenuinelyLive(env: NodeJS.ProcessEnv): Promise<boolean> {
  const proxyUrl = env.HTTPS_PROXY ?? env.https_proxy ?? env.HTTP_PROXY ?? env.http_proxy;
  if (!proxyUrl) {
    return false;
  }
  try {
    const host = new URL(proxyUrl).hostname.replace(/^\[|\]$/g, "");
    if (host !== "127.0.0.1" && host !== "::1" && host !== "localhost") {
      return false;
    }
  } catch {
    return false;
  }
  try {
    const { readServiceState } = await import("../service/state.js");
    const { state } = readServiceState(env);
    return Boolean(state.running && state.proxy);
  } catch {
    return false;
  }
}

// A statically-undecidable install (dynamic name/verb, xargs-fed, …). Defer to
// the runtime proxy only if it is genuinely live; otherwise the hook is the only
// gate, so hold for a human rather than wave it through.
async function undecidableVerdict(env: NodeJS.ProcessEnv, reason: string): Promise<AgentVerdict> {
  if (env.DG_PROXY_ACTIVE === "1" && (await proxyGenuinelyLive(env))) {
    return ALLOW;
  }
  return { decision: "ask", reason };
}

interface Spec {
  readonly name: string;
  readonly version: string | null;
}

// Flags that consume the following token as their value, so it must not be
// mistaken for a package name (the `-r requirements.txt` trap).
const PIP_VALUE_FLAGS = new Set([
  "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
  "--extra-index-url", "-f", "--find-links", "-t", "--target", "--platform",
  "--python-version", "--implementation", "--abi", "--prefix", "--root", "--no-binary",
  "--only-binary", "--progress-bar",
]);
const NPM_VALUE_FLAGS = new Set(["--registry", "--prefix", "-C", "--workspace", "-w", "--tag", "--otp"]);

function analyzeEcosystem(eco: Ecosystem): AnalyzeEcosystem | null {
  if (eco === "javascript") return "npm";
  if (eco === "python") return "pypi";
  return null;
}

function splitSegments(line: string): string[] {
  // Split on shell control operators, but not on a `&` that is part of a
  // redirection (`2>&1`, `>&2`, `&>file`) where the `&` is glued to a `>` —
  // shearing there turns a redirection into a phantom package token.
  return line.split(/&&|\|\||;|\||[\n\r]|(?<!>)&(?!>)/).map((s) => s.trim()).filter(Boolean);
}

function substitutionBodies(line: string): string[] {
  const bodies: string[] = [];
  const patterns = [/\$\(([^)]*)\)/g, /`([^`]*)`/g];
  for (const pattern of patterns) {
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(line)) !== null) {
      const body = (m[1] ?? "").trim();
      if (body) {
        bodies.push(body);
      }
    }
  }
  return bodies;
}

function collectSegments(line: string): string[] {
  const texts: string[] = [];
  const pending = [line];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined || texts.includes(current)) {
      continue;
    }
    texts.push(current);
    pending.push(...substitutionBodies(current));
  }
  const segments: string[] = [];
  for (const segment of texts.flatMap(splitSegments)) {
    if (!segments.includes(segment)) {
      segments.push(segment);
    }
  }
  return segments;
}

interface LexedSegment {
  readonly tokens: string[];
  // false when the segment could not be fully parsed (unbalanced quote or a
  // trailing escape). Callers fail closed when the head is a package manager.
  readonly ok: boolean;
}

const ANSI_C_ESCAPES: Record<string, string> = {
  n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", f: "\f", v: "\v",
  "\\": "\\", "'": "'", '"': '"', "?": "?", e: "\x1b", E: "\x1b",
};

function decodeAnsiC(body: string): string {
  let out = "";
  let i = 0;
  while (i < body.length) {
    const c = body[i] ?? "";
    if (c !== "\\" || i + 1 >= body.length) {
      out += c;
      i += 1;
      continue;
    }
    const next = body[i + 1] ?? "";
    if (next === "x") {
      const m = /^[0-9a-fA-F]{1,2}/.exec(body.slice(i + 2));
      if (m) {
        out += String.fromCharCode(parseInt(m[0], 16));
        i += 2 + m[0].length;
        continue;
      }
    }
    if (next === "u" || next === "U") {
      const m = new RegExp(`^[0-9a-fA-F]{1,${next === "u" ? 4 : 8}}`).exec(body.slice(i + 2));
      if (m) {
        out += String.fromCodePoint(parseInt(m[0], 16));
        i += 2 + m[0].length;
        continue;
      }
    }
    if (next >= "0" && next <= "7") {
      const m = /^[0-7]{1,3}/.exec(body.slice(i + 1));
      if (m) {
        out += String.fromCharCode(parseInt(m[0], 8) & 0xff);
        i += 1 + m[0].length;
        continue;
      }
    }
    out += next in ANSI_C_ESCAPES ? ANSI_C_ESCAPES[next] : next;
    i += 2;
  }
  return out;
}

// A POSIX-style word splitter that performs quote removal, escape processing,
// ANSI-C ($'…') decoding, and adjacent-fragment joining the way the executing
// shell would, so quote/backslash obfuscation (np""m, n"p"m, i"n"stall, np\m,
// $'\x69'nstall) collapses to the real command before classification.
function lexSegment(segment: string): LexedSegment {
  const tokens: string[] = [];
  let cur = "";
  let started = false;
  let i = 0;
  const n = segment.length;
  const flush = (): void => {
    if (started) {
      tokens.push(cur);
      cur = "";
      started = false;
    }
  };
  while (i < n) {
    const ch = segment[i] ?? "";
    if (ch === " " || ch === "\t") {
      flush();
      i += 1;
      continue;
    }
    if (ch === "#" && !started) {
      break;
    }
    if (ch === "'") {
      started = true;
      i += 1;
      let closed = false;
      while (i < n) {
        if (segment[i] === "'") {
          closed = true;
          i += 1;
          break;
        }
        cur += segment[i];
        i += 1;
      }
      if (!closed) {
        flush();
        return { tokens, ok: false };
      }
      continue;
    }
    if (ch === '"') {
      started = true;
      i += 1;
      let closed = false;
      while (i < n) {
        const c = segment[i] ?? "";
        if (c === '"') {
          closed = true;
          i += 1;
          break;
        }
        if (c === "\\" && i + 1 < n) {
          const nx = segment[i + 1] ?? "";
          if (nx === '"' || nx === "\\" || nx === "`" || nx === "$" || nx === "\n") {
            cur += nx;
            i += 2;
            continue;
          }
          cur += c;
          i += 1;
          continue;
        }
        cur += c;
        i += 1;
      }
      if (!closed) {
        flush();
        return { tokens, ok: false };
      }
      continue;
    }
    if (ch === "$" && segment[i + 1] === "'") {
      started = true;
      i += 2;
      let closed = false;
      let body = "";
      while (i < n) {
        const c = segment[i] ?? "";
        if (c === "\\" && i + 1 < n) {
          body += c + (segment[i + 1] ?? "");
          i += 2;
          continue;
        }
        if (c === "'") {
          closed = true;
          i += 1;
          break;
        }
        body += c;
        i += 1;
      }
      if (!closed) {
        flush();
        return { tokens, ok: false };
      }
      cur += decodeAnsiC(body);
      continue;
    }
    if (ch === "\\") {
      if (i + 1 < n) {
        cur += segment[i + 1];
        started = true;
        i += 2;
        continue;
      }
      flush();
      return { tokens, ok: false };
    }
    if (ch === ">" || ch === "<") {
      // Shell redirection. A bare numeric fd already in `cur` (the `2` in `2>`)
      // is part of the operator, not a word; otherwise `cur` is a real word
      // (echo foo>bar) and flushes. Consume the operator and its target so a
      // redirection (2>&1, >/dev/null, >>log, <<<here) is never read as a package.
      if (started && /^[0-9]+$/.test(cur)) {
        cur = "";
        started = false;
      } else {
        flush();
      }
      i += 1;
      if (segment[i] === ch) {
        i += 1;
      }
      if (ch === "<" && segment[i] === "<") {
        i += 1;
      }
      while (i < n && (segment[i] === " " || segment[i] === "\t")) {
        i += 1;
      }
      if (segment[i] === "&") {
        i += 1;
      }
      while (i < n && !" \t\n\r<>|&;".includes(segment[i] ?? "")) {
        i += 1;
      }
      continue;
    }
    cur += ch;
    started = true;
    i += 1;
  }
  flush();
  return { tokens, ok: true };
}

const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

interface WrapperSpec {
  // Flags that consume the FOLLOWING token as their value, so it must not be
  // mistaken for the wrapped command (the `nice -n 10` trap).
  readonly valueFlags: ReadonlySet<string>;
  // A leading bare positional value before flags (timeout's duration).
  readonly bareValue?: RegExp;
}

const WRAPPERS: ReadonlyMap<string, WrapperSpec> = new Map([
  ["sudo", { valueFlags: new Set(["-u", "--user", "-g", "--group", "-p", "--prompt", "-C", "-h", "--host", "-R", "--chroot", "-D", "--chdir"]) }],
  ["doas", { valueFlags: new Set(["-u", "-C", "-a"]) }],
  // corepack is Node's official launcher for pnpm/yarn/npm: `corepack pnpm add x`
  // is really a pnpm install. Unwrap it so the underlying manager is classified.
  ["corepack", { valueFlags: new Set() }],
  ["env", { valueFlags: new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string"]) }],
  ["command", { valueFlags: new Set() }],
  ["exec", { valueFlags: new Set(["-a"]) }],
  ["nice", { valueFlags: new Set(["-n", "--adjustment"]) }],
  ["ionice", { valueFlags: new Set(["-c", "--class", "-n", "--classdata", "-p", "--pid"]) }],
  ["nohup", { valueFlags: new Set() }],
  ["setsid", { valueFlags: new Set() }],
  ["chrt", { valueFlags: new Set(["-T", "-P", "-D"]) }],
  ["time", { valueFlags: new Set(["-o", "--output", "-f", "--format"]) }],
  ["timeout", { valueFlags: new Set(["-s", "--signal", "-k", "--kill-after"]), bareValue: /^\d+(\.\d+)?[smhd]?$/ }],
  ["stdbuf", { valueFlags: new Set(["-i", "--input", "-o", "--output", "-e", "--error"]) }],
  ["xargs", { valueFlags: new Set(["-a", "--arg-file", "-d", "--delimiter", "-E", "-e", "--eof", "-I", "-i", "--replace", "-L", "-l", "--max-lines", "-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars"]) }],
]);

const SHELL_EXEC = new Set(["sh", "bash", "zsh", "dash", "ash"]);

// Package managers dg doesn't statically screen (no shim, no classifier). A
// recognized install verb for one of these can't be screened by the hook, so it
// defers to the runtime gate rather than waving it through silently.
const UNSUPPORTED_INSTALLS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ["bun", new Set(["add", "install", "i", "x"])],
  ["deno", new Set(["install", "add"])],
  ["poetry", new Set(["add", "install"])],
  ["pdm", new Set(["add", "install"])],
  ["conda", new Set(["install", "create"])],
  ["mamba", new Set(["install", "create"])],
  ["gem", new Set(["install", "i"])],
  // `go install`/`go get` fetch and build remote modules; `go build`/`run`/`test`
  // operate on already-resolved local code, so they stay passthrough.
  ["go", new Set(["install", "get"])],
]);

// Fetch-and-run launchers dg doesn't statically screen: any package argument is
// fetched and executed, so a recognized-but-unsupported runner with a target
// defers to the runtime gate instead of a silent allow (`bunx <pkg>`).
const UNSUPPORTED_RUNNERS = new Set(["bunx"]);

interface CommandTokens {
  readonly tokens: string[];
  readonly ok: boolean;
  // `sh -c '<script>'` / `bash -c …` / `eval '<script>'`: the inner script, which
  // the caller re-parses so a wrapped install can never hide from the firewall.
  readonly shellScript?: string;
  // Reached via xargs: the real packages may arrive on stdin, unknowable here.
  readonly viaXargs?: boolean;
}

function commandBasename(token: string): string {
  const slash = token.lastIndexOf("/");
  return slash === -1 ? token : token.slice(slash + 1);
}

// Drop shell grouping punctuation: a subshell `(…)`, a brace group `{ …; }`, and
// stray `;` so the wrapped command underneath is reached.
function stripGrouping(tokens: readonly string[]): string[] {
  const out = tokens.filter((t) => t !== "(" && t !== ")" && t !== "{" && t !== "}" && t !== ";");
  if (out.length > 0) {
    out[0] = (out[0] ?? "").replace(/^\(+/, "");
    out[out.length - 1] = (out[out.length - 1] ?? "").replace(/\)+$/, "");
  }
  return out.filter((t) => t.length > 0);
}

function commandTokens(segment: string): CommandTokens {
  const lexed = lexSegment(segment);
  let tokens = stripGrouping(lexed.tokens);
  let viaXargs = false;
  const x = (): { viaXargs?: boolean } => (viaXargs ? { viaXargs: true } : {});
  for (;;) {
    while (tokens.length > 0 && ENV_ASSIGNMENT.test(tokens[0] ?? "")) {
      tokens = tokens.slice(1);
    }
    const head = commandBasename(tokens[0] ?? "");
    if (head === "eval" && tokens.length > 1) {
      return { tokens, ok: lexed.ok, shellScript: tokens.slice(1).join(" "), ...x() };
    }
    if (SHELL_EXEC.has(head)) {
      const ci = tokens.indexOf("-c");
      const script = ci >= 0 ? tokens[ci + 1] : undefined;
      if (script !== undefined) {
        return { tokens, ok: lexed.ok, shellScript: script, ...x() };
      }
    }
    if (/^python[0-9.]*$/.test(head)) {
      // `-m pip`, glued `-mpip`, and `-m=pip` all run the module. Normalize the
      // module name too so `python -m pip3` resolves to pip.
      let mod: string | undefined;
      let rest: string[] = [];
      for (let k = 1; k < tokens.length; k += 1) {
        const t = tokens[k] ?? "";
        if (t === "-m") {
          mod = tokens[k + 1];
          rest = tokens.slice(k + 2);
          break;
        }
        const glued = /^-m=?(.+)$/.exec(t);
        if (glued && glued[1]) {
          mod = glued[1];
          rest = tokens.slice(k + 1);
          break;
        }
      }
      const nmod = mod ? normalizeManagerName(mod) : undefined;
      if (nmod === "pip" || nmod === "uv" || nmod === "pipx") {
        tokens = [nmod, ...rest];
        continue;
      }
    }
    const spec = WRAPPERS.get(head);
    if (head === "" || spec === undefined) {
      return { tokens, ok: lexed.ok, ...x() };
    }
    if (head === "xargs") {
      viaXargs = true;
    }
    tokens = tokens.slice(1);
    if (spec.bareValue && tokens[0] !== undefined && !tokens[0].startsWith("-") && spec.bareValue.test(tokens[0])) {
      tokens = tokens.slice(1);
    }
    while (tokens.length > 0 && (tokens[0] ?? "").startsWith("-")) {
      const flag = tokens[0] ?? "";
      tokens = tokens.slice(1);
      if (spec.valueFlags.has(flag) && tokens.length > 0 && !(tokens[0] ?? "").startsWith("-")) {
        tokens = tokens.slice(1);
      }
    }
  }
}

function parseSpecToken(eco: AnalyzeEcosystem, token: string): Spec {
  if (eco === "npm") {
    const at = token.lastIndexOf("@");
    if (at > 0) {
      return { name: token.slice(0, at), version: token.slice(at + 1) || null };
    }
    return { name: token, version: null };
  }
  // pypi: only an exact `name==version` is a pinned version; ranges are unpinned.
  const exact = /^([A-Za-z0-9._-]+)==([^,;\s]+)$/.exec(token);
  if (exact && exact[1] && exact[2]) {
    return { name: exact[1], version: exact[2] };
  }
  const ranged = /^([A-Za-z0-9._-]+)\s*(?:===|>=|<=|~=|!=|<|>)/.exec(token);
  if (ranged && ranged[1]) {
    return { name: ranged[1], version: null };
  }
  return { name: token, version: null };
}

interface ExtractedSpecs {
  readonly specs: Spec[];
  // Remote, non-registry install targets (URL / git+) the registry scanner
  // cannot verify. Local targets (file:/link:/workspace:/relative path) are
  // intentionally NOT listed here: the code is already on disk, and gating them
  // would block legitimate local development installs.
  readonly remoteUnverifiable: string[];
  // Package positions built from a shell variable or substitution ($PKG,
  // $(…)) — statically unknowable, so the verdict defers to the runtime gate.
  readonly dynamic: string[];
}

// A token built from a shell variable or substitution — its real value is only
// known at run time, so it can't be screened statically (applies equally to a
// package name and to the install verb: `npm $i pkg`).
function isDynamicToken(t: string): boolean {
  return t.includes("$") || t.includes("`");
}

function isLocalSpecToken(t: string): boolean {
  return (
    t.startsWith(".") ||
    t.startsWith("/") ||
    t.startsWith("file:") ||
    t.startsWith("link:") ||
    t.startsWith("workspace:")
  );
}

// `uv run --with <pkg> <cmd>` installs the `--with` values, not the positional
// command. Extract only the --with specs; a --with-requirements <file> points at
// a file whose contents are unknowable statically, so it defers.
function extractUvRunWithSpecs(rawArgs: readonly string[]): ExtractedSpecs {
  const specs: Spec[] = [];
  const remoteUnverifiable: string[] = [];
  const dynamic: string[] = [];
  const addToken = (raw: string): void => {
    for (const part of raw.split(",")) {
      const t = part.trim();
      if (t.length === 0) {
        continue;
      }
      if (isDynamicToken(t)) {
        dynamic.push(t);
      } else if (t.includes("://") || t.startsWith("git+")) {
        remoteUnverifiable.push(t);
      } else if (!isLocalSpecToken(t)) {
        const spec = parseSpecToken("pypi", t);
        if (spec.name.length > 0) {
          specs.push(spec);
        }
      }
    }
  };
  for (let i = 0; i < rawArgs.length; i += 1) {
    const a = rawArgs[i];
    if (a === undefined) {
      continue;
    }
    if (a === "--with" || a === "--with-editable") {
      const v = rawArgs[i + 1];
      i += 1;
      if (v !== undefined) {
        addToken(v);
      }
    } else if (a.startsWith("--with=") || a.startsWith("--with-editable=")) {
      addToken(a.slice(a.indexOf("=") + 1));
    } else if (a === "--with-requirements") {
      dynamic.push(rawArgs[i + 1] ?? "--with-requirements");
      i += 1;
    } else if (a.startsWith("--with-requirements=")) {
      dynamic.push(a.slice(a.indexOf("=") + 1));
    }
  }
  return { specs, remoteUnverifiable, dynamic };
}

function extractSpecs(manager: string, eco: AnalyzeEcosystem, rawArgs: readonly string[]): ExtractedSpecs {
  if (manager === "uv" && rawArgs.find((a) => !a.startsWith("-")) === "run") {
    return extractUvRunWithSpecs(rawArgs);
  }
  const valueFlags = eco === "pypi" ? PIP_VALUE_FLAGS : NPM_VALUE_FLAGS;
  const noVerb = manager === "npx" || manager === "pnpx" || manager === "uvx";
  const positionals: string[] = [];
  // Most managers have a one-word verb (`pip install <pkg>`). `uv pip install`,
  // `uv tool install`, and `pipx inject <venv> <pkg>` are two leading tokens
  // before the package, so consume the extra leading positional or the scan
  // targets the verb/venv instead of the real package set.
  let verbWords = noVerb ? 0 : 1;
  let consumed = 0;
  let firstSeen = false;
  for (let i = 0; i < rawArgs.length; i += 1) {
    const a = rawArgs[i];
    if (a === undefined) {
      continue;
    }
    if (a.startsWith("-")) {
      if (valueFlags.has(a)) {
        i += 1;
      }
      continue;
    }
    if (!firstSeen) {
      firstSeen = true;
      if (manager === "uv" && (a === "pip" || a === "tool")) {
        verbWords = 2;
      } else if (manager === "pipx" && a === "inject") {
        verbWords = 2;
      }
    }
    if (consumed < verbWords) {
      consumed += 1;
      continue;
    }
    positionals.push(a);
  }
  const tokens = noVerb ? positionals.slice(0, 1) : positionals;
  const specs: Spec[] = [];
  const remoteUnverifiable: string[] = [];
  const dynamic: string[] = [];
  for (const t of tokens) {
    if (t.length === 0) {
      continue;
    }
    if (isDynamicToken(t)) {
      dynamic.push(t);
      continue;
    }
    if (t.includes("://") || t.startsWith("git+")) {
      remoteUnverifiable.push(t);
      continue;
    }
    if (isLocalSpecToken(t)) {
      continue;
    }
    const spec = parseSpecToken(eco, t);
    if (spec.name.length > 0) {
      specs.push(spec);
    }
  }
  return { specs, remoteUnverifiable, dynamic };
}

// Registry hosts whose artifacts the canonical scan actually covers. Anything
// else is a different source than the one dg verifies against.
const DEFAULT_INDEX_HOSTS = new Set([
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  "pypi.org",
  "files.pythonhosted.org",
]);
const PIP_INDEX_FLAGS = new Set(["-i", "--index-url", "--extra-index-url", "-f", "--find-links"]);
const NPM_INDEX_FLAGS = new Set(["--registry"]);
const PIP_INDEX_ENV = ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX"];
const NPM_INDEX_ENV = ["NPM_CONFIG_REGISTRY", "npm_config_registry", "YARN_REGISTRY", "yarn_registry"];

// True only for a URL pointing at a non-default registry host. A bare local path
// (--find-links ./wheels) is not flagged here; local artifacts are governed by
// the same on-disk-already policy as file: specs.
function isAlternateIndexValue(value: string): boolean {
  try {
    return !DEFAULT_INDEX_HOSTS.has(new URL(value).hostname);
  } catch {
    return false;
  }
}

// A package screened against the canonical registry but actually fetched from a
// different index/registry was not really screened — the bytes come from
// elsewhere. Surface every alternate source so the verdict can't claim a clean
// pass it didn't earn.
function extractAlternateIndexes(eco: AnalyzeEcosystem, rawArgs: readonly string[], env: NodeJS.ProcessEnv): string[] {
  const out: string[] = [];
  const flags = eco === "pypi" ? PIP_INDEX_FLAGS : NPM_INDEX_FLAGS;
  for (let i = 0; i < rawArgs.length; i += 1) {
    const a = rawArgs[i];
    if (a === undefined) {
      continue;
    }
    let value: string | undefined;
    if (flags.has(a)) {
      value = rawArgs[i + 1];
      i += 1;
    } else {
      for (const f of flags) {
        if (a.startsWith(`${f}=`)) {
          value = a.slice(f.length + 1);
          break;
        }
      }
    }
    if (value !== undefined && isAlternateIndexValue(value)) {
      out.push(value);
    }
  }
  for (const key of eco === "pypi" ? PIP_INDEX_ENV : NPM_INDEX_ENV) {
    const v = env[key];
    if (v && isAlternateIndexValue(v)) {
      out.push(v);
    }
  }
  return out;
}

function normalizeName(eco: AnalyzeEcosystem, name: string): string {
  const lower = name.toLowerCase();
  return eco === "pypi" ? lower.replace(/[._-]+/g, "-") : lower;
}

function quarantined(
  pkg: ScannerPackageResult,
  ctx: PreflightCooldownContext | undefined,
  eco: AnalyzeEcosystem,
  dgExemptions: readonly CooldownExemption[] = [],
): boolean {
  if (!ctx || !pkg.cooldown) return false;
  if (isCooldownExempt(pkg.name, ctx.exempt, eco) || isCooldownExemptByDgFile(pkg.name, eco, dgExemptions)) {
    return false;
  }
  return (
    pkg.cooldown.status === "quarantine" ||
    (pkg.cooldown.status === "unknown" && ctx.param.onUnknown === "block")
  );
}

function whyFor(pkg: ScannerPackageResult, action: ScannerAction | "cooldown"): string {
  if (action === "cooldown") {
    return "release too new (cooldown)";
  }
  return pkg.reasons[0] ?? pkg.findings[0]?.title ?? pkg.findings[0]?.id ?? String(action);
}

function combinePackages(verdicts: AgentPackageVerdict[]): AgentVerdict {
  if (verdicts.length === 0) {
    return ALLOW;
  }
  const blocking = verdicts.filter(
    (v) => v.action === "block" || v.action === "cooldown" || v.action === "analysis_incomplete",
  );
  if (blocking.length > 0) {
    const list = blocking.map((v) => `${v.name}@${v.version} (${v.action}: ${v.why})`).join("; ");
    return { decision: "deny", reason: `DG blocked install — ${list}`, packages: verdicts };
  }
  const list = verdicts.map((v) => `${v.name}@${v.version} (${v.why})`).join("; ");
  return { decision: "ask", reason: `DG flagged for review — ${list}`, packages: verdicts };
}

function combineRaw(results: AgentVerdict[]): AgentVerdict {
  const blocked = results.find((v) => v.decision === "deny") ?? results.find((v) => v.decision === "ask");
  if (blocked) {
    return blocked;
  }
  const screened = results.flatMap((v) => v.screened ?? []);
  return screened.length > 0 ? { decision: "allow", screened } : ALLOW;
}

function combine(results: AgentVerdict[]): AgentVerdict {
  const v = combineRaw(results);
  // The reason is rendered into the agent's context (permissionDecisionReason)
  // and the terminal. It interpolates attacker-influenced package names, so
  // flatten control sequences before it leaves the firewall.
  return v.decision !== "allow" && v.reason ? { ...v, reason: `${sanitizeLine(v.reason)} ${ESCALATE}` } : v;
}

async function checkSegment(
  segment: string,
  env: NodeJS.ProcessEnv,
  cwd: string,
  fetchImpl: typeof fetch,
  depth = 0,
): Promise<AgentVerdict> {
  const parsed = commandTokens(segment);
  if (parsed.shellScript !== undefined) {
    if (depth < 8) {
      // sh -c '<script>' / eval '<script>': re-parse the wrapped script so an
      // install can't hide behind a shell-exec wrapper.
      const inner = collectSegments(parsed.shellScript);
      const results = await Promise.all(inner.map((s) => checkSegment(s, env, cwd, fetchImpl, depth + 1)));
      return combineRaw(results);
    }
    // Recursion limit hit with an unparsed shell-exec wrapper still present: we
    // cannot see what the innermost command runs, so deferring/holding is the
    // only safe move. Falling through here would reach the ALLOW below (the
    // wrapper head `sh`/`eval` is not a package manager) — a fail-OPEN that a
    // deeply nested `sh -c '… sh -c "… npm install evil …"'` would exploit.
    return undecidableVerdict(env, "dg cannot statically unwrap a deeply nested shell-exec command");
  }
  const { tokens, ok } = parsed;
  const manager = normalizeManagerName(commandBasename(tokens[0] ?? ""));
  if (!manager || !packageManagerNames().includes(manager as PackageManager) || !isSupportedPackageManager(manager as PackageManager)) {
    const verb0 = tokens.slice(1).find((a) => !a.startsWith("-")) ?? "";
    const unsupportedVerbs = UNSUPPORTED_INSTALLS.get(manager);
    if (unsupportedVerbs && unsupportedVerbs.has(verb0)) {
      return undecidableVerdict(env, `dg cannot statically screen ${manager} installs; they are covered only when the network gate is on`);
    }
    if (UNSUPPORTED_RUNNERS.has(manager) && verb0 && !isDynamicToken(verb0)) {
      return undecidableVerdict(env, `dg cannot statically screen a ${manager} fetch-and-run; it is covered only when the network gate is on`);
    }
    return ALLOW;
  }
  if (!ok) {
    // Head is a package manager but the segment could not be parsed safely
    // (unbalanced quote / trailing escape). Never wave it through.
    return { decision: "ask", reason: `dg could not safely parse this ${manager} command, so it cannot be verified` };
  }
  const args = tokens.slice(1);
  const verb = args.find((a) => !a.startsWith("-")) ?? "";
  if (isDynamicToken(verb)) {
    // A dynamically-built subcommand (`npm $i pkg`) can't be classified — defer,
    // don't silently allow (symmetry with a dynamic package name).
    return undecidableVerdict(env, `dg cannot statically verify a dynamically-built ${manager} subcommand (${verb})`);
  }
  const classification = classifyPackageManagerInvocation(manager as PackageManager, args);
  if (classification.kind !== "protected") {
    return ALLOW;
  }
  const eco = analyzeEcosystem(classification.ecosystem);
  if (eco === null) {
    return { decision: "ask", reason: `dg cannot yet verify ${manager} packages` };
  }
  if (parsed.viaXargs) {
    // xargs feeds the real package list on stdin, unknowable statically.
    return undecidableVerdict(env, `dg cannot statically verify an xargs-fed ${manager} install (packages arrive on stdin)`);
  }
  const extracted = extractSpecs(manager, eco, args);
  const { remoteUnverifiable, dynamic } = extracted;
  let specs = extracted.specs;
  if (dynamic.length > 0) {
    return undecidableVerdict(env, `dg cannot statically verify a dynamically-built package name (${dynamic.join(", ")})`);
  }

  // No package named: a manifest install (npm install / npm ci / bare yarn,
  // pip install -r). Screen the manifest's direct dependencies so a cloned
  // hostile repo can't slip a malicious direct package past the static hook;
  // the transitive tree stays the runtime network gate's job.
  let manifestTruncated = false;
  if (specs.length === 0 && remoteUnverifiable.length === 0) {
    const manifest = eco === "npm" ? readNpmManifestSpecs(cwd) : readPipRequirementSpecs(args, cwd);
    if (manifest) {
      specs = manifest.specs;
      manifestTruncated = manifest.truncated;
    }
  }

  if (specs.some((s) => CONTROL_CHARS.test(s.name) || (s.version !== null && CONTROL_CHARS.test(s.version)))) {
    return { decision: "deny", reason: `dg refused a ${manager} install with a malformed package spec` };
  }

  const alternateIndexes = extractAlternateIndexes(eco, args, env);
  const unverifiableReasons: string[] = [];
  if (remoteUnverifiable.length > 0) {
    unverifiableReasons.push(`non-registry source${remoteUnverifiable.length > 1 ? "s" : ""}: ${remoteUnverifiable.join(", ")}`);
  }
  if (alternateIndexes.length > 0) {
    unverifiableReasons.push(`a non-default index/registry dg does not screen against: ${alternateIndexes.join(", ")}`);
  }
  if (manifestTruncated) {
    unverifiableReasons.push("more manifest dependencies than the static hook screens — enable the network gate for full coverage");
  }
  const unverifiable: AgentVerdict | null =
    unverifiableReasons.length > 0
      ? { decision: "ask", reason: `dg cannot fully verify this install — ${unverifiableReasons.join("; ")}` }
      : null;
  if (specs.length === 0) {
    return unverifiable ?? ALLOW;
  }

  const resolved: { name: string; version: string }[] = [];
  for (const spec of specs) {
    let version = spec.version;
    if (!version) {
      version = await resolveLatest(eco, spec.name, fetchImpl);
      if (!version) {
        return {
          decision: "deny",
          reason: `could not resolve a version to verify ${spec.name} on ${eco}, so the install is blocked`,
        };
      }
    }
    resolved.push({ name: spec.name, version });
  }

  const cooldown = resolvePreflightCooldown(env, eco);
  let decisions;
  try {
    decisions = resolvePreflightDecisions(eco, cwd, env);
  } catch {
    decisions = null;
  }
  let response;
  try {
    response = await analyzePackages(resolved, {
      ecosystem: eco,
      env,
      fetchImpl,
      ...(cooldown ? { cooldown: cooldown.param } : {}),
    });
  } catch (error) {
    const message = error instanceof AnalyzeError ? error.message : "the dg scanner could not be reached";
    return {
      decision: "deny",
      reason: `could not verify ${resolved.map((r) => r.name).join(", ")}: ${message}; the install is blocked`,
    };
  }

  const verdicts: AgentPackageVerdict[] = [];
  for (const pkg of response.packages) {
    const isQuar = quarantined(pkg, cooldown, eco, decisions?.file.cooldownExemptions ?? []);
    // A per-package result with no action is a coverage gap, not a clean pass:
    // treat it as analysis_incomplete (blocking) so the firewall fails closed.
    let action: ScannerAction | "cooldown" = isQuar && pkg.action !== "block" ? "cooldown" : pkg.action ?? "analysis_incomplete";
    if (
      action === "warn" &&
      decisions &&
      matchDecision(pkg, decisions.ecosystem, decisions.file.decisions).acknowledged
    ) {
      action = "pass";
    }
    if (action !== "pass") {
      verdicts.push({ name: pkg.name, version: pkg.version, action, why: whyFor(pkg, action) });
    }
  }
  // Every requested spec must come back with a verdict. A package the scanner
  // omitted (partial/truncated/tampered response) must not be silently allowed.
  const returned = new Set(response.packages.map((p) => normalizeName(eco, p.name)));
  for (const spec of resolved) {
    if (!returned.has(normalizeName(eco, spec.name))) {
      verdicts.push({
        name: spec.name,
        version: spec.version,
        action: "analysis_incomplete",
        why: "scanner returned no verdict for this package",
      });
    }
  }
  const base = combinePackages(verdicts);
  if (unverifiable && base.decision === "allow") {
    return unverifiable;
  }
  if (base.decision === "allow" && resolved.length > 0) {
    return {
      decision: "allow",
      screened: resolved.map((r) => ({ name: r.name, version: r.version, ecosystem: eco })),
    };
  }
  return base;
}

async function runAgentCheck(input: AgentCheckInput): Promise<AgentVerdict> {
  const env = input.env ?? process.env;
  const cwd = input.cwd ?? process.cwd();
  const fetchImpl = input.fetchImpl ?? fetch;
  const segments = collectSegments(input.commandLine);
  if (segments.length === 0) {
    return ALLOW;
  }
  const results: AgentVerdict[] = [];
  for (const seg of segments) {
    results.push(await checkSegment(seg, env, cwd, fetchImpl));
  }
  return combine(results);
}

// The PreToolUse hook is killed by the agent at HOOK_TIMEOUT_MS (60s). A scanner
// or registry that is slow but not dead would let the hook die with no decision,
// which most agents read as allow — a silent fail-open. Race the whole check
// against a deadline comfortably under the hook budget and deny on expiry, so a
// slow path fails closed with margin to actually emit the verdict.
const CHECK_DEADLINE_MS = 45_000;

export async function agentCheckCommand(input: AgentCheckInput): Promise<AgentVerdict> {
  const deadlineMs = input.deadlineMs ?? CHECK_DEADLINE_MS;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<AgentVerdict>((resolve) => {
    timer = setTimeout(
      () => resolve({ decision: "deny", reason: `dg could not verify this install in time, so it is blocked. ${ESCALATE}` }),
      deadlineMs,
    );
    if (typeof timer.unref === "function") {
      timer.unref();
    }
  });
  try {
    return await Promise.race([runAgentCheck(input), deadline]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}
