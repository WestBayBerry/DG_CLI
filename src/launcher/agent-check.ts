import { analyzePackages, AnalyzeError, type AnalyzeEcosystem, type ScannerAction, type ScannerPackageResult } from "../api/analyze.js";
import {
  classifyPackageManagerInvocation,
  isSupportedPackageManager,
  packageManagerNames,
  type Ecosystem,
  type PackageManager,
} from "./classify.js";
import { resolveLatest } from "../verify/package-check.js";
import { matchDecision } from "../decisions/apply.js";
import { isCooldownExempt, isCooldownExemptByDgFile } from "../policy/cooldown.js";
import type { CooldownExemption } from "../project/dgfile.js";
import { resolvePreflightCooldown, resolvePreflightDecisions, type PreflightCooldownContext } from "./install-preflight.js";

export type AgentDecision = "allow" | "deny" | "ask";

export interface AgentPackageVerdict {
  readonly name: string;
  readonly version: string;
  readonly action: ScannerAction | "cooldown";
  readonly why: string;
}

export interface AgentVerdict {
  readonly decision: AgentDecision;
  readonly reason?: string;
  readonly packages?: readonly AgentPackageVerdict[];
}

export interface AgentCheckInput {
  readonly commandLine: string;
  readonly cwd?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly fetchImpl?: typeof fetch;
}

const ALLOW: AgentVerdict = { decision: "allow" };

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
  return line.split(/&&|\|\||[;|&\n\r]/).map((s) => s.trim()).filter(Boolean);
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
    cur += ch;
    started = true;
    i += 1;
  }
  flush();
  return { tokens, ok: true };
}

const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const WRAPPER_COMMANDS = new Set(["sudo", "command", "exec", "env", "nice", "nohup", "time", "xargs"]);

function commandBasename(token: string): string {
  const slash = token.lastIndexOf("/");
  return slash === -1 ? token : token.slice(slash + 1);
}

function commandTokens(segment: string): LexedSegment {
  const lexed = lexSegment(segment);
  let tokens = lexed.tokens;
  for (;;) {
    while (tokens.length > 0 && ENV_ASSIGNMENT.test(tokens[0] ?? "")) {
      tokens = tokens.slice(1);
    }
    const head = tokens[0];
    if (head === undefined || !WRAPPER_COMMANDS.has(commandBasename(head))) {
      return { tokens, ok: lexed.ok };
    }
    tokens = tokens.slice(1);
    while (tokens.length > 0 && (tokens[0] ?? "").startsWith("-")) {
      tokens = tokens.slice(1);
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

function extractSpecs(manager: string, eco: AnalyzeEcosystem, rawArgs: readonly string[]): ExtractedSpecs {
  const valueFlags = eco === "pypi" ? PIP_VALUE_FLAGS : NPM_VALUE_FLAGS;
  const noVerb = manager === "npx" || manager === "pnpx" || manager === "uvx";
  const positionals: string[] = [];
  let seenVerb = noVerb;
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
    if (!seenVerb) {
      seenVerb = true;
      continue;
    }
    positionals.push(a);
  }
  const tokens = noVerb ? positionals.slice(0, 1) : positionals;
  const specs: Spec[] = [];
  const remoteUnverifiable: string[] = [];
  for (const t of tokens) {
    if (t.length === 0) {
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
  return { specs, remoteUnverifiable };
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

function combine(results: AgentVerdict[]): AgentVerdict {
  return results.find((v) => v.decision === "deny") ?? results.find((v) => v.decision === "ask") ?? ALLOW;
}

async function checkSegment(
  segment: string,
  env: NodeJS.ProcessEnv,
  cwd: string,
  fetchImpl: typeof fetch,
): Promise<AgentVerdict> {
  const { tokens, ok } = commandTokens(segment);
  const manager = commandBasename(tokens[0] ?? "");
  if (!manager || !packageManagerNames().includes(manager as PackageManager) || !isSupportedPackageManager(manager as PackageManager)) {
    return ALLOW;
  }
  if (!ok) {
    // Head is a package manager but the segment could not be parsed safely
    // (unbalanced quote / trailing escape). Never wave it through.
    return { decision: "ask", reason: `dg could not safely parse this ${manager} command; proceed only if you trust it` };
  }
  const args = tokens.slice(1);
  const classification = classifyPackageManagerInvocation(manager as PackageManager, args);
  if (classification.kind !== "protected") {
    return ALLOW;
  }
  const eco = analyzeEcosystem(classification.ecosystem);
  if (eco === null) {
    return { decision: "ask", reason: `dg cannot yet verify ${manager} packages; proceed manually if you trust them` };
  }
  const { specs, remoteUnverifiable } = extractSpecs(manager, eco, args);
  const unverifiable: AgentVerdict | null =
    remoteUnverifiable.length > 0
      ? {
          decision: "ask",
          reason: `dg cannot verify non-registry source${remoteUnverifiable.length > 1 ? "s" : ""}: ${remoteUnverifiable.join(", ")}; proceed only if you trust ${remoteUnverifiable.length > 1 ? "them" : "it"}`,
        }
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
          reason: `could not resolve a version to verify ${spec.name} on ${eco}; refusing under the firewall`,
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
      reason: `could not verify ${resolved.map((r) => r.name).join(", ")}: ${message}; blocked under the firewall (disable: dg hook <agent> off)`,
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
  return base;
}

export async function agentCheckCommand(input: AgentCheckInput): Promise<AgentVerdict> {
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
