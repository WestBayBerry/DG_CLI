import { describeCooldownSettings, durationToDays, formatCooldownDuration } from "../policy/cooldown.js";
import { readHeldPackages, type HeldPackageEntry } from "../state/index.js";
import { canonicalCooldownName } from "../policy/pypi-name.js";
import { ConfigError, loadUserConfig, setConfigValue, updateUserConfig } from "../config/settings.js";
import {
  appendCooldownExemptions,
  cooldownExemptionActive,
  CooldownExemptionCapError,
  findProjectRoot,
  loadDgFile,
  mutateDgFile,
  removeCooldownExemptions,
  resolveAcceptedBy,
  type CooldownExemption,
  type DgFile,
  type ExemptionEcosystem,
  type NewCooldownExemption
} from "../project/dgfile.js";
import { EXIT_USAGE, type CommandContext, type CommandResult, type CommandSpec } from "./types.js";

export const cooldownCommand: CommandSpec = {
  name: "cooldown",
  summary: "Hold new releases for a window before they can install, with per-package exemptions.",
  usage: "dg cooldown [<window>|off] [--json] | dg cooldown exempt <name> [--reason <text>] [--expires <30d>] | dg cooldown rm <name>",
  subcommands: [
    { name: "list", summary: "Show the cooldown window and exemptions (default).", usage: "dg cooldown list [--json]", details: [], handler: () => unreachable() },
    { name: "<window>", summary: "Set the window directly: dg cooldown 7d, dg cooldown 24h, dg cooldown off.", usage: "dg cooldown <7d|24h|off>", details: [], handler: () => unreachable() },
    { name: "exempt", summary: "Always allow a package through cooldown.", usage: "dg cooldown exempt <name> [--reason <text>] [--expires <30d>] [--ecosystem npm|pypi]", details: [], handler: () => unreachable() },
    { name: "rm", summary: "Drop an exemption so cooldown applies again.", usage: "dg cooldown rm <name> [--ecosystem npm|pypi]", details: [], handler: () => unreachable() },
    { name: "prune", summary: "Remove expired exemptions.", usage: "dg cooldown prune", details: [], handler: () => unreachable() }
  ],
  flags: [
    { flag: "--reason", value: "<text>", summary: "Why this package is exempt (stored in dg.json)." },
    { flag: "--expires", value: "<30d>", summary: "Auto-expire the exemption after a duration (e.g. 14d, 90d)." },
    { flag: "--ecosystem", value: "<npm|pypi>", summary: "Ecosystem when the name is not prefixed (default npm)." },
    { flag: "--json", summary: "Machine-readable listing." }
  ],
  examples: [
    "dg cooldown",
    "dg cooldown 7d",
    "dg cooldown off",
    "dg cooldown exempt left-pad --reason 'vendored, pinned'",
    "dg cooldown exempt pypi:requests --expires 30d",
    "dg cooldown rm left-pad"
  ],
  details: [
    "Cooldown quarantines releases younger than your configured window so a freshly-published compromised version can't install before anyone notices. An exemption opts one package out — use it for internal packages you publish and install immediately, or a dependency you've already vetted. Exemptions live in dg.json at the git root; an --expires window makes them self-revoke so the quarantine comes back on its own."
  ],
  handler: (context) => runCooldownCommand(context)
};

function unreachable(): never {
  throw new Error("subcommand handled by the cooldown router");
}

export function runCooldownCommand(context: CommandContext, cwd: string = process.cwd(), env: NodeJS.ProcessEnv = process.env, now: Date = new Date()): CommandResult {
  const [first, ...rest] = context.args;

  if (first === undefined || first === "list" || first === "--json") {
    const json = first === "--json" || rest.includes("--json");
    const extras = rest.filter((arg) => arg !== "--json");
    if (extras.length > 0) {
      return usage(`unexpected argument '${extras[0]}'`);
    }
    return listExemptions(cwd, env, json, now);
  }

  if (first === "exempt") {
    return addExemption(rest, cwd, env, now);
  }

  if (first === "rm" || first === "remove") {
    return removeExemption(rest, cwd, env);
  }

  if (first === "prune") {
    return pruneExemptions(rest, cwd, env, now);
  }

  if (/^(0|off|[1-9]\d{0,3}[hd])$/i.test(first)) {
    return setWindow(first.toLowerCase(), rest, cwd, env, now);
  }

  return usage(`unknown subcommand '${first}'`);
}

function setWindow(window: string, rest: readonly string[], cwd: string, env: NodeJS.ProcessEnv, now: Date): CommandResult {
  if (rest.length > 0) {
    return usage(`unexpected argument '${rest[0]}'`);
  }
  try {
    updateUserConfig((current) => setConfigValue(current, "cooldown.age", window), env);
  } catch (error) {
    if (error instanceof ConfigError) {
      return usage(error.message);
    }
    throw error;
  }
  return listExemptions(cwd, env, false, now);
}

type ParsedFlags = {
  readonly positionals: readonly string[];
  readonly reason?: string;
  readonly expires?: string;
  readonly ecosystem?: string;
};

function parseFlags(args: readonly string[]): ParsedFlags | { error: string } {
  const positionals: string[] = [];
  let reason: string | undefined;
  let expires: string | undefined;
  let ecosystem: string | undefined;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === undefined) {
      continue;
    }
    if (arg === "--reason" || arg === "--expires" || arg === "--ecosystem") {
      const value = args[i + 1];
      if (value === undefined || value.startsWith("--")) {
        return { error: `${arg} needs a value` };
      }
      if (arg === "--reason") reason = value;
      else if (arg === "--expires") expires = value;
      else ecosystem = value;
      i += 1;
      continue;
    }
    if (arg.startsWith("--reason=")) reason = arg.slice("--reason=".length);
    else if (arg.startsWith("--expires=")) expires = arg.slice("--expires=".length);
    else if (arg.startsWith("--ecosystem=")) ecosystem = arg.slice("--ecosystem=".length);
    else if (arg.startsWith("--")) return { error: `unknown flag '${arg}'` };
    else positionals.push(arg);
  }
  return {
    positionals,
    ...(reason !== undefined ? { reason } : {}),
    ...(expires !== undefined ? { expires } : {}),
    ...(ecosystem !== undefined ? { ecosystem } : {})
  };
}

const EXEMPTION_NAME_RE = /^[@A-Za-z0-9][@A-Za-z0-9._/-]*$/u;

function resolveTarget(token: string, ecosystemFlag: string | undefined): { ecosystem: ExemptionEcosystem; name: string } | { error: string } {
  const colon = token.indexOf(":");
  if (colon > 0) {
    const prefix = token.slice(0, colon);
    if (prefix === "npm" || prefix === "pypi" || prefix === "cargo") {
      return validatedTarget(prefix, token.slice(colon + 1), token);
    }
    return { error: `unknown ecosystem prefix '${prefix}:' (only npm:, pypi:, and cargo: are supported)` };
  }
  const eco = ecosystemFlag ?? "npm";
  if (eco !== "npm" && eco !== "pypi" && eco !== "cargo") {
    return { error: `--ecosystem must be npm, pypi, or cargo, got '${eco}'` };
  }
  return validatedTarget(eco, token, token);
}

function validatedTarget(ecosystem: ExemptionEcosystem, name: string, token: string): { ecosystem: ExemptionEcosystem; name: string } | { error: string } {
  if (name.length === 0) {
    return { error: `'${token}' has no package name` };
  }
  if (!EXEMPTION_NAME_RE.test(name)) {
    return { error: `'${name}' is not a valid package name (no spaces, control characters, or '*' globs; use config cooldown.exempt for globs)` };
  }
  return { ecosystem, name: canonicalName(ecosystem, name) };
}

function canonicalName(ecosystem: ExemptionEcosystem, name: string): string {
  return canonicalCooldownName(ecosystem, name);
}

function expiresAtFrom(expires: string | undefined, now: Date): { value?: string } | { error: string } {
  if (expires === undefined || expires === "off" || expires === "never") {
    return {};
  }
  const days = durationToDays(expires);
  if (days <= 0) {
    if (/^[1-9]\d*(h|d)$/.test(expires)) {
      return { error: `--expires '${expires}' is too large (maximum is 9999d or 9999h)` };
    }
    return { error: `--expires must be a positive duration like 30d or 12h, got '${expires}'` };
  }
  return { value: new Date(now.getTime() + days * 24 * 60 * 60 * 1000).toISOString() };
}

function formatExpiryDisplay(expiresAt: string, acceptedAt: string): string {
  const expiry = Date.parse(expiresAt);
  const accepted = Date.parse(acceptedAt);
  if (Number.isFinite(expiry) && Number.isFinite(accepted) && expiry - accepted < 24 * 60 * 60 * 1000) {
    return `${expiresAt.slice(0, 16).replace("T", " ")}Z`;
  }
  return expiresAt.slice(0, 10);
}

function addExemption(args: readonly string[], cwd: string, env: NodeJS.ProcessEnv, now: Date): CommandResult {
  const parsed = parseFlags(args);
  if ("error" in parsed) {
    return usage(parsed.error);
  }
  if (parsed.positionals.length !== 1 || parsed.positionals[0] === undefined) {
    return usage("exempt takes exactly one <name>");
  }
  const target = resolveTarget(parsed.positionals[0], parsed.ecosystem);
  if ("error" in target) {
    return usage(target.error);
  }
  const expiry = expiresAtFrom(parsed.expires, now);
  if ("error" in expiry) {
    return usage(expiry.error);
  }
  const located = locateWritableDgFile(cwd, env);
  if ("error" in located) {
    return located.error;
  }
  const exemption: NewCooldownExemption = {
    ecosystem: target.ecosystem,
    name: target.name,
    reason: parsed.reason ?? "",
    acceptedBy: resolveAcceptedBy(located.root, env),
    ...(expiry.value ? { expiresAt: expiry.value } : {})
  };
  try {
    mutateDgFile(located.root, env, (file) => appendCooldownExemptions(file, [exemption], now));
  } catch (error) {
    if (error instanceof CooldownExemptionCapError) {
      return { exitCode: 1, stdout: "", stderr: `dg cooldown: ${error.message}.\n` };
    }
    throw error;
  }
  const until = expiry.value ? ` until ${formatExpiryDisplay(expiry.value, now.toISOString())}` : "";
  return {
    exitCode: 0,
    stdout: `Exempted ${target.ecosystem}:${target.name} from cooldown${until}.\n`,
    stderr: ""
  };
}

function removeExemption(args: readonly string[], cwd: string, env: NodeJS.ProcessEnv): CommandResult {
  const parsed = parseFlags(args);
  if ("error" in parsed) {
    return usage(parsed.error);
  }
  if (parsed.positionals.length !== 1 || parsed.positionals[0] === undefined) {
    return usage("rm takes exactly one <name>");
  }
  const target = resolveTarget(parsed.positionals[0], parsed.ecosystem);
  if ("error" in target) {
    return usage(target.error);
  }
  const located = locateWritableDgFile(cwd, env);
  if ("error" in located) {
    return located.error;
  }
  const matches = (e: CooldownExemption): boolean => e.ecosystem === target.ecosystem && e.name === target.name;
  let removed = false;
  mutateDgFile(located.root, env, (file) => {
    if (!file.cooldownExemptions.some(matches)) {
      return file;
    }
    removed = true;
    return removeCooldownExemptions(file, matches);
  });
  if (!removed) {
    return { exitCode: 1, stdout: "", stderr: `dg cooldown: ${target.ecosystem}:${target.name} is not exempt in ${located.file.path}.\n` };
  }
  return { exitCode: 0, stdout: `Removed cooldown exemption for ${target.ecosystem}:${target.name} — cooldown applies again.\n`, stderr: "" };
}

function pruneExemptions(args: readonly string[], cwd: string, env: NodeJS.ProcessEnv, now: Date): CommandResult {
  if (args.length > 0) {
    return usage(`unexpected argument '${args[0]}'`);
  }
  const located = locateWritableDgFile(cwd, env);
  if ("error" in located) {
    return located.error;
  }
  let pruned = 0;
  mutateDgFile(located.root, env, (file) => {
    const expired = (e: CooldownExemption): boolean => !cooldownExemptionActive(e, now);
    pruned = file.cooldownExemptions.filter(expired).length;
    return pruned === 0 ? file : removeCooldownExemptions(file, expired);
  });
  return { exitCode: 0, stdout: `Pruned ${pruned} expired cooldown exemption${pruned === 1 ? "" : "s"}.\n`, stderr: "" };
}

function windowStatusLines(env: NodeJS.ProcessEnv): string[] {
  const config = loadUserConfig(env);
  const window = describeCooldownSettings(config, env);
  const windowLine = window === "off"
    ? "off — new releases install immediately"
    : `${window}      set: dg cooldown 3d`;
  const unknownLine = config.cooldown.onUnknown === "block"
    ? "block (no known publish date → held back)"
    : "allow (no known publish date → not held back)";
  return [
    "Cooldown — versions published less than your window ago wait before installing.",
    "",
    `  window    ${windowLine}`,
    `  unknown   ${unknownLine}`,
    ""
  ];
}

const EXEMPTION_FOOTER = [
  "  add: dg cooldown exempt <name> [--expires 30d]   ·   remove: dg cooldown rm <name>",
  "  An exemption waives only the wait — the package is still scanned. No CVE fast-track yet."
];

function renderTable(columns: readonly string[], rows: readonly (readonly string[])[]): string[] {
  const widths = columns.map((label, column) => Math.max(label.length, ...rows.map((row) => row[column]?.length ?? 0)));
  const renderRow = (row: readonly string[]): string => `  ${row.map((cell, column) => cell.padEnd(widths[column] ?? 0)).join("  ").trimEnd()}`;
  return [renderRow(columns), ...rows.map(renderRow)];
}

function eligibleDisplay(entry: HeldPackageEntry, now: Date): string {
  if (!entry.eligibleAt) {
    return "unknown";
  }
  const eligible = Date.parse(entry.eligibleAt);
  if (!Number.isFinite(eligible)) {
    return "unknown";
  }
  const relative = formatCooldownDuration(Math.max(0, (eligible - now.getTime()) / 86_400_000));
  return `${entry.eligibleAt.slice(0, 10)} (in ${relative})`;
}

function heldSectionLines(env: NodeJS.ProcessEnv, now: Date): string[] {
  const held = readHeldPackages(env, now);
  if (held.length === 0) {
    return ["Currently held: none.", ""];
  }
  const rows = held.map((entry) => [
    `${entry.ecosystem}:${entry.name}@${entry.version}`,
    entry.publishedAt ? entry.publishedAt.slice(0, 10) : "-",
    eligibleDisplay(entry, now)
  ]);
  return [
    "Currently held:",
    "",
    ...renderTable(["PACKAGE", "PUBLISHED", "ELIGIBLE"], rows),
    "",
    "  release now: dg cooldown exempt <name>",
    ""
  ];
}

function listExemptions(cwd: string, env: NodeJS.ProcessEnv, json: boolean, now: Date): CommandResult {
  const root = findProjectRoot(cwd, env);
  if (!root) {
    return { exitCode: EXIT_USAGE, stdout: "", stderr: "dg cooldown: not inside a git repository.\n" };
  }
  const file = loadDgFile(root);
  if (file.exists && !file.readable) {
    return { exitCode: 1, stdout: "", stderr: `dg cooldown: cannot use ${file.path} — ${file.failure ?? "unreadable"}.\n` };
  }
  const config = loadUserConfig(env);
  if (json) {
    return {
      exitCode: 0,
      stdout: `${JSON.stringify({
        schemaVersion: 1,
        path: file.path,
        window: { effective: describeCooldownSettings(config, env), onUnknown: config.cooldown.onUnknown },
        held: readHeldPackages(env, now),
        cooldownExemptions: file.cooldownExemptions.map((e) => exemptionJson(e, now))
      }, null, 2)}\n`,
      stderr: ""
    };
  }
  const header = [...windowStatusLines(env), ...heldSectionLines(env, now)];
  if (file.cooldownExemptions.length === 0) {
    const note = file.exists ? `No exemptions in ${file.path}.` : "No exemptions yet — add one with the command below.";
    return { exitCode: 0, stdout: `${[...header, note, ...EXEMPTION_FOOTER].join("\n")}\n`, stderr: "" };
  }
  const rows = file.cooldownExemptions.map((e) => [
    `${e.ecosystem}:${e.name}`,
    e.reason || "-",
    e.acceptedBy || "-",
    e.acceptedAt.slice(0, 10) || "-",
    e.expiresAt ? formatExpiryDisplay(e.expiresAt, e.acceptedAt) : "-",
    cooldownExemptionActive(e, now) ? "active" : "expired"
  ]);
  const lines = [
    ...header,
    `Exemptions in ${file.path}:`,
    "",
    ...renderTable(["PACKAGE", "REASON", "BY", "WHEN", "EXPIRES", "STATUS"], rows),
    "",
    ...EXEMPTION_FOOTER
  ];
  return { exitCode: 0, stdout: `${lines.join("\n")}\n`, stderr: "" };
}

function locateWritableDgFile(cwd: string, env: NodeJS.ProcessEnv): { root: string; file: DgFile } | { error: CommandResult } {
  const root = findProjectRoot(cwd, env);
  if (!root) {
    return { error: { exitCode: EXIT_USAGE, stdout: "", stderr: "dg cooldown: not inside a git repository.\n" } };
  }
  const file = loadDgFile(root);
  if (!file.readable) {
    return { error: { exitCode: 1, stdout: "", stderr: `dg cooldown: cannot write ${file.path} — ${file.failure ?? "unreadable"}.\n` } };
  }
  return { root, file };
}

function exemptionJson(e: CooldownExemption, now: Date): Record<string, unknown> {
  return {
    ecosystem: e.ecosystem,
    name: e.name,
    reason: e.reason,
    acceptedBy: e.acceptedBy,
    acceptedAt: e.acceptedAt,
    ...(e.expiresAt ? { expiresAt: e.expiresAt } : {}),
    status: cooldownExemptionActive(e, now) ? "active" : "expired"
  };
}

function usage(message: string): CommandResult {
  return {
    exitCode: EXIT_USAGE,
    stdout: "",
    stderr: `dg cooldown: ${message}. Usage: ${cooldownCommand.usage}\n`
  };
}
