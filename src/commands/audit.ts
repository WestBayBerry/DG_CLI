import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { writeReportAtomic } from "../util/report-writer.js";
import type { CommandResult, CommandSpec } from "./types.js";
import { EXIT_TOOL_ERROR, EXIT_USAGE_VERDICT } from "./types.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme, type Role, type Theme } from "../presentation/theme.js";
import { actionForFindings, detectFindings, findingLocation, type AuditContext, type AuditFinding } from "../audit/detectors.js";
import { buildAuditFile } from "../publish-set/collect.js";
import { npmPublishSet } from "../publish-set/npm.js";
import { pypiPublishSet } from "../publish-set/pypi.js";
import { deepDecision, runDeepUpload, consentGiven, deepSummary, teamPolicyBlocksUpload, type DeepResult } from "../audit/deep.js";
import { loadUserConfig, saveUserConfig, setConfigValue } from "../config/settings.js";
import { promptYesNo } from "../util/tty-prompt.js";
import { authStatus } from "../auth/store.js";
import { shouldLaunchAuditTui, launchAuditTui } from "../audit-ui/launch.js";
import { renderCommandHelp } from "./help.js";

export type AuditFormat = "text" | "json";
export type AuditAction = "pass" | "warn" | "block";

export interface ParsedAuditArgs {
  readonly target: string;
  readonly format: AuditFormat;
  readonly outputPath: string | null;
  readonly local: boolean;
  readonly requireDeep: boolean;
  readonly failOn: "warn" | "block";
}

export interface PackageScope {
  readonly root: string;
  readonly ecosystem: "npm" | "pypi" | "cargo" | "unknown";
  readonly packageJson: Record<string, unknown> | null;
  readonly artifact: string;
}

interface AuditReport {
  readonly target: string;
  readonly artifact: string;
  readonly ecosystem: string;
  readonly action: AuditAction;
  readonly fileCount: number;
  readonly publishSetSource: string;
  readonly findings: readonly AuditFinding[];
  readonly deep: DeepResult;
}

export const auditCommand: CommandSpec = {
  name: "audit",
  summary: "Audit the package you're about to publish for leaked secrets and risky files.",
  usage: "dg audit [path] [--json] [--output <path>] [--local] [--require-deep] [--fail-on <warn|block>]",
  args: [
    { name: "[path]", summary: "Package directory to audit (default: the nearest package from the current directory)." }
  ],
  flags: [
    { flag: "--json", summary: "Machine-readable report." },
    { flag: "--output", value: "<path>", summary: "Write the report to a file (alias -o)." },
    { flag: "--local", summary: "Run only the local audit; skip the paid deep behavioral upload." },
    { flag: "--require-deep", summary: "Fail if the deep behavioral audit could not run (for CI)." },
    { flag: "--fail-on", value: "<warn|block>", summary: "Exit non-zero at or above this level (default: block)." }
  ],
  examples: ["dg audit", "dg audit ./packages/api", "dg audit --json", "dg audit --local"],
  details: [
    "Audits exactly what you're about to publish — the resolved publish set of one package, never the whole repo.",
    "Basic checks run 100% locally and never upload anything. If you're on a paid plan (and your org allows it), it also runs a deep behavioral scan of your package on the scanner; raw bytes are never retained. Exit codes: 0 clean (warn counts as clean under the default --fail-on block), 1 warn with --fail-on warn, 2 block, 3 deep audit required but unavailable (--require-deep), 4 analysis incomplete, 64 usage error."
  ],
  handler: (context) => runAuditCommand(context.args)
};

export interface Gathered {
  readonly parsed: ParsedAuditArgs;
  readonly scope: PackageScope;
  readonly localAction: AuditAction;
  readonly findings: readonly AuditFinding[];
  readonly publishSetSource: string;
  readonly fileCount: number;
}

function privatePackageResult(scope: PackageScope): CommandResult {
  const theme = createTheme(resolvePresentation().color);
  const name = typeof scope.packageJson?.name === "string" ? scope.packageJson.name : basename(scope.root);
  return {
    exitCode: 0,
    stdout: `${theme.paint("pass", "✓")} ${name} is private — npm refuses to publish it, so there is nothing to audit ${theme.paint("muted", "(remove \"private\": true to audit it for publish)")}\n`,
    stderr: ""
  };
}

function gather(args: readonly string[]): Gathered | { error: string; usage: true } | { error: string; usage: false } | { privatePackage: PackageScope } {
  const parsed = parseAuditArgs(args);
  if ("error" in parsed) {
    return { error: parsed.error, usage: true };
  }
  const scope = resolveScope(parsed.target);
  if ("error" in scope) {
    return { error: scope.error, usage: false };
  }
  if (scope.ecosystem === "npm" && scope.packageJson?.private === true) {
    return { privatePackage: scope };
  }
  const set = scope.ecosystem === "pypi" ? pypiPublishSet(scope.root) : npmPublishSet(scope.root);
  const files = set.relPaths
    .map((relPath) => buildAuditFile(scope.root, relPath))
    .filter((file): file is NonNullable<typeof file> => file !== null);
  const context: AuditContext = {
    packageJson: scope.packageJson,
    ecosystem: scope.ecosystem,
    hasFilesAllowlist: set.hasAllowlist,
    fileCount: files.length
  };
  const findings = detectFindings(files, context);
  return { parsed, scope, localAction: actionForFindings(findings), findings, publishSetSource: set.source, fileCount: files.length };
}

function finalize(gathered: Gathered, deep: DeepResult): CommandResult {
  const { parsed, scope } = gathered;
  const report: AuditReport = {
    target: displayTarget(scope.root),
    artifact: scope.artifact,
    ecosystem: scope.ecosystem,
    action: combineAction(gathered.localAction, deep),
    fileCount: gathered.fileCount,
    publishSetSource: gathered.publishSetSource,
    findings: gathered.findings,
    deep
  };
  const theme = createTheme(resolvePresentation().color);
  const rendered = parsed.format === "json" ? `${JSON.stringify({ schemaVersion: 1, ...report }, null, 2)}\n` : renderReport(report, theme);
  if (parsed.outputPath) {
    try {
      writeReportAtomic(resolve(parsed.outputPath), rendered);
    } catch (error) {
      return { exitCode: EXIT_TOOL_ERROR, stdout: "", stderr: `dg audit could not write ${parsed.outputPath}: ${error instanceof Error ? error.message : "write error"}\n` };
    }
    return { exitCode: exitCodeFor(report, parsed), stdout: `Wrote ${parsed.format} audit report to ${parsed.outputPath}\n`, stderr: "" };
  }
  return { exitCode: exitCodeFor(report, parsed), stdout: rendered, stderr: "" };
}

function gatherError(gathered: { error: string; usage: boolean }): CommandResult {
  return gathered.usage ? usageError(gathered.error) : { exitCode: EXIT_USAGE_VERDICT, stdout: "", stderr: `dg audit: ${gathered.error}.\n` };
}

function runAuditCommand(args: readonly string[]): CommandResult {
  const gathered = gather(args);
  if ("error" in gathered) {
    return gatherError(gathered);
  }
  if ("privatePackage" in gathered) {
    return privatePackageResult(gathered.privatePackage);
  }
  const decision = deepDecision(gathered.scope, gathered.parsed.local);
  return finalize(gathered, { ran: false, reason: decision.reason });
}

export async function maybeAudit(args: readonly string[]): Promise<{ handled: boolean; result: CommandResult }> {
  if (args[0] !== "audit") {
    return { handled: false, result: { exitCode: 0, stdout: "", stderr: "" } };
  }
  const sub = args.slice(1);
  if (sub[0] === "--help" || sub[0] === "-h" || sub[0] === "help") {
    return { handled: true, result: { exitCode: 0, stdout: renderCommandHelp(auditCommand), stderr: "" } };
  }
  const gathered = gather(sub);
  if ("error" in gathered) {
    return { handled: true, result: gatherError(gathered) };
  }
  if ("privatePackage" in gathered) {
    return { handled: true, result: privatePackageResult(gathered.privatePackage) };
  }

  let decision = deepDecision(gathered.scope, gathered.parsed.local);
  if (!decision.upload && canPromptConsent(gathered)) {
    if (!(await teamPolicyBlocksUpload())) {
      if (grantConsentInteractively()) {
        decision = deepDecision(gathered.scope, gathered.parsed.local);
      }
    }
  }

  if (shouldLaunchAuditTui({ format: gathered.parsed.format, outputPath: gathered.parsed.outputPath })) {
    const uploadAbort = new AbortController();
    const deepPromise = decision.upload
      ? runDeepUpload(gathered.scope, gathered.scope.packageJson, { signal: uploadAbort.signal })
      : null;
    const initialDeep: DeepResult | null = decision.upload ? null : { ran: false, reason: decision.reason };
    const exitCode = await launchAuditTui({ gathered, initialDeep, deepPromise });
    uploadAbort.abort();
    return { handled: true, result: { exitCode, stdout: "", stderr: "" } };
  }

  if (!decision.upload) {
    return { handled: true, result: finalize(gathered, { ran: false, reason: decision.reason }) };
  }
  try {
    const deep = await runDeepUpload(gathered.scope, gathered.scope.packageJson);
    return { handled: true, result: finalize(gathered, deep) };
  } catch (error) {
    const reason = error instanceof Error ? error.message : "deep audit failed";
    return { handled: true, result: finalize(gathered, { ran: false, reason }) };
  }
}

function canPromptConsent(gathered: Gathered): boolean {
  return (
    !gathered.parsed.local &&
    gathered.parsed.format !== "json" &&
    !gathered.parsed.outputPath &&
    gathered.scope.ecosystem === "npm" &&
    Boolean(process.stdin.isTTY && process.stderr.isTTY) &&
    !consentGiven() &&
    safeAuthed()
  );
}

function safeAuthed(): boolean {
  try {
    return authStatus().authenticated;
  } catch {
    return false;
  }
}

function grantConsentInteractively(): boolean {
  process.stderr.write(
    "\n  dg audit can also run a deep behavioral scan of this package on Dependency Guardian's scanner.\n" +
      "  That uploads a packed copy of your package (no lifecycle scripts run); raw bytes are never retained,\n" +
      "  only the verdict + redacted findings are recorded to your dashboard.\n"
  );
  const yes = promptYesNo("  Enable the deep upload for this machine?", false);
  if (yes === true) {
    try {
      saveUserConfig(setConfigValue(loadUserConfig(), "audit.upload", "true"));
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

export function combineAction(local: AuditAction, deep: DeepResult): AuditAction {
  if (deep.ran && deep.action === "block") {
    return "block";
  }
  if (deep.ran && deep.action === "warn" && local === "pass") {
    return "warn";
  }
  return local;
}

export function auditExitCode(
  localAction: AuditAction,
  deep: DeepResult,
  policy: { readonly requireDeep: boolean; readonly failOn: "warn" | "block" }
): number {
  const action = combineAction(localAction, deep);
  if (policy.requireDeep && !deep.ran) {
    return 3;
  }
  if (deep.ran && deep.action === "analysis_incomplete" && action !== "block") {
    return 4;
  }
  if (action === "block") {
    return 2;
  }
  if (action === "warn") {
    return policy.failOn === "warn" ? 1 : 0;
  }
  return 0;
}

function exitCodeFor(report: AuditReport, parsed: ParsedAuditArgs): number {
  return auditExitCode(report.action, report.deep, { requireDeep: parsed.requireDeep, failOn: parsed.failOn });
}

function resolveScope(target: string): PackageScope | { error: string } {
  const absolute = resolve(target);
  if (!existsSync(absolute)) {
    return { error: `path does not exist: ${target}` };
  }
  const start = statSync(absolute).isDirectory() ? absolute : dirname(absolute);
  const root = findPackageRoot(start);
  if (!root) {
    return { error: "no package manifest found here — run inside the package you're publishing, or pass its path" };
  }
  if (existsSync(resolve(root, "package.json"))) {
    const packageJson = safeReadJson(resolve(root, "package.json"));
    const name = packageJson && typeof packageJson.name === "string" ? packageJson.name : basename(root);
    const version = packageJson && typeof packageJson.version === "string" ? packageJson.version : "(unknown)";
    return { root, ecosystem: "npm", packageJson, artifact: `${name}@${version}` };
  }
  if (existsSync(resolve(root, "pyproject.toml")) || existsSync(resolve(root, "setup.py")) || existsSync(resolve(root, "setup.cfg"))) {
    return { root, ecosystem: "pypi", packageJson: null, artifact: basename(root) };
  }
  if (existsSync(resolve(root, "Cargo.toml"))) {
    return { root, ecosystem: "cargo", packageJson: null, artifact: basename(root) };
  }
  return { root, ecosystem: "unknown", packageJson: null, artifact: basename(root) };
}

function findPackageRoot(start: string): string | null {
  let current = start;
  for (let depth = 0; depth < 40; depth += 1) {
    if (
      existsSync(resolve(current, "package.json")) ||
      existsSync(resolve(current, "pyproject.toml")) ||
      existsSync(resolve(current, "setup.py")) ||
      existsSync(resolve(current, "setup.cfg")) ||
      existsSync(resolve(current, "Cargo.toml"))
    ) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
  return null;
}

const WARN_GLYPH = "\u26A0\uFE0E";

function renderReport(report: AuditReport, theme: Theme): string {
  const muted = (text: string): string => theme.paint("muted", text);
  const accent = (text: string): string => theme.paint("accent", text);
  const role: Role = report.action === "block" ? "block" : report.action === "warn" ? "warn" : "pass";
  const glyph = report.action === "block" ? "✘" : report.action === "warn" ? WARN_GLYPH : "✓";

  const blocking = report.findings.filter((finding) => finding.severity >= 4).length;
  const warnings = report.findings.filter((finding) => finding.severity === 3).length;
  const notes = report.findings.filter((finding) => finding.severity < 3).length;
  const counts = [
    blocking ? `${blocking} blocking` : "",
    warnings ? `${warnings} warning${warnings === 1 ? "" : "s"}` : "",
    notes ? `${notes} note${notes === 1 ? "" : "s"}` : ""
  ].filter(Boolean).join(" · ") || "no issues";
  const fileLabel = `${report.fileCount} file${report.fileCount === 1 ? "" : "s"}`;
  const fallback = report.publishSetSource === "fallback" ? " · publish set approximated" : "";

  const lines = [
    ...verdictBox([
      `${theme.paint(role, `${glyph} ${report.action.toUpperCase()}`)}   ${accent(report.artifact)} ${muted(`· ${report.ecosystem}`)}`,
      muted(`${counts} in ${fileLabel}${fallback}`)
    ], theme, role),
    ""
  ];

  for (const finding of report.findings) {
    const tag = finding.severity >= 4
      ? theme.paint("block", "✘")
      : finding.severity >= 3
        ? theme.paint("warn", WARN_GLYPH)
        : theme.paint("muted", "·");
    lines.push(`  ${tag} ${accent(findingLocation(finding))}`);
    lines.push(`     ${finding.title}`);
    if (finding.evidence && finding.evidence !== `path: ${finding.location}` && finding.evidence !== finding.location) {
      lines.push(`     ${muted(finding.evidence)}`);
    }
    lines.push(`     ${accent("→")} ${finding.recommendation}`);
    lines.push("");
  }

  lines.push(`  ${muted(`Deep behavioral scan · ${deepSummary(report.deep)}`)}`);
  return `${lines.join("\n")}\n`;
}

function visibleWidth(text: string): number {
  return text.replace(/\u001b\[[0-9;]*m/g, "").replace(/[\uFE0E\uFE0F]/gu, "").length;
}

function verdictBox(content: readonly string[], theme: Theme, role: Role): string[] {
  const inner = Math.max(...content.map(visibleWidth));
  const edge = (text: string): string => theme.paint(role, text);
  return [
    `  ${edge(`╭${"─".repeat(inner + 2)}╮`)}`,
    ...content.map((line) => `  ${edge("│")} ${line}${" ".repeat(inner - visibleWidth(line))} ${edge("│")}`),
    `  ${edge(`╰${"─".repeat(inner + 2)}╯`)}`
  ];
}

function parseAuditArgs(args: readonly string[]): ParsedAuditArgs | { error: string } {
  let target = ".";
  let sawTarget = false;
  let format: AuditFormat = "text";
  let outputPath: string | null = null;
  let local = false;
  let requireDeep = false;
  let failOn: "warn" | "block" = "block";

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg) {
      return { error: "empty argument" };
    }
    if (arg === "--json") {
      format = "json";
    } else if (arg === "--local") {
      local = true;
    } else if (arg === "--require-deep") {
      requireDeep = true;
    } else if (arg === "--output" || arg === "-o") {
      const next = args[index + 1];
      if (!next) {
        return { error: `${arg} requires a path` };
      }
      outputPath = next;
      index += 1;
    } else if (arg === "--fail-on") {
      const next = args[index + 1];
      if (next !== "warn" && next !== "block") {
        return { error: "--fail-on requires 'warn' or 'block'" };
      }
      failOn = next;
      index += 1;
    } else if (arg.startsWith("--fail-on=")) {
      const value = arg.slice("--fail-on=".length);
      if (value !== "warn" && value !== "block") {
        return { error: "--fail-on requires 'warn' or 'block'" };
      }
      failOn = value;
    } else if (arg.startsWith("-")) {
      return { error: `unknown option '${arg}'` };
    } else if (sawTarget) {
      return { error: "audit accepts at most one path" };
    } else {
      target = arg;
      sawTarget = true;
    }
  }

  if (local && requireDeep) {
    return { error: "--local skips the deep audit, so it cannot be combined with --require-deep" };
  }

  return { target, format, outputPath, local, requireDeep, failOn };
}

export function displayTarget(root: string): string {
  const rel = root.startsWith(process.cwd()) ? root.slice(process.cwd().length).replace(/^[/\\]/u, "") : root;
  return rel.length === 0 ? "." : rel;
}

function safeReadJson(path: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function usageError(message: string): CommandResult {
  return {
    exitCode: EXIT_USAGE_VERDICT,
    stdout: "",
    stderr: `dg audit: ${message}. Usage: ${auditCommand.usage}\n`
  };
}
