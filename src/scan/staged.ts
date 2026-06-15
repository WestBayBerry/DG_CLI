import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { createTheme, type Theme } from "../presentation/theme.js";
import { resolvePresentation } from "../presentation/mode.js";
import { DEFAULT_CONFIG, loadUserConfig } from "../config/settings.js";
import { offerRememberSync, type RememberPackage, type SyncRememberPrompts } from "../decisions/remember-prompt.js";
import { packageKey } from "../decisions/apply.js";
import { loadDgFile, resolveAcceptedBy, warnUnreadableDgFile, type DgFile } from "../project/dgfile.js";
import { gitSync, gitTrimmed } from "../util/git.js";
import { promptYesNo } from "../util/tty-prompt.js";
import { GUARD_SELFTEST_ENV } from "../setup/git-hook.js";
import { isLockfileName } from "./collect.js";
import { runScannerScan, tryScannerScan, type ScannerScanOutcome } from "./scanner-report.js";
import type { ScanFinding, ScanReport } from "./types.js";
import { EXIT_USAGE_VERDICT, type CommandResult } from "../commands/types.js";

export interface StagedScanOptions {
  readonly hook: boolean;
  readonly targetPath?: string | null;
  readonly env?: NodeJS.ProcessEnv;
  readonly cwd?: string;
  readonly useDecisions?: boolean;
}

export type StagedDecisionContext = {
  readonly root: string;
  readonly file: DgFile;
  readonly prompts?: SyncRememberPrompts;
};

function emptyLocalReport(target: string): ScanReport {
  return {
    target,
    status: "unknown",
    projects: [],
    findings: [],
    errors: [],
    summary: {
      projectCount: 0,
      dependencyCount: 0,
      findingCount: 0,
      warnCount: 0,
      blockCount: 0,
      errorCount: 0
    }
  };
}

export function stagedLockfilePaths(cwd: string, env: NodeJS.ProcessEnv): string[] | null {
  const diff = gitSync(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], { cwd, env });
  if (!diff.ok) {
    return null;
  }
  return diff.stdout.split("\0").filter(Boolean).filter((path) => isLockfileName(basename(path)));
}

export function scopeStagedPaths(
  paths: readonly string[],
  root: string,
  cwd: string,
  targetPath: string | null
): string[] | null {
  if (!targetPath) {
    return [...paths];
  }
  const prefix = relative(safeRealpath(root), safeRealpath(resolve(safeRealpath(cwd), targetPath)));
  if (prefix.startsWith("..") || isAbsolute(prefix)) {
    return null;
  }
  if (prefix === "" || prefix === ".") {
    return [...paths];
  }
  const normalized = prefix.split(sep).join("/");
  return paths.filter((path) => path === normalized || path.startsWith(`${normalized}/`));
}

export function materializeStaged(relPaths: readonly string[], cwd: string, env: NodeJS.ProcessEnv): { dir: string; count: number } {
  const dir = mkdtempSync(join(tmpdir(), "dg-staged-"));
  let count = 0;
  for (const relative of relPaths) {
    const blob = gitSync(["show", `:${relative}`], { cwd, env });
    if (!blob.ok) {
      continue;
    }
    const destination = join(dir, relative);
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, blob.stdout, "utf8");
    count += 1;
  }
  return { dir, count };
}

export function runStagedScan(options: StagedScanOptions): CommandResult {
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const theme = createTheme(resolvePresentation().color);

  // git exports GIT_INDEX_FILE to real pre-commit runs; its absence separates dg's hook self-test from a user commit that inherited the env var.
  if (options.hook && env[GUARD_SELFTEST_ENV] === "1" && env.GIT_INDEX_FILE === undefined) {
    return { exitCode: 2, stdout: "", stderr: "dg guard-commit self-test: synthetic block (exit 2)\n" };
  }

  const root = gitTrimmed(["rev-parse", "--show-toplevel"], { cwd, env });
  if (!root) {
    return notARepoResult();
  }

  const onIncomplete = gitHookOnIncomplete(env);
  const lockfiles = stagedLockfilePaths(cwd, env);
  if (lockfiles === null) {
    return failOpen(theme, "could not read staged changes", onIncomplete);
  }
  const scoped = scopeStagedPaths(lockfiles, root, cwd, options.targetPath ?? null);
  if (scoped === null) {
    return outsideRepoResult(options.targetPath ?? "");
  }
  if (scoped.length === 0) {
    return { exitCode: 0, stdout: "", stderr: "" };
  }

  const dgFile = options.useDecisions === false ? null : loadDgFile(root);
  if (dgFile) {
    warnUnreadableDgFile(dgFile);
  }
  const usableDgFile = dgFile?.readable ? dgFile : null;

  const { dir, count } = materializeStaged(scoped, cwd, env);
  try {
    if (count === 0) {
      return failOpen(theme, "could not read the staged lockfile contents", onIncomplete);
    }
    const report = tryScannerScan(dir, emptyLocalReport(dir), env, usableDgFile);
    if (!report || !report.scanner) {
      return failOpen(theme, "could not reach the scanner", onIncomplete);
    }
    return decideStagedVerdict(report, env, options.hook, usableDgFile ? { root, file: usableDgFile } : undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export type StagedScanReportResult =
  | { result: CommandResult }
  | { report: ScanReport; outcome: ScannerScanOutcome };

export function stagedScanReport(options: {
  readonly targetPath?: string | null;
  readonly env?: NodeJS.ProcessEnv;
  readonly cwd?: string;
  readonly useDecisions?: boolean;
}): StagedScanReportResult {
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? process.cwd();

  const root = gitTrimmed(["rev-parse", "--show-toplevel"], { cwd, env });
  if (!root) {
    return { result: notARepoResult() };
  }
  const base: ScanReport = { ...emptyLocalReport(root), status: "pass" };

  const lockfiles = stagedLockfilePaths(cwd, env);
  if (lockfiles === null) {
    return { report: base, outcome: { kind: "failed", error: { kind: "worker", message: "could not read staged changes" } } };
  }
  const scoped = scopeStagedPaths(lockfiles, root, cwd, options.targetPath ?? null);
  if (scoped === null) {
    return { result: outsideRepoResult(options.targetPath ?? "") };
  }
  if (scoped.length === 0) {
    return { report: base, outcome: { kind: "skipped", reason: "no_lockfiles" } };
  }

  const dgFile = options.useDecisions === false ? null : loadDgFile(root);
  if (dgFile) {
    warnUnreadableDgFile(dgFile);
  }

  const { dir, count } = materializeStaged(scoped, cwd, env);
  try {
    if (count === 0) {
      return { report: base, outcome: { kind: "failed", error: { kind: "worker", message: "could not read the staged lockfile contents" } } };
    }
    return { report: base, outcome: runScannerScan(dir, base, env, dgFile?.readable ? dgFile : null) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function safeRealpath(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

function notARepoResult(): CommandResult {
  return { exitCode: EXIT_USAGE_VERDICT, stdout: "", stderr: "dg scan --staged: not a git repository.\n" };
}

function outsideRepoResult(targetPath: string): CommandResult {
  return { exitCode: EXIT_USAGE_VERDICT, stdout: "", stderr: `dg scan --staged: ${targetPath} is outside this repository.\n` };
}

export function decideStagedVerdict(
  report: ScanReport,
  env: NodeJS.ProcessEnv = process.env,
  hook = false,
  decisionContext?: StagedDecisionContext
): CommandResult {
  const theme = createTheme(resolvePresentation().color);
  const action = report.scanner?.action ?? report.status;
  const config = loadUserConfig(env);
  const count = report.summary.dependencyCount;
  const effective = config.policy.mode === "strict" ? action : report.decisions?.effectiveAction ?? action;
  const acknowledgedCount = report.decisions?.acknowledgedCount ?? 0;

  if (action === "block") {
    return { exitCode: 2, stdout: "", stderr: renderBlock(report.findings, theme) };
  }

  if (action === "error" || action === "unknown") {
    return scannerUnavailable(theme, config.gitHook.onIncomplete);
  }

  if (action === "warn") {
    if (acknowledgedCount > 0 && effective === "pass") {
      return {
        exitCode: 0,
        stdout: "",
        stderr: `  ${theme.paint("pass", "✓")} ${theme.paint("muted", `DG verified ${count} staged package${count === 1 ? "" : "s"} — ${acknowledgedCount} warning${acknowledgedCount === 1 ? "" : "s"} previously accepted (dg.json)`)}\n`
      };
    }
    if (acknowledgedCount > 0 && effective === "analysis_incomplete") {
      return decideIncomplete(config.gitHook.onIncomplete, theme);
    }
    const activeFindings = report.findings.filter((finding) => !finding.acknowledged);
    return decideWarn(activeFindings, theme, config.gitHook.onWarn, config.policy.mode, hook, stagedRememberOffer(report, decisionContext, env));
  }

  if (action === "analysis_incomplete") {
    return decideIncomplete(config.gitHook.onIncomplete, theme);
  }

  return { exitCode: 0, stdout: "", stderr: `  ${theme.paint("pass", "✓")} ${theme.paint("muted", `DG verified ${count} staged package${count === 1 ? "" : "s"} — clean`)}\n` };
}

function decideIncomplete(onIncomplete: "allow" | "block", theme: Theme): CommandResult {
  if (onIncomplete === "block") {
    return { exitCode: 1, stdout: "", stderr: incompleteNotice(theme, true) };
  }
  return { exitCode: 0, stdout: "", stderr: incompleteNotice(theme, false) };
}

export function stagedRememberOffer(
  report: ScanReport,
  decisionContext: StagedDecisionContext | undefined,
  env: NodeJS.ProcessEnv
): (() => void) | undefined {
  if (!decisionContext || !report.scanner || !report.decisions) {
    return undefined;
  }
  const annotations = report.decisions.packages;
  const packages: RememberPackage[] = [];
  for (const pkg of report.scanner.packages) {
    if ((pkg.action ?? "pass") !== "warn") {
      continue;
    }
    const annotation = annotations[packageKey(pkg.name, pkg.version)];
    if (!annotation || annotation.acknowledged) {
      continue;
    }
    packages.push({ ecosystem: annotation.ecosystem, name: pkg.name, version: pkg.version, findings: pkg.findings });
  }
  if (packages.length === 0) {
    return undefined;
  }
  return () => {
    offerRememberSync({
      file: decisionContext.file,
      packages,
      acceptedBy: resolveAcceptedBy(decisionContext.root, env),
      surface: "guard-commit",
      env,
      ...(decisionContext.prompts ? { prompts: decisionContext.prompts } : {})
    });
  };
}

function decideWarn(
  findings: readonly ScanFinding[],
  theme: Theme,
  onWarn: "prompt" | "allow" | "block",
  policyMode: string,
  hook: boolean,
  onAccepted?: () => void
): CommandResult {
  const summary = warnSummary(findings, theme);
  if (onWarn === "allow") {
    return { exitCode: 0, stdout: "", stderr: `${summary}  ${theme.paint("muted", "proceeding (gitHook.onWarn=allow)")}\n` };
  }
  if (onWarn === "block") {
    return { exitCode: 1, stdout: "", stderr: `${summary}  ${theme.paint("muted", "commit blocked (gitHook.onWarn=block). Use")} ${theme.paint("accent", "git commit --no-verify")} ${theme.paint("muted", "to override.")}\n` };
  }

  const answer = hook ? null : promptYesNo(`${summary}  ${theme.paint("accent", "Commit anyway?")}`, false);
  if (answer === null) {
    const proceed = policyMode === "warn" || policyMode === "off";
    if (proceed) {
      return { exitCode: 0, stdout: "", stderr: `${summary}  ${theme.paint("muted", `proceeding (no terminal; policy ${policyMode})`)}\n` };
    }
    return { exitCode: 1, stdout: "", stderr: `${summary}  ${theme.paint("muted", `commit blocked (no terminal; policy ${policyMode}). Use`)} ${theme.paint("accent", "git commit --no-verify")} ${theme.paint("muted", "to override.")}\n` };
  }
  if (answer) {
    onAccepted?.();
    return { exitCode: 0, stdout: "", stderr: "" };
  }
  return { exitCode: 1, stdout: "", stderr: `  ${theme.paint("muted", "Nothing was committed.")}\n` };
}

function warnSummary(findings: readonly ScanFinding[], theme: Theme): string {
  const warns = findings.filter((finding) => finding.severity === "warn");
  const lines = [`  ${theme.paint("warn", "⚠")} ${theme.paint("warn", `DG flagged ${warns.length} staged package${warns.length === 1 ? "" : "s"}`)}`];
  for (const finding of warns.slice(0, 5)) {
    lines.push(`    ${theme.paint("warn", "⚠")} ${finding.location}  ${theme.paint("muted", finding.message)}`);
  }
  if (warns.length > 5) {
    lines.push(`    ${theme.paint("muted", `…and ${warns.length - 5} more`)}`);
  }
  return `${lines.join("\n")}\n`;
}

function renderBlock(findings: readonly ScanFinding[], theme: Theme): string {
  const blocks = findings.filter((finding) => finding.severity === "block");
  const lines = [
    "",
    `  ${theme.paint("block", "✘ DG blocked this commit")} ${theme.paint("muted", "— a staged dependency is unsafe")}`
  ];
  for (const finding of blocks) {
    lines.push(`    ${theme.paint("block", "✘")} ${finding.location}  ${theme.paint("muted", finding.message)}`);
  }
  lines.push(`  ${theme.paint("muted", "Details:")}  ${theme.paint("accent", `dg verify ${blocks[0]?.location ?? "<package>"}`)}`);
  lines.push(`  ${theme.paint("muted", "Override:")} ${theme.paint("accent", "git commit --no-verify")} ${theme.paint("muted", "(installs nothing — only skips the check)")}`);
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function incompleteNotice(theme: Theme, blocked: boolean): string {
  const head = `  ${theme.paint("unknown", "?")} ${theme.paint("muted", "DG could not fully analyze the staged change")}`;
  if (blocked) {
    return `${head}\n  ${theme.paint("muted", "commit blocked (gitHook.onIncomplete=block). Use")} ${theme.paint("accent", "git commit --no-verify")} ${theme.paint("muted", "to override.")}\n`;
  }
  return `${head} ${theme.paint("muted", "— proceeding")}\n`;
}

function gitHookOnIncomplete(env: NodeJS.ProcessEnv): "allow" | "block" {
  try {
    return loadUserConfig(env).gitHook.onIncomplete;
  } catch {
    return DEFAULT_CONFIG.gitHook.onIncomplete;
  }
}

function failOpen(theme: Theme, reason: string, onIncomplete: "allow" | "block"): CommandResult {
  if (onIncomplete === "block") {
    return {
      exitCode: 1,
      stdout: "",
      stderr: `  ${theme.paint("unknown", "?")} ${theme.paint("muted", `DG could not verify (${reason}) — commit blocked (gitHook.onIncomplete=block). Use`)} ${theme.paint("accent", "git commit --no-verify")} ${theme.paint("muted", "to override.")}\n`
    };
  }
  return {
    exitCode: 0,
    stdout: "",
    stderr: `  ${theme.paint("unknown", "?")} ${theme.paint("muted", `DG could not verify (${reason}) — commit allowed (gitHook.onIncomplete=allow)`)}\n`
  };
}

function scannerUnavailable(theme: Theme, onIncomplete: "allow" | "block"): CommandResult {
  if (onIncomplete === "block") {
    return {
      exitCode: 1,
      stdout: "",
      stderr: `  ${theme.paint("unknown", "?")} ${theme.paint("muted", "dg: scanner unavailable — staged changes not verified; commit blocked (gitHook.onIncomplete=block). Use")} ${theme.paint("accent", "git commit --no-verify")} ${theme.paint("muted", "to override.")}\n`
    };
  }
  return {
    exitCode: 0,
    stdout: "",
    stderr: `  ${theme.paint("unknown", "?")} ${theme.paint("muted", "dg: scanner unavailable — staged changes not verified")}\n`
  };
}
