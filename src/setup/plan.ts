import { accessSync, constants, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, delimiter, dirname, join, resolve, sep } from "node:path";
import { chmodSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { createTheme, type Role, type Theme } from "../presentation/theme.js";
import { AGENTS, AGENT_IDS, agentLabel, resolveAgentHookContext, reverseAgentHookEntry } from "../agents/registry.js";
import { GATE_ENABLE_HINT, readNetworkGatePosture } from "../agents/gate-posture.js";
import {
  acquireLockSync,
  findStaleSessionsSync,
  preserveCorruptCleanupRegistrySync,
  resolveDgPaths,
  sweepStaleSessionsSync,
  CLEANUP_REGISTRY_LOCK,
  type CleanupRegistry,
  type CleanupRegistryEntry,
  type DgPathEnvironment,
  type DgPaths
} from "../state/index.js";
import { currentNodeVersion, isSupportedNode } from "../runtime/node-version.js";
import { dgVersion } from "../commands/version.js";
import { compareVersions, readLatestVersion } from "../commands/update.js";
import { AuthError, authStatus, displayTier, readAuthState } from "../auth/store.js";
import { ConfigError, DEFAULT_CONFIG, loadUserConfig } from "../config/settings.js";
import { describeCooldownSettings } from "../policy/cooldown.js";
import { resolveRealBinary } from "../launcher/resolve-real-binary.js";
import { packageManagerNames } from "../launcher/classify.js";
import { readServiceState } from "../service/state.js";
import { OPTIONAL_SUPPORT_GATES } from "./optional-support.js";

export const SHIM_COMMANDS = Object.freeze(["npm", "npx", "pnpm", "pnpx", "yarn", "pip", "pip3", "pipx", "uv", "uvx", "cargo"]);
export const SHIM_SENTINEL = "dg-shim-v1";
export const RC_SENTINEL = "dg-shell-rc-v1";
export const RC_FUNCTIONS_SENTINEL = "dg-shim-functions-v1";
const RC_SHIM_HELPER = "__dg_shim";
export const GUARD_HOOK_SENTINEL = "dg-git-hook-v1";
export const RC_BEGIN = "# >>> dg setup >>>";
export const RC_END = "# <<< dg setup <<<";
const LEGACY_RC_MARKERS: ReadonlyArray<{ readonly begin: string; readonly end: string }> = [
  { begin: "# >>> dg-managed >>>", end: "# <<< dg-managed <<<" }
];
const LEGACY_RC_CANDIDATES = [".zshrc", ".bashrc", ".bash_profile", ".profile", join(".config", "fish", "config.fish")];
const LEGACY_PYTHON_HOOK_PY = "dg_pip_hook.py";
const LEGACY_PYTHON_HOOK_PTH = "dg_pip_hook.pth";
const LEGACY_PYTHON_HOOK_MARKER = "Dependency Guardian pip-install interceptor";
const LEGACY_PYTHON_HOOK_PTH_MARKER = "import dg_pip_hook";
export const SETUP_UNINSTALL_LOCK = "setup-uninstall";
export const SETUP_UNINSTALL_LOCK_STALE_MS = 30 * 60 * 1000;
export const STALE_SESSION_OLDER_THAN_MS = 24 * 60 * 60 * 1000;

export type SetupShell = "auto" | "zsh" | "bash" | "fish";

export interface SetupPlan {
  readonly paths: DgPaths;
  readonly shell: Exclude<SetupShell, "auto">;
  readonly shimDir: string;
  readonly rcPath: string;
  readonly failClosed: boolean;
  readonly writes: readonly PlannedWrite[];
  readonly reloadInstructions: readonly string[];
}

function readShimFailClosed(env: DgPathEnvironment): boolean {
  try {
    return loadUserConfig(env).policy.shimFailClosed;
  } catch {
    return false;
  }
}

export interface PlannedWrite {
  readonly kind: "directory" | "shim" | "shell-rc" | "state";
  readonly path: string;
  readonly action: string;
}

export interface SetupOptions {
  readonly shell: SetupShell;
  readonly env?: NodeJS.ProcessEnv;
}

export interface ApplySetupResult {
  readonly plan: SetupPlan;
  readonly registry: CleanupRegistry;
}

export interface UninstallOptions {
  readonly keepConfig: boolean;
  readonly all: boolean;
  readonly env?: NodeJS.ProcessEnv;
}

export interface UninstallResult {
  readonly removed: readonly string[];
  readonly missing: readonly string[];
  readonly warnings: readonly string[];
  readonly staleSessions: readonly string[];
}

export type DoctorGroup = "environment" | "setup" | "account" | "gated";

type RawDoctorCheck = {
  readonly name: string;
  readonly status: "pass" | "warn" | "fail" | "unavailable";
  readonly message: string;
  readonly fix?: string;
};

export interface DoctorCheck extends RawDoctorCheck {
  readonly group: DoctorGroup;
  readonly fix?: string;
}

export interface DoctorReport {
  readonly version: string;
  readonly checks: readonly DoctorCheck[];
}

const DOCTOR_GROUP_BY_NAME: Record<string, DoctorGroup> = {
  node: "environment",
  package: "environment",
  update: "environment",
  "dg-binary-path": "environment",
  "real-binary-resolution": "environment",
  "recursive-shim-guard": "environment",
  "package-manager-discovery": "environment",
  "cleanup-registry": "setup",
  "cleanup-registry-stale-entries": "setup",
  config: "setup",
  policy: "setup",
  "script-gate": "setup",
  shims: "setup",
  "shell-rc": "setup",
  "python-hook-drift": "setup",
  path: "setup",
  "path-noninteractive": "setup",
  "commit-guard": "setup",
  "stale-sessions": "setup",
  service: "setup",
  "agent-gate": "setup",
  auth: "account",
  api: "account"
};

const DOCTOR_FIX_BY_NAME: Record<string, string> = {
  node: "upgrade Node to >=22.14.0",
  update: "dg update",
  "dg-binary-path": "put the dg bin directory first on PATH",
  "cleanup-registry": "re-run dg setup",
  "cleanup-registry-stale-entries": "re-run dg setup to refresh",
  config: "fix or remove ~/.dg, then re-run dg setup",
  policy: "fix ~/.dg config",
  shims: "dg setup",
  "shell-rc": "dg setup",
  "python-hook-drift": "dg uninstall, or re-run dg setup, to remove the stale pip hook",
  path: "reload your shell after setup",
  "commit-guard": "dg guard-commit",
  "stale-sessions": "clears on the next protected run",
  auth: "dg login"
};

function enrichDoctorCheck(check: RawDoctorCheck): DoctorCheck {
  const group: DoctorGroup = check.status === "unavailable" ? "gated" : DOCTOR_GROUP_BY_NAME[check.name] ?? "setup";
  const fix = check.status === "pass" || check.status === "unavailable" ? undefined : check.fix ?? DOCTOR_FIX_BY_NAME[check.name];
  return fix ? { ...check, group, fix } : { ...check, group };
}

export interface RegistryReadResult {
  readonly registry: CleanupRegistry;
  readonly malformed: boolean;
  readonly preservedPath?: string;
}

export class SetupUnsupportedPlatformError extends Error {
  constructor(readonly platform: NodeJS.Platform) {
    super(`dg setup does not support ${platform} — Linux and macOS only`);
    this.name = "SetupUnsupportedPlatformError";
  }
}

export function buildSetupPlan(options: SetupOptions): SetupPlan {
  if (process.platform === "win32") {
    throw new SetupUnsupportedPlatformError(process.platform);
  }
  const env = options.env ?? process.env;
  const paths = resolveDgPaths(env);
  const shell = resolveShell(options.shell, env);
  const shimDir = join(paths.homeDir, ".dg", "shims");
  const rcPath = shellRcPath(paths.homeDir, shell);

  return {
    paths,
    shell,
    shimDir,
    rcPath,
    failClosed: readShimFailClosed(env),
    writes: [
      {
        kind: "directory",
        path: shimDir,
        action: "create dg-owned shim directory"
      },
      ...SHIM_COMMANDS.map((command) => ({
        kind: "shim" as const,
        path: join(shimDir, command),
        action: `write ${command} shim that dispatches to dg ${command}`
      })),
      {
        kind: "shell-rc",
        path: rcPath,
        action: `insert or replace ${RC_SENTINEL} PATH block`
      },
      {
        kind: "state",
        path: paths.cleanupRegistryPath,
        action: "record dg-owned writes for uninstall"
      }
    ],
    reloadInstructions: reloadInstructions(shell)
  };
}

export function renderSetupPlan(plan: SetupPlan): string {
  const lines = [
    "Dependency Guardian setup write plan",
    "",
    "No files are changed until this plan is confirmed.",
    ...plan.writes.map((write) => `- ${write.action}: ${write.path}`),
    "",
    "After setup, reload your shell:",
    ...plan.reloadInstructions.map((line) => `- ${line}`)
  ];
  return `${lines.join("\n")}\n`;
}

export function applySetupPlan(plan: SetupPlan, now = new Date()): ApplySetupResult {
  const entries: CleanupRegistryEntry[] = [];
  mkdirSync(plan.shimDir, {
    recursive: true,
    mode: 0o700
  });

  for (const command of SHIM_COMMANDS) {
    const path = join(plan.shimDir, command);
    writeFileSync(path, shimSource(command, { failClosed: plan.failClosed }), {
      encoding: "utf8",
      mode: 0o755
    });
    chmodSync(path, 0o755);
    entries.push(cleanupEntry("shim", path, "mode1", now, SHIM_SENTINEL));
  }

  installStandaloneUninstaller(plan.paths.homeDir);

  mkdirSync(dirname(plan.rcPath), {
    recursive: true,
    mode: 0o700
  });
  writeRcFileAtomic(plan.rcPath, withRcBlock(readText(plan.rcPath), plan));
  entries.push(cleanupEntry("rc", plan.rcPath, "mode1", now, RC_SENTINEL));

  sweepLegacyPythonHooks(plan.paths.homeDir, [], []);

  const registry = withRegistryLock(plan.paths, () => {
    const merged = mergeRegistry(readRegistry(plan.paths).registry, entries);
    writeRegistry(plan.paths, merged);
    return merged;
  });
  return {
    plan,
    registry
  };
}

export function applySetupPlanWithLock(plan: SetupPlan, now = new Date()): ApplySetupResult {
  const lock = acquireLockSync(plan.paths, SETUP_UNINSTALL_LOCK, {
    staleMs: SETUP_UNINSTALL_LOCK_STALE_MS
  });
  try {
    return applySetupPlan(plan, now);
  } finally {
    lock.release();
  }
}

// Shims written by a dg that predates the self-cleaning template carry no
// auto-cleanup, so a plain `npm uninstall -g` leaves them stranded forever.
// Rewriting the installed shims and reinstalling the standalone uninstaller on
// the first run after a version bump propagates the current template to setups
// created by older releases.
export function refreshSetupOnUpgrade(env: DgPathEnvironment = process.env): boolean {
  const paths = resolveDgPaths(env);
  const shimDir = join(paths.homeDir, ".dg", "shims");
  if (!isShimFile(join(shimDir, "npm"))) {
    return false;
  }
  const failClosed = readShimFailClosed(env);
  try {
    const lock = acquireLockSync(paths, SETUP_UNINSTALL_LOCK, {
      staleMs: SETUP_UNINSTALL_LOCK_STALE_MS
    });
    try {
      for (const command of SHIM_COMMANDS) {
        const shimPath = join(shimDir, command);
        if (!isShimFile(shimPath)) {
          continue;
        }
        writeFileSync(shimPath, shimSource(command, { failClosed }), {
          encoding: "utf8",
          mode: 0o755
        });
        chmodSync(shimPath, 0o755);
      }
      installStandaloneUninstaller(paths.homeDir);
    } finally {
      lock.release();
    }
  } catch {
    return false;
  }
  return true;
}

export function uninstallSetup(options: UninstallOptions): UninstallResult {
  const paths = resolveDgPaths(options.env ?? process.env);
  const hadCacheDirBeforeLock = existsSync(paths.cacheDir);
  const hadStateDirBeforeLock = existsSync(paths.stateDir);
  const lock = acquireLockSync(paths, SETUP_UNINSTALL_LOCK, {
    staleMs: SETUP_UNINSTALL_LOCK_STALE_MS
  });
  try {
    const registryRead = readRegistry(paths);
    const removed: string[] = [];
    const missing: string[] = [];
    const warnings: string[] = [];
    const staleSessions = sweepStaleSessionsSync(paths, {
      olderThanMs: STALE_SESSION_OLDER_THAN_MS
    }).removed;

    if (registryRead.malformed) {
      warnings.push(
        registryRead.preservedPath
          ? `cleanup registry was malformed: ${paths.cleanupRegistryPath} (preserved at ${registryRead.preservedPath})`
          : `cleanup registry is malformed: ${paths.cleanupRegistryPath}`
      );
    }

    for (const entry of registryRead.registry.entries) {
      if (entry.owner !== "dg") {
        continue;
      }
      if (entry.kind === "shim") {
        removeShim(entry, removed, missing, warnings);
      } else if (entry.kind === "rc") {
        removeRcBlock(entry, removed, missing, warnings);
      } else if (entry.kind === "git-hook") {
        reverseGitHookEntry(entry, removed, missing, warnings);
      } else if (entry.kind === "agent-hook") {
        reverseAgentHookEntry(entry, removed, missing, warnings);
      }
    }

    sweepLegacyRcBlocks(paths.homeDir, removed, warnings);
    sweepLegacyPythonHooks(paths.homeDir, removed, warnings);

    if (!options.all && !registryRead.malformed && options.keepConfig) {
      writeRegistryWithLock(paths, {
        version: 1,
        entries: registryRead.registry.entries.filter((entry) => entry.owner !== "dg")
      });
    }
    if (!options.keepConfig && hadCacheDirBeforeLock) {
      removeDirectory(paths.cacheDir, removed, missing);
    }
    if (!options.keepConfig && hadStateDirBeforeLock) {
      removeDirectory(paths.stateDir, removed, missing);
    }
    if (options.all) {
      removeDirectory(paths.configDir, removed, missing);
    }

    return {
      removed,
      missing,
      warnings,
      staleSessions
    };
  } finally {
    lock.release();
  }
}

export function doctorReport(options: { readonly env?: NodeJS.ProcessEnv } = {}): DoctorReport {
  const env = options.env ?? process.env;
  const paths = resolveDgPaths(env);
  const shimDir = join(paths.homeDir, ".dg", "shims");
  const registryRead = readRegistry(paths);
  const staleSessions = findStaleSessionsSync(paths, {
    olderThanMs: STALE_SESSION_OLDER_THAN_MS
  }).stale;
  const checks: RawDoctorCheck[] = [];

  checks.push({
    name: "node",
    status: isSupportedNode(currentNodeVersion()) ? "pass" : "fail",
    message: `Node ${currentNodeVersion()} with required >=22.14.0`
  });
  checks.push({
    name: "package",
    status: "pass",
    message: `dg ${dgVersion()}`
  });
  checks.push(dgPathCheck(env));
  checks.push({
    name: "cleanup-registry",
    status: registryRead.malformed ? "fail" : "pass",
    message: registryRead.malformed ? `Malformed cleanup registry at ${paths.cleanupRegistryPath}` : paths.cleanupRegistryPath
  });
  checks.push({
    name: "cleanup-registry-stale-entries",
    status: staleRegistryEntries(registryRead.registry).length === 0 ? "pass" : "warn",
    message:
      staleRegistryEntries(registryRead.registry).length === 0
        ? "No stale cleanup registry entries detected"
        : `Missing registered paths: ${staleRegistryEntries(registryRead.registry).join(", ")}`
  });
  checks.push(configCheck(paths, env));
  checks.push(authCheck(env));
  checks.push(policyCheck(env));
  checks.push(scriptGateCheck(env));

  const missingShims = SHIM_COMMANDS.filter((command) => !validShim(join(shimDir, command), command));
  checks.push({
    name: "shims",
    status: missingShims.length === 0 ? "pass" : "warn",
    message: missingShims.length === 0 ? `All setup shims exist in ${shimDir}` : `Missing or drifted shims: ${missingShims.join(", ")}`
  });

  const rcEntries = registryRead.registry.entries.filter((entry) => entry.owner === "dg" && entry.kind === "rc");
  const missingRc = rcEntries.filter((entry) => !readText(entry.path).includes(RC_SENTINEL));
  const functionsPresent = rcEntries.some((entry) => readText(entry.path).includes(RC_FUNCTIONS_SENTINEL));
  checks.push({
    name: "shell-rc",
    status: rcEntries.length > 0 && missingRc.length === 0 ? "pass" : "warn",
    message: rcEntries.length === 0 ? "No dg shell rc block is registered" : `Registered shell rc blocks: ${rcEntries.length}`
  });

  const staleHookSites = legacyPythonHookSites(paths.homeDir);
  checks.push({
    name: "python-hook-drift",
    status: staleHookSites.length === 0 ? "pass" : "warn",
    message:
      staleHookSites.length === 0
        ? "No legacy dg pip hooks in user site-packages"
        : `Legacy dg pip hooks break pip in: ${staleHookSites.join(", ")}`
  });

  checks.push(pathPrecedenceCheck(env, shimDir, functionsPresent));
  checks.push(nonInteractivePathCheck(env, shimDir));
  checks.push(commitGuardCheck(registryRead.registry, env));
  checks.push({
    name: "stale-sessions",
    status: staleSessions.length === 0 ? "pass" : "warn",
    message: staleSessions.length === 0 ? "No stale sessions detected" : `Stale sessions detected: ${staleSessions.join(", ")}`
  });
  checks.push(realBinaryResolutionCheck(env));
  checks.push({
    name: "recursive-shim-guard",
    status: "pass",
    message: `Real binary resolver skips ${shimDir} and dg shim sentinel files`
  });
  checks.push({
    name: "package-manager-discovery",
    status: "pass",
    message: `Classifiers are registered for ${SHIM_COMMANDS.join(", ")}; gated managers remain ${packageManagerNames()
      .filter((name) => !SHIM_COMMANDS.includes(name))
      .join(", ")}`
  });
  checks.push(...unavailableDoctorChecks());
  checks.push(serviceCheck(env));
  checks.push(agentGateCheck(env, paths.homeDir));

  return {
    version: dgVersion(),
    checks: checks.map(enrichDoctorCheck)
  };
}

const API_HEALTH_TIMEOUT_MS = 2000;
const UPDATE_LOOKUP_TIMEOUT_MS = 1500;

export interface DoctorRemoteOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly fetchImpl?: typeof fetch;
  readonly apiTimeoutMs?: number;
}

export async function doctorReportWithRemote(options: DoctorRemoteOptions = {}): Promise<DoctorReport> {
  const env = options.env ?? process.env;
  const base = doctorReport({ env });
  const checks = [...base.checks];
  insertAfter(checks, "package", enrichDoctorCheck(updateFreshnessCheck()));
  insertAfter(
    checks,
    "auth",
    enrichDoctorCheck(await apiHealthCheck(env, options.fetchImpl ?? fetch, options.apiTimeoutMs ?? API_HEALTH_TIMEOUT_MS))
  );
  return { version: base.version, checks };
}

function insertAfter(checks: DoctorCheck[], name: string, check: DoctorCheck): void {
  const index = checks.findIndex((candidate) => candidate.name === name);
  checks.splice(index === -1 ? checks.length : index + 1, 0, check);
}

function updateFreshnessCheck(): RawDoctorCheck {
  const latest = readLatestVersion(UPDATE_LOOKUP_TIMEOUT_MS);
  if (!latest) {
    return {
      name: "update",
      status: "unavailable",
      message: "Latest published dg version is unknown (npm registry metadata unavailable). Run 'dg update' to retry."
    };
  }
  if (compareVersions(latest, dgVersion()) > 0) {
    return {
      name: "update",
      status: "warn",
      message: `dg ${dgVersion()} is behind the latest published ${latest}`
    };
  }
  return {
    name: "update",
    status: "pass",
    message: `dg ${dgVersion()} is the latest published version`
  };
}

async function apiHealthCheck(env: NodeJS.ProcessEnv, fetchImpl: typeof fetch, timeoutMs: number): Promise<RawDoctorCheck> {
  let baseUrl: string;
  try {
    baseUrl = doctorApiBaseUrl(env);
  } catch (error) {
    return {
      name: "api",
      status: "fail",
      message: error instanceof ConfigError ? error.message : "Unable to resolve api.baseUrl"
    };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();
  try {
    const response = await fetchImpl(`${baseUrl}/health`, { method: "GET", signal: controller.signal });
    const latencyMs = Date.now() - started;
    if (response.ok) {
      return {
        name: "api",
        status: "pass",
        message: `${baseUrl}/health responded ${response.status} in ${latencyMs}ms`
      };
    }
    return {
      name: "api",
      status: "warn",
      message: `${baseUrl}/health responded ${response.status} after ${latencyMs}ms`,
      fix: "check api.baseUrl (dg config get api.baseUrl) and the service status"
    };
  } catch (error) {
    return {
      name: "api",
      status: "warn",
      message: `${baseUrl} is unreachable: ${describeFetchError(error, timeoutMs)}`,
      fix: "check your network and api.baseUrl (dg config get api.baseUrl)"
    };
  } finally {
    clearTimeout(timer);
  }
}

function doctorApiBaseUrl(env: NodeJS.ProcessEnv): string {
  try {
    const apiBaseUrl = readAuthState(env)?.apiBaseUrl;
    if (apiBaseUrl) {
      return apiBaseUrl;
    }
  } catch {
    return loadUserConfig(env).api.baseUrl;
  }
  return loadUserConfig(env).api.baseUrl;
}

function describeFetchError(error: unknown, timeoutMs: number): string {
  if (error instanceof Error && error.name === "AbortError") {
    return `no response within ${timeoutMs}ms`;
  }
  if (error instanceof Error && error.cause instanceof Error && error.cause.message) {
    return error.cause.message;
  }
  return error instanceof Error ? error.message : "request failed";
}

const DOCTOR_STATUS_ROLE: Record<DoctorCheck["status"], Role> = {
  pass: "pass",
  warn: "warn",
  fail: "block",
  unavailable: "muted"
};

const DOCTOR_STATUS_GLYPH: Record<DoctorCheck["status"], string> = {
  pass: "✓",
  warn: "⚠",
  fail: "✘",
  unavailable: "·"
};

const DOCTOR_GROUP_ORDER: readonly { readonly key: DoctorGroup; readonly title: string }[] = [
  { key: "environment", title: "Environment" },
  { key: "setup", title: "Setup" },
  { key: "account", title: "Account" }
];

export function renderDoctorReport(report: DoctorReport, theme: Theme = createTheme(false), verbose = false): string {
  const failures = report.checks.filter((check) => check.status === "fail").length;
  const warnings = report.checks.filter((check) => check.status === "warn").length;
  const role: Role = failures > 0 ? "block" : warnings > 0 ? "warn" : "pass";
  const glyph = failures > 0 ? "✘" : warnings > 0 ? "⚠" : "✓";
  const summary =
    failures > 0
      ? `${failures} ${failures === 1 ? "issue needs" : "issues need"} attention`
      : warnings > 0
        ? `${warnings} ${warnings === 1 ? "warning" : "warnings"}`
        : "all good";
  const lines = [`${theme.paint(role, `${glyph} DG doctor`)} — ${summary}`];

  for (const { key, title } of DOCTOR_GROUP_ORDER) {
    const groupChecks = report.checks.filter((check) => check.group === key);
    if (groupChecks.length === 0) {
      continue;
    }
    if (verbose) {
      lines.push("", title);
      const width = nameWidth(groupChecks);
      for (const check of groupChecks) {
        lines.push(doctorLine(check, width, theme));
      }
      continue;
    }
    let nonPass = groupChecks.filter((check) => check.status !== "pass");
    if (key === "setup") {
      const setupCore = ["shims", "shell-rc", "path", "path-noninteractive"];
      const allWarn = setupCore.every((name) => nonPass.some((check) => check.name === name && check.status === "warn"));
      if (allWarn) {
        nonPass = nonPass.filter(
          (check) => !setupCore.includes(check.name) && !(check.name === "config" && check.status === "warn")
        );
        const notSetUp = "not set up — bare npm/pip installs aren't protected";
        if (nonPass.length === 0) {
          lines.push(rollupInlineLine(title, "warn", "⚠", notSetUp, "dg setup", theme));
          continue;
        }
        const worst = worstCheck(nonPass);
        lines.push(`  ${theme.paint(DOCTOR_STATUS_ROLE[worst.status], `${DOCTOR_STATUS_GLYPH[worst.status]} ${title}`)}`);
        lines.push(`  ${theme.paint("warn", "⚠")} ${notSetUp}  ${theme.paint("muted", "→ dg setup")}`);
        const width = nameWidth(nonPass);
        for (const check of nonPass) {
          lines.push(doctorLine(check, width, theme));
        }
        continue;
      }
    }
    if (nonPass.length === 0) {
      lines.push(`  ${theme.paint("pass", `✓ ${title}`)}`);
      continue;
    }
    const worst = worstCheck(nonPass);
    if (nonPass.length === 1) {
      lines.push(rollupInlineLine(title, worst.status, DOCTOR_STATUS_GLYPH[worst.status], worst.message, worst.fix, theme));
      continue;
    }
    lines.push(`  ${theme.paint(DOCTOR_STATUS_ROLE[worst.status], `${DOCTOR_STATUS_GLYPH[worst.status]} ${title}`)}`);
    const width = nameWidth(nonPass);
    for (const check of nonPass) {
      lines.push(doctorLine(check, width, theme));
    }
  }

  const gated = report.checks.filter((check) => check.group === "gated");
  if (gated.length > 0) {
    if (verbose) {
      lines.push("", "Gated / remote");
      const width = nameWidth(gated);
      for (const check of gated) {
        lines.push(doctorLine(check, width, theme));
      }
    } else {
      lines.push("", theme.paint("muted", `${gated.length} gated/remote checks hidden · dg doctor --verbose`));
    }
  }

  return `${lines.join("\n")}\n`;
}

function nameWidth(checks: readonly DoctorCheck[]): number {
  return checks.reduce((max, check) => Math.max(max, check.name.length), 0);
}

const DOCTOR_STATUS_SEVERITY: Record<DoctorCheck["status"], number> = {
  pass: 0,
  unavailable: 1,
  warn: 2,
  fail: 3
};

function worstCheck(checks: readonly DoctorCheck[]): DoctorCheck {
  return checks.reduce((worst, check) =>
    DOCTOR_STATUS_SEVERITY[check.status] > DOCTOR_STATUS_SEVERITY[worst.status] ? check : worst
  );
}

function rollupInlineLine(
  title: string,
  status: DoctorCheck["status"],
  glyph: string,
  message: string,
  fix: string | undefined,
  theme: Theme
): string {
  const head = theme.paint(DOCTOR_STATUS_ROLE[status], `${glyph} ${title}`);
  const fixSuffix = fix ? `  ${theme.paint("muted", `→ ${fix}`)}` : "";
  return `  ${head}  ${message}${fixSuffix}`;
}

function doctorLine(check: DoctorCheck, width: number, theme: Theme): string {
  const glyph = theme.paint(DOCTOR_STATUS_ROLE[check.status], DOCTOR_STATUS_GLYPH[check.status]);
  const name = check.name.padEnd(width);
  const message = check.status === "unavailable" ? theme.paint("muted", check.message) : check.message;
  const fix = check.fix ? `  ${theme.paint("muted", `→ ${check.fix}`)}` : "";
  return `  ${glyph} ${name}  ${message}${fix}`;
}

function resolveShell(shell: SetupShell, env: NodeJS.ProcessEnv): Exclude<SetupShell, "auto"> {
  if (shell !== "auto") {
    return shell;
  }
  const detected = basename(env.SHELL ?? "");
  if (detected === "fish") {
    return "fish";
  }
  if (detected === "bash") {
    return "bash";
  }
  return "zsh";
}

function shellRcPath(homeDir: string, shell: Exclude<SetupShell, "auto">): string {
  if (shell === "fish") {
    return join(homeDir, ".config", "fish", "config.fish");
  }
  if (shell === "bash") {
    return join(homeDir, ".bashrc");
  }
  return join(homeDir, ".zshrc");
}

export function tildifyPath(path: string, home = homedir()): string {
  return home && path.startsWith(home) ? `~${path.slice(home.length)}` : path;
}

export function activationCommand(shell: Exclude<SetupShell, "auto">, rcDisplay: string): string {
  if (shell === "fish") {
    return `source ${rcDisplay}`;
  }
  if (shell === "bash") {
    return `source ${rcDisplay} && hash -r`;
  }
  return `source ${rcDisplay} && rehash`;
}

function reloadInstructions(shell: Exclude<SetupShell, "auto">): readonly string[] {
  if (shell === "fish") {
    return ["start a new shell or run: source ~/.config/fish/config.fish"];
  }
  if (shell === "bash") {
    return ["start a new shell or run: source ~/.bashrc", "clear cached command paths with: hash -r"];
  }
  return ["start a new shell or run: source ~/.zshrc", "clear cached command paths with: rehash"];
}

// The baked absolute dg path stops a PATH-shadowing dg from hijacking the shim;
// the fallbacks make it fail open — a removed or moved dg (uninstall, mid-upgrade)
// runs the real manager instead of bricking it.
export function shimSource(command: string, options: { readonly failClosed?: boolean } = {}): string {
  const dg = escapeDoubleQuotedSh(dgEntrypoint());
  const nonce = '"${DG_SHIM_ACTIVE:+$DG_SHIM_ACTIVE,}' + `${command}:$$"`;
  const head = [
    "#!/bin/sh",
    `# ${SHIM_SENTINEL}`,
    `if [ -x "${dg}" ]; then`,
    `  DG_SHIM_ACTIVE=${nonce} exec "${dg}" ${command} "$@"`,
    "fi",
    `shim_dir=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)`,
    `dg_path=$(printf '%s' "$PATH" | awk -v RS=':' -v ORS=':' -v shim="$shim_dir" '$0 != shim && $0 != ENVIRON["HOME"] "/.dg/shims"' | sed 's/:$//')`,
    `dg_bin=$(PATH="$dg_path" command -v dg 2>/dev/null)`,
    `if [ -n "$dg_bin" ]; then`,
    `  DG_SHIM_ACTIVE=${nonce} exec "$dg_bin" ${command} "$@"`,
    "fi"
  ];
  // dg is gone from this machine. fail-closed (managed/CI) refuses the command
  // so an unscanned install can't slip through; the operator removes the guard
  // explicitly via `dg uninstall` while dg is present. fail-open (default)
  // self-cleans dg's footprint and falls back to the real binary, because a
  // plain `npm uninstall -g dg` cannot run cleanup and must not brick npm.
  const failClosedTail = [
    `echo "dg: install firewall required by policy (policy.shimFailClosed) but dg is unavailable; refusing to run ${command}" >&2`,
    `echo "dg: reinstall dg, or run 'dg uninstall' while dg is present, to remove this guard" >&2`,
    "exit 127",
    ""
  ];
  const failOpenTail = [
    `dg_home=$(dirname "$shim_dir")`,
    `if [ -f "$dg_home/uninstall.mjs" ] && command -v node >/dev/null 2>&1; then`,
    `  ( sleep 10`,
    `    if [ ! -x "${dg}" ] && ! PATH="$dg_path" command -v dg >/dev/null 2>&1; then`,
    `      node "$dg_home/uninstall.mjs" --quiet >/dev/null 2>&1`,
    `    fi`,
    `  ) >/dev/null 2>&1 &`,
    "fi",
    `real_bin=$(PATH="$dg_path" command -v ${command} 2>/dev/null)`,
    `if [ -n "$real_bin" ]; then`,
    `  exec "$real_bin" "$@"`,
    "fi",
    `echo "dg: protection unavailable and no real ${command} found on PATH" >&2`,
    "exit 127",
    ""
  ];
  return [...head, ...(options.failClosed ? failClosedTail : failOpenTail)].join("\n");
}

function escapeDoubleQuotedSh(value: string): string {
  return value.replace(/[\\"$`]/g, "\\$&");
}

function escapeDoubleQuotedFish(value: string): string {
  return value.replace(/[\\"$]/g, "\\$&");
}

function dgEntrypoint(): string {
  const argv1 = process.argv[1];
  return argv1 ? resolve(argv1) : "dg";
}

function standaloneUninstallerSource(): string | undefined {
  try {
    return fileURLToPath(new URL("../standalone/uninstall.mjs", import.meta.url));
  } catch {
    return undefined;
  }
}

function installStandaloneUninstaller(homeDir: string): void {
  const source = standaloneUninstallerSource();
  if (!source || !existsSync(source)) {
    return;
  }
  const dgRoot = join(homeDir, ".dg");
  mkdirSync(dgRoot, { recursive: true, mode: 0o700 });
  const dest = join(dgRoot, "uninstall.mjs");
  copyFileSync(source, dest);
  chmodSync(dest, 0o600);
}

function withRcBlock(existing: string, plan: SetupPlan): string {
  const withoutExisting = stripRcBlock(existing);
  const block = plan.shell === "fish" ? fishRcBlock(plan.shimDir) : posixRcBlock(plan.shimDir);
  const prefix = withoutExisting.length > 0 && !withoutExisting.endsWith("\n") ? `${withoutExisting}\n` : withoutExisting;
  return `${prefix}${block}`;
}

// The PATH export covers child processes that inherit it; the shell functions
// win even when a virtualenv prepends its own bin ahead of the shim dir, since
// a function is resolved before PATH. Each delegates to the fail-open shim and
// falls back to the real command if the shim is gone.
function posixRcBlock(shimDir: string): string {
  const dir = escapeDoubleQuotedSh(shimDir);
  const helper = `${RC_SHIM_HELPER}() { local __dg_c="$1"; shift; if [ -x "${dir}/$__dg_c" ]; then "${dir}/$__dg_c" "$@"; else command "$__dg_c" "$@"; fi; }`;
  const fns = SHIM_COMMANDS.map((command) => `${command}() { ${RC_SHIM_HELPER} ${command} "$@"; }`).join("\n");
  return `${RC_BEGIN}\n# ${RC_SENTINEL}\n# ${RC_FUNCTIONS_SENTINEL}\nexport PATH="${dir}:$PATH"\n${helper}\n${fns}\n${RC_END}\n`;
}

function fishRcBlock(shimDir: string): string {
  const dir = escapeDoubleQuotedFish(shimDir);
  const fns = SHIM_COMMANDS.map(
    (command) => `function ${command}; if test -x "${dir}/${command}"; "${dir}/${command}" $argv; else; command ${command} $argv; end; end`
  ).join("\n");
  return `${RC_BEGIN}\n# ${RC_SENTINEL}\n# ${RC_FUNCTIONS_SENTINEL}\nfish_add_path -p "${dir}"\n${fns}\n${RC_END}\n`;
}

function stripRcBlock(existing: string): string {
  return stripRcBlockDetailed(existing).content;
}

function writeRcFileAtomic(rcPath: string, content: string): void {
  let target = rcPath;
  let mode = 0o644;
  try {
    target = realpathSync(rcPath);
    mode = statSync(target).mode & 0o7777;
  } catch {
    // no existing file: write a fresh rc at the requested path
  }
  const tempPath = join(dirname(target), `.${basename(target)}.dg-${randomBytes(6).toString("hex")}.tmp`);
  writeFileSync(tempPath, content, { encoding: "utf8", mode, flag: "wx" });
  try {
    renameSync(tempPath, target);
  } catch (error) {
    rmSync(tempPath, { force: true });
    throw error;
  }
}

// An unterminated begin marker must never strip to EOF: only lines verifiably
// written by dg are removed, so user content below a stale marker survives.
function stripRcBlockDetailed(existing: string): { readonly content: string; readonly repairedLines: readonly string[] } {
  let content = existing.replace(rcPairPattern(RC_BEGIN, RC_END), "");
  const repairedLines: string[] = [];
  for (;;) {
    const lines = content.split("\n");
    const begin = lines.indexOf(RC_BEGIN);
    if (begin === -1) {
      break;
    }
    let end = begin;
    while (end + 1 < lines.length && isDgWrittenRcLine(lines[end + 1] ?? "")) {
      end += 1;
    }
    repairedLines.push(begin === end ? `line ${begin + 1}` : `lines ${begin + 1}-${end + 1}`);
    lines.splice(begin, end - begin + 1);
    content = lines.join("\n");
  }
  return { content, repairedLines };
}

function rcPairPattern(begin: string, end: string): RegExp {
  return new RegExp(`${escapeRegex(begin)}\\n(?:(?!${escapeRegex(begin)})[\\s\\S])*?${escapeRegex(end)}\\n?`, "g");
}

function isDgWrittenRcLine(line: string): boolean {
  return line === RC_END || line.startsWith("# dg-") || line.includes(RC_SHIM_HELPER) || line.includes(`${sep}.dg${sep}shims`);
}

function sweepLegacyRcBlocks(homeDir: string, removed: string[], warnings: string[]): void {
  for (const rel of LEGACY_RC_CANDIDATES) {
    const rcPath = join(homeDir, rel);
    const existing = readText(rcPath);
    if (!existing) {
      continue;
    }
    let next = existing;
    for (const marker of LEGACY_RC_MARKERS) {
      if (!next.includes(marker.begin)) {
        continue;
      }
      if (!next.includes(marker.end)) {
        warnings.push(`legacy dg block in ${rcPath} is missing its end marker; left untouched`);
        continue;
      }
      next = next.replace(rcPairPattern(marker.begin, marker.end), "");
    }
    if (next === existing) {
      continue;
    }
    try {
      writeRcFileAtomic(rcPath, next);
      removed.push(`${rcPath} (legacy dg block)`);
    } catch (error) {
      warnings.push(`could not strip legacy dg block from ${rcPath}: ${error instanceof Error ? error.message : "write error"}`);
    }
  }
}

function isLegacyPthHook(pthPath: string): boolean {
  const content = readText(pthPath);
  return content.includes(LEGACY_PYTHON_HOOK_PTH_MARKER) || content.includes(LEGACY_PYTHON_HOOK_MARKER);
}

export function legacyPythonHookSites(homeDir: string): readonly string[] {
  return candidateSitePackagesDirs(homeDir).filter(
    (dir) => isLegacyPthHook(join(dir, LEGACY_PYTHON_HOOK_PTH)) || readText(join(dir, LEGACY_PYTHON_HOOK_PY)).includes(LEGACY_PYTHON_HOOK_MARKER)
  );
}

export function sweepLegacyPythonHooks(homeDir: string, removed: string[], warnings: string[]): void {
  for (const dir of candidateSitePackagesDirs(homeDir)) {
    const pyPath = join(dir, LEGACY_PYTHON_HOOK_PY);
    const pthPath = join(dir, LEGACY_PYTHON_HOOK_PTH);
    const pyIsHook = readText(pyPath).includes(LEGACY_PYTHON_HOOK_MARKER);
    const pthIsHook = isLegacyPthHook(pthPath);
    if (!pyIsHook && !pthIsHook) {
      continue;
    }
    if (pthIsHook) {
      removePythonHookFile(pthPath, removed, warnings);
    }
    if (pyIsHook) {
      removePythonHookFile(pyPath, removed, warnings);
    }
  }
}

function removePythonHookFile(path: string, removed: string[], warnings: string[]): void {
  try {
    rmSync(path, { force: true });
    removed.push(`${path} (legacy dg pip hook)`);
  } catch (error) {
    warnings.push(`could not remove legacy dg pip hook ${path}: ${error instanceof Error ? error.message : "remove error"}`);
  }
}

function candidateSitePackagesDirs(homeDir: string): readonly string[] {
  const dirs: string[] = [];
  for (const version of safeReaddir(join(homeDir, "Library", "Python"))) {
    dirs.push(join(homeDir, "Library", "Python", version, "lib", "python", "site-packages"));
  }
  for (const entry of safeReaddir(join(homeDir, ".local", "lib"))) {
    if (entry.startsWith("python")) {
      dirs.push(join(homeDir, ".local", "lib", entry, "site-packages"));
    }
  }
  return dirs;
}

function safeReaddir(dir: string): readonly string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

export function cleanupEntry(
  kind: CleanupRegistryEntry["kind"],
  path: string,
  mode: CleanupRegistryEntry["mode"],
  now: Date,
  sentinel: string
): CleanupRegistryEntry {
  return {
    kind,
    path,
    mode,
    sentinel,
    installedAt: now.toISOString(),
    owner: "dg"
  };
}

export function mergeRegistry(registry: CleanupRegistry, entries: readonly CleanupRegistryEntry[]): CleanupRegistry {
  const retained = registry.entries.filter(
    (entry) => !entries.some((next) => entry.kind === next.kind && entry.path === next.path && entry.sentinel === next.sentinel)
  );
  return {
    version: 1,
    entries: [...retained, ...entries]
  };
}

export function readRegistry(paths: DgPaths): RegistryReadResult {
  try {
    if (!existsSync(paths.cleanupRegistryPath)) {
      return {
        registry: {
          version: 1,
          entries: []
        },
        malformed: false
      };
    }
    const registry = JSON.parse(readFileSync(paths.cleanupRegistryPath, "utf8")) as CleanupRegistry;
    if (registry.version !== 1 || !Array.isArray(registry.entries)) {
      throw new Error("unsupported cleanup registry");
    }
    return {
      registry,
      malformed: false
    };
  } catch {
    const preservedPath = preserveCorruptCleanupRegistrySync(paths);
    return {
      registry: {
        version: 1,
        entries: []
      },
      malformed: true,
      ...(preservedPath ? { preservedPath } : {})
    };
  }
}

function staleRegistryEntries(registry: CleanupRegistry): readonly string[] {
  return registry.entries.filter((entry) => entry.owner === "dg" && !existsSync(entry.path)).map((entry) => entry.path);
}

function configCheck(paths: DgPaths, env: NodeJS.ProcessEnv): RawDoctorCheck {
  if (!existsSync(paths.configDir)) {
    return {
      name: "config",
      status: "warn",
      message: `No dg config directory exists at ${paths.configDir}`
    };
  }
  try {
    accessSync(paths.configDir, constants.R_OK);
    const config = loadUserConfig(env);
    if (config.api.baseUrl !== DEFAULT_CONFIG.api.baseUrl) {
      // The verdict API is the firewall's source of truth. A non-default
      // endpoint is legitimate for enterprise self-host, but a silent repoint
      // is also how an attacker would make every verdict come back clean, so
      // surface it on the standard health check rather than trusting it quietly.
      return {
        name: "config",
        status: "warn",
        message: `dg is fetching verdicts from a non-default API endpoint: ${config.api.baseUrl} (default ${DEFAULT_CONFIG.api.baseUrl})`,
        fix: `if you did not set this, your verdict source may be tampered — restore with: dg config set api.baseUrl ${DEFAULT_CONFIG.api.baseUrl}`
      };
    }
    return {
      name: "config",
      status: "pass",
      message: `${paths.configDir} is readable and config is valid`
    };
  } catch (error) {
    return {
      name: "config",
      status: "fail",
      message: error instanceof ConfigError ? error.message : `${paths.configDir} is not readable`
    };
  }
}

function unavailableDoctorChecks(): readonly RawDoctorCheck[] {
  const unavailable: readonly (readonly [string, string])[] = [
    ["path-cache", "Shell command path cache checks are guidance only. After setup, run 'hash -r' for bash or 'rehash' for zsh."],
    ["proxy", "Per-command proxy health is checked when a protected prefix command runs, for example 'dg npm install <package>'."],
    ["ca", "CA health is checked during protected HTTPS artifact fetches or explicit service startup."],
    ["upstream-proxy", "Corporate proxy chain health is checked during protected fetches when proxy environment variables are configured."],
    ...OPTIONAL_SUPPORT_GATES.map((gate) => [gate.id, gate.message] as const),
    ["dashboard", "Dashboard setup status is checked after authentication. Run 'dg login' and open the Dependency Guardian dashboard."],
    ["docs-api", "Docs/OpenAPI health is a remote service check. Run 'dg login', then use 'dg verify <target>' or a protected prefix command."]
  ];
  return unavailable.map(([name, message]) => ({
    name,
    status: "unavailable",
    message
  }));
}

function dgPathCheck(env: NodeJS.ProcessEnv): RawDoctorCheck {
  const current = currentDgBinaryPath(env);
  const candidates = findDgExecutables(env);
  const first = candidates[0] ?? null;

  if (!first) {
    return {
      name: "dg-binary-path",
      status: "warn",
      message: current
        ? `The running dg binary is ${current}, but no dg executable is on PATH. Add ${dirname(current)} to PATH or invoke this path directly.`
        : "No dg executable was found on PATH. Add the installed dg bin directory to PATH, then run 'dg doctor' again."
    };
  }

  if (current && resolve(first) !== resolve(current)) {
    return {
      name: "dg-binary-path",
      status: "warn",
      message: `Another dg executable is earlier on PATH: ${first}. This command is running ${current}. Run 'which -a dg' and put ${dirname(current)} before older dg entries.`
    };
  }

  return {
    name: "dg-binary-path",
    status: "pass",
    message: `dg on PATH resolves to ${first}`
  };
}

function currentDgBinaryPath(env: NodeJS.ProcessEnv): string | null {
  const explicit = env.NODE_ENV === "test" ? env.DG_TEST_CURRENT_DG_PATH : undefined;
  if (explicit) {
    return explicit;
  }
  const invoked = process.argv[1];
  if (!invoked) {
    return null;
  }
  const invokedName = basename(invoked);
  return invokedName === "dg" || invokedName === "dg.js" ? invoked : null;
}

function findDgExecutables(env: NodeJS.ProcessEnv): readonly string[] {
  const extensions = process.platform === "win32" ? ["", ".cmd", ".exe", ".bat"] : [""];
  const matches: string[] = [];
  for (const rawDir of (env.PATH ?? "").split(delimiter).filter(Boolean)) {
    for (const extension of extensions) {
      const candidate = join(rawDir, `dg${extension}`);
      try {
        accessSync(candidate, constants.X_OK);
        matches.push(candidate);
        break;
      } catch {
        // Keep scanning PATH entries.
      }
    }
  }
  return matches;
}

function serviceCheck(env: NodeJS.ProcessEnv): RawDoctorCheck {
  const state = readServiceState(env).state;
  if (!state.configured) {
    return {
      name: "service",
      status: "pass",
      message: "Off (optional Team feature for CI / private registries)"
    };
  }
  if (!state.running) {
    return {
      name: "service",
      status: "warn",
      message: `Service mode is configured but stopped; trust installed: ${state.trustInstalled ? "yes" : "no"}`
    };
  }
  if (!state.proxy) {
    return {
      name: "service",
      status: "warn",
      message: state.lastError ?? "Service mode is running without a persistent proxy"
    };
  }
  return {
    name: "service",
    status: "pass",
    message: `Service mode is running at ${state.proxy.proxyUrl}; trust installed: ${state.trustInstalled ? "yes" : "no"}`
  };
}

function hookedAgentLabels(env: NodeJS.ProcessEnv, home: string): string[] {
  const labels: string[] = [];
  for (const agent of AGENT_IDS) {
    const integration = AGENTS[agent];
    if (!integration.detect(home)) {
      continue;
    }
    const ctx = resolveAgentHookContext(agent, { env, home });
    const hooked = integration.verify(ctx).find((check) => check.name === integration.isInstalledCheckName)?.ok ?? false;
    if (hooked) {
      labels.push(agentLabel(agent));
    }
  }
  return labels;
}

function agentGateCheck(env: NodeJS.ProcessEnv, home: string): RawDoctorCheck {
  const hooked = hookedAgentLabels(env, home);
  if (hooked.length === 0) {
    return {
      name: "agent-gate",
      status: "unavailable",
      message: "No AI agent has the dg install hook; run 'dg agents on' to protect agent-run installs"
    };
  }
  const posture = readNetworkGatePosture(env);
  if (posture.live) {
    return {
      name: "agent-gate",
      status: "pass",
      message: `${hooked.join(", ")} hooked; network gate live at ${posture.proxyUrl} (installs screened at fetch by artifact hash)`
    };
  }
  return {
    name: "agent-gate",
    status: "warn",
    message: `${hooked.join(", ")} hooked but the fetch-time network gate is OFF — static pre-screen only; absolute-path, manifest-only, dynamic, and unsupported-manager installs are NOT screened`,
    fix: GATE_ENABLE_HINT
  };
}

function pathPrecedenceCheck(env: NodeJS.ProcessEnv, shimDir: string, functionsPresent: boolean): RawDoctorCheck {
  const pathEntries = (env.PATH ?? "").split(delimiter).filter(Boolean);
  const shimIndex = pathEntries.indexOf(shimDir);
  const activateFix = `activate this shell: ${currentShellActivation(env)} — or open a new terminal`;
  if (shimIndex === -1) {
    return {
      name: "path",
      status: "warn",
      message: `${shimDir} is not on PATH`,
      fix: activateFix
    };
  }

  let offender: { readonly dir: string; readonly command: string } | null = null;
  let resolvedAny = false;
  for (const command of SHIM_COMMANDS) {
    const real = resolveRealBinary({ name: command, env }).path;
    if (!real) {
      continue;
    }
    resolvedAny = true;
    const dir = dirname(real);
    const dirIndex = pathEntries.indexOf(dir);
    if (dirIndex !== -1 && dirIndex < shimIndex && !offender) {
      offender = { dir, command };
    }
  }

  if (!resolvedAny) {
    return {
      name: "path",
      status: "pass",
      message: `${shimDir} is on PATH; no shimmed package managers found to shadow`
    };
  }
  if (offender) {
    if (functionsPresent) {
      return {
        name: "path",
        status: "pass",
        message: `${offender.dir} resolves ${offender.command} first (e.g. an active virtualenv); dg shell functions intercept bare installs regardless`
      };
    }
    return {
      name: "path",
      status: "warn",
      message: `${shimDir} is on PATH but ${offender.dir} resolves ${offender.command} first`,
      fix: `re-run dg setup to intercept inside virtualenvs — or ${activateFix}`
    };
  }
  return {
    name: "path",
    status: "pass",
    message: `${shimDir} precedes the real package-manager directories on PATH`
  };
}

// Shell functions only protect interactive shells; scripts, Makefiles,
// lifecycle scripts, and CI resolve commands by raw PATH order, so a version
// manager bin dir ahead of the shim dir bypasses dg there.
function nonInteractivePathCheck(env: NodeJS.ProcessEnv, shimDir: string): RawDoctorCheck {
  const pathEntries = (env.PATH ?? "").split(delimiter).filter(Boolean);
  const shimIndex = pathEntries.findIndex((entry) => resolve(entry) === resolve(shimDir));
  if (shimIndex === -1) {
    return {
      name: "path-noninteractive",
      status: "warn",
      message: `${shimDir} is not on PATH, so scripts, Makefiles, lifecycle scripts, and CI bypass dg`,
      fix: "dg setup, then make sure the dg PATH block loads where non-interactive shells read it"
    };
  }
  const offenders = new Map<string, { readonly index: number; readonly commands: string[] }>();
  for (const command of SHIM_COMMANDS) {
    const hit = firstExecutableOnPath(command, pathEntries);
    if (!hit || resolve(hit.dir) === resolve(shimDir) || isShimFile(hit.path)) {
      continue;
    }
    const offender = offenders.get(hit.dir) ?? { index: hit.index, commands: [] };
    offender.commands.push(command);
    offenders.set(hit.dir, offender);
  }
  if (offenders.size === 0) {
    return {
      name: "path-noninteractive",
      status: "pass",
      message: `Non-interactive shells resolve the dg shims in ${shimDir} first for every shimmed command`
    };
  }
  const details = [...offenders.entries()]
    .map(([dir, offender]) => `${offender.commands.join(", ")} from ${dir}${versionManagerLabel(dir)} at PATH position ${offender.index + 1}`)
    .join("; ");
  const firstDir = [...offenders.keys()][0] ?? "";
  return {
    name: "path-noninteractive",
    status: "warn",
    message: `Non-interactive shells (scripts, Makefiles, lifecycle scripts, CI) run ${details}, bypassing the dg shims at PATH position ${shimIndex + 1}`,
    fix: `put ${shimDir} before ${firstDir} on PATH for non-interactive shells (load the dg setup block after the version-manager init)`
  };
}

function firstExecutableOnPath(
  command: string,
  pathEntries: readonly string[]
): { readonly path: string; readonly dir: string; readonly index: number } | null {
  for (const [index, dir] of pathEntries.entries()) {
    const candidate = join(dir, command);
    try {
      accessSync(candidate, constants.X_OK);
      return { path: candidate, dir, index };
    } catch {
      continue;
    }
  }
  return null;
}

function isShimFile(path: string): boolean {
  return readText(path).slice(0, 160).includes(SHIM_SENTINEL);
}

const VERSION_MANAGER_DIR_NAMES = ["nvm", "asdf", "volta", "corepack", "fnm", "n"];

function versionManagerLabel(dir: string): string {
  const segments = dir.split(sep).map((segment) => segment.replace(/^\./, ""));
  const manager = VERSION_MANAGER_DIR_NAMES.find((name) => segments.includes(name));
  return manager ? ` (${manager})` : "";
}

export function currentShellActivation(env: NodeJS.ProcessEnv = process.env): string {
  const shell = resolveShell("auto", env);
  const homeDir = resolveDgPaths(env).homeDir;
  const rcPath = shellRcPath(homeDir, shell);
  const rcDisplay = rcPath.startsWith(homeDir) ? `~${rcPath.slice(homeDir.length)}` : rcPath;
  return activationCommand(shell, rcDisplay);
}

function realBinaryResolutionCheck(env: NodeJS.ProcessEnv): RawDoctorCheck {
  const installed = SHIM_COMMANDS.filter((command) => resolveRealBinary({ name: command, env }).path);
  const absent = SHIM_COMMANDS.filter((command) => !resolveRealBinary({ name: command, env }).path);
  return {
    name: "real-binary-resolution",
    status: "pass",
    message:
      absent.length === 0
        ? `Protecting ${installed.join(", ")}`
        : `Protecting ${installed.join(", ")} (${absent.join(", ")} not installed — nothing to protect there)`
  };
}

function authCheck(env: NodeJS.ProcessEnv): RawDoctorCheck {
  try {
    const status = authStatus(env);
    const connected = status.email && status.tier
      ? `${status.email} · ${displayTier(status.tier)} plan`
      : `Authenticated from ${status.source} token ${status.tokenPreview}`;
    return {
      name: "auth",
      status: status.authenticated ? "pass" : "warn",
      message: status.authenticated ? connected : "not signed in"
    };
  } catch (error) {
    return {
      name: "auth",
      status: "fail",
      message: error instanceof AuthError ? error.message : "Unable to read auth state"
    };
  }
}

function policyCheck(env: NodeJS.ProcessEnv): RawDoctorCheck {
  try {
    const config = loadUserConfig(env);
    return {
      name: "policy",
      status: "pass",
      message: `Local policy mode ${config.policy.mode}; project allowlists trusted: ${config.policy.trustProjectAllowlists}; release cooldown ${describeCooldownSettings(config, env)}`
    };
  } catch (error) {
    return {
      name: "policy",
      status: "fail",
      message: error instanceof ConfigError ? error.message : "Unable to read policy config"
    };
  }
}

function scriptGateCheck(env: NodeJS.ProcessEnv): RawDoctorCheck {
  try {
    const mode = loadUserConfig(env).scriptGate.mode;
    if (mode === "off") {
      return {
        name: "script-gate",
        status: "pass",
        message: "Install-script gate is off; protected installs do not report script-running packages"
      };
    }
    if (mode === "enforce") {
      return {
        name: "script-gate",
        status: "pass",
        message: "Install-script gate enforces: protected npm/yarn installs run with --ignore-scripts so packages cannot run lifecycle scripts (pnpm blocks them natively)"
      };
    }
    return {
      name: "script-gate",
      status: "pass",
      message: "Install-script gate observes: protected npm/yarn installs report packages that ran install scripts (pnpm blocks them natively)"
    };
  } catch (error) {
    return {
      name: "script-gate",
      status: "fail",
      message: error instanceof ConfigError ? error.message : "Unable to read script gate config"
    };
  }
}

export function writeRegistry(paths: DgPaths, registry: CleanupRegistry): void {
  mkdirSync(dirname(paths.cleanupRegistryPath), {
    recursive: true,
    mode: 0o700
  });
  const tempPath = `${paths.cleanupRegistryPath}.${randomBytes(6).toString("hex")}.tmp`;
  writeFileSync(tempPath, `${JSON.stringify(registry, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx"
  });
  try {
    renameSync(tempPath, paths.cleanupRegistryPath);
  } catch (error) {
    rmSync(tempPath, { force: true });
    throw error;
  }
}

function withRegistryLock<T>(paths: DgPaths, action: () => T): T {
  const lock = acquireLockSync(paths, CLEANUP_REGISTRY_LOCK, {
    staleMs: SETUP_UNINSTALL_LOCK_STALE_MS
  });
  try {
    return action();
  } finally {
    lock.release();
  }
}

function writeRegistryWithLock(paths: DgPaths, registry: CleanupRegistry): void {
  withRegistryLock(paths, () => writeRegistry(paths, registry));
}

function removeShim(entry: CleanupRegistryEntry, removed: string[], missing: string[], warnings: string[]): void {
  if (!existsSync(entry.path)) {
    missing.push(entry.path);
    return;
  }
  if (!validShim(entry.path, basename(entry.path))) {
    warnings.push(`refused to remove drifted shim: ${entry.path}`);
    return;
  }
  rmSync(entry.path, {
    force: true
  });
  removed.push(entry.path);
}

function removeRcBlock(entry: CleanupRegistryEntry, removed: string[], missing: string[], warnings: string[]): void {
  const existing = readText(entry.path);
  if (!existing) {
    missing.push(entry.path);
    return;
  }
  if (!existing.includes(RC_SENTINEL)) {
    warnings.push(`refused to edit shell rc without dg sentinel: ${entry.path}`);
    return;
  }
  const stripped = stripRcBlockDetailed(existing);
  try {
    writeRcFileAtomic(entry.path, stripped.content);
  } catch (error) {
    warnings.push(`could not rewrite shell rc ${entry.path}: ${error instanceof Error ? error.message : "write error"}`);
    return;
  }
  if (stripped.repairedLines.length > 0) {
    warnings.push(
      `repaired an unterminated dg block in ${entry.path}: removed only dg-written lines (${stripped.repairedLines.join(", ")})`
    );
  }
  removed.push(entry.path);
}

// The command -v guard keeps the hook fail-open: a removed or moved dg prints
// a one-line notice and lets the commit (and any chained hook) proceed instead
// of blocking every commit with exit 127.
export function guardHookScript(dgPath: string, chainedOriginal: string | null): string {
  const dg = escapeDoubleQuotedSh(dgPath);
  const lines = [
    "#!/bin/sh",
    `# ${GUARD_HOOK_SENTINEL}`,
    `if command -v "${dg}" >/dev/null 2>&1; then`,
    `  "${dg}" scan --staged --hook || exit $?`,
    "else",
    `  echo "dg: pre-commit scan skipped (dg not runnable at ${dg}); commit allowed" >&2`,
    "fi"
  ];
  if (chainedOriginal) {
    const chained = escapeDoubleQuotedSh(chainedOriginal);
    lines.push(`[ -x "${chained}" ] && exec "${chained}" "$@"`);
  }
  lines.push("exit 0");
  return `${lines.join("\n")}\n`;
}

function unescapeDoubleQuotedSh(value: string): string {
  return value.replace(/\\([\\"$`])/g, "$1");
}

export function chainedHookOriginal(content: string): string | null {
  const matched = content.match(/^\[ -x "(.+)" \] && exec "\1" "\$@"$/m)?.[1];
  return matched ? unescapeDoubleQuotedSh(matched) : null;
}

export function guardHookDgPath(content: string): string | null {
  const matched =
    content.match(/^if command -v "(.+)" >\/dev\/null 2>&1; then$/m)?.[1] ??
    content.match(/^"(.+)" scan --staged --hook/m)?.[1] ??
    null;
  return matched ? unescapeDoubleQuotedSh(matched) : null;
}

function commitGuardCheck(registry: CleanupRegistry, env: NodeJS.ProcessEnv): RawDoctorCheck {
  const hooks = registry.entries.filter((entry) => entry.owner === "dg" && entry.kind === "git-hook");
  if (hooks.length === 0) {
    return {
      name: "commit-guard",
      status: "pass",
      message: "No commit guard installed (optional; run dg guard-commit inside a repo)"
    };
  }
  const missing = hooks.filter((entry) => !hookOwnedByDg(entry));
  if (missing.length > 0) {
    return {
      name: "commit-guard",
      status: "warn",
      message: `Commit guard hook missing or replaced at: ${missing.map((entry) => entry.path).join(", ")}`,
      fix: "re-run dg guard-commit in that repo, or dg guard-commit off to forget it"
    };
  }
  const broken = hooks.filter((entry) => {
    const dgPath = guardHookDgPath(readText(entry.path));
    return dgPath !== null && !runnableDgPath(dgPath, env);
  });
  if (broken.length > 0) {
    return {
      name: "commit-guard",
      status: "warn",
      message: `Commit guard at ${broken.map((entry) => entry.path).join(", ")} points at a dg binary that is not runnable, so commits there fail open with a notice`,
      fix: "reinstall dg, then re-run dg guard-commit"
    };
  }
  return {
    name: "commit-guard",
    status: "pass",
    message: `Commit guard installed (${hooks.length} ${hooks.length === 1 ? "repo" : "repos"}); hook and dg binary resolve`
  };
}

function hookOwnedByDg(entry: CleanupRegistryEntry): boolean {
  return readText(entry.path).split("\n", 2)[1]?.includes(entry.sentinel ?? GUARD_HOOK_SENTINEL) ?? false;
}

function runnableDgPath(dgPath: string, env: NodeJS.ProcessEnv): boolean {
  if (dgPath.includes(sep)) {
    try {
      accessSync(dgPath, constants.X_OK);
      return true;
    } catch {
      return false;
    }
  }
  return findDgExecutables(env).length > 0;
}

export function reverseGitHookEntry(
  entry: CleanupRegistryEntry,
  removed: string[],
  missing: string[],
  warnings: string[]
): void {
  const sentinel = entry.sentinel ?? GUARD_HOOK_SENTINEL;
  let ownsTarget = false;
  if (!existsSync(entry.path)) {
    missing.push(entry.path);
    ownsTarget = true;
  } else if (readText(entry.path).split("\n", 2)[1]?.includes(sentinel)) {
    rmSync(entry.path, { force: true });
    removed.push(entry.path);
    ownsTarget = true;
  } else {
    warnings.push(`refused to remove git hook without dg sentinel: ${entry.path}`);
  }
  if (!ownsTarget) {
    return;
  }
  if (entry.original) {
    if (existsSync(entry.original)) {
      try {
        renameSync(entry.original, entry.path);
        removed.push(entry.original);
      } catch (error) {
        warnings.push(`could not restore chained hook ${entry.original}: ${error instanceof Error ? error.message : "unknown error"}`);
      }
    } else {
      missing.push(entry.original);
    }
  }
}

function removeDirectory(path: string, removed: string[], missing: string[]): void {
  if (!existsSync(path)) {
    missing.push(path);
    return;
  }
  rmSync(path, {
    force: true,
    recursive: true
  });
  removed.push(path);
}

function validShim(path: string, command: string): boolean {
  if (!existsSync(path)) {
    return false;
  }
  return isValidShimSource(readText(path), command);
}

export function isValidShimSource(content: string, command: string): boolean {
  if (!content.includes(SHIM_SENTINEL)) {
    return false;
  }
  return content.includes("DG_SHIM_ACTIVE=") && content.includes('exec "') && content.includes(`" ${command} "$@"`);
}

function readText(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
