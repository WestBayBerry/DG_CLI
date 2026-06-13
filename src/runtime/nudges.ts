import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { authStatus } from "../auth/store.js";
import { compareVersions, readLatestVersion } from "../commands/update.js";
import { dgVersion } from "../commands/version.js";
import { isCiEnv } from "../presentation/mode.js";
import { createTheme } from "../presentation/theme.js";
import { resolveDgPaths, type DgPathEnvironment } from "../state/index.js";

const UPDATE_THROTTLE_MS = 24 * 60 * 60 * 1000;
const LOGIN_THROTTLE_MS = 7 * 24 * 60 * 60 * 1000;
const LATEST_LOOKUP_TIMEOUT_MS = 1500;

const SKIP_COMMANDS = new Set([
  "",
  "help",
  "--help",
  "-h",
  "--help-all",
  "version",
  "--version",
  "-v",
  "login",
  "logout",
  "setup",
  "update",
  "upgrade",
  "uninstall",
  "scan",
  "licenses",
  "sbom"
]);

type NudgeState = {
  updateCheckedAt?: string;
  updateLatest?: string;
  loginNudgedAt?: string;
  setupNudgedAt?: string;
};

export function nudgeStatePath(env: DgPathEnvironment = process.env): string {
  return join(resolveDgPaths(env).stateDir, "nudges.json");
}

export function maybeShowNudges(
  args: readonly string[],
  options: {
    readonly env?: DgPathEnvironment;
    readonly stderr?: { isTTY?: boolean; write(text: string): unknown };
    readonly now?: Date;
  } = {}
): void {
  const env = options.env ?? process.env;
  const stderr = options.stderr ?? process.stderr;
  const now = options.now ?? new Date();
  const command = args[0] ?? "";

  if (!stderr.isTTY || isCiEnv(env)) {
    return;
  }
  if (SKIP_COMMANDS.has(command) || args.some((arg) => arg === "--json" || arg === "--sarif" || arg === "--quiet")) {
    return;
  }

  const statePath = nudgeStatePath(env);
  const state = readState(statePath);
  const theme = createTheme(true);
  const lines: string[] = [];
  let stateChanged = false;

  if (due(state.updateCheckedAt, UPDATE_THROTTLE_MS, now)) {
    const latest = readLatestVersion(LATEST_LOOKUP_TIMEOUT_MS);
    if (latest) {
      state.updateCheckedAt = now.toISOString();
      state.updateLatest = latest;
      stateChanged = true;
      if (compareVersions(latest, dgVersion()) > 0) {
        lines.push(
          `${theme.paint("warn", "⚠")} ${theme.paint("muted", `Update available: ${dgVersion()} → ${latest}. Run`)} ${theme.paint("accent", "dg update")}${theme.paint("muted", ".")}`
        );
      }
    }
  }

  if (due(state.loginNudgedAt, LOGIN_THROTTLE_MS, now) && !isAuthenticated(env)) {
    state.loginNudgedAt = now.toISOString();
    stateChanged = true;
    lines.push(`${theme.paint("muted", "Run")} ${theme.paint("accent", "dg login")} ${theme.paint("muted", "to connect your account.")}`);
  }

  if (lines.length > 0) {
    stderr.write(`\n${lines.join("\n")}\n`);
  }
  if (stateChanged) {
    writeState(statePath, state);
  }
}

export function maybeSetupNudge(
  manager: string,
  options: {
    readonly env?: DgPathEnvironment;
    readonly stderrIsTTY?: boolean;
    readonly now?: Date;
  } = {}
): string {
  const env = options.env ?? process.env;
  if (!(options.stderrIsTTY ?? process.stderr.isTTY)) {
    return "";
  }
  if (isCiEnv(env)) {
    return "";
  }
  if (env.DG_SHIM_ACTIVE) {
    return "";
  }
  const paths = resolveDgPaths(env);
  if (existsSync(join(paths.homeDir, ".dg", "shims", manager))) {
    return "";
  }
  const statePath = nudgeStatePath(env);
  const state = readState(statePath);
  if (state.setupNudgedAt) {
    return "";
  }
  state.setupNudgedAt = (options.now ?? new Date()).toISOString();
  writeState(statePath, state);
  const theme = createTheme(true);
  return `\n  ${theme.paint("muted", "Make this automatic —")} ${theme.paint("accent", "dg setup")} ${theme.paint("muted", "protects every install, no prefix.")}\n`;
}

export function recordLoginNudge(env: DgPathEnvironment = process.env, now = new Date()): void {
  const statePath = nudgeStatePath(env);
  const state = readState(statePath);
  state.loginNudgedAt = now.toISOString();
  writeState(statePath, state);
}

export function pendingUpdate(env: DgPathEnvironment = process.env): { current: string; latest: string } | null {
  const latest = readState(nudgeStatePath(env)).updateLatest;
  if (!latest || compareVersions(latest, dgVersion()) <= 0) {
    return null;
  }
  return { current: dgVersion(), latest };
}

function isAuthenticated(env: DgPathEnvironment): boolean {
  try {
    return authStatus(env).authenticated;
  } catch {
    return true;
  }
}

function due(last: string | undefined, throttleMs: number, now: Date): boolean {
  if (!last) {
    return true;
  }
  const parsed = Date.parse(last);
  return !Number.isFinite(parsed) || now.getTime() - parsed >= throttleMs;
}

function readState(path: string): NudgeState {
  try {
    if (!existsSync(path)) {
      return {};
    }
    return JSON.parse(readFileSync(path, "utf8")) as NudgeState;
  } catch {
    return {};
  }
}

function writeState(path: string, state: NudgeState): void {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  } catch {
    return;
  }
}
