import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { dgVersion } from "../commands/version.js";
import { isCiEnv } from "../presentation/mode.js";
import { createTheme } from "../presentation/theme.js";
import { refreshSetupOnUpgrade, sweepLegacyPythonHooks } from "../setup/plan.js";
import { resolveDgPaths, type DgPathEnvironment } from "../state/index.js";

const SKIP_COMMANDS = new Set([
  "help",
  "--help",
  "-h",
  "--help-all",
  "version",
  "--version",
  "-v",
  "login",
  "logout",
  "update",
  "upgrade",
  "uninstall"
]);

export const MACHINE_OUTPUT_FLAGS = new Set([
  "--json",
  "--sarif",
  "--csv",
  "--markdown",
  "--output",
  "-o",
  "--quiet"
]);

export function firstRunMarkerPath(env: DgPathEnvironment = process.env): string {
  return join(resolveDgPaths(env).stateDir, "first-run-shown");
}

export function lastRunVersionMarkerPath(env: DgPathEnvironment = process.env): string {
  return join(resolveDgPaths(env).stateDir, "last-run-version");
}

export function sweepLegacyHooksOnVersionChange(
  env: DgPathEnvironment = process.env,
  version = dgVersion()
): boolean {
  try {
    const marker = lastRunVersionMarkerPath(env);
    const recorded = existsSync(marker) ? readFileSync(marker, "utf8").trim() : undefined;
    if (recorded === version) {
      return false;
    }
    sweepLegacyPythonHooks(resolveDgPaths(env).homeDir, [], []);
    refreshSetupOnUpgrade(env);
    mkdirSync(dirname(marker), { recursive: true, mode: 0o700 });
    writeFileSync(marker, `${version}\n`, { encoding: "utf8", mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

export function markFirstRunShown(env: DgPathEnvironment = process.env, now = new Date()): void {
  try {
    const marker = firstRunMarkerPath(env);
    mkdirSync(dirname(marker), { recursive: true, mode: 0o700 });
    writeFileSync(marker, `${now.toISOString()}\n`, { encoding: "utf8", mode: 0o600 });
  } catch {
    return;
  }
}

export function maybeShowFirstRun(
  args: readonly string[],
  options: {
    readonly env?: DgPathEnvironment;
    readonly stderr?: { isTTY?: boolean; write(text: string): unknown };
  } = {}
): boolean {
  const env = options.env ?? process.env;
  const stderr = options.stderr ?? process.stderr;
  const command = args[0] ?? "";

  sweepLegacyHooksOnVersionChange(env);

  if (!stderr.isTTY || isCiEnv(env)) {
    return false;
  }
  if (SKIP_COMMANDS.has(command) || args.some((arg) => MACHINE_OUTPUT_FLAGS.has(arg))) {
    return false;
  }
  const marker = firstRunMarkerPath(env);
  if (existsSync(marker)) {
    return false;
  }

  const theme = createTheme(true);
  const command_ = (text: string): string => theme.paint("accent", text);
  const lines = [
    "",
    `  ${theme.paint("pass", "✓")} Dependency Guardian is ready.`,
    "",
    `  ${theme.paint("muted", "dg npm install / dg pip install scan packages before they run.")}`,
    `  ${theme.paint("muted", "Run")} ${command_("dg setup")} ${theme.paint("muted", "once to protect bare npm/pip installs too.")}`,
    "",
    ""
  ];
  stderr.write(lines.join("\n"));
  markFirstRunShown(env);
  return true;
}
