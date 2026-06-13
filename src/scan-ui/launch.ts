import { loadUserConfig } from "../config/settings.js";
import { resolvePresentation } from "../presentation/mode.js";
import { pendingUpdate } from "../runtime/nudges.js";
import { enterTui, leaveTui } from "./alt-screen.js";
import type { CLIConfig, ScanMode } from "./shims.js";

export function shouldLaunchScanTui(options: {
  readonly targetPath: string;
  readonly format: string;
  readonly outputPath?: string | undefined;
}): boolean {
  if (options.format !== "text" || options.outputPath) {
    return false;
  }
  if (options.targetPath !== ".") {
    return false;
  }
  if (process.env.TERM === "dumb") {
    return false;
  }
  if (!process.stdin.isTTY) {
    return false;
  }
  return resolvePresentation().mode === "rich";
}

export async function launchScanTui(initialView: "results" | "licenses" = "results"): Promise<void> {
  const ci = process.env.CI;
  const ciCleared = ci === "" || ci === "0" || ci === "false";
  if (ciCleared) {
    delete process.env.CI;
  }
  const [{ render }, react, app] = await Promise.all([
    import("ink"),
    import("react"),
    import("./LegacyApp.js")
  ]);
  const mode: ScanMode = loadUserConfig().policy.mode;
  const config: CLIConfig = { mode };
  const update = pendingUpdate();
  const updateAvailable = update
    ? `Update available: ${update.current} → ${update.latest} · run dg update`
    : undefined;
  enterTui();
  const instance = render(
    react.default.createElement(app.App, { config, initialView, updateAvailable }),
    { exitOnCtrlC: true }
  );
  try {
    await instance.waitUntilExit();
  } finally {
    if (ciCleared) process.env.CI = ci;
    leaveTui();
  }
}
