import { createLaunchPlan, prepareProxyWorker, runWithProductionProxyLive, EXIT_INSTALL_BLOCKED, type PreparedProxyWorker, type RunPackageManagerOptions } from "./run.js";
import { runInstallPreflight, type InstallPreflight } from "./install-preflight.js";
import { isSupportedPackageManager, normalizeManagerName, type PackageManager } from "./classify.js";
import { isCiEnv, resolvePresentation } from "../presentation/mode.js";
import { startPrepSpinner } from "../install-ui/prep-spinner.js";
import type { CommandResult } from "../commands/types.js";
import type { ForceOverrideRequest } from "../proxy/enforcement.js";

export type LiveInstallOutcome =
  | { readonly handled: false }
  | { readonly handled: true; readonly result: CommandResult };

const FALL_THROUGH: LiveInstallOutcome = { handled: false };

export async function maybeRunLiveInstall(
  args: readonly string[],
  options: RunPackageManagerOptions = {}
): Promise<LiveInstallOutcome> {
  const env = options.env ?? process.env;
  if (!process.stdout.isTTY || isCiEnv(env) || resolvePresentation().mode !== "rich") {
    return FALL_THROUGH;
  }

  const [rawManager, ...rest] = args;
  const manager = normalizeManagerName(rawManager ?? "") as PackageManager;
  if (!rawManager || !isSupportedPackageManager(manager)) {
    return FALL_THROUGH;
  }

  const { childArgs, forceOverride } = stripControlArgs(rest);
  const plan = createLaunchPlan(manager as PackageManager, childArgs, env);
  if (plan.classification.kind !== "protected" || !plan.realBinary.path) {
    return FALL_THROUGH;
  }

  const appLoading = import("../install-ui/live-install-app.js");
  appLoading.catch(() => undefined);
  let prepared: PreparedProxyWorker | undefined = forceOverride ? undefined : prepareProxyWorker(plan.classification, env);

  let effectiveOverride = forceOverride;
  let preverified: InstallPreflight["preverified"];
  if (!forceOverride) {
    const spinner = startPrepSpinner("DG preparing…");
    let preflight;
    try {
      preflight = await runInstallPreflight(manager, plan.realBinary.path, childArgs, env, process.cwd(), spinner.stop);
    } finally {
      spinner.stop();
    }
    if (!preflight.proceed) {
      prepared?.discard();
      return { handled: true, result: { exitCode: EXIT_INSTALL_BLOCKED, stdout: "", stderr: "  Install cancelled.\n" } };
    }
    effectiveOverride = preflight.forceOverride;
    preverified = preflight.preverified;
    if (effectiveOverride) {
      prepared?.discard();
      prepared = undefined;
    }
  }

  const runOptions: RunPackageManagerOptions = {
    env,
    ...(effectiveOverride ? { forceOverride: effectiveOverride } : {}),
    ...(preverified && preverified.length > 0 && !effectiveOverride ? { preverified } : {})
  };

  try {
    const { renderLiveInstall } = await appLoading;
    const result = await renderLiveInstall((onView) =>
      runWithProductionProxyLive(plan, childArgs, runOptions, onView, prepared)
    );
    return { handled: true, result };
  } catch (error) {
    prepared?.discard();
    return {
      handled: true,
      result: {
        exitCode: 1,
        stdout: "",
        stderr: `dg protection failed: ${error instanceof Error ? error.message : "unknown error"}\n`
      }
    };
  }
}

function stripControlArgs(args: readonly string[]): { childArgs: string[]; forceOverride?: ForceOverrideRequest } {
  const childArgs: string[] = [];
  let force = false;
  for (const arg of args) {
    if (arg === "--dg-force-install") {
      force = true;
      continue;
    }
    childArgs.push(arg);
  }
  return force ? { childArgs, forceOverride: { force: true } } : { childArgs };
}
