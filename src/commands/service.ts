import type { CommandContext, CommandResult, CommandSpec } from "./types.js";
import { EXIT_UNAVAILABLE, EXIT_USAGE } from "./types.js";
import { renderCommandHelp } from "./help.js";
import {
  buildServiceUninstallPlan,
  buildTrustInstallPlan,
  buildTrustUninstallPlan,
  installServiceTrust,
  readServiceState,
  renderServicePlan,
  resolveServicePaths,
  restartService,
  ServiceNotConfiguredError,
  ServiceProxyError,
  ServiceTrustStoreError,
  ServiceTrustToolMissingError,
  startService,
  stopService,
  uninstallService,
  uninstallServiceTrust
} from "../service/state.js";
import { LockBusyError } from "../state/locks.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme } from "../presentation/theme.js";

const trustCommand: CommandSpec = {
  name: "trust",
  summary: "Manage explicit service-mode trust installation.",
  usage: "dg service trust <install|uninstall>",
  details: ["Trust-store changes require explicit service-mode setup, printed write plans, consent, and full reversal."],
  subcommands: [
    {
      name: "install",
      summary: "Install explicit service-mode trust.",
      usage: "dg service trust install [--print] [--yes]",
      details: ["Managed trust installation is never part of package install or default setup."],
      handler: (context) => trustInstallHandler(context.args)
    },
    {
      name: "uninstall",
      summary: "Remove explicit service-mode trust.",
      usage: "dg service trust uninstall [--print] [--yes]",
      details: ["Managed trust removal reverses dg-owned trust-store writes."],
      handler: (context) => trustUninstallHandler(context.args)
    }
  ],
  handler: routeService
};

const serviceSubcommands: CommandSpec[] = [
  mutationSpec("start", "Start explicit service mode.", () => startService()),
  mutationSpec("stop", "Stop explicit service mode.", () => stopService()),
  mutationSpec("restart", "Restart explicit service mode.", () => restartService()),
  {
    name: "status",
    summary: "Show explicit service mode status.",
    usage: "dg service status [--json]",
    details: ["Service mode status does not mutate service or trust state."],
    handler: (context) => statusHandler(context.args)
  },
  {
    name: "doctor",
    summary: "Diagnose explicit service mode.",
    usage: "dg service doctor [--json]",
    details: ["Service doctor reports service health, trust state, policy sync, and admin guidance."],
    handler: (context) => serviceDoctorHandler(context.args)
  },
  {
    name: "uninstall",
    summary: "Uninstall explicit service mode.",
    usage: "dg service uninstall [--print] [--yes]",
    details: ["Service uninstall reverses dg-owned service and trust writes."],
    handler: (context) => serviceUninstallHandler(context.args)
  }
];

export const serviceCommand: CommandSpec = {
  name: "service",
  summary: "Manage explicit service/private-registry mode.",
  usage: "dg service <start|stop|restart|status|doctor|uninstall|trust>",
  examples: ["dg service start", "dg service status --json", "dg service trust install --print"],
  details: [
    "Service mode is never silently enabled by package install or default setup.",
    "status and doctor accept --json; uninstall and trust accept --print / --yes; start, stop, and restart accept --print."
  ],
  subcommands: [...serviceSubcommands, trustCommand],
  handler: routeService
};

function routeService(context: CommandContext): CommandResult | Promise<CommandResult> {
  const [action, trustAction, ...rest] = context.args;

  if (!action || action === "--help" || action === "-h" || action === "help") {
    return {
      exitCode: 0,
      stdout: renderCommandHelp(serviceCommand),
      stderr: ""
    };
  }

  if (action === "trust") {
    if (!trustAction || trustAction === "--help" || trustAction === "-h" || trustAction === "help") {
      return {
        exitCode: 0,
        stdout: renderCommandHelp(trustCommand, ["service", "trust"]),
        stderr: ""
      };
    }

    const trustSubcommand = trustCommand.subcommands?.find((subcommand) => subcommand.name === trustAction);
    if (!trustSubcommand) {
      return {
        exitCode: EXIT_USAGE,
        stdout: "",
        stderr: `dg service: unknown trust subcommand '${trustAction}'. Run 'dg service trust --help'.\n`
      };
    }

    return trustSubcommand.handler({
      commandPath: ["service", "trust", trustAction],
      args: rest
    });
  }

  const subcommand = serviceSubcommands.find((candidate) => candidate.name === action);
  if (!subcommand) {
    return {
      exitCode: EXIT_USAGE,
      stdout: "",
      stderr: `dg service: unknown subcommand '${action}'. Run 'dg service --help'.\n`
    };
  }

  return subcommand.handler({
    commandPath: ["service", action],
    args: [trustAction, ...rest].filter((arg): arg is string => arg !== undefined)
  });
}

function statusHandler(args: readonly string[]): CommandResult {
  const parsed = parseJsonArgs("dg service status", args);
  if ("error" in parsed) {
    return parsed.error;
  }
  const result = readServiceState();
  if (parsed.json) {
    return {
      exitCode: 0,
      stdout: `${JSON.stringify(serviceStatusJson(result.state), null, 2)}\n`,
      stderr: ""
    };
  }
  return {
    exitCode: 0,
    stdout: renderServiceStatus(result.state),
    stderr: ""
  };
}

function serviceDoctorHandler(args: readonly string[]): CommandResult {
  const parsed = parseJsonArgs("dg service doctor", args);
  if ("error" in parsed) {
    return parsed.error;
  }
  const result = readServiceState();
  const checks = serviceDoctorChecks(result.state);
  if (parsed.json) {
    return {
      exitCode: 0,
      stdout: `${JSON.stringify({ checks }, null, 2)}\n`,
      stderr: ""
    };
  }
  return {
    exitCode: 0,
    stdout: `Dependency Guardian service doctor\n\n${checks
      .map((check) => `${check.status.toUpperCase()} ${check.name}: ${check.message}`)
      .join("\n")}\n`,
    stderr: ""
  };
}

type ServiceMutationAction = "start" | "stop" | "restart";

function mutationSpec(action: ServiceMutationAction, summary: string, run: () => ReturnType<typeof startService>): CommandSpec {
  const spec: CommandSpec = {
    name: action,
    summary,
    usage: `dg service ${action} [--print]`,
    flags: [{ flag: "--print", summary: "Show what this would change without acting." }],
    details: ["Service mode is explicit, reversible, documented, and separate from default setup."],
    handler: (context) => mutationHandler(spec, action, run, context.args)
  };
  return spec;
}

function mutationHandler(
  spec: CommandSpec,
  action: ServiceMutationAction,
  run: () => ReturnType<typeof startService>,
  args: readonly string[]
): CommandResult {
  let printOnly = false;
  for (const arg of args) {
    if (arg === "--help" || arg === "-h" || arg === "help") {
      return {
        exitCode: 0,
        stdout: renderCommandHelp(spec, ["service", action]),
        stderr: ""
      };
    }
    if (arg === "--print") {
      printOnly = true;
      continue;
    }
    return {
      exitCode: EXIT_USAGE,
      stdout: "",
      stderr: `dg service ${action}: unknown option '${arg}'. Run 'dg service ${action} --help'.\n`
    };
  }
  if (printOnly) {
    return {
      exitCode: 0,
      stdout: renderServicePlan(`Dependency Guardian service ${action} plan`, { writes: mutationPlanWrites(action) }),
      stderr: ""
    };
  }
  return serviceMutation(action, run);
}

function mutationPlanWrites(action: ServiceMutationAction): readonly { readonly action: string; readonly path: string }[] {
  const paths = resolveServicePaths();
  const startWrites = [
    { action: "start the dg service proxy worker and record its runtime state", path: paths.runtimePath },
    { action: "mark explicit service mode running", path: paths.statePath }
  ];
  const stopWrites = [
    { action: "stop the dg service proxy worker and remove its runtime state", path: paths.runtimePath },
    { action: "mark explicit service mode stopped", path: paths.statePath }
  ];
  if (action === "start") {
    return startWrites;
  }
  if (action === "stop") {
    return stopWrites;
  }
  return [...stopWrites.slice(0, 1), ...startWrites];
}

function serviceMutation(action: ServiceMutationAction, run: () => ReturnType<typeof startService>): CommandResult {
  try {
    const result = run();
    const theme = createTheme(resolvePresentation().color);
    const changed = result.changed ? actionPastTense(action) : `already ${action === "start" ? "running" : "stopped"}`;
    const detail = result.state.running && result.state.proxy ? ` ${theme.paint("muted", `at ${result.state.proxy.proxyUrl}`)}` : "";
    return {
      exitCode: 0,
      stdout: `${theme.paint("pass", "✓")} Service ${changed}${detail} ${theme.paint("muted", "· dg service status")}\n`,
      stderr: ""
    };
  } catch (error) {
    if (error instanceof ServiceNotConfiguredError) {
      return serviceNotConfiguredResult();
    }
    if (error instanceof ServiceProxyError || error instanceof ServiceTrustStoreError || error instanceof LockBusyError) {
      return {
        exitCode: 1,
        stdout: "",
        stderr: `dg service ${action}: ${error.message}\n`
      };
    }
    throw error;
  }
}

function trustInstallHandler(args: readonly string[]): CommandResult {
  const parsed = parsePlanArgs("dg service trust install", args);
  if ("error" in parsed) {
    return parsed.error;
  }
  const planText = renderServicePlan("Dependency Guardian service trust install plan", buildTrustInstallPlan());
  if (parsed.printOnly) {
    return {
      exitCode: 0,
      stdout: planText,
      stderr: ""
    };
  }
  if (!parsed.yes) {
    return {
      exitCode: EXIT_USAGE,
      stdout: planText,
      stderr: "dg service trust install requires --yes to apply this non-interactive write plan.\n"
    };
  }
  try {
    const result = installServiceTrust();
    return {
      exitCode: 0,
      stdout: `${planText}\nService trust ${result.changed ? "installed" : "already installed"}.\n`,
      stderr: ""
    };
  } catch (error) {
    if (error instanceof ServiceNotConfiguredError) {
      return serviceNotConfiguredResult();
    }
    if (error instanceof ServiceTrustToolMissingError) {
      return trustToolMissingResult(planText, error.tool);
    }
    if (error instanceof ServiceTrustStoreError) {
      return trustStoreFailureResult(planText, "install", error.message);
    }
    if (error instanceof LockBusyError) {
      return { exitCode: 1, stdout: "", stderr: `dg service trust install: ${error.message}\n` };
    }
    throw error;
  }
}

function trustUninstallHandler(args: readonly string[]): CommandResult {
  const parsed = parsePlanArgs("dg service trust uninstall", args);
  if ("error" in parsed) {
    return parsed.error;
  }
  const planText = renderServicePlan("Dependency Guardian service trust uninstall plan", buildTrustUninstallPlan());
  if (parsed.printOnly) {
    return {
      exitCode: 0,
      stdout: planText,
      stderr: ""
    };
  }
  if (!parsed.yes) {
    return {
      exitCode: EXIT_USAGE,
      stdout: planText,
      stderr: "dg service trust uninstall requires --yes to apply this non-interactive write plan.\n"
    };
  }
  try {
    const result = uninstallServiceTrust();
    return {
      exitCode: 0,
      stdout: `${planText}\nService trust ${result.changed ? "uninstalled" : "was already absent"}.\n`,
      stderr: ""
    };
  } catch (error) {
    if (error instanceof ServiceTrustStoreError) {
      return trustStoreFailureResult(planText, "uninstall", error.message);
    }
    if (error instanceof LockBusyError) {
      return { exitCode: 1, stdout: "", stderr: `dg service trust uninstall: ${error.message}\n` };
    }
    throw error;
  }
}

export function serviceUninstallHandler(args: readonly string[]): CommandResult {
  const parsed = parsePlanArgs("dg service uninstall", args);
  if ("error" in parsed) {
    return parsed.error;
  }
  const planText = renderServicePlan("Dependency Guardian service uninstall plan", buildServiceUninstallPlan());
  if (parsed.printOnly) {
    return {
      exitCode: 0,
      stdout: planText,
      stderr: ""
    };
  }
  if (!parsed.yes) {
    return {
      exitCode: EXIT_USAGE,
      stdout: planText,
      stderr: "dg service uninstall requires --yes to remove service-mode writes in non-interactive mode.\n"
    };
  }
  try {
    const result = uninstallService();
    return {
      exitCode: 0,
      stdout: `${planText}\n${[
        "Dependency Guardian service uninstall",
        ...result.removed.map((path) => `removed: ${path}`),
        result.removed.length === 0 ? "No dg-owned service writes were present." : "Service uninstall completed."
      ].join("\n")}\n`,
      stderr: ""
    };
  } catch (error) {
    if (error instanceof ServiceTrustStoreError) {
      return trustStoreFailureResult(planText, "uninstall", error.message);
    }
    if (error instanceof LockBusyError) {
      return { exitCode: 1, stdout: "", stderr: `dg service uninstall: ${error.message}\n` };
    }
    throw error;
  }
}

function parsePlanArgs(command: string, args: readonly string[]):
  | {
      readonly printOnly: boolean;
      readonly yes: boolean;
    }
  | {
      readonly error: CommandResult;
    } {
  let printOnly = false;
  let yes = false;
  for (const arg of args) {
    if (arg === "--print") {
      printOnly = true;
    } else if (arg === "--yes") {
      yes = true;
    } else {
      return {
        error: {
          exitCode: EXIT_USAGE,
          stdout: "",
          stderr: `${command}: unknown option '${arg}'. Run '${command} --help'.\n`
        }
      };
    }
  }
  return {
    printOnly,
    yes
  };
}

function parseJsonArgs(command: string, args: readonly string[]):
  | {
      readonly json: boolean;
    }
  | {
      readonly error: CommandResult;
    } {
  let json = false;
  for (const arg of args) {
    if (arg === "--json") {
      json = true;
    } else {
      return {
        error: {
          exitCode: EXIT_USAGE,
          stdout: "",
          stderr: `${command}: unknown option '${arg}'. Run '${command} --help'.\n`
        }
      };
    }
  }
  return {
    json
  };
}

function renderServiceStatus(state: ReturnType<typeof readServiceState>["state"]): string {
  const theme = createTheme(resolvePresentation().color);
  const pass = (text: string): string => `${theme.paint("pass", "✓")} ${text}`;
  const warn = (text: string): string => `${theme.paint("warn", "⚠")} ${text}`;
  const configured = state.configured
    ? pass("yes")
    : warn(`no — run ${theme.paint("accent", "dg setup --service --yes")}`);
  const running = state.running && state.proxy
    ? pass(`yes ${theme.paint("muted", `(${state.proxy.proxyUrl})`)}`)
    : warn(state.configured ? `no — run ${theme.paint("accent", "dg service start")}` : "no");
  const trust = state.trust
    ? pass(`${state.trust.provider} ${theme.paint("muted", `(${state.trust.fingerprintSha256.slice(0, 12)}…)`)}`)
    : warn(`not installed — run ${theme.paint("accent", "dg service trust install --yes")}`);
  const lines = [
    "Dependency Guardian service",
    "",
    `  Configured   ${configured}`,
    `  Running      ${running}`,
    `  Trust        ${trust}`
  ];
  if (state.trustDrift) {
    lines.push(`  Trust drift  ${warn(state.trustDrift.message)}`);
  }
  lines.push(`  Policy sync  ${state.policySyncedAt ? pass(state.policySyncedAt) : theme.paint("muted", "never")}`);
  if (state.lastError) {
    lines.push(`  Last error   ${warn(state.lastError)}`);
  }
  lines.push("");
  lines.push(`Full diagnostics: ${theme.paint("accent", "dg service doctor")}`);
  return `${lines.join("\n")}\n`;
}

function serviceStatusJson(state: ReturnType<typeof readServiceState>["state"]): object {
  return {
    configured: state.configured,
    running: state.running,
    trustInstalled: state.trustInstalled,
    trust: state.trust
      ? {
          provider: state.trust.provider,
          native: state.trust.native,
          adminRequired: state.trust.adminRequired,
          target: state.trust.target,
          fingerprintSha256: state.trust.fingerprintSha256,
          installedAt: state.trust.installedAt
        }
      : null,
    proxy: state.proxy ? {
      pid: state.proxy.pid,
      proxyUrl: state.proxy.proxyUrl,
      healthUrl: state.proxy.healthUrl,
      sessionDir: state.proxy.sessionDir,
      caPath: state.proxy.caPath,
      startedAt: state.proxy.startedAt
    } : null,
    trustDrift: state.trustDrift ? {
      installedFingerprintSha256: state.trustDrift.installedFingerprintSha256,
      activeFingerprintSha256: state.trustDrift.activeFingerprintSha256 ?? null,
      message: state.trustDrift.message
    } : null,
    lastError: state.lastError ?? null,
    policySyncedAt: state.policySyncedAt ?? null
  };
}

function serviceDoctorChecks(state: ReturnType<typeof readServiceState>["state"]): readonly {
  readonly name: string;
  readonly status: "pass" | "warn" | "fail";
  readonly message: string;
}[] {
  return [
    {
      name: "configured",
      status: state.configured ? "pass" : "warn",
      message: state.configured ? "Explicit service mode is configured" : "Run dg setup --service --yes before service start"
    },
    {
      name: "running",
      status: state.running ? "pass" : state.lastError?.startsWith("stale service runtime state") ? "fail" : "warn",
      message: state.running ? "Service controller state is running" : state.lastError ?? "Service is stopped"
    },
    {
      name: "trust",
      status: state.trustInstalled ? "pass" : "warn",
      message: state.trust
        ? `Managed service trust is installed through ${state.trust.provider} for ${state.trust.fingerprintSha256}`
        : "No managed service trust-store entry is installed"
    },
    {
      name: "trust-drift",
      status: state.trustDrift ? "warn" : "pass",
      message: state.trustDrift?.message ?? "Managed service trust matches the active CA or is not installed"
    },
    {
      name: "policy-sync",
      status: state.policySyncedAt ? "pass" : "warn",
      message: state.policySyncedAt ? `Last policy sync ${state.policySyncedAt}` : "Policy has not been synced for service mode"
    },
    {
      name: "service-proxy",
      status: state.running && state.proxy ? "pass" : state.lastError?.startsWith("stale service runtime state") ? "fail" : "warn",
      message: state.running && state.proxy ? `Persistent service proxy listening at ${state.proxy.proxyUrl}` : state.lastError ?? "Service proxy is not running"
    },
    {
      name: "health-endpoint",
      status: state.running && state.proxy ? "pass" : state.lastError?.startsWith("stale service runtime state") ? "fail" : "warn",
      message: state.running && state.proxy ? `Health endpoint available at ${state.proxy.healthUrl}` : state.lastError ?? "Service health endpoint is not running"
    },
    {
      name: "admin",
      status: state.trust?.adminRequired ? "warn" : "pass",
      message:
        "Native service trust-store mutation is consent-gated; Linux system trust requires admin/root, macOS user-keychain trust does not, and CI/Docker can use an explicit file trust backend"
    }
  ];
}

function actionPastTense(action: "start" | "stop" | "restart"): string {
  if (action === "start") {
    return "started";
  }
  if (action === "stop") {
    return "stopped";
  }
  return "restarted";
}

function serviceNotConfiguredResult(): CommandResult {
  const theme = createTheme(resolvePresentation().color);
  return {
    exitCode: EXIT_USAGE,
    stdout: "",
    stderr: `${theme.paint("warn", "dg service is not configured")} — run ${theme.paint("accent", "dg setup --service --yes")} first ${theme.paint("muted", "(no service or trust state was changed)")}\n`
  };
}

function trustStoreFailureResult(planText: string, action: "install" | "uninstall", message: string): CommandResult {
  return {
    exitCode: 1,
    stdout: planText,
    stderr: `dg service trust ${action} failed before recording successful trust state: ${message}\n`
  };
}

function trustToolMissingResult(planText: string, tool: string): CommandResult {
  return {
    exitCode: EXIT_UNAVAILABLE,
    stdout: planText,
    stderr:
      `dg service trust install: '${tool}' is not available on this system, so no trust state was changed.\n` +
      "Native trust install is supported on macOS (security) and Debian/Ubuntu Linux (update-ca-certificates).\n" +
      "On other systems, set DG_SERVICE_TRUST_STORE_BACKEND=file with DG_SERVICE_TRUST_STORE_DIR=<dir> and point your tooling at the exported CA file.\n"
  };
}
