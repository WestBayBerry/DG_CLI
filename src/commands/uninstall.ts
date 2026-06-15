import type { CommandSpec } from "./types.js";
import { EXIT_USAGE, type CommandResult } from "./types.js";
import { LockBusyError } from "../state/index.js";
import { uninstallSetup } from "../setup/plan.js";
import { serviceUninstallHandler } from "./service.js";

export const uninstallCommand: CommandSpec = {
  name: "uninstall",
  summary: "Reverse dg-owned setup writes.",
  usage: "dg uninstall [--yes] [--service] [--all] [--keep-config]",
  flags: [
    { flag: "--yes", summary: "Remove without the confirmation prompt." },
    { flag: "--keep-config", summary: "Keep ~/.dg config and cache." },
    { flag: "--all", summary: "Also remove the config directory — a full wipe." },
    { flag: "--service", summary: "Reverse only service-mode writes." }
  ],
  examples: ["dg uninstall", "dg uninstall --yes --keep-config", "dg uninstall --all --yes"],
  details: [
    "Removes only dg-owned writes (shims, shell-rc block, git hooks), tolerates missing or malformed state, runs twice safely, and preserves user content.",
    "Running 'npm uninstall -g @westbayberry/dg' on its own leaves these writes behind; the next npm or pip command then clears them automatically. Run this to remove everything immediately."
  ],
  handler: (context) => uninstallHandler(context.args)
};

function uninstallHandler(args: readonly string[]): CommandResult {
  const parsed = parseUninstallArgs(args);
  if ("error" in parsed) {
    return {
      exitCode: parsed.exitCode,
      stdout: "",
      stderr: parsed.error
    };
  }

  if (parsed.service) {
    return serviceUninstallHandler(args.filter((arg) => arg !== "--service"));
  }

  if (!parsed.yes) {
    return {
      exitCode: EXIT_USAGE,
      stdout: "Dependency Guardian uninstall will remove only registered dg-owned setup writes.\n",
      stderr: "dg uninstall requires --yes to remove files in non-interactive mode.\n"
    };
  }

  let result;
  try {
    result = uninstallSetup({
      keepConfig: parsed.keepConfig,
      all: parsed.all
    });
  } catch (error) {
    if (error instanceof LockBusyError) {
      return {
        exitCode: 1,
        stdout: "Dependency Guardian uninstall will remove only registered dg-owned setup writes.\n",
        stderr: `dg uninstall cannot run while another setup or uninstall is running: ${error.path}\n`
      };
    }
    throw error;
  }
  const lines = [
    "Dependency Guardian uninstall",
    "",
    ...result.removed.map((path) => `removed: ${path}`),
    ...result.staleSessions.map((id) => `stale session removed: ${id}`),
    ...result.missing.map((path) => `already absent: ${path}`),
    ...result.warnings.map((warning) => `warning: ${warning}`),
    result.removed.length === 0 && result.staleSessions.length === 0 && result.warnings.length === 0
      ? "No dg-owned setup writes were present."
      : "Uninstall completed."
  ];

  return {
    exitCode: 0,
    stdout: `${lines.join("\n")}\n`,
    stderr: ""
  };
}

type ParsedUninstallArgs =
  | {
      readonly yes: boolean;
      readonly keepConfig: boolean;
      readonly all: boolean;
      readonly service: boolean;
    }
  | {
      readonly error: string;
      readonly exitCode: number;
    };

function parseUninstallArgs(args: readonly string[]): ParsedUninstallArgs {
  let yes = false;
  let keepConfig = false;
  let all = false;
  let service = false;

  for (const arg of args) {
    if (arg === "--yes") {
      yes = true;
    } else if (arg === "--keep-config") {
      keepConfig = true;
    } else if (arg === "--all") {
      all = true;
    } else if (arg === "--service") {
      service = true;
    } else {
      return {
        exitCode: EXIT_USAGE,
        error: `dg uninstall: unknown option '${arg}'. Run 'dg uninstall --help'.\n`
      };
    }
  }

  if (all && keepConfig) {
    return {
      exitCode: EXIT_USAGE,
      error: "dg uninstall: --all and --keep-config conflict — choose one. Run 'dg uninstall --help'.\n"
    };
  }

  return {
    yes,
    keepConfig,
    all,
    service
  };
}
