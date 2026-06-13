import { configCommand } from "./config.js";
import { auditCommand } from "./audit.js";
import { cooldownCommand } from "./cooldown.js";
import { decisionsCommand } from "./decisions.js";
import { doctorCommand } from "./doctor.js";
import { guardCommitCommand } from "./guard-commit.js";
import { agentsCommand } from "./agents.js";
import { renderCommandHelp, renderRootHelp } from "./help.js";
import { licensesCommand } from "./licenses.js";
import { sbomCommand } from "./sbom.js";
import { loginCommand } from "./login.js";
import { logoutCommand } from "./logout.js";
import { packageManagerCommands } from "./wrap.js";
import { scanCommand } from "./scan.js";
import { serviceCommand } from "./service.js";
import { setupCommand } from "./setup.js";
import { statusCommand } from "./status.js";
import { closestCommand } from "./suggest.js";
import type { CommandResult, CommandSpec } from "./types.js";
import { EXIT_USAGE } from "./types.js";
import { uninstallCommand } from "./uninstall.js";
import { updateCommand } from "./update.js";
import { verifyCommand } from "./verify.js";
import { dgVersion, versionResult } from "./version.js";

export const commandCatalog: readonly CommandSpec[] = [
  scanCommand,
  sbomCommand,
  verifyCommand,
  setupCommand,
  guardCommitCommand,
  agentsCommand,
  decisionsCommand,
  cooldownCommand,
  uninstallCommand,
  doctorCommand,
  statusCommand,
  ...packageManagerCommands(),
  loginCommand,
  logoutCommand,
  configCommand,
  licensesCommand,
  auditCommand,
  updateCommand,
  serviceCommand
];

function commandNames(): string[] {
  const names = new Set<string>(["help", "version", "upgrade"]);
  for (const command of commandCatalog) {
    names.add(command.name);
    for (const alias of command.aliases ?? []) {
      names.add(alias);
    }
  }
  return [...names];
}

export async function routeCommand(args: readonly string[]): Promise<CommandResult> {
  const [commandName, ...rest] = args;

  if (commandName === "--help-all" || commandName === "help-all") {
    return {
      exitCode: 0,
      stdout: renderRootHelp(dgVersion(), commandCatalog, { all: true }),
      stderr: ""
    };
  }

  if (!commandName || commandName === "--help" || commandName === "-h" || commandName === "help") {
    return {
      exitCode: 0,
      stdout: renderRootHelp(dgVersion(), commandCatalog),
      stderr: ""
    };
  }

  if (commandName === "--version" || commandName === "-v" || commandName === "version") {
    return versionResult();
  }

  if (commandName === "upgrade") {
    return updateCommand.handler({
      commandPath: ["upgrade"],
      args: rest
    });
  }

  const command = commandCatalog.find((candidate) => candidate.name === commandName || candidate.aliases?.includes(commandName));

  if (!command) {
    const suggestion = closestCommand(commandName, commandNames());
    const hint = suggestion ? ` Did you mean '${suggestion}'?` : "";
    return {
      exitCode: EXIT_USAGE,
      stdout: "",
      stderr: `dg: unknown command '${commandName}'.${hint} Run 'dg --help'.\n`
    };
  }

  const [firstArg] = rest;
  if (firstArg === "--help" || firstArg === "-h" || firstArg === "help") {
    return {
      exitCode: 0,
      stdout: renderCommandHelp(command),
      stderr: ""
    };
  }

  return command.handler({
    commandPath: [commandName],
    args: rest
  });
}
