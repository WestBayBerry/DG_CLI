import { routeCommand } from "../commands/router.js";
import type { CommandResult } from "../commands/types.js";

export function runCli(args: readonly string[]): Promise<CommandResult> {
  return routeCommand(args);
}

export function writeCliResult(result: CommandResult): void {
  if (result.stdout) {
    process.stdout.write(result.stdout);
  }
  if (result.stderr) {
    process.stderr.write(result.stderr);
  }
  process.exitCode = result.exitCode;
}
