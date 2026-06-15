import { rmSync } from "node:fs";
import { join } from "node:path";
import { uninstallSetup } from "./plan.js";
import { LockBusyError, resolveDgPaths } from "../state/index.js";

function run(): void {
  const quiet = process.argv.includes("--quiet");
  try {
    const result = uninstallSetup({ keepConfig: false, all: true });
    if (!quiet) {
      process.stderr.write(
        `Dependency Guardian cleaned up ${result.removed.length} leftover item(s) after the package was removed.\n`
      );
    }
  } catch (error) {
    if (!quiet && !(error instanceof LockBusyError)) {
      process.stderr.write(`dg self-cleanup could not finish: ${(error as Error).message}\n`);
    }
  }
  try {
    rmSync(join(resolveDgPaths().homeDir, ".dg"), { recursive: true, force: true });
  } catch {
    return;
  }
}

run();
