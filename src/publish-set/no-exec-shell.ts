import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface NoExecShell {
  readonly env: NodeJS.ProcessEnv;
  cleanup(): void;
}

export function noExecPackEnv(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform): NoExecShell {
  const dir = mkdtempSync(join(tmpdir(), "dg-noexec-shell-"));
  const windows = platform === "win32";
  const shellPath = join(dir, windows ? "noop.cmd" : "noop.sh");
  if (windows) {
    writeFileSync(shellPath, "@exit /b 0\r\n", "utf8");
  } else {
    writeFileSync(shellPath, "#!/bin/sh\nexit 0\n", "utf8");
    chmodSync(shellPath, 0o755);
  }
  return {
    env: { ...env, npm_config_script_shell: shellPath },
    cleanup: () => rmSync(dir, { recursive: true, force: true })
  };
}
