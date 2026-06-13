import { spawnSync } from "node:child_process";
import { mkdirSync, rmSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";

const LOCK_STALE_MS = 180_000;

export default async function setup(): Promise<void> {
  const cliRoot = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
  const lockDir = join(cliRoot, ".vitest-build-lock");
  await acquireLock(lockDir);
  try {
    const build = spawnSync(process.execPath, ["build.mjs"], {
      cwd: cliRoot,
      encoding: "utf8"
    });
    if (build.status !== 0) {
      throw new Error(`dist build failed before tests:\n${build.stdout}\n${build.stderr}`);
    }
  } finally {
    rmSync(lockDir, { force: true, recursive: true });
  }
}

async function acquireLock(lockDir: string): Promise<void> {
  for (;;) {
    try {
      mkdirSync(lockDir);
      return;
    } catch {
      try {
        if (Date.now() - statSync(lockDir).mtimeMs > LOCK_STALE_MS) {
          rmSync(lockDir, { force: true, recursive: true });
          continue;
        }
      } catch {
        continue;
      }
      await new Promise((r) => setTimeout(r, 500));
    }
  }
}
