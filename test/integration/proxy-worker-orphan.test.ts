import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { classifyPackageManagerInvocation } from "../../src/launcher/classify.js";
import { createSessionSync, resolveDgPaths } from "../../src/state/index.js";

const workerPath = fileURLToPath(new URL("../../dist/proxy/worker.js", import.meta.url));

const fakeParentScript = [
  'const { spawn } = require("node:child_process");',
  "const [workerPath, sessionJsonPath, apiBaseUrl] = process.argv.slice(1);",
  'const worker = spawn(process.execPath, [workerPath, sessionJsonPath, apiBaseUrl], { stdio: ["inherit", "inherit", "inherit"] });',
  "process.stdout.write(`worker-pid ${worker.pid}\\n`);",
  "setInterval(() => {}, 1000);"
].join("\n");

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitFor(predicate: () => boolean, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return predicate();
}

describe("proxy worker orphan handling", () => {
  it("exits via the parent-pid poll and removes its session dir after the parent is SIGKILLed", async () => {
    const home = await mkdtemp(join(tmpdir(), "dg-worker-orphan-"));
    const paths = resolveDgPaths({ HOME: home });
    const session = createSessionSync(paths);
    const sessionJsonPath = join(session.dir, "session.json");
    await writeFile(sessionJsonPath, `${JSON.stringify(session)}\n`, "utf8");

    const fakeParent = spawn(
      process.execPath,
      ["-e", fakeParentScript, workerPath, sessionJsonPath, "http://127.0.0.1:9"],
      {
        env: {
          ...process.env,
          HOME: home,
          XDG_CONFIG_HOME: "",
          XDG_STATE_HOME: "",
          XDG_CACHE_HOME: "",
          DG_PROXY_CLASSIFICATION: JSON.stringify(classifyPackageManagerInvocation("npm", ["install", "left-pad"]))
        },
        stdio: ["pipe", "pipe", "pipe"]
      }
    );

    let stdout = "";
    let stderr = "";
    fakeParent.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    fakeParent.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });

    try {
      const started = await waitFor(() => /worker-pid \d+/.test(stdout) && /ready \d+/.test(stdout), 20_000);
      expect(started, `worker did not start: stdout=${stdout} stderr=${stderr}`).toBe(true);
      const workerPid = Number(/worker-pid (\d+)/.exec(stdout)?.[1]);
      expect(Number.isInteger(workerPid)).toBe(true);
      expect(isAlive(workerPid)).toBe(true);
      await expect(readFile(session.files.pid, "utf8")).resolves.toBe(`${workerPid}\n`);

      fakeParent.kill("SIGKILL");

      expect(await waitFor(() => !isAlive(workerPid), 15_000)).toBe(true);
      expect(await waitFor(() => !existsSync(session.dir), 5_000)).toBe(true);
    } finally {
      if (fakeParent.exitCode === null && fakeParent.signalCode === null) {
        fakeParent.kill("SIGKILL");
      }
      await rm(home, { recursive: true, force: true });
    }
  }, 45_000);
});
