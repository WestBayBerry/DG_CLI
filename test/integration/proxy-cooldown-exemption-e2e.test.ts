import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createServer as createHttpServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { classifyPackageManagerInvocation } from "../../src/launcher/classify.js";
import { createSessionSync, resolveDgPaths } from "../../src/state/index.js";
import { loadProjectCooldownExemptions } from "../../src/launcher/run.js";
import { appendCooldownExemptions, findProjectRoot, mutateDgFile } from "../../src/project/dgfile.js";
import { proxyAuthorizationValue, readProxyAuthToken } from "../../src/proxy/auth.js";
import { COOLDOWN_EXEMPTIONS_ENV, writeCooldownExemptionsFile } from "../../src/proxy/cooldown-exemptions-file.js";

const workerPath = fileURLToPath(new URL("../../dist/proxy/worker.js", import.meta.url));

const made: string[] = [];
const closers: Array<() => Promise<void> | void> = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}

afterEach(async () => {
  for (const close of closers.splice(0)) {
    await close();
  }
  for (const dir of made.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

type ServerHandle = { readonly port: number; readonly url: string; readonly close: () => Promise<void> };

function listen(server: ReturnType<typeof createHttpServer>): Promise<ServerHandle> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      if (typeof address !== "object" || address === null) {
        reject(new Error("test server did not bind"));
        return;
      }
      const handle: ServerHandle = {
        port: address.port,
        url: `http://127.0.0.1:${address.port}`,
        close: () => new Promise((done) => server.close(() => done()))
      };
      closers.push(handle.close);
      resolve(handle);
    });
  });
}

function startRegistry(artifact: Buffer): Promise<ServerHandle> {
  return listen(createHttpServer((_request, response) => {
    response.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": artifact.length });
    response.end(artifact);
  }));
}

function startApi(onBody: (body: Record<string, unknown>) => void): Promise<ServerHandle> {
  return listen(createHttpServer((request: IncomingMessage, response: ServerResponse) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.once("end", () => {
      onBody(JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>);
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "ok" }));
    });
  }));
}

function proxyGet(proxy: { readonly port: number; readonly proxyAuthorization: string }, targetUrl: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const target = new URL(targetUrl);
    const request = httpRequest(
      {
        hostname: "127.0.0.1",
        port: proxy.port,
        path: target.toString(),
        method: "GET",
        headers: { Host: target.host, "Proxy-Authorization": proxy.proxyAuthorization }
      },
      (response) => {
        response.on("data", () => {});
        response.on("end", () => resolve(response.statusCode ?? 0));
      }
    );
    request.once("error", reject);
    request.end();
  });
}

function waitFor(predicate: () => boolean, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve) => {
    const tick = (): void => {
      if (predicate()) {
        resolve(true);
        return;
      }
      if (Date.now() > deadline) {
        resolve(false);
        return;
      }
      setTimeout(tick, 50);
    };
    tick();
  });
}

function baseEnv(home: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" };
  for (const marker of ["CI", "GITHUB_ACTIONS", "GITLAB_CI"]) {
    delete env[marker];
  }
  return env;
}

async function startWorker(
  apiUrl: string,
  home: string,
  exemptionsEnv: Record<string, string>
): Promise<{ port: number; proxyAuthorization: string; child: ChildProcess }> {
  const session = createSessionSync(resolveDgPaths({ HOME: home }));
  const sessionJsonPath = join(session.dir, "session.json");
  writeFileSync(sessionJsonPath, `${JSON.stringify(session)}\n`, "utf8");
  let stdout = "";
  let stderr = "";
  const child = spawn(process.execPath, [workerPath, sessionJsonPath, apiUrl], {
    env: {
      ...process.env,
      HOME: home,
      DG_PROXY_CLASSIFICATION: JSON.stringify(classifyPackageManagerInvocation("npm", ["install", "left-pad"])),
      DG_COOLDOWN_AGE: "24h",
      ...exemptionsEnv
    },
    stdio: ["pipe", "pipe", "pipe"]
  });
  closers.push(() => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
    }
  });
  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });
  const ready = await waitFor(() => /ready \d+/.test(stdout), 20_000);
  expect(ready, `worker did not become ready: stdout=${stdout} stderr=${stderr}`).toBe(true);
  const token = readProxyAuthToken(session.dir);
  expect(token, "ready worker did not persist a proxy auth token in its session dir").toBeDefined();
  return {
    port: Number(/ready (\d+)/.exec(stdout)?.[1]),
    proxyAuthorization: proxyAuthorizationValue(token ?? ""),
    child
  };
}

describe("proxy cooldown exemption (real worker process, end-to-end)", () => {
  it("loads dg.json, writes the file, and the spawned worker suppresses cooldown for the exempt package only", async () => {
    const home = tempDir("dg-e2e-home-");
    const project = tempDir("dg-e2e-project-");
    const env = baseEnv(home);
    spawnSync("git", ["init", "-q"], { cwd: project, env });
    // Author through the stamped write path (what `dg cooldown add` does) so the
    // exemption carries the local-author tag the enforcement gate now requires.
    const root = findProjectRoot(project, env) ?? project;
    mutateDgFile(root, env, (file) =>
      appendCooldownExemptions(file, [{ ecosystem: "npm", name: "left-pad", reason: "vendored", acceptedBy: "alice" }]),
    );

    const exemptions = loadProjectCooldownExemptions(env, project);
    expect(exemptions).toHaveLength(1);
    expect(exemptions[0]?.name).toBe("left-pad");

    const seen: Record<string, unknown>[] = [];
    const registry = await startRegistry(Buffer.from("left-pad-and-right-pad-tarball-bytes", "utf8"));
    const api = await startApi((body) => seen.push(body));

    const session = createSessionSync(resolveDgPaths({ HOME: home }));
    const exemptionsEnv = writeCooldownExemptionsFile(session.dir, exemptions);
    expect(exemptionsEnv[COOLDOWN_EXEMPTIONS_ENV]).toBeDefined();

    const worker = await startWorker(api.url, home, exemptionsEnv);

    const exemptStatus = await proxyGet(worker, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
    const enforcedStatus = await proxyGet(worker, `${registry.url}/right-pad/-/right-pad-1.0.0.tgz`);
    expect(await waitFor(() => seen.length >= 2, 15_000)).toBe(true);

    const leftPad = seen.find((body) => body.name === "left-pad");
    const rightPad = seen.find((body) => body.name === "right-pad");
    expect(leftPad, "API never saw the left-pad verdict request").toBeDefined();
    expect(rightPad, "API never saw the right-pad verdict request").toBeDefined();

    expect(leftPad?.cooldown).toBeUndefined();
    expect(rightPad?.cooldown).toEqual({ minAgeDays: 1, onUnknown: "block" });

    expect(exemptStatus).toBe(200);
    expect(enforcedStatus).toBe(200);
  }, 45_000);

  it("loadProjectCooldownExemptions fails open outside a repo, with no dg.json, and on a corrupt dg.json", () => {
    const env = baseEnv(tempDir("dg-e2e-fo-home-"));
    const notRepo = tempDir("dg-e2e-norepo-");
    expect(loadProjectCooldownExemptions(env, notRepo)).toEqual([]);

    const repo = tempDir("dg-e2e-emptyrepo-");
    spawnSync("git", ["init", "-q"], { cwd: repo, env });
    expect(loadProjectCooldownExemptions(env, repo)).toEqual([]);

    writeFileSync(join(repo, "dg.json"), "{ not json", "utf8");
    expect(loadProjectCooldownExemptions(env, repo)).toEqual([]);
  });

  it("fails open: a corrupt exemptions file lets the worker start and apply cooldown normally (never hard-blocks startup)", async () => {
    const home = tempDir("dg-e2e-home-corrupt-");
    const env = baseEnv(home);

    const seen: Record<string, unknown>[] = [];
    const registry = await startRegistry(Buffer.from("bytes", "utf8"));
    const api = await startApi((body) => seen.push(body));

    const session = createSessionSync(resolveDgPaths({ HOME: home }));
    const corruptPath = join(session.dir, "cooldown-exemptions.json");
    writeFileSync(corruptPath, "{ this is not valid json", "utf8");

    const worker = await startWorker(api.url, home, { [COOLDOWN_EXEMPTIONS_ENV]: corruptPath });

    await proxyGet(worker, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
    expect(await waitFor(() => seen.length >= 1, 15_000)).toBe(true);
    expect(seen[0]?.cooldown).toEqual({ minAgeDays: 1, onUnknown: "block" });
  }, 45_000);
});
