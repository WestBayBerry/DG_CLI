import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { pathToFileURL } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import { connect, type Socket } from "node:net";
import { beforeAll, describe, expect, it } from "vitest";
import forge from "node-forge";
import { CI_MARKERS } from "../../src/presentation/mode.js";
import { proxyUrlWithAuth, readProxyAuthToken } from "../../src/proxy/auth.js";

const cliRoot = new URL("../..", import.meta.url);

describe("dg binary Node guard", () => {
  beforeAll(() => {
    expect(existsSync(new URL("dist/bin/dg.js", cliRoot)), "dist must be built by the vitest global setup").toBe(true);
  });

  it("rejects unsupported Node before importing CLI runtime", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-node-guard-"));
    const sentinel = join(temp, "runtime-loaded");
    const probe = await writeRuntimeLoadProbe(temp, sentinel);

    const result = spawnSync(process.execPath, ["--import", probe, "dist/bin/dg.js", "--help"], {
      cwd: cliRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        DG_TEST_NODE_VERSION: "22.13.1",
        DG_SHIM_ACTIVE: "",
        NODE_ENV: "test"
      }
    });

    const runtimeLoaded = existsSync(sentinel);

    await rm(temp, {
      force: true,
      recursive: true
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("dg requires Node.js >=22.14.0");
    expect(runtimeLoaded).toBe(false);
  });

  it("falls through to the real package manager when a shim hits the Node guard", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-node-guard-shim-"));
    const binDir = join(temp, "bin");
    const sentinel = join(temp, "runtime-loaded");
    const probe = await writeRuntimeLoadProbe(temp, sentinel);

    try {
      await writeNoFetchNpm(binDir);
      const result = spawnSync(process.execPath, ["--import", probe, "dist/bin/dg.js", "npm", "install", "left-pad"], {
        cwd: cliRoot,
        encoding: "utf8",
        env: {
          ...process.env,
          HOME: temp,
          PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
          DG_TEST_NODE_VERSION: "22.13.1",
          DG_SHIM_ACTIVE: "npm:12345",
          NODE_ENV: "test"
        }
      });

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(result.stdout).toContain("no-network-npm");
      expect(result.stderr).toContain("dg: protection inactive");
      expect(existsSync(sentinel)).toBe(false);
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("keeps the hard error for a shim invocation when no real manager exists outside dg", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-node-guard-shim-miss-"));
    const result = spawnSync(process.execPath, ["dist/bin/dg.js", "npm", "install", "left-pad"], {
      cwd: cliRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        HOME: temp,
        PATH: join(temp, "empty-bin"),
        DG_TEST_NODE_VERSION: "22.13.1",
        DG_SHIM_ACTIVE: "npm:12345",
        NODE_ENV: "test"
      }
    });
    await rm(temp, { force: true, recursive: true });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("dg requires Node.js >=22.14.0");
  });

  it("runs help on a supported Node", () => {
    const result = spawnSync(process.execPath, ["dist/bin/dg.js", "--help"], {
      cwd: cliRoot,
      encoding: "utf8"
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Usage:");
  });

  it("returns the command-contract failure through the built binary without real registry access", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-built-contract-"));
    const binDir = join(temp, "bin");
    try {
      await writeNoFetchNpm(binDir);
      const result = spawnSync(process.execPath, ["dist/bin/dg.js", "npm", "install", "left-pad"], {
        cwd: cliRoot,
        encoding: "utf8",
        env: {
          ...process.env,
          HOME: temp,
          PATH: [binDir, process.env.PATH ?? ""].join(delimiter)
        }
      });

      expect(result.status).toBe(2);
      expect(result.stderr).toContain("Nothing was downloaded");
      expect(result.stderr).toContain("nothing to verify");
      expect(result.stderr).toContain("dg scan");
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  it("enforces HTTP artifact verdicts through the built prefix command and tears down sessions", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-e2e-"));
    const binDir = join(temp, "bin");
    const artifact = "artifact-body";
    const seenApiBodies: unknown[] = [];
    const registry = await startHttpServer((_request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/octet-stream"
      });
      response.end(artifact);
    });
    const api = await startHttpServer(async (request, response) => {
      seenApiBodies.push(JSON.parse(await readRequestBody(request)) as unknown);
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "pass",
        packageName: "left-pad",
        cause: "pass",
        reason: "fake API allowed the artifact"
      }));
    });

    try {
      await writeFakeNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "left-pad"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_ARTIFACT_URL: `${registry.url}/left-pad.tgz`
      });

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(result.stdout).toContain("fake-npm received 200 artifact-body");
      expect(result.stderr).toContain("DG verified");
      expect(seenApiBodies).toHaveLength(1);
      expect(JSON.stringify(seenApiBodies[0])).toContain(createHash("sha256").update(artifact).digest("hex"));
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("waits for a slow cold scan and delivers the clean verdict (no false timeout block)", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-slow-pass-"));
    const binDir = join(temp, "bin");
    const artifact = "slow-but-clean-artifact";
    const registry = await startHttpServer((_request, response) => {
      response.writeHead(200, { "Content-Type": "application/octet-stream" });
      response.end(artifact);
    });
    const api = await startHttpServer(async (_request, response) => {
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({
        verdict: "pass",
        packageName: "big-pkg",
        cause: "pass",
        reason: "cold scan finished clean"
      }));
    });

    try {
      await writeFakeNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "big-pkg"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_ARTIFACT_URL: `${registry.url}/big-pkg.tgz`
      });

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(result.stdout).toContain("fake-npm received 200 slow-but-clean-artifact");
      expect(result.stderr).toContain("DG verified");
      expect(result.stderr).not.toContain("scanner timed out");
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("fails closed when a scan exceeds the configured verdict budget", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-slow-block-"));
    const binDir = join(temp, "bin");
    const registry = await startHttpServer((_request, response) => {
      response.writeHead(200, { "Content-Type": "application/octet-stream" });
      response.end("would-be-clean");
    });
    const api = await startHttpServer(async (_request, response) => {
      await new Promise((resolve) => setTimeout(resolve, 1_500));
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "too late" }));
    });

    try {
      await writeFakeNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "slow-pkg"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_ARTIFACT_URL: `${registry.url}/slow-pkg.tgz`,
        DG_INSTALL_VERDICT_TIMEOUT_MS: "300"
      });

      expect(result.status).toBe(2);
      expect(result.stdout).not.toContain("would-be-clean");
      expect(result.stderr).toContain("scanner timed out");
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("uses registry metadata identity for hash-first HTTP artifact verdicts", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-identity-e2e-"));
    const binDir = join(temp, "bin");
    const artifact = "metadata-artifact-body";
    const seenApiBodies: Record<string, unknown>[] = [];
    const registry = await startHttpServer((request, response) => {
      if (request.url === "/left-pad") {
        response.writeHead(200, {
          "Content-Type": "application/json"
        });
        response.end(JSON.stringify({
          name: "left-pad",
          versions: {
            "1.3.0": {
              dist: {
                tarball: `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`
              }
            }
          }
        }));
        return;
      }
      response.writeHead(200, {
        "Content-Type": "application/octet-stream"
      });
      response.end(artifact);
    });
    const api = await startHttpServer(async (request, response) => {
      seenApiBodies.push(JSON.parse(await readRequestBody(request)) as Record<string, unknown>);
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "pass",
        cause: "pass",
        reason: "fake API allowed the metadata-mapped artifact",
        scannedSha256: createHash("sha256").update(artifact).digest("hex")
      }));
    });

    try {
      await writeFakeMetadataNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "left-pad"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_METADATA_URL: `${registry.url}/left-pad`
      });

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(result.stdout).toContain("fake-npm received 200 metadata-artifact-body");
      expect(seenApiBodies).toHaveLength(1);
      expect(seenApiBodies[0]).toMatchObject({
        ecosystem: "npm",
        name: "left-pad",
        version: "1.3.0",
        sourceKind: "registry-metadata",
        registryHost: "127.0.0.1",
        sha256: createHash("sha256").update(artifact).digest("hex")
      });
      expect(typeof seenApiBodies[0].artifactUrlHash).toBe("string");
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("verifies a pip wheel via the PyPI Simple index identity (pass)", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-pip-pass-"));
    const binDir = join(temp, "bin");
    const artifact = "wheel-artifact-body";
    const seenApiBodies: Record<string, unknown>[] = [];
    const registry = await startHttpServer((request, response) => {
      if (request.url === "/simple/requests/") {
        response.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8"
        });
        response.end(`<!DOCTYPE html><html><body>`
          + `<a href="${registry.url}/packages/ab/requests-2.31.0-py3-none-any.whl#sha256=dead">requests-2.31.0-py3-none-any.whl</a>`
          + `</body></html>`);
        return;
      }
      response.writeHead(200, {
        "Content-Type": "application/octet-stream"
      });
      response.end(artifact);
    });
    const api = await startHttpServer(async (request, response) => {
      seenApiBodies.push(JSON.parse(await readRequestBody(request)) as Record<string, unknown>);
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "pass",
        cause: "pass",
        reason: "fake API allowed the simple-index wheel",
        scannedSha256: createHash("sha256").update(artifact).digest("hex")
      }));
    });

    try {
      await writeFakePip(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["pip", "install", "requests"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_INDEX_URL: `${registry.url}/simple/requests/`
      });

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(result.stdout).toContain("fake-pip received 200 wheel-artifact-body");
      expect(seenApiBodies).toHaveLength(1);
      expect(seenApiBodies[0]).toMatchObject({
        ecosystem: "pypi",
        name: "requests",
        version: "2.31.0",
        sourceKind: "registry-metadata",
        registryHost: "127.0.0.1",
        sha256: createHash("sha256").update(artifact).digest("hex")
      });
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("blocks a hostile pip wheel resolved through the PyPI Simple index", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-pip-block-"));
    const binDir = join(temp, "bin");
    const registry = await startHttpServer((request, response) => {
      if (request.url === "/simple/evil-pkg/") {
        response.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8"
        });
        response.end(`<a href="${registry.url}/packages/zz/evil_pkg-9.9.9-py3-none-any.whl">evil_pkg-9.9.9-py3-none-any.whl</a>`);
        return;
      }
      response.writeHead(200, {
        "Content-Type": "application/octet-stream"
      });
      response.end("malicious wheel bytes");
    });
    const api = await startHttpServer(async (request, response) => {
      const body = JSON.parse(await readRequestBody(request)) as Record<string, unknown>;
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "block",
        packageName: `pypi:${body.name}@${body.version}`,
        cause: "malware",
        reason: "fake API detected malware"
      }));
    });

    try {
      await writeFakePip(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["pip", "install", "evil-pkg"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_INDEX_URL: `${registry.url}/simple/evil-pkg/`
      });

      expect(result.status).toBe(2);
      expect(result.stdout).not.toContain("malicious wheel bytes");
      expect(result.stderr).toContain("DG blocked install");
      expect(result.stderr).toContain("evil-pkg");
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("blocks metadata-mapped artifacts when server scanned SHA-256 mismatches streamed bytes", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-hash-mismatch-"));
    const binDir = join(temp, "bin");
    const artifact = "substituted-artifact-body";
    const seenApiBodies: Record<string, unknown>[] = [];
    const registry = await startHttpServer((request, response) => {
      if (request.url === "/left-pad") {
        response.writeHead(200, {
          "Content-Type": "application/json"
        });
        response.end(JSON.stringify({
          name: "left-pad",
          versions: {
            "1.3.0": {
              dist: {
                tarball: `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`
              }
            }
          }
        }));
        return;
      }
      response.writeHead(200, {
        "Content-Type": "application/octet-stream"
      });
      response.end(artifact);
    });
    const api = await startHttpServer(async (request, response) => {
      seenApiBodies.push(JSON.parse(await readRequestBody(request)) as Record<string, unknown>);
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "pass",
        cause: "pass",
        reason: "stale server verdict",
        scannedSha256: createHash("sha256").update("different-artifact-body").digest("hex")
      }));
    });

    try {
      await writeFakeMetadataNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "left-pad"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_METADATA_URL: `${registry.url}/left-pad`
      });

      expect(result.status).toBe(2);
      expect(result.stdout).not.toContain(artifact);
      expect(result.stderr).toContain("artifact integrity mismatch");
      expect(result.stderr).toContain("server scanned SHA-256");
      expect(seenApiBodies[0]).toMatchObject({
        name: "left-pad",
        version: "1.3.0",
        sourceKind: "registry-metadata",
        sha256: createHash("sha256").update(artifact).digest("hex")
      });
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("blocks hostile HTTP artifact verdicts before delivery through the built prefix command", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-block-e2e-"));
    const binDir = join(temp, "bin");
    const registry = await startHttpServer((_request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/octet-stream"
      });
      response.end("malicious artifact");
    });
    const api = await startHttpServer((_request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "block",
        packageName: "evil-pkg",
        cause: "malware",
        reason: "fake API detected malware"
      }));
    });

    try {
      await writeFakeNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "evil-pkg"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_ARTIFACT_URL: `${registry.url}/evil-pkg.tgz`
      });

      expect(result.status).toBe(2);
      expect(result.stdout).not.toContain("malicious artifact");
      expect(result.stderr).toContain("DG blocked install");
      expect(result.stderr).toContain("confirmed malware");
      expect(result.stderr).toContain("fake API detected malware");
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("blocks with a quota-exceeded message when the verdict API returns 402", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-quota-e2e-"));
    const binDir = join(temp, "bin");
    const registry = await startHttpServer((_request, response) => {
      response.writeHead(200, { "Content-Type": "application/octet-stream" });
      response.end("over-quota artifact");
    });
    const api = await startHttpServer((_request, response) => {
      response.writeHead(402, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "monthly scan limit reached", resetsAt: "2026-07-01T00:00:00.000Z", quotaBehavior: "block" }));
    });

    try {
      await writeFakeNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "some-pkg"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_ARTIFACT_URL: `${registry.url}/some-pkg.tgz`
      });

      expect(result.status).toBe(2);
      expect(result.stdout).not.toContain("over-quota artifact");
      expect(result.stderr).toContain("Quota hit");
      expect(result.stderr).toContain("resets 07/01");
      expect(result.stderr).toContain("--dg-force-install");
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("lets the install through with a warning when over quota and quotaBehavior is pass", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-quota-pass-e2e-"));
    const binDir = join(temp, "bin");
    const registry = await startHttpServer((_request, response) => {
      response.writeHead(200, { "Content-Type": "application/octet-stream" });
      response.end("over-quota artifact");
    });
    const api = await startHttpServer((_request, response) => {
      response.writeHead(402, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "monthly scan limit reached", resetsAt: "2026-07-01T00:00:00.000Z", quotaBehavior: "pass" }));
    });

    try {
      await writeFakeNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "some-pkg"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_ARTIFACT_URL: `${registry.url}/some-pkg.tgz`
      });

      expect(result.status).not.toBe(2);
      expect(result.stderr).toContain("Over quota");
      expect(result.stderr).toContain("resets 07/01");
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("fails closed when the verdict API reports analysis incomplete", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-analysis-e2e-"));
    const binDir = join(temp, "bin");
    const registry = await startHttpServer((_request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/octet-stream"
      });
      response.end("pending artifact");
    });
    const api = await startHttpServer((_request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "block",
        packageName: "pending-pkg",
        cause: "analysis-incomplete",
        reason: "analysis has not completed"
      }));
    });

    try {
      await writeFakeNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "pending-pkg"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_ARTIFACT_URL: `${registry.url}/pending-pkg.tgz`
      });

      expect(result.status).toBe(2);
      expect(result.stdout).not.toContain("pending artifact");
      expect(result.stderr).toContain("analysis incomplete");
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("runs a persistent service proxy with health, pass/block verdicts, and cleanup", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-service-proxy-e2e-"));
    const trustDir = join(temp, "ci-trust");
    const passArtifact = "service-pass-artifact";
    const blockArtifact = "service-block-artifact";
    const seenApiBodies: Record<string, unknown>[] = [];
    const registry = await startHttpServer((request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/octet-stream"
      });
      response.end(request.url?.includes("blocked") ? blockArtifact : passArtifact);
    });
    const api = await startHttpServer(async (request, response) => {
      const body = JSON.parse(await readRequestBody(request)) as Record<string, unknown>;
      seenApiBodies.push(body);
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: seenApiBodies.length === 1 ? "pass" : "block",
        packageName: seenApiBodies.length === 1 ? "service-safe" : "service-blocked",
        cause: seenApiBodies.length === 1 ? "pass" : "malware",
        reason: seenApiBodies.length === 1 ? "service proxy allowed artifact" : "service proxy blocked malware"
      }));
    });

    try {
      await writeConfig(temp, api.url);
      await runBuiltDg(["login", "--token", "dg_test_token_abcdefghi"], {
        HOME: temp,
        PATH: process.env.PATH ?? ""
      });
      const setup = await runBuiltDg(["setup", "--service", "--yes"], {
        HOME: temp,
        PATH: process.env.PATH ?? ""
      });
      const start = await runBuiltDg(["service", "start"], {
        HOME: temp,
        PATH: process.env.PATH ?? "",
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        ALL_PROXY: "",
        NO_PROXY: "localhost,127.0.0.1"
      });
      const status = await runBuiltDg(["service", "status", "--json"], {
        HOME: temp,
        PATH: process.env.PATH ?? ""
      });
      const parsed = JSON.parse(status.stdout) as {
        readonly proxy: null | {
          readonly proxyUrl: string;
          readonly healthUrl: string;
          readonly sessionDir: string;
        };
      };
      const serviceToken = readProxyAuthToken(parsed.proxy?.sessionDir ?? "");
      expect(serviceToken, "service session must persist a proxy auth token").toBeTruthy();
      const authedProxyUrl = proxyUrlWithAuth(parsed.proxy?.proxyUrl ?? "", serviceToken ?? "");

      expect(setup.status).toBe(0);
      expect(start.status, `${start.stdout}\n${start.stderr}`).toBe(0);
      expect(parsed.proxy?.proxyUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
      expect(parsed.proxy?.healthUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/health$/);

      const trustInstall = await runBuiltDg(["service", "trust", "install", "--yes"], {
        HOME: temp,
        PATH: process.env.PATH ?? "",
        DG_SERVICE_TRUST_STORE_BACKEND: "file",
        DG_SERVICE_TRUST_STORE_DIR: trustDir
      });
      const trustStatus = await runBuiltDg(["service", "status", "--json"], {
        HOME: temp,
        PATH: process.env.PATH ?? ""
      });
      const trustFiles = await readdir(trustDir);
      const parsedTrustStatus = JSON.parse(trustStatus.stdout) as {
        readonly trust: null | {
          readonly provider: string;
          readonly native: boolean;
          readonly fingerprintSha256: string;
        };
      };

      expect(trustInstall.status, `${trustInstall.stdout}\n${trustInstall.stderr}`).toBe(0);
      expect(trustInstall.stdout).toContain("trust provider: file");
      expect(parsedTrustStatus.trust).toMatchObject({
        provider: "file",
        native: false
      });
      expect(parsedTrustStatus.trust?.fingerprintSha256).toMatch(/^[a-f0-9]{64}$/);
      expect(trustFiles).toHaveLength(1);
      expect(trustFiles[0]).toMatch(/^dependency-guardian-[a-f0-9]{16}\.pem$/);

      const health = await requestHttpUrl(parsed.proxy?.healthUrl ?? "");
      const unauthenticated = await requestViaHttpProxy(parsed.proxy?.proxyUrl ?? "", `${registry.url}/safe.tgz`);
      expect(unauthenticated.statusCode).toBe(407);
      const pass = await requestViaHttpProxy(authedProxyUrl, `${registry.url}/safe.tgz`);
      const block = await requestViaHttpProxy(authedProxyUrl, `${registry.url}/blocked.tgz`);

      expect(health.statusCode).toBe(200);
      expect(JSON.parse(health.body.toString("utf8"))).toMatchObject({
        ok: true
      });
      expect(pass.statusCode).toBe(200);
      expect(pass.body.toString("utf8")).toBe(passArtifact);
      expect(block.statusCode).toBe(403);
      expect(block.body.toString("utf8")).not.toContain(blockArtifact);
      expect(seenApiBodies).toHaveLength(2);
      expect(JSON.stringify(seenApiBodies)).toContain(createHash("sha256").update(passArtifact).digest("hex"));

      const trustUninstall = await runBuiltDg(["service", "trust", "uninstall", "--yes"], {
        HOME: temp,
        PATH: process.env.PATH ?? "",
        DG_SERVICE_TRUST_STORE_BACKEND: "file",
        DG_SERVICE_TRUST_STORE_DIR: trustDir
      });
      const stop = await runBuiltDg(["service", "stop"], {
        HOME: temp,
        PATH: process.env.PATH ?? ""
      });
      const trustFilesAfterUninstall = await readdir(trustDir);
      expect(trustUninstall.status, `${trustUninstall.stdout}\n${trustUninstall.stderr}`).toBe(0);
      expect(trustFilesAfterUninstall).toHaveLength(0);
      expect(stop.status).toBe(0);
      await expectSessionDirsRemoved(temp);
      await expectNoPrivateKeyFiles(temp);
    } finally {
      await api.close();
      await registry.close();
      await runBuiltDg(["service", "uninstall", "--yes"], {
        HOME: temp,
        PATH: process.env.PATH ?? ""
      });
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 60_000);

  it("detects a killed service worker and restart removes stale runtime plus drifted trust", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-service-crash-restart-"));
    const trustDir = join(temp, "ci-trust");
    const api = await startHttpServer((_request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "pass",
        packageName: "service-safe",
        cause: "pass",
        reason: "service crash restart test"
      }));
    });

    try {
      await writeConfig(temp, api.url);
      const env = {
        HOME: temp,
        PATH: process.env.PATH ?? "",
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        ALL_PROXY: "",
        NO_PROXY: "localhost,127.0.0.1"
      };
      await runBuiltDg(["login", "--token", "dg_test_token_abcdefghi"], env);
      const setup = await runBuiltDg(["setup", "--service", "--yes"], env);
      const start = await runBuiltDg(["service", "start"], env);
      const status = await runBuiltDg(["service", "status", "--json"], env);
      const parsed = JSON.parse(status.stdout) as {
        readonly running: boolean;
        readonly proxy: null | {
          readonly pid: number;
          readonly healthUrl: string;
        };
      };

      expect(setup.status).toBe(0);
      expect(start.status, `${start.stdout}\n${start.stderr}`).toBe(0);
      expect(parsed.running).toBe(true);
      expect(parsed.proxy?.pid).toBeGreaterThan(0);

      const trustInstall = await runBuiltDg(["service", "trust", "install", "--yes"], {
        ...env,
        DG_SERVICE_TRUST_STORE_BACKEND: "file",
        DG_SERVICE_TRUST_STORE_DIR: trustDir
      });
      expect(trustInstall.status, `${trustInstall.stdout}\n${trustInstall.stderr}`).toBe(0);
      expect(await readdir(trustDir)).toHaveLength(1);

      process.kill(parsed.proxy?.pid ?? 0, "SIGKILL");
      await waitForPidExit(parsed.proxy?.pid ?? 0);

      const staleStatus = await runBuiltDg(["service", "status", "--json"], env);
      const parsedStale = JSON.parse(staleStatus.stdout) as {
        readonly running: boolean;
        readonly lastError: string;
      };
      expect(parsedStale.running).toBe(false);
      expect(parsedStale.lastError).toContain("stale service runtime state");

      const restart = await runBuiltDg(["service", "restart"], env);
      const restartedStatus = await runBuiltDg(["service", "status", "--json"], env);
      const parsedRestarted = JSON.parse(restartedStatus.stdout) as {
        readonly running: boolean;
        readonly trustInstalled: boolean;
        readonly trust: null | unknown;
        readonly proxy: null | {
          readonly pid: number;
          readonly healthUrl: string;
        };
        readonly lastError: string | null;
      };

      expect(restart.status, `${restart.stdout}\n${restart.stderr}`).toBe(0);
      expect(parsedRestarted.running).toBe(true);
      expect(parsedRestarted.proxy?.pid).not.toBe(parsed.proxy?.pid);
      expect(parsedRestarted.trustInstalled).toBe(false);
      expect(parsedRestarted.trust).toBeNull();
      expect(parsedRestarted.lastError).toContain("stale dg-owned trust record was removed");
      expect(await readdir(trustDir)).toHaveLength(0);
      expect((await requestHttpUrl(parsedRestarted.proxy?.healthUrl ?? "")).statusCode).toBe(200);
      await expectNoPrivateKeyFiles(temp);
    } finally {
      await api.close();
      await runBuiltDg(["service", "uninstall", "--yes"], {
        HOME: temp,
        PATH: process.env.PATH ?? ""
      });
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  it("enforces HTTPS artifact verdicts through per-session MITM CA without leaking key files", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-https-e2e-"));
    const binDir = join(temp, "bin");
    const artifact = "tls-artifact-body";
    const seenApiBodies: unknown[] = [];
    const certs = await writeTestTlsMaterial(temp, "localhost");
    const registry = await startHttpsServer({
      cert: certs.certPem,
      key: certs.keyPem,
      handler: (_request, response) => {
        response.writeHead(200, {
          "Content-Type": "application/octet-stream",
          "Content-Length": Buffer.byteLength(artifact)
        });
        response.end(artifact);
      }
    });
    const api = await startHttpServer(async (request, response) => {
      seenApiBodies.push(JSON.parse(await readRequestBody(request)) as unknown);
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "pass",
        packageName: "left-pad",
        cause: "pass",
        reason: "fake API allowed the HTTPS artifact"
      }));
    });

    try {
      await writeFakeHttpsNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "left-pad"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_ARTIFACT_URL: `${registry.url}/left-pad.tgz`,
        DG_PROXY_MITM_HOSTS: "localhost",
        DG_UPSTREAM_CA_CERT: certs.caCertPath,
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        ALL_PROXY: "",
        NO_PROXY: "localhost,127.0.0.1"
      });

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(result.stdout).toContain("fake-npm received 200 tls-artifact-body");
      expect(result.stderr).toContain("DG verified");
      expect(seenApiBodies).toHaveLength(1);
      expect(JSON.stringify(seenApiBodies[0])).toContain(createHash("sha256").update(artifact).digest("hex"));
      expect(result.stderr).not.toContain("BEGIN PRIVATE KEY");
      await expectNoPrivateKeyFiles(temp);
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  it("fails closed and removes sessions when the package manager crashes before any artifact verdict", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-child-crash-"));
    const binDir = join(temp, "bin");

    try {
      await writeCrashingNpm(binDir);
      await writeConfig(temp, "http://127.0.0.1:9");
      const result = await runBuiltDg(["npm", "install", "left-pad"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        ALL_PROXY: "",
        NO_PROXY: "localhost,127.0.0.1"
      });

      // Fail-closed = the command's non-zero exit is propagated and the session
      // is cleaned up. A command that exits with an error before any fetch is no
      // longer presented as a dg "block" with an override hint (misleading — an
      // override cannot fix the command's own error); dg just notes it didn't run
      // a check and shows the command's own error.
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("fake-npm crashed before fetch");
      expect(result.stderr).toContain("dg did not check this install");
      expect(result.stderr).not.toContain("--dg-force-install");
      await expectSessionDirsRemoved(temp);
      await expectNoPrivateKeyFiles(temp);
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    it(`closes the built production proxy worker on ${signal} without persisting private keys`, async () => {
      const temp = await mkdtemp(join(tmpdir(), `dg-worker-${signal.toLowerCase()}-`));
      const worker = await startBuiltProxyWorker(temp);

      try {
        worker.process.kill(signal);
        const result = await waitForProcessClose(worker.process);

        expect(result.signal).toBe(null);
        expect(result.status).toBe(0);
        await expectPortClosed(worker.port);
        await expectNoPrivateKeyFiles(temp);
      } finally {
        worker.process.kill("SIGKILL");
        await rm(temp, {
          force: true,
          recursive: true
        });
      }
    }, 20_000);
  }

  it("releases the built production proxy port when the worker is killed", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-worker-sigkill-"));
    const worker = await startBuiltProxyWorker(temp);

    try {
      worker.process.kill("SIGKILL");
      const result = await waitForProcessClose(worker.process);

      expect(result.status).toBe(null);
      expect(result.signal).toBe("SIGKILL");
      await expectPortClosed(worker.port);
      await expectNoPrivateKeyFiles(temp);
    } finally {
      worker.process.kill("SIGKILL");
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  it("blocks hostile bytes served behind a registry 302 redirect through the built prefix command", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-redirect-block-"));
    const binDir = join(temp, "bin");
    const hostileBytes = "hostile-redirect-bytes";
    const seenApiBodies: Record<string, unknown>[] = [];
    const hostile = await startHttpServer((_request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/octet-stream"
      });
      response.end(hostileBytes);
    });
    const registry = await startHttpServer((_request, response) => {
      response.writeHead(302, {
        Location: `${hostile.url}/evil-pkg-redirected.tgz`
      });
      response.end();
    });
    const api = await startHttpServer(async (request, response) => {
      seenApiBodies.push(JSON.parse(await readRequestBody(request)) as Record<string, unknown>);
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "block",
        packageName: "evil-pkg",
        cause: "malware",
        reason: "fake API detected malware"
      }));
    });

    try {
      await writeFakeNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "evil-pkg"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_ARTIFACT_URL: `${registry.url}/evil-pkg.tgz`
      });

      expect(result.status).toBe(2);
      expect(result.stdout).not.toContain(hostileBytes);
      expect(result.stderr).toContain("DG blocked install");
      expect(result.stderr).toContain("confirmed malware");
      expect(seenApiBodies).toHaveLength(1);
      expect(seenApiBodies[0]).toMatchObject({
        sha256: createHash("sha256").update(hostileBytes).digest("hex")
      });
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await hostile.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  it("fails closed when a registry redirect loops back to itself", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-redirect-loop-"));
    const binDir = join(temp, "bin");
    const registry = await startHttpServer((request, response) => {
      response.writeHead(302, {
        Location: `${registry.url}${request.url ?? "/loop-pkg.tgz"}`
      });
      response.end();
    });
    const api = await startHttpServer((_request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "pass",
        cause: "pass",
        reason: "verdict path is never reached on a redirect loop"
      }));
    });

    try {
      await writeFakeNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "loop-pkg"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_ARTIFACT_URL: `${registry.url}/loop-pkg.tgz`
      });

      expect(result.status).toBe(2);
      expect(result.stderr).toContain("redirect chain");
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  it("fails closed without leaking a stack trace when ~/.dg/config.json is corrupt", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-fatal-corrupt-config-"));
    const configDir = join(temp, ".dg");
    await mkdir(configDir, {
      recursive: true
    });
    await writeFile(join(configDir, "config.json"), "{nope", "utf8");

    try {
      const result = await runBuiltDg(["verify", "npm:left-pad"], {
        HOME: temp
      });

      expect(result.status).toBe(70);
      expect(result.stderr).toContain("dg: unexpected error");
      expect(result.stderr).toContain("Run 'dg doctor'");
      expect(result.stderr).not.toMatch(/\n\s+at /);
      expect(result.stderr).not.toContain(".js:");
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  it("exits cleanly when the consumer of dg --help closes the read end early (EPIPE)", async () => {
    const child = spawn(process.execPath, ["dist/bin/dg.js", "--help"], {
      cwd: cliRoot,
      env: {
        ...process.env,
        CI: "",
        ...Object.fromEntries(CI_MARKERS.map((marker) => [marker, ""]))
      }
    });
    const stderr: Buffer[] = [];
    let destroyed = false;
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.stdout.on("data", () => {
      if (!destroyed) {
        destroyed = true;
        child.stdout.destroy();
      }
    });

    const result = await new Promise<{
      readonly status: number | null;
      readonly signal: NodeJS.Signals | null;
    }>((resolve, reject) => {
      child.on("error", reject);
      child.on("close", (status, signal) => resolve({
        status,
        signal
      }));
    });

    expect(result.signal).toBe(null);
    expect(result.status).toBe(0);
    expect(Buffer.concat(stderr).toString("utf8")).not.toContain("EPIPE");
  }, 20_000);

  it("fails closed when the registry answers a protected artifact with 206 partial content", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-partial-block-"));
    const binDir = join(temp, "bin");
    const fragment = "partial-fragment-bytes";
    const registry = await startHttpServer((_request, response) => {
      response.writeHead(206, {
        "Content-Type": "application/octet-stream",
        "Content-Range": `bytes 0-${fragment.length - 1}/4096`
      });
      response.end(fragment);
    });
    const api = await startHttpServer((_request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "pass",
        cause: "pass",
        reason: "verdict path is never reached on partial content"
      }));
    });

    try {
      await writeFakeNpm(binDir);
      await writeConfig(temp, api.url);
      const result = await runBuiltDg(["npm", "install", "partial-pkg"], {
        HOME: temp,
        PATH: [binDir, process.env.PATH ?? ""].join(delimiter),
        DG_FAKE_ARTIFACT_URL: `${registry.url}/partial-pkg.tgz`
      });

      expect(result.status).toBe(2);
      expect(result.stdout).not.toContain(fragment);
      expect(result.stderr).toContain("DG blocked install");
      expect(result.stderr).toContain("partial content");
      await expectSessionDirsRemoved(temp);
    } finally {
      await api.close();
      await registry.close();
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  it("exits the built production proxy worker on startup failure without a ready port", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-worker-startup-fail-"));
    const session = await writeWorkerSession(temp, "startup-fail");
    await mkdir(session.files.ca, {
      recursive: true
    });
    const worker = spawn(process.execPath, ["dist/proxy/worker.js", session.bootstrapPath, "http://127.0.0.1:9"], {
      cwd: cliRoot,
      env: {
        ...process.env,
        DG_PROXY_CLASSIFICATION: JSON.stringify({
          kind: "protected",
          manager: "npm",
          realBinaryName: "npm",
          action: "install",
          args: ["install", "left-pad"]
        })
      }
    });

    try {
      const output = await waitForProcessClose(worker);

      expect(output.status).not.toBe(0);
      expect(output.stdout).not.toContain("ready ");
      await expectNoPrivateKeyFiles(temp);
    } finally {
      worker.kill("SIGKILL");
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);
});

function runBuiltDg(args: readonly string[], env: NodeJS.ProcessEnv): Promise<{
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["dist/bin/dg.js", ...args], {
      cwd: cliRoot,
      env: {
        ...process.env,
        CI: "",
        ...Object.fromEntries(CI_MARKERS.map((marker) => [marker, ""])),
        ...env
      }
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (status) => {
      resolve({
        status,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8")
      });
    });
  });
}

async function writeFakeNpm(binDir: string): Promise<void> {
  await mkdir(binDir, {
    recursive: true
  });
  const path = join(binDir, "npm");
  await writeFile(path, `#!/bin/sh
node -e '
const http = require("node:http");
const target = process.env.DG_FAKE_ARTIFACT_URL;
const proxy = new URL(process.env.HTTP_PROXY);
const headers = proxy.username ? { "Proxy-Authorization": "Basic " + Buffer.from(decodeURIComponent(proxy.username) + ":" + decodeURIComponent(proxy.password)).toString("base64") } : {};
const req = http.request({ hostname: proxy.hostname, port: proxy.port, path: target, method: "GET", headers: headers }, (res) => {
  let body = "";
  res.setEncoding("utf8");
  res.on("data", (chunk) => { body += chunk; });
  res.on("end", () => {
    if (res.statusCode === 200) {
      process.stdout.write("fake-npm received " + res.statusCode + " " + body);
      process.exit(0);
    }
    process.stderr.write("fake-npm blocked " + res.statusCode + " " + body);
    process.exit(1);
  });
});
req.on("error", (error) => {
  process.stderr.write(error.message);
  process.exit(1);
});
req.end();
'
`, "utf8");
  await chmod(path, 0o755);
}

async function writeFakeMetadataNpm(binDir: string): Promise<void> {
  await mkdir(binDir, {
    recursive: true
  });
  const path = join(binDir, "npm");
  await writeFile(path, `#!/bin/sh
node <<'NODE'
const http = require("node:http");
const proxy = new URL(process.env.HTTP_PROXY);

const proxyHeaders = proxy.username ? { "Proxy-Authorization": "Basic " + Buffer.from(decodeURIComponent(proxy.username) + ":" + decodeURIComponent(proxy.password)).toString("base64") } : {};

function fetchViaProxy(target) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: proxy.hostname, port: proxy.port, path: target, method: "GET", headers: proxyHeaders }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

(async () => {
  const metadata = await fetchViaProxy(process.env.DG_FAKE_METADATA_URL);
  if (metadata.status !== 200) {
    process.stderr.write("fake-npm metadata failed " + metadata.status + " " + metadata.body);
    process.exit(1);
  }
  const parsed = JSON.parse(metadata.body);
  const tarball = parsed.versions["1.3.0"].dist.tarball;
  const artifact = await fetchViaProxy(tarball);
  if (artifact.status === 200) {
    process.stdout.write("fake-npm received " + artifact.status + " " + artifact.body);
    process.exit(0);
  }
  process.stderr.write("fake-npm blocked " + artifact.status + " " + artifact.body);
  process.exit(1);
})().catch((error) => {
  process.stderr.write(error.message);
  process.exit(1);
});
NODE
`, "utf8");
  await chmod(path, 0o755);
}

async function writeFakePip(binDir: string): Promise<void> {
  await mkdir(binDir, {
    recursive: true
  });
  const path = join(binDir, "pip");
  await writeFile(path, `#!/bin/sh
node <<'NODE'
const http = require("node:http");
const proxy = new URL(process.env.http_proxy || process.env.HTTP_PROXY);

const proxyHeaders = proxy.username ? { "Proxy-Authorization": "Basic " + Buffer.from(decodeURIComponent(proxy.username) + ":" + decodeURIComponent(proxy.password)).toString("base64") } : {};

function fetchViaProxy(target) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: proxy.hostname, port: proxy.port, path: target, method: "GET", headers: proxyHeaders }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

(async () => {
  const index = await fetchViaProxy(process.env.DG_FAKE_INDEX_URL);
  if (index.status !== 200) {
    process.stderr.write("fake-pip index failed " + index.status + " " + index.body);
    process.exit(1);
  }
  const href = /href="([^"#]+\\.whl)[^"]*"/.exec(index.body);
  if (!href) {
    process.stderr.write("fake-pip found no wheel href in index");
    process.exit(1);
  }
  const wheel = await fetchViaProxy(href[1]);
  if (wheel.status === 200) {
    process.stdout.write("fake-pip received " + wheel.status + " " + wheel.body);
    process.exit(0);
  }
  process.stderr.write("fake-pip blocked " + wheel.status + " " + wheel.body);
  process.exit(1);
})().catch((error) => {
  process.stderr.write(error.message);
  process.exit(1);
});
NODE
`, "utf8");
  await chmod(path, 0o755);
}

async function writeFakeHttpsNpm(binDir: string): Promise<void> {
  await mkdir(binDir, {
    recursive: true
  });
  const path = join(binDir, "npm");
  await writeFile(path, `#!/bin/sh
node <<'NODE'
const fs = require("node:fs");
const net = require("node:net");
const tls = require("node:tls");
const target = new URL(process.env.DG_FAKE_ARTIFACT_URL);
const proxy = new URL(process.env.HTTPS_PROXY || process.env.HTTP_PROXY);
const caPath = process.env.DG_FAKE_EXTRA_CA_CERT || process.env.NODE_EXTRA_CA_CERTS;
const proxyAuthLine = proxy.username ? "Proxy-Authorization: Basic " + Buffer.from(decodeURIComponent(proxy.username) + ":" + decodeURIComponent(proxy.password)).toString("base64") + "\\r\\n" : "";
const socket = net.connect(Number(proxy.port), proxy.hostname, () => {
  socket.write("CONNECT " + target.hostname + ":" + target.port + " HTTP/1.1\\r\\nHost: " + target.hostname + ":" + target.port + "\\r\\n" + proxyAuthLine + "\\r\\n");
});
const chunks = [];
socket.on("data", function onConnect(chunk) {
  chunks.push(chunk);
  const buffered = Buffer.concat(chunks);
  const headerEnd = buffered.indexOf("\\r\\n\\r\\n");
  if (headerEnd === -1) {
    return;
  }
  socket.off("data", onConnect);
  const statusLine = buffered.subarray(0, headerEnd).toString("latin1").split("\\r\\n")[0];
  if (!/ 2\\d\\d /.test(statusLine + " ")) {
    process.stderr.write("fake-npm connect failed " + statusLine);
    process.exit(1);
  }
  const secure = tls.connect({
    socket,
    servername: target.hostname,
    ca: fs.readFileSync(caPath)
  }, () => {
    secure.write("GET " + target.pathname + " HTTP/1.1\\r\\nHost: " + target.host + "\\r\\nAuthorization: Bearer child-secret\\r\\nConnection: close\\r\\n\\r\\n");
  });
  const responseChunks = [];
  secure.on("data", (responseChunk) => responseChunks.push(responseChunk));
  secure.on("end", () => {
    const raw = Buffer.concat(responseChunks);
    const end = raw.indexOf("\\r\\n\\r\\n");
    const head = raw.subarray(0, end).toString("latin1");
    const body = raw.subarray(end + 4).toString("utf8");
    const status = /HTTP\\/1\\.[01] (\\d+)/.exec(head)?.[1] || "000";
    if (status === "200") {
      process.stdout.write("fake-npm received " + status + " " + body);
      process.exit(0);
    }
    process.stderr.write("fake-npm blocked " + status + " " + body);
    process.exit(1);
  });
  secure.on("error", (error) => {
    process.stderr.write(error.message);
    process.exit(1);
  });
});
socket.on("error", (error) => {
  process.stderr.write(error.message);
  process.exit(1);
});
NODE
`, "utf8");
  await chmod(path, 0o755);
}

async function writeCrashingNpm(binDir: string): Promise<void> {
  await mkdir(binDir, {
    recursive: true
  });
  const path = join(binDir, "npm");
  await writeFile(path, "#!/bin/sh\nprintf 'fake-npm crashed before fetch\\n' >&2\nexit 42\n", "utf8");
  await chmod(path, 0o755);
}

async function writeRuntimeLoadProbe(dir: string, sentinel: string): Promise<string> {
  const hooks = join(dir, "runtime-load-hooks.mjs");
  await writeFile(hooks, `import { writeFileSync } from "node:fs";
export async function resolve(specifier, context, nextResolve) {
  const result = await nextResolve(specifier, context);
  if (result.url && result.url.endsWith("/runtime/cli.js")) {
    writeFileSync(${JSON.stringify(sentinel)}, "loaded\\n");
  }
  return result;
}
`, "utf8");
  const probe = join(dir, "runtime-load-probe.mjs");
  await writeFile(probe, `import { register } from "node:module";
register(${JSON.stringify(pathToFileURL(hooks).href)});
`, "utf8");
  return probe;
}

async function writeNoFetchNpm(binDir: string): Promise<void> {
  await mkdir(binDir, {
    recursive: true
  });
  const path = join(binDir, "npm");
  await writeFile(path, "#!/bin/sh\nprintf no-network-npm\n", "utf8");
  await chmod(path, 0o755);
}

async function writeConfig(home: string, apiBaseUrl: string): Promise<void> {
  const configDir = join(home, ".dg");
  await mkdir(configDir, {
    recursive: true
  });
  await writeFile(join(configDir, "config.json"), `${JSON.stringify({
    version: 1,
    api: {
      baseUrl: apiBaseUrl
    },
    org: {
      id: ""
    },
    policy: {
      mode: "block",
      trustProjectAllowlists: false,
      allowForceOverride: true,
      scriptHardening: false
    },
    telemetry: {
      enabled: false
    },
    webhooks: {
      enabled: false
    }
  }, null, 2)}\n`, "utf8");
}

async function expectSessionDirsRemoved(home: string): Promise<void> {
  const sessionsDir = join(home, ".dg", "state", "sessions");
  const entries = await readdir(sessionsDir).catch((error: unknown) => {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") {
      return [];
    }
    throw error;
  });
  expect(entries).toEqual([]);
}

function requestHttpUrl(url: string): Promise<{
  readonly statusCode: number;
  readonly body: Buffer;
}> {
  const target = new URL(url);
  return new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: target.hostname,
      port: target.port,
      path: `${target.pathname}${target.search}`,
      method: "GET"
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => {
        resolve({
          statusCode: response.statusCode ?? 0,
          body: Buffer.concat(chunks)
        });
      });
    });
    request.on("error", reject);
    request.end();
  });
}

function requestViaHttpProxy(proxyUrl: string, artifactUrl: string): Promise<{
  readonly statusCode: number;
  readonly body: Buffer;
}> {
  const proxy = new URL(proxyUrl);
  const headers: Record<string, string> = proxy.username
    ? {
        "Proxy-Authorization": `Basic ${Buffer.from(
          `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`,
          "utf8"
        ).toString("base64")}`
      }
    : {};
  return new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: proxy.hostname,
      port: proxy.port,
      path: artifactUrl,
      method: "GET",
      headers
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => {
        resolve({
          statusCode: response.statusCode ?? 0,
          body: Buffer.concat(chunks)
        });
      });
    });
    request.on("error", reject);
    request.end();
  });
}

async function expectNoPrivateKeyFiles(root: string): Promise<void> {
  const found: string[] = [];
  async function walk(directory: string): Promise<void> {
    const entries = await readdir(directory, {
      withFileTypes: true
    }).catch(() => []);
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(path);
        continue;
      }
      if (entry.name.endsWith(".key")) {
        found.push(path);
      }
      if (entry.isFile()) {
        const text = await readFileMaybe(path);
        if (text.includes("BEGIN PRIVATE KEY") || text.includes("BEGIN RSA PRIVATE KEY")) {
          found.push(path);
        }
      }
    }
  }
  await walk(join(root, ".dg"));
  expect(found).toEqual([]);
}

async function waitForPidExit(pid: number): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (!pidIsAlive(pid)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`process ${pid} did not exit`);
}

function pidIsAlive(pid: number): boolean {
  if (pid <= 0) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function startBuiltProxyWorker(home: string): Promise<{
  readonly port: number;
  readonly process: ReturnType<typeof spawn>;
}> {
  const session = await writeWorkerSession(home, "signal-test");
  const child = spawn(process.execPath, ["dist/proxy/worker.js", session.bootstrapPath, "http://127.0.0.1:9"], {
    cwd: cliRoot,
    env: {
      ...process.env,
      HOME: home,
      DG_PROXY_CLASSIFICATION: JSON.stringify({
        kind: "protected",
        manager: "npm",
        realBinaryName: "npm",
        action: "install",
        args: ["install", "left-pad"]
      })
    }
  });
  const ready = await waitForReadyLine(child);
  return {
    port: ready,
    process: child
  };
}

async function writeWorkerSession(home: string, id: string): Promise<{
  readonly bootstrapPath: string;
  readonly files: {
    readonly ca: string;
  };
}> {
  const sessionDir = join(home, ".dg", "state", "sessions", id);
  await mkdir(sessionDir, {
    recursive: true
  });
  const session = {
    id,
    dir: sessionDir,
    files: {
      proxy: join(sessionDir, "proxy.json"),
      ca: join(sessionDir, "ca.pem"),
      block: join(sessionDir, "block.json"),
      hash: join(sessionDir, "hash.json"),
      log: join(sessionDir, "log.jsonl"),
      pid: join(sessionDir, "pid")
    }
  };
  const bootstrapPath = join(sessionDir, "session.json");
  await writeFile(bootstrapPath, `${JSON.stringify(session)}\n`, "utf8");
  return {
    bootstrapPath,
    files: {
      ca: session.files.ca
    }
  };
}

function waitForReadyLine(child: ReturnType<typeof spawn>): Promise<number> {
  return new Promise((resolve, reject) => {
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    const timeout = setTimeout(() => {
      reject(new Error(`proxy worker did not become ready: ${Buffer.concat(stderr).toString("utf8")}`));
    }, 5_000);
    child.stdout.on("data", (chunk: Buffer) => {
      stdout.push(chunk);
      const text = Buffer.concat(stdout).toString("utf8");
      const port = /^ready (\d+)$/m.exec(text)?.[1];
      if (port) {
        clearTimeout(timeout);
        resolve(Number(port));
      }
    });
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on("close", (status, signal) => {
      clearTimeout(timeout);
      reject(new Error(`proxy worker exited before ready: status=${status ?? "null"} signal=${signal ?? "null"} stderr=${Buffer.concat(stderr).toString("utf8")}`));
    });
  });
}

function waitForProcessClose(child: ReturnType<typeof spawn>): Promise<{
  readonly signal: NodeJS.Signals | null;
  readonly status: number | null;
  readonly stderr: string;
  readonly stdout: string;
}> {
  return new Promise((resolve, reject) => {
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (status, signal) => {
      resolve({
        signal,
        status,
        stderr: Buffer.concat(stderr).toString("utf8"),
        stdout: Buffer.concat(stdout).toString("utf8")
      });
    });
  });
}

function expectPortClosed(port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket: Socket = connect(port, "127.0.0.1");
    socket.once("connect", () => {
      socket.destroy();
      reject(new Error(`proxy port ${port} was still accepting connections`));
    });
    socket.once("error", () => resolve());
  });
}

function startHttpServer(handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>): Promise<{
  readonly url: string;
  readonly close: () => Promise<void>;
}> {
  const server = createServer((request, response) => {
    void handler(request, response);
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      if (typeof address !== "object" || address === null) {
        reject(new Error("test server did not bind a TCP port"));
        return;
      }
      resolve({
        url: `http://127.0.0.1:${address.port}`,
        close: () => closeServer(server)
      });
    });
  });
}

function startHttpsServer(options: {
  readonly cert: string;
  readonly key: string;
  readonly handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>;
}): Promise<{
  readonly url: string;
  readonly close: () => Promise<void>;
}> {
  const server = createHttpsServer({
    cert: options.cert,
    key: options.key
  }, (request, response) => {
    void options.handler(request, response);
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      if (typeof address !== "object" || address === null) {
        reject(new Error("test HTTPS server did not bind a TCP port"));
        return;
      }
      resolve({
        url: `https://localhost:${address.port}`,
        close: () => closeServer(server)
      });
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}

async function writeTestTlsMaterial(root: string, host: string): Promise<{
  readonly caCertPath: string;
  readonly certPem: string;
  readonly keyPem: string;
}> {
  const caKeys = forge.pki.rsa.generateKeyPair({
    bits: 2048,
    workers: -1
  });
  const ca = forge.pki.createCertificate();
  ca.publicKey = caKeys.publicKey;
  ca.serialNumber = "01";
  ca.validity.notBefore = new Date(Date.now() - 60_000);
  ca.validity.notAfter = new Date(Date.now() + 60 * 60 * 1_000);
  const caAttrs = [{
    name: "commonName",
    value: "DG test upstream CA"
  }];
  ca.setSubject(caAttrs);
  ca.setIssuer(caAttrs);
  ca.setExtensions([{
    name: "basicConstraints",
    cA: true
  }]);
  ca.sign(caKeys.privateKey, forge.md.sha256.create());

  const leafKeys = forge.pki.rsa.generateKeyPair({
    bits: 2048,
    workers: -1
  });
  const leaf = forge.pki.createCertificate();
  leaf.publicKey = leafKeys.publicKey;
  leaf.serialNumber = "02";
  leaf.validity.notBefore = new Date(Date.now() - 60_000);
  leaf.validity.notAfter = new Date(Date.now() + 60 * 60 * 1_000);
  leaf.setSubject([{
    name: "commonName",
    value: host
  }]);
  leaf.setIssuer(ca.subject.attributes);
  leaf.setExtensions([{
    name: "basicConstraints",
    cA: false
  }, {
    name: "extKeyUsage",
    serverAuth: true
  }, {
    name: "subjectAltName",
    altNames: [{
      type: 2,
      value: host
    }]
  }]);
  leaf.sign(caKeys.privateKey, forge.md.sha256.create());

  const caCertPath = join(root, "upstream-ca.pem");
  await writeFile(caCertPath, forge.pki.certificateToPem(ca), "utf8");
  return {
    caCertPath,
    certPem: forge.pki.certificateToPem(leaf),
    keyPem: forge.pki.privateKeyToPem(leafKeys.privateKey)
  };
}

async function readFileMaybe(path: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return "";
  }
}

function readRequestBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}
