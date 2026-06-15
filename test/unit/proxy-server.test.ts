import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import {
  createServer as createHttpServer,
  request as httpRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type ServerResponse
} from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect, createServer as createNetServer, type Server as NetServer, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { describe, expect, it } from "vitest";
import forge from "node-forge";
import { classifyPackageManagerInvocation } from "../../src/launcher/classify.js";
import { readProxySessionState, startProductionHttpProxy, upstreamTlsOptions } from "../../src/proxy/server.js";
import { writePreverifiedFile, type PreverifiedEntry } from "../../src/proxy/preverified.js";
import { cleanupSessionSync, createSessionSync, readHeldPackages, resolveDgPaths } from "../../src/state/index.js";

describe("production proxy private scan-tarball routing", () => {
  it("uploads configured private registry artifacts to scan-tarball with auth and privacy headers", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-scan-tarball-"));
    const artifact = Buffer.from("private artifact body", "utf8");
    const sha256 = createHash("sha256").update(artifact).digest("hex");
    const registry = await startHttpOrigin(artifact);
    const seenApiRequests: Array<{
      readonly body: Buffer;
      readonly headers: IncomingHttpHeaders;
      readonly url: string;
    }> = [];
    const api = await startHttpApi(async (requestBody, request, response) => {
      seenApiRequests.push({
        body: requestBody,
        headers: request.headers,
        url: request.url ?? ""
      });
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "pass",
        packageName: "npm:private-pkg@1.0.0",
        cause: "pass",
        reason: "private artifact scan passed",
        scannedSha256: sha256,
        cacheHit: true
      }));
    });
    const session = createSessionSync(resolveDgPaths({
      HOME: temp
    }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "private-pkg"]),
      env: {
        HOME: temp,
        DG_API_TOKEN: "secret-private-token",
        DG_PRIVATE_REGISTRY_HOSTS: "127.0.0.1",
        DG_SCAN_TARBALL_UPLOAD: "1"
      }
    });

    try {
      const target = `${registry.url}/private-pkg/-/private-pkg-1.0.0.tgz`;
      const response = await requestViaHttpProxy(handle, target);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(200);
      expect(response.body.equals(artifact)).toBe(true);
      expect(seenApiRequests).toHaveLength(1);
      expect(seenApiRequests[0]?.url).toBe("/v1/scan-tarball");
      expect(seenApiRequests[0]?.body.equals(artifact)).toBe(true);
      expect(seenApiRequests[0]?.headers.authorization).toBe("Bearer secret-private-token");
      expect(seenApiRequests[0]?.headers["x-dg-artifact-sha256"]).toBe(sha256);
      expect(seenApiRequests[0]?.headers["x-dg-cache-key"]).toBe(`sha256:${sha256}`);
      expect(seenApiRequests[0]?.headers["x-dg-privacy"]).toBe("private-artifact");
      expect(seenApiRequests[0]?.headers["x-dg-artifact-url-hash"]).toMatch(/^[a-f0-9]{64}$/);
      expect(JSON.stringify(seenApiRequests[0]?.headers)).not.toContain(target);
      expect(state.decisions[0]).toMatchObject({
        action: "pass",
        cause: "pass",
        packageName: "npm:private-pkg@1.0.0"
      });
      expect(state.hashes[0]?.identity?.sourceKind).toBe("url-fallback");
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("blocks configured private registry artifacts when upload is not enabled", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-scan-disabled-"));
    const artifact = Buffer.from("private bytes must not be delivered", "utf8");
    const registry = await startHttpOrigin(artifact);
    const session = createSessionSync(resolveDgPaths({
      HOME: temp
    }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: "http://127.0.0.1:9",
      classification: classifyPackageManagerInvocation("npm", ["install", "private-pkg"]),
      env: {
        HOME: temp,
        DG_PRIVATE_REGISTRY_HOSTS: "127.0.0.1"
      }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/private-pkg/-/private-pkg-1.0.0.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(response.body.toString("utf8")).not.toContain(artifact.toString("utf8"));
      expect(state.decisions[0]).toMatchObject({
        action: "block",
        cause: "private-upload-disabled"
      });
    } finally {
      await handle.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("blocks private artifacts when scan-tarball returns a mismatched SHA-256", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-scan-hash-mismatch-"));
    const artifact = Buffer.from("private artifact body", "utf8");
    const registry = await startHttpOrigin(artifact);
    const api = await startHttpApi(async (_requestBody, _request, response) => {
      response.writeHead(200, {
        "Content-Type": "application/json"
      });
      response.end(JSON.stringify({
        verdict: "pass",
        reason: "stale cache entry",
        scannedSha256: "0".repeat(64)
      }));
    });
    const session = createSessionSync(resolveDgPaths({
      HOME: temp
    }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "private-pkg"]),
      env: {
        HOME: temp,
        DG_API_TOKEN: "secret-private-token",
        DG_PRIVATE_REGISTRY_HOSTS: "127.0.0.1",
        DG_SCAN_TARBALL_UPLOAD: "1"
      }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/private-pkg/-/private-pkg-1.0.0.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(response.body.toString("utf8")).not.toContain(artifact.toString("utf8"));
      expect(state.decisions[0]).toMatchObject({
        action: "block",
        cause: "hash-mismatch"
      });
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("blocks with a quota-exceeded cause (not api-unavailable) when the verdict API returns 402", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-cap-"));
    const artifact = Buffer.from("public artifact body must not be delivered", "utf8");
    const registry = await startHttpOrigin(artifact);
    const api = await startHttpApi(async (_requestBody, request, response) => {
      expect(request.url).toBe("/v1/install-verdict");
      response.writeHead(402, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "monthly scan limit reached", freeTierCapReached: true }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(response.body.toString("utf8")).not.toContain(artifact.toString("utf8"));
      expect(state.decisions[0]).toMatchObject({ action: "block", cause: "quota-exceeded" });
      expect(state.decisions[0]?.reason ?? "").toContain("monthly scan limit");
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("sends X-Device-Id and Bearer identity headers on install-verdict calls", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-identity-"));
    const artifact = Buffer.from("artifact body", "utf8");
    const registry = await startHttpOrigin(artifact);
    const seenHeaders: IncomingHttpHeaders[] = [];
    const api = await startHttpApi(async (_requestBody, request, response) => {
      seenHeaders.push(request.headers);
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp, DG_API_TOKEN: "identity-test-token" }
    });

    try {
      await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);

      expect(seenHeaders.length).toBeGreaterThan(0);
      const headers = seenHeaders[0] ?? {};
      expect(headers["x-device-id"]).toMatch(/^[0-9a-f-]{36}$/i);
      expect(headers.authorization).toBe("Bearer identity-test-token");
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("preserves the api-unavailable cause from a 200 verdict (isProxyCause must allow it)", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-cause-"));
    const artifact = Buffer.from("artifact must not be delivered on a block", "utf8");
    const registry = await startHttpOrigin(artifact);
    const api = await startHttpApi(async (_body, _request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "block", cause: "api-unavailable", reason: "scanner backend is down" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(response.body.toString("utf8")).not.toContain(artifact.toString("utf8"));
      expect(state.decisions[0]).toMatchObject({ action: "block", cause: "api-unavailable" });
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("passes a 404 artifact response through (registry error, not a package to verify)", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-404-"));
    const registry = await startStatusOrigin(404, Buffer.from("Not Found", "utf8"));
    let apiCalled = false;
    const api = await startHttpApi(async (_body, _request, response) => {
      apiCalled = true;
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "ok" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-9.9.9.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(404);
      expect(response.body.toString("utf8")).toContain("Not Found");
      expect(apiCalled).toBe(false);
      expect(state.decisions).toHaveLength(0);
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("blocks a redirect with no Location header instead of delivering it", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-noloc-"));
    const registry = await startLocationlessRedirect();
    const api = await startHttpApi(async (_body, _request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "ok" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(state.decisions[0]).toMatchObject({ action: "block" });
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("follows a registry redirect chain in-proxy and gates the final-hop bytes", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-redirect-follow-"));
    const finalBytes = Buffer.from("relocated artifact body must not be delivered", "utf8");
    const finalSha256 = createHash("sha256").update(finalBytes).digest("hex");
    const finalOrigin = await startHttpOrigin(finalBytes);
    const registry = await startHttpRedirect(`${finalOrigin.url}/left-pad/-/left-pad-1.3.0.tgz`);
    const seenSha256: string[] = [];
    const api = await startHttpApi(async (body, _request, response) => {
      seenSha256.push((JSON.parse(body.toString("utf8")) as { sha256?: string }).sha256 ?? "");
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "block", cause: "malware", reason: "malware in relocated artifact" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(response.body.toString("utf8")).not.toContain(finalBytes.toString("utf8"));
      expect(seenSha256).toEqual([finalSha256]);
      expect(state.hashes[0]?.sha256).toBe(finalSha256);
      expect(state.decisions[0]).toMatchObject({ action: "block", cause: "malware" });
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      await finalOrigin.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("fails closed when a redirect chain exceeds the hop limit", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-redirect-loop-"));
    const registry = await startInfiniteRedirect();
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: "http://127.0.0.1:9",
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(state.decisions[0]).toMatchObject({ action: "block", cause: "registry-timeout" });
      expect(state.decisions[0]?.reason ?? "").toContain("redirect chain exceeded");
      expect(state.hashes).toEqual([]);
    } finally {
      await handle.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("fails closed when the registry returns 206 partial content", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-partial-"));
    const artifact = Buffer.from("ZZZZ-undelivered-partial-artifact-body", "utf8");
    const registry = await startHttpPartialOrigin(artifact);
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: "http://127.0.0.1:9",
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(response.body.toString("utf8")).not.toContain(artifact.subarray(0, 4).toString("utf8"));
      expect(state.decisions[0]).toMatchObject({ action: "block", cause: "policy" });
      expect(state.decisions[0]?.reason ?? "").toContain("partial content");
      expect(state.hashes).toEqual([]);
    } finally {
      await handle.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("strips a client Range header before reaching the upstream registry", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-range-strip-"));
    const artifact = Buffer.from("full artifact body", "utf8");
    const registry = await startHeaderRecordingOrigin(artifact);
    const api = await startHttpApi(async (_body, _request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "ok" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(
        handle,
        `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`,
        { Range: "bytes=0-3", "If-None-Match": "\"etag\"" }
      );

      expect(response.statusCode).toBe(200);
      expect(response.body.equals(artifact)).toBe(true);
      expect(registry.seenHeaders).toHaveLength(1);
      expect(registry.seenHeaders[0]?.range).toBeUndefined();
      expect(registry.seenHeaders[0]?.["if-none-match"]).toBeUndefined();
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });
});

describe("production proxy compressed registry metadata", () => {
  it("recognizes a gzip-encoded packument as metadata and verifies its tarball by name@version", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-gzip-meta-"));
    const tarball = Buffer.from("chalk tarball bytes", "utf8");
    const routes: Record<string, { status?: number; headers: Record<string, string | number>; body: Buffer }> = {};
    const registry = await startRoutedOrigin(routes);
    const gzippedPackument = gzipSync(Buffer.from(JSON.stringify({
      name: "chalk",
      versions: { "5.6.2": { dist: { tarball: `${registry.url}/chalk/-/chalk-5.6.2.tgz` } } }
    })));
    routes["/chalk"] = {
      headers: { "Content-Type": "application/vnd.npm.install-v1+json", "Content-Encoding": "gzip" },
      body: gzippedPackument
    };
    routes["/chalk/-/chalk-5.6.2.tgz"] = {
      headers: { "Content-Type": "application/octet-stream" },
      body: tarball
    };
    const verdictBodies: unknown[] = [];
    const api = await startHttpApi(async (requestBody, _request, response) => {
      verdictBodies.push(JSON.parse(requestBody.toString("utf8")));
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "ok" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "chalk"]),
      env: { HOME: temp, DG_COOLDOWN_AGE: "0" }
    });

    try {
      const metadataResponse = await requestViaHttpProxy(handle, `${registry.url}/chalk`);
      expect(metadataResponse.statusCode).toBe(200);
      expect(metadataResponse.body.equals(gzippedPackument)).toBe(true);
      expect(verdictBodies).toHaveLength(0);
      expect(readProxySessionState(session).decisions).toHaveLength(0);

      const tarballResponse = await requestViaHttpProxy(handle, `${registry.url}/chalk/-/chalk-5.6.2.tgz`);
      expect(tarballResponse.statusCode).toBe(200);
      expect(tarballResponse.body.equals(tarball)).toBe(true);
      expect(verdictBodies).toHaveLength(1);
      expect(verdictBodies[0]).toMatchObject({ name: "chalk", version: "5.6.2", sourceKind: "registry-metadata" });
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });
});

describe("production proxy streaming tail-hold (large artifacts)", () => {
  const BIG = Buffer.alloc(512 * 1024, 7);
  const BIG_SHA = createHash("sha256").update(BIG).digest("hex");

  function streamViaHttpProxy(
    proxy: { readonly port: number; readonly proxyAuthorization?: string },
    targetUrl: string
  ): Promise<{ bytes: number; firstByteAtMs: number; endedAtMs: number; errored: boolean; statusCode: number }> {
    return new Promise((resolve) => {
      const target = new URL(targetUrl);
      const started = Date.now();
      let bytes = 0;
      let firstByteAtMs = -1;
      let statusCode = 0;
      let settled = false;
      const finish = (errored: boolean): void => {
        if (settled) return;
        settled = true;
        resolve({ bytes, firstByteAtMs, endedAtMs: Date.now() - started, errored, statusCode });
      };
      const request = httpRequest({
        hostname: "127.0.0.1",
        port: proxy.port,
        path: target.toString(),
        method: "GET",
        headers: {
          Host: target.host,
          ...(proxy.proxyAuthorization ? { "Proxy-Authorization": proxy.proxyAuthorization } : {})
        }
      }, (response) => {
        statusCode = response.statusCode ?? 0;
        response.on("data", (chunk: Buffer) => {
          if (firstByteAtMs < 0) firstByteAtMs = Date.now() - started;
          bytes += chunk.length;
        });
        response.once("end", () => finish(false));
        response.once("aborted", () => finish(true));
        response.once("error", () => finish(true));
      });
      request.once("error", () => finish(true));
      request.end();
    });
  }

  async function runStreamScenario(verdict: { verdict: string; cause: string; reason: string }, apiDelayMs = 0): Promise<{
    result: Awaited<ReturnType<typeof streamViaHttpProxy>>;
    apiBodies: unknown[];
    decisions: ReturnType<typeof readProxySessionState>["decisions"];
  }> {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-stream-"));
    const registry = await startRoutedOrigin({
      "/left-pad/-/left-pad-9.9.9.tgz": { headers: { "Content-Type": "application/octet-stream" }, body: BIG }
    });
    const apiBodies: unknown[] = [];
    const api = await startHttpApi(async (requestBody, _request, response) => {
      apiBodies.push(JSON.parse(requestBody.toString("utf8")));
      if (apiDelayMs > 0) {
        await new Promise((r) => setTimeout(r, apiDelayMs));
      }
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify(verdict));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp, DG_COOLDOWN_AGE: "0", DG_STREAM_THRESHOLD_BYTES: "262144" }
    });
    try {
      const result = await streamViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-9.9.9.tgz`);
      return { result, apiBodies, decisions: readProxySessionState(session).decisions };
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  }

  it("delivers the full artifact on pass and sends the streamed sha to the API", async () => {
    const { result, apiBodies, decisions } = await runStreamScenario({ verdict: "pass", cause: "pass", reason: "ok" });
    expect(result.errored).toBe(false);
    expect(result.statusCode).toBe(200);
    expect(result.bytes).toBe(BIG.length);
    expect(JSON.stringify(apiBodies[0])).toContain(BIG_SHA);
    expect(decisions[0]).toMatchObject({ action: "pass" });
  });

  it("streams body bytes to the client before the verdict resolves", async () => {
    const { result } = await runStreamScenario({ verdict: "pass", cause: "pass", reason: "ok" }, 700);
    expect(result.errored).toBe(false);
    expect(result.bytes).toBe(BIG.length);
    expect(result.firstByteAtMs).toBeGreaterThanOrEqual(0);
    expect(result.endedAtMs - result.firstByteAtMs).toBeGreaterThanOrEqual(500);
  });

  it("withholds the tail on a block so the client never receives the complete artifact", async () => {
    const { result, decisions } = await runStreamScenario({ verdict: "block", cause: "malware", reason: "confirmed malicious" });
    expect(result.bytes).toBeLessThan(BIG.length);
    expect(result.bytes).toBeLessThanOrEqual(BIG.length - 64 * 1024);
    expect(decisions[0]).toMatchObject({ action: "block", cause: "malware" });
  });

  it("does NOT stream by default — a large block delivers zero bytes (buffered 403)", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-nostream-"));
    const registry = await startRoutedOrigin({
      "/left-pad/-/left-pad-9.9.9.tgz": { headers: { "Content-Type": "application/octet-stream" }, body: BIG }
    });
    const api = await startHttpApi(async (_body, _request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "block", cause: "malware", reason: "confirmed malicious" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp, DG_COOLDOWN_AGE: "0" }
    });
    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-9.9.9.tgz`);
      expect(response.statusCode).toBe(403);
      expect(response.body.includes(BIG.subarray(0, 64))).toBe(false);
      expect(readProxySessionState(session).decisions[0]).toMatchObject({ action: "block", cause: "malware" });
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });
});

describe("production proxy preverified install set", () => {
  const WHEEL = Buffer.from("requests wheel bytes", "utf8");
  const WHEEL_SHA = createHash("sha256").update(WHEEL).digest("hex");

  function pypiRoutes(registryUrl: () => string): Record<string, { status?: number; headers: Record<string, string | number>; body: Buffer }> {
    const routes: Record<string, { status?: number; headers: Record<string, string | number>; body: Buffer }> = {};
    routes["/packages/requests-2.32.0-py3-none-any.whl"] = {
      headers: { "Content-Type": "application/octet-stream" },
      body: WHEEL
    };
    routes["/simple/requests/"] = {
      headers: { "Content-Type": "application/vnd.pypi.simple.v1+json" },
      body: Buffer.from(JSON.stringify({
        files: [{ url: `${registryUrl()}/packages/requests-2.32.0-py3-none-any.whl`, filename: "requests-2.32.0-py3-none-any.whl" }]
      }))
    };
    return routes;
  }

  async function runPreverifiedScenario(input: {
    readonly entry: Partial<PreverifiedEntry> & { readonly action: "pass" | "warn" };
    readonly env?: Record<string, string>;
  }): Promise<{ statusCode: number; body: Buffer; apiCalls: number; decisions: ReturnType<typeof readProxySessionState>["decisions"] }> {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-preverified-"));
    let registryUrl = "";
    const routes = pypiRoutes(() => registryUrl);
    const registry = await startRoutedOrigin(routes);
    registryUrl = registry.url;
    let apiCalls = 0;
    const api = await startHttpApi(async (_body, _request, response) => {
      apiCalls += 1;
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "api answered" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    writePreverifiedFile(session.dir, [{
      ecosystem: "pypi",
      name: "requests",
      version: "2.32.0",
      cooldownEvaluated: true,
      ...input.entry
    } as PreverifiedEntry]);
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("pip", ["install", "requests"]),
      env: { HOME: temp, ...(input.env ?? { DG_COOLDOWN_AGE: "0" }) }
    });

    try {
      const index = await requestViaHttpProxy(handle, `${registry.url}/simple/requests/`);
      expect(index.statusCode).toBe(200);
      const wheel = await requestViaHttpProxy(handle, `${registry.url}/packages/requests-2.32.0-py3-none-any.whl`);
      const state = readProxySessionState(session);
      return { statusCode: wheel.statusCode, body: wheel.body, apiCalls, decisions: state.decisions };
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  }

  it("delivers a preflight-verified artifact without any install-verdict call", async () => {
    const result = await runPreverifiedScenario({ entry: { action: "pass", scannedSha256: WHEEL_SHA } });
    expect(result.statusCode).toBe(200);
    expect(result.body.equals(WHEEL)).toBe(true);
    expect(result.apiCalls).toBe(0);
    expect(result.decisions[0]).toMatchObject({ action: "pass" });
  });

  it("blocks on a scanned-SHA mismatch from the preflight verdict without asking the API", async () => {
    const result = await runPreverifiedScenario({ entry: { action: "pass", scannedSha256: "f".repeat(64) } });
    expect(result.statusCode).toBe(403);
    expect(result.apiCalls).toBe(0);
    expect(result.decisions[0]).toMatchObject({ action: "block", cause: "hash-mismatch" });
  });

  it("falls through to the API when the proxy would apply a cooldown the preflight did not evaluate", async () => {
    const result = await runPreverifiedScenario({
      entry: { action: "pass", cooldownEvaluated: false },
      env: { DG_COOLDOWN_AGE: "24h" }
    });
    expect(result.statusCode).toBe(200);
    expect(result.apiCalls).toBe(1);
  });

  it("short-circuits under an active cooldown when the preflight already evaluated it", async () => {
    const result = await runPreverifiedScenario({
      entry: { action: "pass", cooldownEvaluated: true, scannedSha256: WHEEL_SHA },
      env: { DG_COOLDOWN_AGE: "24h" }
    });
    expect(result.statusCode).toBe(200);
    expect(result.apiCalls).toBe(0);
  });

  it("re-scans the streamed bytes for a preverified pass that carries no scanned SHA (TOCTOU defense, H9)", async () => {
    const result = await runPreverifiedScenario({ entry: { action: "pass" } });
    expect(result.statusCode).toBe(200);
    // No byte fingerprint to cross-check, so the proxy must call the API to scan
    // the actual streamed bytes instead of trusting the name@version verdict.
    expect(result.apiCalls).toBe(1);
  });

  it("never trusts a preverified entry for a url-fallback identity", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-preverified-fb-"));
    const artifact = Buffer.from("tarball bytes", "utf8");
    const registry = await startRoutedOrigin({
      "/left-pad-1.3.0.tgz": { headers: { "Content-Type": "application/octet-stream" }, body: artifact }
    });
    let apiCalls = 0;
    const api = await startHttpApi(async (_body, _request, response) => {
      apiCalls += 1;
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "api answered" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    writePreverifiedFile(session.dir, [{
      ecosystem: "npm",
      name: "left-pad",
      version: "1.3.0",
      action: "pass",
      cooldownEvaluated: true
    }]);
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp, DG_COOLDOWN_AGE: "0" }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad-1.3.0.tgz`);
      expect(response.statusCode).toBe(200);
      expect(apiCalls).toBe(1);
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });
});

describe("production proxy cooldown wiring", () => {
  it("sends the default 24h cooldown param and enforces a cooldown quarantine verdict", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-cooldown-"));
    const artifact = Buffer.from("fresh artifact must not be delivered", "utf8");
    const registry = await startHttpOrigin(artifact);
    const seenBodies: Array<Record<string, unknown>> = [];
    const api = await startHttpApi(async (requestBody, _request, response) => {
      seenBodies.push(JSON.parse(requestBody.toString("utf8")) as Record<string, unknown>);
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({
        verdict: "block",
        cause: "cooldown",
        packageName: "left-pad@2.0.1",
        reason: "published 3h ago — younger than your 24h cooldown",
        cooldown: { requiredDays: 1, ageDays: 0.125, publishedAt: "2026-06-10T00:00:00.000Z", eligibleAt: "2030-06-11T00:00:00.000Z" }
      }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-2.0.1.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(response.body.toString("utf8")).not.toContain(artifact.toString("utf8"));
      expect(response.body.toString("utf8")).toContain("holds: dg cooldown");
      expect(seenBodies).toHaveLength(1);
      expect(seenBodies[0]?.cooldown).toEqual({ minAgeDays: 1, onUnknown: "block" });
      expect(state.decisions[0]).toMatchObject({
        action: "block",
        cause: "cooldown",
        cooldown: { requiredDays: 1, ageDays: 0.125, publishedAt: "2026-06-10T00:00:00.000Z", eligibleAt: "2030-06-11T00:00:00.000Z" }
      });
      expect(readHeldPackages({ HOME: temp })).toMatchObject([{
        ecosystem: "npm",
        name: "left-pad",
        version: "2.0.1",
        requiredDays: 1,
        eligibleAt: "2030-06-11T00:00:00.000Z",
        manager: "npm"
      }]);
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("records no held entry for a malware block", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-malware-hold-"));
    const artifact = Buffer.from("malicious artifact", "utf8");
    const registry = await startHttpOrigin(artifact);
    const api = await startHttpApi(async (_requestBody, _request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({
        verdict: "block",
        cause: "malware",
        packageName: "evil@1.0.0",
        reason: "confirmed malware: credential exfiltration"
      }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "evil"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/evil/-/evil-1.0.0.tgz`);
      expect(response.statusCode).toBe(403);
      expect(response.body.toString("utf8")).not.toContain("holds: dg cooldown");
      expect(readHeldPackages({ HOME: temp })).toEqual([]);
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("omits the cooldown param when DG_COOLDOWN_AGE=0 and for exempt packages", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-cooldown-off-"));
    const artifact = Buffer.from("artifact body", "utf8");
    const registry = await startHttpOrigin(artifact);
    const seenBodies: Array<Record<string, unknown>> = [];
    const api = await startHttpApi(async (requestBody, _request, response) => {
      seenBodies.push(JSON.parse(requestBody.toString("utf8")) as Record<string, unknown>);
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "ok" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const envOffHandle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp, DG_COOLDOWN_AGE: "0" }
    });
    try {
      await requestViaHttpProxy(envOffHandle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
    } finally {
      await envOffHandle.close();
    }

    await mkdir(join(temp, ".dg"), { recursive: true });
    await writeFile(join(temp, ".dg", "config.json"), JSON.stringify({ cooldown: { exempt: "left-pad" } }), "utf8");
    const exemptHandle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });
    try {
      await requestViaHttpProxy(exemptHandle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);

      expect(seenBodies).toHaveLength(2);
      expect(seenBodies[0]?.cooldown).toBeUndefined();
      expect(seenBodies[1]?.cooldown).toBeUndefined();
    } finally {
      await exemptHandle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("omits the cooldown param for a package exempted via dg.json cooldownExemptions", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-cooldown-dgfile-"));
    const artifact = Buffer.from("artifact body", "utf8");
    const registry = await startHttpOrigin(artifact);
    const seenBodies: Array<Record<string, unknown>> = [];
    const api = await startHttpApi(async (requestBody, _request, response) => {
      seenBodies.push(JSON.parse(requestBody.toString("utf8")) as Record<string, unknown>);
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "ok" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp, DG_COOLDOWN_AGE: "24h" },
      cooldownExemptions: [{ ecosystem: "npm", name: "left-pad", reason: "vendored", acceptedBy: "alice", acceptedAt: "2026-06-01T00:00:00.000Z" }]
    });
    try {
      await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      expect(seenBodies).toHaveLength(1);
      expect(seenBodies[0]?.cooldown).toBeUndefined();
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("still sends the cooldown param when the dg.json exemption is for a different package", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-cooldown-dgfile-miss-"));
    const artifact = Buffer.from("fresh artifact must not be delivered", "utf8");
    const registry = await startHttpOrigin(artifact);
    const seenBodies: Array<Record<string, unknown>> = [];
    const api = await startHttpApi(async (requestBody, _request, response) => {
      seenBodies.push(JSON.parse(requestBody.toString("utf8")) as Record<string, unknown>);
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "ok" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp, DG_COOLDOWN_AGE: "24h" },
      cooldownExemptions: [{ ecosystem: "npm", name: "right-pad", reason: "", acceptedBy: "alice", acceptedAt: "2026-06-01T00:00:00.000Z" }]
    });
    try {
      await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      expect(seenBodies).toHaveLength(1);
      expect(seenBodies[0]?.cooldown).toEqual({ minAgeDays: 1, onUnknown: "block" });
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("delivers the artifact as a warn when a cooldown block is force-overridden", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-cooldown-force-"));
    const artifact = Buffer.from("fresh artifact delivered under override", "utf8");
    const registry = await startHttpOrigin(artifact);
    const api = await startHttpApi(async (_requestBody, _request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({
        verdict: "block",
        cause: "cooldown",
        packageName: "left-pad@2.0.1",
        reason: "published 3h ago — younger than your 24h cooldown",
        cooldown: { requiredDays: 1, ageDays: 0.125 }
      }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp },
      forceOverride: { force: true }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-2.0.1.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(200);
      expect(response.body.equals(artifact)).toBe(true);
      expect(state.decisions[0]).toMatchObject({
        action: "warn",
        cause: "cooldown",
        forceOverride: { allowed: true }
      });
      expect(readHeldPackages({ HOME: temp })).toEqual([]);
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });
});

describe("production proxy TLS routing", () => {
  it("fails startup on an occupied listen port without leaving private key files", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-listen-fail-"));
    const occupied = await listenNetServer(createNetServer());
    const session = createSessionSync(resolveDgPaths({
      HOME: temp
    }));

    try {
      await expect(startProductionHttpProxy({
        session,
        apiBaseUrl: "http://127.0.0.1:9",
        classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
        env: {
          HOME: temp
        },
        listenPort: occupied.port
      })).rejects.toThrow();
      await expectNoPrivateKeyFiles(join(temp, ".dg"));
    } finally {
      await occupied.close();
      cleanupSessionSync(session);
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("blind-tunnels non-allowlisted HTTPS through an upstream proxy without recording proxy credentials", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-blind-"));
    const certs = await writeTestTlsMaterial(temp, "localhost");
    const artifact = Buffer.from("blind tunnel artifact", "utf8");
    const origin = await startHttpsOrigin(certs, artifact);
    const upstream = await startConnectProxy();
    const session = createSessionSync(resolveDgPaths({
      HOME: temp
    }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: "http://127.0.0.1:9",
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: {
        HOME: temp,
        DG_UPSTREAM_PROXY: `http://user:secret@127.0.0.1:${upstream.port}`,
        DG_PROXY_MITM_HOSTS: "registry.npmjs.org"
      }
    });

    try {
      const response = await requestViaConnect({
        ca: certs.caCertPem,
        path: "/blind.tgz",
        proxyPort: handle.port,
        proxyAuthorization: handle.proxyAuthorization,
        targetHost: "localhost",
        targetPort: origin.port
      });
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(200);
      expect(response.body.equals(artifact)).toBe(true);
      expect(upstream.connectTargets).toContain(`localhost:${origin.port}`);
      expect(upstream.proxyAuthorizations).toHaveLength(1);
      expect(state.events.join("\n")).toContain(`tunnel:localhost:${origin.port}`);
      expect(state.events.join("\n")).not.toContain("secret");
      expect(state.decisions).toEqual([]);
      await expectNoPrivateKeyFiles(join(temp, ".dg"));
    } finally {
      await handle.close();
      await origin.close();
      await upstream.close();
      cleanupSessionSync(session);
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  it("refuses a CONNECT to an un-screened host under policy.strictEgress instead of blind-tunneling (H7)", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-strict-"));
    const certs = await writeTestTlsMaterial(temp, "localhost");
    const origin = await startHttpsOrigin(certs, Buffer.from("unscreened artifact", "utf8"));
    await mkdir(join(temp, ".dg"), { recursive: true });
    await writeFile(join(temp, ".dg", "config.json"), JSON.stringify({ policy: { strictEgress: true } }), "utf8");
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: "http://127.0.0.1:9",
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp, DG_PROXY_MITM_HOSTS: "registry.npmjs.org" }
    });

    try {
      await expect(
        requestViaConnect({
          ca: certs.caCertPem,
          path: "/blind.tgz",
          proxyPort: handle.port,
          proxyAuthorization: handle.proxyAuthorization,
          targetHost: "localhost",
          targetPort: origin.port
        })
      ).rejects.toThrow(/403/);
      const state = readProxySessionState(session);
      expect(state.decisions[0]).toMatchObject({ action: "block", cause: "policy" });
      expect(state.decisions[0]?.reason).toContain("strict egress");
    } finally {
      await handle.close();
      await origin.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  }, 20_000);

  it("fails closed on bad upstream certificates after the child trusts only the dg session CA", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-bad-cert-"));
    const certs = await writeTestTlsMaterial(temp, "localhost");
    const origin = await startHttpsOrigin(certs, Buffer.from("untrusted upstream", "utf8"));
    const session = createSessionSync(resolveDgPaths({
      HOME: temp
    }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: "http://127.0.0.1:9",
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: {
        HOME: temp,
        DG_PROXY_MITM_HOSTS: "localhost",
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        ALL_PROXY: "",
        NO_PROXY: "localhost,127.0.0.1"
      }
    });

    try {
      const response = await requestViaConnect({
        ca: await readFile(session.files.ca, "utf8"),
        path: "/bad-cert.tgz",
        proxyPort: handle.port,
        proxyAuthorization: handle.proxyAuthorization,
        targetHost: "localhost",
        targetPort: origin.port
      });
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(response.body.toString("utf8")).not.toContain("untrusted upstream");
      expect(state.decisions[0]?.action).toBe("block");
      expect(state.decisions[0]?.cause).toBe("registry-timeout");
      expect(state.hashes).toEqual([]);
      await expectNoPrivateKeyFiles(join(temp, ".dg"));
    } finally {
      await handle.close();
      await origin.close();
      cleanupSessionSync(session);
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  it("fails closed with a registry cause when an upstream proxy returns malformed CONNECT", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-bad-connect-"));
    const upstream = await startMalformedConnectProxy();
    const session = createSessionSync(resolveDgPaths({
      HOME: temp
    }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: "http://127.0.0.1:9",
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: {
        HOME: temp,
        DG_PROXY_MITM_HOSTS: "localhost",
        DG_UPSTREAM_PROXY: `http://user:secret@127.0.0.1:${upstream.port}`,
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        ALL_PROXY: "",
        NO_PROXY: ""
      }
    });

    try {
      const response = await requestViaConnect({
        ca: await readFile(session.files.ca, "utf8"),
        path: "/left-pad.tgz",
        proxyPort: handle.port,
        proxyAuthorization: handle.proxyAuthorization,
        targetHost: "localhost",
        targetPort: 443
      });
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(response.body.toString("utf8")).not.toContain("secret");
      expect(state.decisions[0]?.action).toBe("block");
      expect(state.decisions[0]?.cause).toBe("registry-timeout");
      expect(state.decisions[0]?.reason).toContain("upstream proxy CONNECT failed");
      expect(JSON.stringify(state)).not.toContain("secret");
      await expectNoPrivateKeyFiles(join(temp, ".dg"));
    } finally {
      await handle.close();
      await upstream.close();
      cleanupSessionSync(session);
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);
});

describe("production proxy hardening", () => {
  it("rejects plain proxy requests without the per-session credential (407, nothing fetched, no decision)", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-noauth-"));
    const artifact = Buffer.from("must not be fetched", "utf8");
    const registry = await startHeaderRecordingOrigin(artifact);
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: "http://127.0.0.1:9",
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy({ port: handle.port }, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(407);
      expect(registry.seenHeaders).toHaveLength(0);
      expect(state.decisions).toEqual([]);
      expect(handle.proxyAuthorization).toMatch(/^Basic /);
    } finally {
      await handle.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("rejects CONNECT without the per-session credential with 407", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-noauth-connect-"));
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: "http://127.0.0.1:9",
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      await expect(requestViaConnect({
        ca: "",
        path: "/left-pad.tgz",
        proxyPort: handle.port,
        targetHost: "registry.npmjs.org",
        targetPort: 443
      })).rejects.toThrow(/407/);
    } finally {
      await handle.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("refuses link-local/metadata initial targets for artifact requests and CONNECT", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-linklocal-"));
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: "http://127.0.0.1:9",
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(handle, "http://169.254.169.254/latest/meta-data/");
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(state.decisions[0]).toMatchObject({ action: "block", cause: "policy" });
      expect(state.decisions[0]?.reason ?? "").toContain("link-local");

      await expect(requestViaConnect({
        ca: "",
        path: "/",
        proxyPort: handle.port,
        proxyAuthorization: handle.proxyAuthorization,
        targetHost: "169.254.169.254",
        targetPort: 443
      })).rejects.toThrow(/403/);
    } finally {
      await handle.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("strips VT control characters from verdict strings and drops non-https dashboard URLs", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-sanitize-"));
    const artifact = Buffer.from("artifact must not be delivered", "utf8");
    const registry = await startHttpOrigin(artifact);
    const api = await startHttpApi(async (_body, _request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({
        verdict: "block",
        cause: "malware",
        packageName: "left\u001b[2Jpad",
        reason: "\u001b[32mPASS\u001b[0m malware found",
        dashboardUrl: "http://evil.example/spoof"
      }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(state.decisions[0]?.packageName).toBe("leftpad");
      expect(state.decisions[0]?.reason).toBe("PASS malware found");
      expect(state.decisions[0]?.dashboardUrl).toBeUndefined();
      expect(JSON.stringify(state.decisions)).not.toContain("\\u001b");
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("keeps an https dashboard URL after sanitization", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-dashurl-"));
    const artifact = Buffer.from("artifact must not be delivered", "utf8");
    const registry = await startHttpOrigin(artifact);
    const api = await startHttpApi(async (_body, _request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({
        verdict: "block",
        cause: "malware",
        reason: "malware found",
        dashboardUrl: "https://westbayberry.com/p/npm/left-pad"
      }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      const state = readProxySessionState(session);
      expect(state.decisions[0]?.dashboardUrl).toBe("https://westbayberry.com/p/npm/left-pad");
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("redacts embedded credentials from the artifact URL sent to the verdict API", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-url-redact-"));
    const artifact = Buffer.from("artifact body", "utf8");
    const registry = await startHttpOrigin(artifact);
    const seenBodies: Array<Record<string, unknown>> = [];
    const api = await startHttpApi(async (requestBody, _request, response) => {
      seenBodies.push(JSON.parse(requestBody.toString("utf8")) as Record<string, unknown>);
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "ok" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp }
    });

    try {
      const response = await requestViaHttpProxy(
        handle,
        `http://user:secretpass@127.0.0.1:${registry.port}/left-pad/-/left-pad-1.3.0.tgz`
      );

      expect(response.statusCode).toBe(200);
      expect(seenBodies).toHaveLength(1);
      expect(String(seenBodies[0]?.url)).toContain("<redacted>@127.0.0.1");
      expect(JSON.stringify(seenBodies)).not.toContain("secretpass");
    } finally {
      await handle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("ignores DG_TEST_UPSTREAM_HOST_MAP unless NODE_ENV is test", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-hostmap-"));
    const artifact = Buffer.from("artifact body", "utf8");
    const registry = await startHttpOrigin(artifact);
    const api = await startHttpApi(async (_body, _request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ verdict: "pass", cause: "pass", reason: "ok" }));
    });
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));

    const gatedHandle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp, NODE_ENV: "production", DG_TEST_UPSTREAM_HOST_MAP: "127.0.0.1=127.0.0.2" }
    });
    try {
      const response = await requestViaHttpProxy(gatedHandle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      expect(response.statusCode).toBe(200);
      expect(response.body.equals(artifact)).toBe(true);
    } finally {
      await gatedHandle.close();
    }

    const mappedHandle = await startProductionHttpProxy({
      session,
      apiBaseUrl: api.url,
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp, NODE_ENV: "test", DG_TEST_UPSTREAM_HOST_MAP: "registry.invalid=127.0.0.1" }
    });
    try {
      const response = await requestViaHttpProxy(
        mappedHandle,
        `http://registry.invalid:${registry.port}/left-pad/-/left-pad-1.3.0.tgz`
      );
      expect(response.statusCode).toBe(200);
      expect(response.body.equals(artifact)).toBe(true);
    } finally {
      await mappedHandle.close();
      await api.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("fails closed with a registry-timeout cause when the upstream stalls mid-body", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-proxy-stall-"));
    const registry = await startStallingOrigin();
    const session = createSessionSync(resolveDgPaths({ HOME: temp }));
    const handle = await startProductionHttpProxy({
      session,
      apiBaseUrl: "http://127.0.0.1:9",
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: temp, DG_UPSTREAM_IDLE_TIMEOUT_MS: "300" }
    });

    try {
      const response = await requestViaHttpProxy(handle, `${registry.url}/left-pad/-/left-pad-1.3.0.tgz`);
      const state = readProxySessionState(session);

      expect(response.statusCode).toBe(403);
      expect(state.decisions[0]).toMatchObject({ action: "block", cause: "registry-timeout" });
      expect(state.decisions[0]?.reason ?? "").toContain("timed out");
      expect(state.hashes).toEqual([]);
    } finally {
      await handle.close();
      await registry.close();
      cleanupSessionSync(session);
      await rm(temp, { force: true, recursive: true });
    }
  }, 20_000);
});

function startStallingOrigin(): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
  readonly url: string;
}> {
  const sockets = new Set<Socket>();
  const server = createHttpServer((_request, response) => {
    response.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Length": 1024
    });
    response.write("partial-bytes-then-silence");
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  return listenHttpServer(server).then((listening) => ({
    ...listening,
    close: () => {
      for (const socket of sockets) {
        socket.destroy();
      }
      return listening.close();
    }
  }));
}

function startHttpOrigin(artifact: Buffer): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
  readonly url: string;
}> {
  const server = createHttpServer((_request, response) => {
    response.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Length": artifact.length
    });
    response.end(artifact);
  });
  return listenHttpServer(server);
}

function startHttpRedirect(location: string): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
  readonly url: string;
}> {
  const server = createHttpServer((_request, response) => {
    response.writeHead(302, {
      Location: location,
      "Content-Length": 0
    });
    response.end();
  });
  return listenHttpServer(server);
}

function startRoutedOrigin(routes: Record<string, { status?: number; headers: Record<string, string | number>; body: Buffer }>): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
  readonly url: string;
}> {
  const server = createHttpServer((request, response) => {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    const route = routes[path];
    if (!route) {
      response.writeHead(404, { "Content-Length": 0 });
      response.end();
      return;
    }
    response.writeHead(route.status ?? 200, { ...route.headers, "Content-Length": route.body.length });
    response.end(route.body);
  });
  return listenHttpServer(server);
}

function startStatusOrigin(statusCode: number, body: Buffer): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
  readonly url: string;
}> {
  const server = createHttpServer((_request, response) => {
    response.writeHead(statusCode, { "Content-Type": "text/plain", "Content-Length": body.length });
    response.end(body);
  });
  return listenHttpServer(server);
}

function startLocationlessRedirect(): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
  readonly url: string;
}> {
  const server = createHttpServer((_request, response) => {
    response.writeHead(301, { "Content-Length": 0 });
    response.end();
  });
  return listenHttpServer(server);
}

function startInfiniteRedirect(): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
  readonly url: string;
}> {
  const server = createHttpServer((request, response) => {
    const hop = Number.parseInt(new URL(request.url ?? "/", "http://127.0.0.1").searchParams.get("hop") ?? "0", 10);
    response.writeHead(302, {
      Location: `?hop=${hop + 1}`,
      "Content-Length": 0
    });
    response.end();
  });
  return listenHttpServer(server);
}

function startHttpPartialOrigin(artifact: Buffer): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
  readonly url: string;
}> {
  const partial = artifact.subarray(0, Math.min(artifact.length, 4));
  const server = createHttpServer((_request, response) => {
    response.writeHead(206, {
      "Content-Type": "application/octet-stream",
      "Content-Range": `bytes 0-${partial.length - 1}/${artifact.length}`,
      "Content-Length": partial.length
    });
    response.end(partial);
  });
  return listenHttpServer(server);
}

function startHeaderRecordingOrigin(artifact: Buffer): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
  readonly url: string;
  readonly seenHeaders: IncomingHttpHeaders[];
}> {
  const seenHeaders: IncomingHttpHeaders[] = [];
  const server = createHttpServer((request, response) => {
    seenHeaders.push(request.headers);
    response.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Length": artifact.length
    });
    response.end(artifact);
  });
  return listenHttpServer(server).then((listening) => ({
    ...listening,
    seenHeaders
  }));
}

function startHttpApi(
  handler: (body: Buffer, request: IncomingMessage, response: ServerResponse) => void | Promise<void>
): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
  readonly url: string;
}> {
  const server = createHttpServer((request, response) => {
    readHttpBody(request).then((body) => handler(body, request, response)).catch((error: unknown) => {
      response.writeHead(500, {
        "Content-Type": "text/plain; charset=utf-8"
      });
      response.end(error instanceof Error ? error.message : "test api failure");
    });
  });
  return listenHttpServer(server);
}

function listenHttpServer(server: ReturnType<typeof createHttpServer>): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
  readonly url: string;
}> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      if (typeof address !== "object" || address === null) {
        reject(new Error("test HTTP server did not bind"));
        return;
      }
      resolve({
        port: address.port,
        url: `http://127.0.0.1:${address.port}`,
        close: () => new Promise((closeResolve) => {
          server.close(() => closeResolve());
        })
      });
    });
  });
}

function requestViaHttpProxy(
  proxy: { readonly port: number; readonly proxyAuthorization?: string },
  targetUrl: string,
  extraHeaders: Record<string, string> = {}
): Promise<{
  readonly body: Buffer;
  readonly statusCode: number;
}> {
  return new Promise((resolve, reject) => {
    const target = new URL(targetUrl);
    const request = httpRequest({
      hostname: "127.0.0.1",
      port: proxy.port,
      path: target.toString(),
      method: "GET",
      headers: {
        Host: target.host,
        ...(proxy.proxyAuthorization ? { "Proxy-Authorization": proxy.proxyAuthorization } : {}),
        ...extraHeaders
      }
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => {
        resolve({
          body: Buffer.concat(chunks),
          statusCode: response.statusCode ?? 0
        });
      });
    });
    request.once("error", reject);
    request.end();
  });
}

function readHttpBody(request: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.once("end", () => resolve(Buffer.concat(chunks)));
    request.once("error", reject);
  });
}

async function requestViaConnect(options: {
  readonly ca: string;
  readonly path: string;
  readonly proxyPort: number;
  readonly proxyAuthorization?: string;
  readonly targetHost: string;
  readonly targetPort: number;
}): Promise<{
  readonly statusCode: number;
  readonly body: Buffer;
}> {
  const socket = await new Promise<Socket>((resolve, reject) => {
    const client = connect(options.proxyPort, "127.0.0.1");
    client.once("connect", () => resolve(client));
    client.once("error", reject);
  });
  await writeConnect(socket, options.targetHost, options.targetPort, options.proxyAuthorization);
  const tlsSocket = await new Promise<ReturnType<typeof tlsConnect>>((resolve, reject) => {
    const secure = tlsConnect({
      socket,
      servername: options.targetHost,
      ca: options.ca
    }, () => resolve(secure));
    secure.once("error", reject);
  });
  tlsSocket.write(`GET ${options.path} HTTP/1.1\r\nHost: ${options.targetHost}:${options.targetPort}\r\nAuthorization: Bearer test-secret\r\nConnection: close\r\n\r\n`);
  const raw = await readSocket(tlsSocket);
  const headerEnd = raw.indexOf("\r\n\r\n");
  const head = raw.subarray(0, headerEnd).toString("latin1");
  const body = raw.subarray(headerEnd + 4);
  return {
    statusCode: Number(/HTTP\/1\.[01] (\d+)/.exec(head)?.[1] ?? 0),
    body: head.toLowerCase().includes("transfer-encoding: chunked") ? decodeChunkedBody(body) : body
  };
}

function writeConnect(socket: Socket, host: string, port: number, proxyAuthorization?: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const authLine = proxyAuthorization ? `Proxy-Authorization: ${proxyAuthorization}\r\n` : "";
    socket.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${authLine}\r\n`);
    socket.on("data", function onData(chunk: Buffer) {
      chunks.push(chunk);
      const buffered = Buffer.concat(chunks);
      const headerEnd = buffered.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        return;
      }
      socket.off("data", onData);
      const statusLine = buffered.subarray(0, headerEnd).toString("latin1").split("\r\n")[0] ?? "";
      if (!/^HTTP\/1\.[01] 2\d\d\b/.test(statusLine)) {
        reject(new Error(`CONNECT failed: ${statusLine}`));
        return;
      }
      const head = buffered.subarray(headerEnd + 4);
      if (head.length > 0) {
        socket.unshift(head);
      }
      resolve();
    });
    socket.once("error", reject);
  });
}

function readSocket(socket: Socket): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.once("end", () => resolve(Buffer.concat(chunks)));
    socket.once("error", reject);
  });
}

function startHttpsOrigin(certs: {
  readonly certPem: string;
  readonly keyPem: string;
}, artifact: Buffer): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
}> {
  const server = createHttpsServer({
    cert: certs.certPem,
    key: certs.keyPem
  }, (_request, response) => {
    response.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Length": artifact.length
    });
    response.end(artifact);
  });
  return listenNetServer(server);
}

function startConnectProxy(): Promise<{
  readonly close: () => Promise<void>;
  readonly connectTargets: string[];
  readonly port: number;
  readonly proxyAuthorizations: string[];
}> {
  const connectTargets: string[] = [];
  const proxyAuthorizations: string[] = [];
  const server = createNetServer((client) => {
    const chunks: Buffer[] = [];
    client.on("data", function onData(chunk: Buffer) {
      chunks.push(chunk);
      const buffered = Buffer.concat(chunks);
      const headerEnd = buffered.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        return;
      }
      client.off("data", onData);
      const head = buffered.subarray(0, headerEnd).toString("latin1");
      const [requestLine = "", ...headers] = head.split("\r\n");
      const target = /^CONNECT ([^ ]+) HTTP\/1\.[01]$/.exec(requestLine)?.[1] ?? "";
      connectTargets.push(target);
      const auth = headers.find((line) => line.toLowerCase().startsWith("proxy-authorization:"));
      if (auth) {
        proxyAuthorizations.push(auth);
      }
      const [host, rawPort] = target.split(":");
      const upstream = connect(Number(rawPort), host);
      upstream.once("connect", () => {
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        const rest = buffered.subarray(headerEnd + 4);
        if (rest.length > 0) {
          upstream.write(rest);
        }
        client.pipe(upstream);
        upstream.pipe(client);
      });
      upstream.once("error", () => client.destroy());
    });
  });
  return listenNetServer(server).then((listening) => ({
    ...listening,
    connectTargets,
    proxyAuthorizations
  }));
}

function startMalformedConnectProxy(): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
}> {
  const server = createNetServer((client) => {
    client.once("data", () => {
      client.end("DG BAD CONNECT RESPONSE\r\n\r\n");
    });
  });
  return listenNetServer(server);
}

function listenNetServer(server: NetServer): Promise<{
  readonly close: () => Promise<void>;
  readonly port: number;
}> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      if (typeof address !== "object" || address === null) {
        reject(new Error("test server did not bind"));
        return;
      }
      resolve({
        port: address.port,
        close: () => new Promise((closeResolve) => {
          server.close(() => closeResolve());
        })
      });
    });
  });
}

async function writeTestTlsMaterial(root: string, host: string): Promise<{
  readonly caCertPem: string;
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
    value: "DG test CA"
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
  leaf.serialNumber = createHash("sha256").update(host).digest("hex").slice(0, 16);
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
  await writeFile(join(root, "test-ca.pem"), forge.pki.certificateToPem(ca), "utf8");
  return {
    caCertPem: forge.pki.certificateToPem(ca),
    certPem: forge.pki.certificateToPem(leaf),
    keyPem: forge.pki.privateKeyToPem(leafKeys.privateKey)
  };
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
      const text = await readFile(path, "utf8").catch(() => "");
      if (text.includes("BEGIN PRIVATE KEY") || text.includes("BEGIN RSA PRIVATE KEY")) {
        found.push(path);
      }
    }
  }
  await walk(root);
  expect(found).toEqual([]);
}

function decodeChunkedBody(body: Buffer): Buffer {
  const chunks: Buffer[] = [];
  let offset = 0;
  while (offset < body.length) {
    const lineEnd = body.indexOf("\r\n", offset);
    if (lineEnd === -1) {
      break;
    }
    const size = Number.parseInt(body.subarray(offset, lineEnd).toString("latin1"), 16);
    if (size === 0) {
      return Buffer.concat(chunks);
    }
    const start = lineEnd + 2;
    const end = start + size;
    chunks.push(body.subarray(start, end));
    offset = end + 2;
  }
  return Buffer.concat(chunks);
}

describe("upstreamTlsOptions (H6: ambient CA must not be trusted upstream)", () => {
  it("ignores ambient NODE_EXTRA_CA_CERTS so it cannot MITM the real registry", () => {
    expect(upstreamTlsOptions({ NODE_EXTRA_CA_CERTS: "/tmp/attacker-ca.pem" } as NodeJS.ProcessEnv)).toEqual({});
  });

  it("returns no extra CA when neither knob is set", () => {
    expect(upstreamTlsOptions({} as NodeJS.ProcessEnv)).toEqual({});
  });

  it("honors the explicit DG_UPSTREAM_CA_CERT knob", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dg-upstream-ca-"));
    const caPath = join(dir, "ca.pem");
    await writeFile(caPath, "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n", "utf8");
    try {
      const opts = upstreamTlsOptions({ DG_UPSTREAM_CA_CERT: caPath } as NodeJS.ProcessEnv);
      expect(opts.ca).toBeDefined();
      expect(opts.ca?.some((c) => c.includes("FAKE"))).toBe(true);
    } finally {
      await rm(dir, { force: true, recursive: true });
    }
  });

  it("DG_UPSTREAM_CA_CERT wins even when NODE_EXTRA_CA_CERTS is also set", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dg-upstream-ca-"));
    const caPath = join(dir, "ca.pem");
    await writeFile(caPath, "-----BEGIN CERTIFICATE-----\nTRUSTED\n-----END CERTIFICATE-----\n", "utf8");
    try {
      const opts = upstreamTlsOptions({ DG_UPSTREAM_CA_CERT: caPath, NODE_EXTRA_CA_CERTS: "/tmp/attacker-ca.pem" } as NodeJS.ProcessEnv);
      expect(opts.ca?.some((c) => c.includes("TRUSTED"))).toBe(true);
    } finally {
      await rm(dir, { force: true, recursive: true });
    }
  });
});
