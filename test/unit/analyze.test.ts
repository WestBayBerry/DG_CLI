import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AnalyzeError, analyzePackages, normalizeAnalyzeResponse } from "../../src/api/analyze.js";

const tempRoots: string[] = [];

async function tempHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-analyze-"));
  tempRoots.push(root);
  return root;
}

function fakeFetch(handler: (url: string, init: RequestInit) => { status?: number; body?: unknown }): typeof fetch {
  const calls: Array<{ url: string; body: unknown; headers: Record<string, string> }> = [];
  const impl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ url, body, headers: (init?.headers ?? {}) as Record<string, string> });
    const result = handler(url, init ?? {});
    return new Response(JSON.stringify(result.body ?? {}), {
      status: result.status ?? 200,
      headers: { "Content-Type": "application/json" }
    });
  }) as typeof fetch;
  (impl as unknown as { calls: typeof calls }).calls = calls;
  return impl;
}

function callsOf(impl: typeof fetch): Array<{ url: string; body: { packages: Array<{ name: string }> }; headers: Record<string, string> }> {
  return (impl as unknown as { calls: Array<{ url: string; body: { packages: Array<{ name: string }> }; headers: Record<string, string> }> }).calls;
}

function ndjsonStream(init: RequestInit | undefined, pump: (push: (line: string) => void, close: () => void) => void): Response {
  const encoder = new TextEncoder();
  let settled = false;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      init?.signal?.addEventListener("abort", () => {
        if (settled) return;
        settled = true;
        controller.error(new DOMException("The operation was aborted.", "AbortError"));
      });
      pump(
        (line) => {
          if (!settled) controller.enqueue(encoder.encode(line));
        },
        () => {
          if (settled) return;
          settled = true;
          controller.close();
        }
      );
    }
  });
  return new Response(stream, { headers: { "Content-Type": "application/x-ndjson" } });
}

function slowNdjsonFetch(lines: readonly string[], intervalMs: number): typeof fetch {
  return (async (_input: string | URL | Request, init?: RequestInit) =>
    ndjsonStream(init, (push, close) => {
      let index = 0;
      const tick = (): void => {
        const line = lines[index];
        index += 1;
        if (line === undefined) {
          close();
          return;
        }
        push(line);
        setTimeout(tick, intervalMs);
      };
      setTimeout(tick, intervalMs);
    })) as typeof fetch;
}

function silentNdjsonFetch(firstLine: string): typeof fetch {
  return (async (_input: string | URL | Request, init?: RequestInit) =>
    ndjsonStream(init, (push) => {
      push(firstLine);
    })) as typeof fetch;
}

const okBody = {
  score: 82,
  action: "warn",
  packages: [
    {
      name: "left-pad",
      version: "1.3.0",
      score: 82,
      action: "warn",
      findings: [{ severity: 3, title: "lifecycle script" }],
      reasons: ["install lifecycle script"],
      cached: false
    }
  ],
  safeVersions: {},
  durationMs: 12
};

describe("analyzePackages", () => {
  afterEach(async () => {
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
  });

  it("posts the package batch and returns the scanner verdict verbatim", async () => {
    const home = await tempHome();
    const impl = fakeFetch(() => ({ body: okBody }));
    const result = await analyzePackages([{ name: "left-pad", version: "1.3.0" }], {
      ecosystem: "npm",
      env: { HOME: home },
      fetchImpl: impl
    });

    expect(result.action).toBe("warn");
    expect(result.score).toBe(82);
    expect(result.packages[0]?.action).toBe("warn");
    expect(callsOf(impl)[0]?.url).toContain("/analyze");
    expect(callsOf(impl)[0]?.body.packages).toEqual([{ name: "left-pad", version: "1.3.0" }]);
  });

  it("sends the cooldown policy param when provided and omits it otherwise", async () => {
    const home = await tempHome();
    const impl = fakeFetch(() => ({ body: okBody }));
    await analyzePackages([{ name: "requests", version: "2.31.0" }], {
      ecosystem: "pypi",
      env: { HOME: home },
      fetchImpl: impl,
      cooldown: { minAgeDays: 1, onUnknown: "allow" }
    });
    await analyzePackages([{ name: "requests", version: "2.31.0" }], {
      ecosystem: "pypi",
      env: { HOME: home },
      fetchImpl: impl
    });
    const calls = callsOf(impl) as Array<{ body: { cooldown?: unknown } }>;
    expect(calls[0]?.body.cooldown).toEqual({ minAgeDays: 1, onUnknown: "allow" });
    expect(calls[1]?.body.cooldown).toBeUndefined();
  });

  it("passes the per-package cooldown annotation through to the caller", async () => {
    const home = await tempHome();
    const impl = fakeFetch(() => ({
      body: {
        score: 0,
        action: "pass",
        packages: [{
          name: "fresh-wheel", version: "0.0.2", score: 0, action: "pass", findings: [], reasons: [], cached: false,
          cooldown: { status: "quarantine", requiredDays: 1, ageDays: 0.2 }
        }],
        safeVersions: {},
        durationMs: 1
      }
    }));
    const result = await analyzePackages([{ name: "fresh-wheel", version: "0.0.2" }], {
      ecosystem: "pypi",
      env: { HOME: home },
      fetchImpl: impl,
      cooldown: { minAgeDays: 1, onUnknown: "allow" }
    });
    expect(result.packages[0]?.cooldown).toEqual({ status: "quarantine", requiredDays: 1, ageDays: 0.2 });
  });

  it("consumes the NDJSON progress stream and reports per-package progress", async () => {
    const home = await tempHome();
    const events = [
      { type: "started", total: 2 },
      { type: "cache_hit", done: 1, total: 2 },
      { type: "progress", done: 2, total: 2, name: "b", version: "1", cached: false, score: 0 },
      {
        type: "result",
        payload: {
          score: 5,
          action: "pass",
          packages: [
            { name: "a", version: "1", score: 0, action: "pass", findings: [], reasons: [], cached: true },
            { name: "b", version: "1", score: 5, action: "pass", findings: [], reasons: [], cached: false }
          ],
          safeVersions: {},
          durationMs: 10
        }
      }
    ];
    const ndjson = events.map((e) => JSON.stringify(e)).join("\n") + "\n";
    const impl = (async () =>
      new Response(ndjson, { headers: { "Content-Type": "application/x-ndjson" } })) as typeof fetch;
    const progress: number[] = [];
    const result = await analyzePackages([{ name: "a", version: "1" }, { name: "b", version: "1" }], {
      ecosystem: "npm",
      env: { HOME: home },
      fetchImpl: impl,
      onProgress: (p) => progress.push(p.done)
    });

    expect(result.action).toBe("pass");
    expect(result.packages).toHaveLength(2);
    expect(progress).toContain(1);
    expect(progress[progress.length - 1]).toBe(2);
  });

  it("splits >200 packages into concurrent batches and merges every result", async () => {
    const home = await tempHome();
    const pkgs = Array.from({ length: 450 }, (_, i) => ({ name: `p${i}`, version: "1.0.0" }));
    const impl = (async (_input: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { packages: Array<{ name: string; version: string }> };
      const packages = body.packages.map((p) => ({ ...p, score: 0, action: "pass", findings: [], reasons: [], cached: true }));
      return new Response(JSON.stringify({ score: 0, action: "pass", packages, safeVersions: {}, durationMs: 1 }), {
        headers: { "Content-Type": "application/json" }
      });
    }) as typeof fetch;
    const result = await analyzePackages(pkgs, { ecosystem: "npm", env: { HOME: home }, fetchImpl: impl });
    expect(result.packages).toHaveLength(450);
  });

  it("sends a bearer token when DG_API_TOKEN is set and none otherwise", async () => {
    const home = await tempHome();
    const impl = fakeFetch(() => ({ body: okBody }));
    await analyzePackages([{ name: "a", version: "1" }], {
      ecosystem: "npm",
      env: { HOME: home, DG_API_TOKEN: "dg_test_token" },
      fetchImpl: impl
    });
    await analyzePackages([{ name: "a", version: "1" }], {
      ecosystem: "npm",
      env: { HOME: home },
      fetchImpl: impl
    });

    const calls = callsOf(impl);
    expect(calls[0]?.headers.Authorization).toBe("Bearer dg_test_token");
    expect(calls[1]?.headers.Authorization).toBeUndefined();
  });

  it("splits large inputs into 200-package batches and merges by worst action", async () => {
    const home = await tempHome();
    let call = 0;
    const impl = fakeFetch(() => {
      call += 1;
      return {
        body: {
          ...okBody,
          action: call === 2 ? "block" : "pass",
          packages: []
        }
      };
    });
    const packages = Array.from({ length: 450 }, (_, index) => ({ name: `pkg-${index}`, version: "1.0.0" }));
    const result = await analyzePackages(packages, {
      ecosystem: "npm",
      env: { HOME: home },
      fetchImpl: impl
    });

    expect(callsOf(impl)).toHaveLength(3);
    expect(callsOf(impl)[0]?.body.packages).toHaveLength(200);
    expect(callsOf(impl)[2]?.body.packages).toHaveLength(50);
    expect(result.action).toBe("block");
  });

  it("reports batch position through onProgress across multiple batches", async () => {
    const home = await tempHome();
    const impl = fakeFetch(() => ({ body: { ...okBody, packages: [] } }));
    const packages = Array.from({ length: 450 }, (_, index) => ({ name: `pkg-${index}`, version: "1.0.0" }));
    const progress: Array<{ done: number; total: number; batchIndex: number; batchCount: number }> = [];
    await analyzePackages(packages, {
      ecosystem: "npm",
      env: { HOME: home },
      fetchImpl: impl,
      onProgress: (update) => { progress.push(update); }
    });

    expect(progress[0]).toEqual({ done: 0, total: 450, batchIndex: 0, batchCount: 3 });
    expect(progress.every((update) => update.batchCount === 3)).toBe(true);
    expect(progress.map((update) => update.batchIndex)).toContain(3);
    expect(progress[progress.length - 1]).toEqual({ done: 450, total: 450, batchIndex: 3, batchCount: 3 });
  });

  it("throws AnalyzeError with the status for non-OK responses", async () => {
    const home = await tempHome();
    const impl = fakeFetch(() => ({ status: 404, body: {} }));
    await expect(
      analyzePackages([{ name: "a", version: "1" }], {
        ecosystem: "npm",
        env: { HOME: home },
        fetchImpl: impl
      })
    ).rejects.toMatchObject({ name: "AnalyzeError", statusCode: 404 });
  });

  it("routes pypi to the pypi analyze path", async () => {
    const home = await tempHome();
    const impl = fakeFetch(() => ({ body: okBody }));
    await analyzePackages([{ name: "requests", version: "2.0.0" }], {
      ecosystem: "pypi",
      env: { HOME: home },
      fetchImpl: impl
    });
    expect(callsOf(impl)[0]?.url).toContain("/pypi/analyze");
  });

  it("retries network failures (fetch failed) up to three attempts then surfaces a connection error", async () => {
    const home = await tempHome();
    let attempts = 0;
    const impl = (async () => {
      attempts += 1;
      throw new TypeError("fetch failed");
    }) as typeof fetch;
    await expect(
      analyzePackages([{ name: "a", version: "1" }], { ecosystem: "npm", env: { HOME: home }, fetchImpl: impl })
    ).rejects.toMatchObject({ name: "AnalyzeError", statusCode: 0 });
    expect(attempts).toBe(3);
  });

  it("does not retry a programming error and rethrows it after one attempt", async () => {
    const home = await tempHome();
    let attempts = 0;
    const impl = (async () => {
      attempts += 1;
      throw new TypeError("x is not a function");
    }) as typeof fetch;
    await expect(
      analyzePackages([{ name: "a", version: "1" }], { ecosystem: "npm", env: { HOME: home }, fetchImpl: impl })
    ).rejects.toThrow("x is not a function");
    expect(attempts).toBe(1);
  });

  it("does not retry a 4xx scanner error", async () => {
    const home = await tempHome();
    let attempts = 0;
    const impl = (async () => {
      attempts += 1;
      return new Response(JSON.stringify({ error: "bad request" }), { status: 400 });
    }) as typeof fetch;
    await expect(
      analyzePackages([{ name: "a", version: "1" }], { ecosystem: "npm", env: { HOME: home }, fetchImpl: impl })
    ).rejects.toMatchObject({ name: "AnalyzeError", statusCode: 400 });
    expect(attempts).toBe(1);
  });

  it("classifies the canonical quota body on a 403 with real numbers", async () => {
    const home = await tempHome();
    const impl = fakeFetch(() => ({
      status: 403,
      body: { error: "Free scan limit reached", code: "quota_exceeded", scansUsed: 10, scansLimit: 15 }
    }));
    await expect(
      analyzePackages([{ name: "a", version: "1" }], { ecosystem: "npm", env: { HOME: home }, fetchImpl: impl })
    ).rejects.toMatchObject({
      name: "AnalyzeError",
      statusCode: 403,
      code: "quota_exceeded",
      scansUsed: 10,
      scansLimit: 15,
      message: "Free scan limit reached"
    });
  });

  it("classifies the legacy reason/maxScans quota body on 402 and 429", async () => {
    const home = await tempHome();
    for (const status of [402, 429]) {
      const impl = fakeFetch(() => ({
        status,
        body: { error: "limit", reason: "monthly_limit", scansUsed: 15, maxScans: 15 }
      }));
      await expect(
        analyzePackages([{ name: "a", version: "1" }], { ecosystem: "npm", env: { HOME: home }, fetchImpl: impl })
      ).rejects.toMatchObject({ code: "quota_exceeded", scansUsed: 15, scansLimit: 15, statusCode: status });
    }
  });

  it("treats a 429 without a quota body as rate-limited with a retry hint, never a quota or auth error", async () => {
    const home = await tempHome();
    const impl = fakeFetch(() => ({ status: 429, body: {} }));
    await expect(
      analyzePackages([{ name: "a", version: "1" }], { ecosystem: "npm", env: { HOME: home }, fetchImpl: impl })
    ).rejects.toMatchObject({
      code: "rate_limited",
      message: "scanner rate limit reached — wait a moment and retry"
    });
  });

  it("classifies bare 401 and 403 as auth errors", async () => {
    const home = await tempHome();
    for (const status of [401, 403]) {
      const impl = fakeFetch(() => ({ status, body: {} }));
      await expect(
        analyzePackages([{ name: "a", version: "1" }], { ecosystem: "npm", env: { HOME: home }, fetchImpl: impl })
      ).rejects.toMatchObject({ code: "auth", statusCode: status });
    }
  });

  it("sends one X-Scan-Id across every batch and honors an explicit scanId", async () => {
    const home = await tempHome();
    const impl = fakeFetch(() => ({ body: { ...okBody, packages: [] } }));
    const packages = Array.from({ length: 450 }, (_, index) => ({ name: `pkg-${index}`, version: "1.0.0" }));
    await analyzePackages(packages, { ecosystem: "npm", env: { HOME: home }, fetchImpl: impl });

    const generated = callsOf(impl).map((call) => call.headers["X-Scan-Id"]);
    expect(generated).toHaveLength(3);
    expect(new Set(generated).size).toBe(1);
    expect(generated[0]).toMatch(/^[0-9a-f-]{36}$/);

    await analyzePackages([{ name: "a", version: "1" }], {
      ecosystem: "npm",
      env: { HOME: home },
      fetchImpl: impl,
      scanId: "scan-id-fixed"
    });
    expect(callsOf(impl)[3]?.headers["X-Scan-Id"]).toBe("scan-id-fixed");
  });

  it("keeps a slow stream alive as long as NDJSON events keep arriving", async () => {
    const home = await tempHome();
    const events = [
      { type: "progress", done: 1, total: 2 },
      { type: "progress", done: 1, total: 2 },
      { type: "progress", done: 2, total: 2 },
      {
        type: "result",
        payload: {
          score: 0,
          action: "pass",
          packages: [
            { name: "a", version: "1", score: 0, action: "pass", findings: [], reasons: [], cached: true },
            { name: "b", version: "1", score: 0, action: "pass", findings: [], reasons: [], cached: true }
          ],
          safeVersions: {},
          durationMs: 10
        }
      }
    ];
    const impl = slowNdjsonFetch(events.map((event) => `${JSON.stringify(event)}\n`), 60);
    const result = await analyzePackages([{ name: "a", version: "1" }, { name: "b", version: "1" }], {
      ecosystem: "npm",
      env: { HOME: home },
      fetchImpl: impl,
      timeoutMs: 120
    });
    expect(result.action).toBe("pass");
    expect(result.packages).toHaveLength(2);
  });

  it("aborts with a distinct timeout error after sustained stream silence", async () => {
    const home = await tempHome();
    const impl = silentNdjsonFetch(`${JSON.stringify({ type: "progress", done: 1, total: 2 })}\n`);
    await expect(
      analyzePackages([{ name: "a", version: "1" }], {
        ecosystem: "npm",
        env: { HOME: home },
        fetchImpl: impl,
        timeoutMs: 80
      })
    ).rejects.toMatchObject({
      name: "AnalyzeError",
      code: "timeout",
      message: expect.stringContaining("no data for 80ms")
    });
  });

  it("propagates an external abort without retrying or relabeling it", async () => {
    const home = await tempHome();
    let attempts = 0;
    const impl = ((_input: string | URL | Request, init?: RequestInit) => {
      attempts += 1;
      return new Promise<Response>((_, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new DOMException("The operation was aborted.", "AbortError"));
        });
      });
    }) as typeof fetch;
    const controller = new AbortController();
    const pending = analyzePackages([{ name: "a", version: "1" }], {
      ecosystem: "npm",
      env: { HOME: home },
      fetchImpl: impl,
      signal: controller.signal
    });
    setTimeout(() => controller.abort(), 20);
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(attempts).toBe(1);
  });

  it("retries 5xx scanner errors", async () => {
    const home = await tempHome();
    let attempts = 0;
    const impl = (async () => {
      attempts += 1;
      if (attempts < 3) {
        return new Response(JSON.stringify({ error: "down" }), { status: 503 });
      }
      return new Response(JSON.stringify(okBody), { status: 200 });
    }) as typeof fetch;
    const result = await analyzePackages([{ name: "a", version: "1" }], {
      ecosystem: "npm",
      env: { HOME: home },
      fetchImpl: impl
    });
    expect(attempts).toBe(3);
    expect(result.action).toBe("warn");
  });
});

describe("normalizeAnalyzeResponse", () => {
  it("keeps the scanner action even when the score disagrees", () => {
    const normalized = normalizeAnalyzeResponse({
      ...okBody,
      score: 5,
      action: "block",
      packages: [{ ...okBody.packages[0], score: 5, action: "block" }]
    });
    expect(normalized.action).toBe("block");
    expect(normalized.packages[0]?.action).toBe("block");
  });

  it("treats a missing per-package action as pass without re-deriving from score", () => {
    const normalized = normalizeAnalyzeResponse({
      ...okBody,
      packages: [{ name: "x", version: "1", score: 99, findings: [], reasons: [], cached: false }]
    });
    expect(normalized.packages[0]?.action).toBeUndefined();
  });

  it("normalizes an unrecognized action to analysis_incomplete, never pass", () => {
    const normalized = normalizeAnalyzeResponse({
      ...okBody,
      action: "quarantine",
      packages: [{ ...okBody.packages[0], action: "quarantine" }]
    });
    expect(normalized.action).toBe("analysis_incomplete");
    expect(normalized.packages[0]?.action).toBe("analysis_incomplete");
  });

  it("rejects malformed responses", () => {
    expect(() => normalizeAnalyzeResponse({ packages: [] })).toThrowError(AnalyzeError);
    expect(() => normalizeAnalyzeResponse(null)).toThrowError(AnalyzeError);
  });

  it("strips VT control sequences from every server string before rendering", () => {
    const esc = String.fromCharCode(27);
    const bel = String.fromCharCode(7);
    const normalized = normalizeAnalyzeResponse({
      ...okBody,
      packages: [
        {
          name: "left-pad",
          version: "1.3.0",
          score: 82,
          action: "warn",
          findings: [{ severity: 3, title: `lifecycle${esc}[31m script` }],
          reasons: [`install ${esc}[2Jlifecycle script`],
          recommendation: `pin ${esc}]0;evil${bel}left-pad`,
          cached: false
        }
      ],
      safeVersions: { [`left-${esc}[1mpad`]: "1.3.1" }
    });
    const pkg = normalized.packages[0]!;
    expect(pkg.findings[0]?.title).toBe("lifecycle script");
    expect(pkg.reasons[0]).toBe("install lifecycle script");
    expect(pkg.recommendation).toBe("pin left-pad");
    expect(Object.keys(normalized.safeVersions)[0]).toBe("left-pad");
  });
});
