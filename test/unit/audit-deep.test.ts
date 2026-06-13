import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { deepDecision, runDeepUpload } from "../../src/audit/deep.js";

const made: string[] = [];

afterEach(() => {
  for (const dir of made.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function pkgDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "dg-deep-"));
  made.push(dir);
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "deep-fixture", version: "1.0.0", files: ["index.js"] }));
  writeFileSync(join(dir, "index.js"), "module.exports = 1;\n");
  return dir;
}

function baseEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const home = mkdtempSync(join(tmpdir(), "dg-deep-home-"));
  made.push(home);
  return { ...process.env, HOME: home, DG_API_TOKEN: "dg_live_token", DG_AUDIT_UPLOAD: "1", ...extra };
}

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as unknown as Response;
}

const scope = (root: string) => ({ root, ecosystem: "npm", artifact: "deep-fixture@1.0.0" });

describe("deepDecision gating", () => {
  it("does not upload in --local mode", () => {
    expect(deepDecision(scope("/x"), true, baseEnv()).upload).toBe(false);
  });
  it("does not upload for non-npm ecosystems", () => {
    expect(deepDecision({ root: "/x", ecosystem: "pypi", artifact: "x" }, false, baseEnv()).upload).toBe(false);
  });
  it("does not upload when not signed in", () => {
    const env = baseEnv();
    delete env.DG_API_TOKEN;
    const d = deepDecision(scope("/x"), false, env);
    expect(d.upload).toBe(false);
    expect(d.reason).toContain("not signed in");
  });
  it("does not upload without consent", () => {
    const env = baseEnv();
    delete env.DG_AUDIT_UPLOAD;
    expect(deepDecision(scope("/x"), false, env).upload).toBe(false);
  });
  it("uploads when signed in + consented + npm", () => {
    expect(deepDecision(scope("/x"), false, baseEnv()).upload).toBe(true);
  });
});

describe("runDeepUpload (mock scanner)", () => {
  it("maps a block verdict and uploads the packed bytes with a SHA-256 header", async () => {
    const dir = pkgDir();
    let headers: Record<string, string> = {};
    let bodyLen = 0;
    const fetchImpl = (async (_url: string | URL, init?: RequestInit) => {
      headers = init?.headers as Record<string, string>;
      bodyLen = (init?.body as Buffer).length;
      return jsonResponse({ verdict: "block", scannedSha256: headers["X-DG-Artifact-SHA256"], reason: "malware" });
    }) as unknown as typeof fetch;
    const result = await runDeepUpload(scope(dir), { name: "deep-fixture", version: "1.0.0" }, { fetchImpl, env: baseEnv() });
    expect(result).toEqual({ ran: true, action: "block", reason: "malware" });
    expect(headers["X-DG-Source-Kind"]).toBe("pre-publish");
    expect(headers["X-DG-Artifact-SHA256"]).toMatch(/^[a-f0-9]{64}$/u);
    expect(bodyLen).toBeGreaterThan(0);
  });

  it("maps pass and warn verdicts", async () => {
    const dir = pkgDir();
    const pass = (async () => jsonResponse({ verdict: "pass", scannedSha256: "x" })) as unknown as typeof fetch;
    expect((await runDeepUpload(scope(dir), null, { fetchImpl: pass, env: baseEnv() })).ran).toBe(true);
    const warn = (async () => jsonResponse({ verdict: "warn", scannedSha256: "x", reason: "lifecycle" })) as unknown as typeof fetch;
    const r = await runDeepUpload(scope(dir), null, { fetchImpl: warn, env: baseEnv() });
    expect(r).toMatchObject({ ran: true, action: "warn" });
  });

  it("maps 403 entitlement codes to plan and team wording", async () => {
    const dir = pkgDir();
    const notPaid = (async () => jsonResponse({ error: "pro tier required", code: "tier-required" }, 403)) as unknown as typeof fetch;
    expect(await runDeepUpload(scope(dir), null, { fetchImpl: notPaid, env: baseEnv() })).toEqual({ ran: false, reason: "deep behavioral scan requires a paid plan" });
    const teamOff = (async () => jsonResponse({ error: "org policy does not enable private artifact upload", code: "artifact-upload-disabled" }, 403)) as unknown as typeof fetch;
    const teamOffReason = (await runDeepUpload(scope(dir), null, { fetchImpl: teamOff, env: baseEnv() })).reason;
    expect(teamOffReason).toContain("team disabled artifact uploads");
    expect(teamOffReason).not.toContain("organization");
    const noPolicy = (async () => jsonResponse({ error: "private artifact upload requires an organization policy", code: "org-policy-required" }, 403)) as unknown as typeof fetch;
    const noPolicyReason = (await runDeepUpload(scope(dir), null, { fetchImpl: noPolicy, env: baseEnv() })).reason;
    expect(noPolicyReason).toContain("team hasn't enabled artifact uploads");
    expect(noPolicyReason).not.toContain("organization");
    const unknownCode = (async () => jsonResponse({ error: "denied" }, 402)) as unknown as typeof fetch;
    expect((await runDeepUpload(scope(dir), null, { fetchImpl: unknownCode, env: baseEnv() })).reason).toBe("deep behavioral scan requires a paid plan");
  });

  it("treats a network error as offline (fail-open)", async () => {
    const dir = pkgDir();
    const offline = (async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    const r = await runDeepUpload(scope(dir), null, { fetchImpl: offline, env: baseEnv() });
    expect(r).toEqual({ ran: false, reason: expect.stringContaining("offline") });
  });

  it("treats a 5xx as analysis incomplete", async () => {
    const dir = pkgDir();
    const err = (async () => jsonResponse({}, 503)) as unknown as typeof fetch;
    expect(await runDeepUpload(scope(dir), null, { fetchImpl: err, env: baseEnv() })).toMatchObject({ ran: true, action: "analysis_incomplete" });
  });

  it("does not run lifecycle scripts while packing for deep upload", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dg-deep-"));
    made.push(dir);
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      name: "noexec-deep",
      version: "1.0.0",
      files: ["index.js"],
      scripts: { prepare: "node -e \"require('fs').writeFileSync('SENTINEL','x')\"" }
    }));
    writeFileSync(join(dir, "index.js"), "1;\n");
    const ok = (async () => jsonResponse({ verdict: "pass", scannedSha256: "x" })) as unknown as typeof fetch;
    await runDeepUpload(scope(dir), null, { fetchImpl: ok, env: baseEnv() });
    expect(existsSync(join(dir, "SENTINEL"))).toBe(false);
  });
});
