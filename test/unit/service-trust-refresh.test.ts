import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createEphemeralCertificateAuthority } from "../../src/proxy/ca.js";
import { readServiceState, TRUST_SENTINEL } from "../../src/service/state.js";
import {
  clearTrustRefreshError,
  readTrustRefreshError,
  refreshServiceTrustAfterCaRotation,
  trustRefreshErrorPath
} from "../../src/service/trust-refresh.js";
import {
  applyTrustInstall,
  readServiceTrustRecord,
  resolveTrustInstallPlan,
  writeServiceTrustRecord
} from "../../src/service/trust-store.js";

const tempRoots: string[] = [];

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-trust-refresh-"));
  tempRoots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

function fileBackendEnv(trustDir: string): NodeJS.ProcessEnv {
  return {
    DG_SERVICE_TRUST_STORE_BACKEND: "file",
    DG_SERVICE_TRUST_STORE_DIR: trustDir
  };
}

describe("service trust refresh after CA rotation", () => {
  it("swaps the installed root for the new CA and updates the trust record", async () => {
    const root = await tempRoot();
    const trustDir = join(root, "trust");
    const serviceDir = join(root, "service");
    const trustRecordPath = join(serviceDir, "trust-store.json");
    const env = fileBackendEnv(trustDir);

    const oldCaPath = join(root, "sessions", "one", "ca.pem");
    createEphemeralCertificateAuthority(oldCaPath);
    const oldPlan = resolveTrustInstallPlan(oldCaPath, env);
    const oldRecord = applyTrustInstall(oldPlan, new Date(), TRUST_SENTINEL);
    writeServiceTrustRecord(trustRecordPath, oldRecord);
    expect(existsSync(oldRecord.target)).toBe(true);

    const newCaPath = join(root, "sessions", "two", "ca.pem");
    createEphemeralCertificateAuthority(newCaPath);

    refreshServiceTrustAfterCaRotation({
      serviceDir,
      trustRecordPath,
      sentinel: TRUST_SENTINEL,
      caPath: newCaPath,
      env
    });

    const refreshed = readServiceTrustRecord(trustRecordPath, TRUST_SENTINEL);
    expect(refreshed).toBeDefined();
    expect(refreshed?.fingerprintSha256).not.toBe(oldRecord.fingerprintSha256);
    expect(existsSync(oldRecord.target)).toBe(false);
    expect(existsSync(refreshed?.target ?? "")).toBe(true);
    expect(readTrustRefreshError(serviceDir)).toBeUndefined();
  });

  it("sweeps stale dg-named roots left behind in the trust dir", async () => {
    const root = await tempRoot();
    const trustDir = join(root, "trust");
    const serviceDir = join(root, "service");
    const trustRecordPath = join(serviceDir, "trust-store.json");
    const env = fileBackendEnv(trustDir);

    const oldCaPath = join(root, "sessions", "one", "ca.pem");
    createEphemeralCertificateAuthority(oldCaPath);
    const oldRecord = applyTrustInstall(resolveTrustInstallPlan(oldCaPath, env), new Date(), TRUST_SENTINEL);
    writeServiceTrustRecord(trustRecordPath, oldRecord);
    await writeFile(join(trustDir, `dependency-guardian-${"ab".repeat(8)}.pem`), "stale root", "utf8");
    await writeFile(join(trustDir, "unrelated.pem"), "not ours", "utf8");

    const newCaPath = join(root, "sessions", "two", "ca.pem");
    createEphemeralCertificateAuthority(newCaPath);

    refreshServiceTrustAfterCaRotation({
      serviceDir,
      trustRecordPath,
      sentinel: TRUST_SENTINEL,
      caPath: newCaPath,
      env
    });

    const remaining = await readdir(trustDir);
    expect(remaining).toContain("unrelated.pem");
    expect(remaining.filter((name) => name.startsWith("dependency-guardian-"))).toHaveLength(1);
  });

  it("records a surfaced error flag when the refresh fails and clears it on success", async () => {
    const root = await tempRoot();
    const trustDir = join(root, "trust");
    const serviceDir = join(root, "service");
    const trustRecordPath = join(serviceDir, "trust-store.json");
    const env = fileBackendEnv(trustDir);

    const oldCaPath = join(root, "sessions", "one", "ca.pem");
    createEphemeralCertificateAuthority(oldCaPath);
    const oldRecord = applyTrustInstall(resolveTrustInstallPlan(oldCaPath, env), new Date(), TRUST_SENTINEL);
    writeServiceTrustRecord(trustRecordPath, oldRecord);

    refreshServiceTrustAfterCaRotation({
      serviceDir,
      trustRecordPath,
      sentinel: TRUST_SENTINEL,
      caPath: join(root, "missing-ca.pem"),
      env
    });

    const failure = readTrustRefreshError(serviceDir);
    expect(failure).toBeDefined();
    expect(failure?.message).toContain("missing-ca.pem");
    expect(existsSync(trustRefreshErrorPath(serviceDir))).toBe(true);

    const newCaPath = join(root, "sessions", "two", "ca.pem");
    createEphemeralCertificateAuthority(newCaPath);
    refreshServiceTrustAfterCaRotation({
      serviceDir,
      trustRecordPath,
      sentinel: TRUST_SENTINEL,
      caPath: newCaPath,
      env
    });
    expect(readTrustRefreshError(serviceDir)).toBeUndefined();
  });

  it("does nothing when no trust record exists", async () => {
    const root = await tempRoot();
    const serviceDir = join(root, "service");

    refreshServiceTrustAfterCaRotation({
      serviceDir,
      trustRecordPath: join(serviceDir, "trust-store.json"),
      sentinel: TRUST_SENTINEL,
      caPath: join(root, "missing-ca.pem"),
      env: {}
    });

    expect(readTrustRefreshError(serviceDir)).toBeUndefined();
  });

  it("surfaces the refresh failure through dg service status state", async () => {
    const home = await tempRoot();
    const serviceDir = join(home, ".dg", "state", "service");
    await mkdir(serviceDir, { recursive: true });
    await writeFile(
      join(serviceDir, "service.json"),
      `${JSON.stringify({ version: 1, configured: true, running: false })}\n`,
      "utf8"
    );
    await writeFile(
      trustRefreshErrorPath(serviceDir),
      `${JSON.stringify({ at: "2026-06-11T00:00:00.000Z", message: "keychain said no" })}\n`,
      "utf8"
    );

    const result = readServiceState({ HOME: home });
    expect(result.state.lastError).toContain("service CA trust refresh failed");
    expect(result.state.lastError).toContain("keychain said no");

    clearTrustRefreshError(serviceDir);
    const cleared = readServiceState({ HOME: home });
    expect(cleared.state.lastError).toBeUndefined();
  });
});
