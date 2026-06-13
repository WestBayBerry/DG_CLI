import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runCli } from "../../src/runtime/cli.js";
import { createEphemeralCertificateAuthority } from "../../src/proxy/ca.js";
import {
  applyTrustInstall,
  resolveTrustInstallPlan,
  TrustToolMissingError,
  type TrustStorePlan
} from "../../src/service/trust-store.js";

vi.mock("../../src/service/trust-store.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/service/trust-store.js")>();
  return {
    ...actual,
    resolveTrustInstallPlan: vi.fn(actual.resolveTrustInstallPlan)
  };
});

const tempRoots: string[] = [];

function makePlan(provider: TrustStorePlan["provider"], caPath: string, target: string, tool: string): TrustStorePlan {
  return {
    provider,
    supported: true,
    adminRequired: false,
    native: true,
    caPath,
    target,
    fingerprintSha256: "a".repeat(64),
    fingerprintSha1: "a".repeat(40),
    installCommand: [tool, "install"],
    uninstallCommand: [tool, "uninstall"],
    reason: undefined
  };
}

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-trust-tool-"));
  tempRoots.push(root);
  return root;
}

describe("service trust install without a native trust tool", () => {
  afterEach(async () => {
    vi.clearAllMocks();
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
  });

  it("raises TrustToolMissingError when the native tool binary does not exist", async () => {
    const root = await tempRoot();
    const caPath = join(root, "ca.pem");
    await writeFile(caPath, "stub-ca", "utf8");
    const plan = makePlan("darwin-user-keychain", caPath, join(root, "fake-keychain.db"), "dg-missing-trust-tool-xyz");

    let caught: unknown;
    try {
      applyTrustInstall(plan, new Date(), "dg-service-trust-v1");
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(TrustToolMissingError);
    expect((caught as TrustToolMissingError).tool).toBe("dg-missing-trust-tool-xyz");
  });

  it("removes the partially-written Linux CA file when update-ca-certificates is missing", async () => {
    const root = await tempRoot();
    const caPath = join(root, "ca.pem");
    await writeFile(caPath, "stub-ca", "utf8");
    const target = join(root, "ca-certificates", "dependency-guardian-test.crt");
    const plan = makePlan("linux-system-ca", caPath, target, "ignored");
    const emptyBin = join(root, "empty-bin");
    await mkdir(emptyBin, { recursive: true });

    const savedPath = process.env.PATH;
    process.env.PATH = emptyBin;
    let caught: unknown;
    try {
      applyTrustInstall(plan, new Date(), "dg-service-trust-v1");
    } catch (error) {
      caught = error;
    } finally {
      process.env.PATH = savedPath;
    }

    expect(caught).toBeInstanceOf(TrustToolMissingError);
    expect((caught as TrustToolMissingError).tool).toBe("update-ca-certificates");
    expect(existsSync(target)).toBe(false);
  });

  it("maps the missing tool to exit 69 with platform guidance and records no trust state", async () => {
    const home = await tempRoot();
    const caPath = join(home, ".dg", "state", "sessions", "svc", "ca", "ca.pem");
    createEphemeralCertificateAuthority(caPath);
    const serviceDir = join(home, ".dg", "state", "service");
    await mkdir(serviceDir, { recursive: true });
    const runtime = {
      pid: process.pid,
      proxyUrl: "http://127.0.0.1:4567",
      healthUrl: "http://127.0.0.1:4567/health",
      sessionDir: join(home, ".dg", "state", "sessions", "svc"),
      caPath,
      startedAt: "2026-06-01T00:00:00.000Z"
    };
    await writeFile(
      join(serviceDir, "service.json"),
      `${JSON.stringify({ version: 1, configured: true, running: true, trustInstalled: false, proxy: runtime }, null, 2)}\n`,
      "utf8"
    );
    await writeFile(join(serviceDir, "runtime.json"), `${JSON.stringify(runtime, null, 2)}\n`, "utf8");
    vi.mocked(resolveTrustInstallPlan).mockReturnValue(
      makePlan("darwin-user-keychain", caPath, join(home, "fake-keychain.db"), "dg-missing-trust-tool-xyz")
    );

    const savedHome = process.env.HOME;
    process.env.HOME = home;
    let result;
    try {
      result = await runCli(["service", "trust", "install", "--yes"]);
    } finally {
      if (savedHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = savedHome;
      }
    }

    expect(result.exitCode).toBe(69);
    expect(result.stderr).toContain("'dg-missing-trust-tool-xyz' is not available on this system");
    expect(result.stderr).toContain("no trust state was changed");
    expect(result.stderr).toContain("DG_SERVICE_TRUST_STORE_BACKEND=file");
    expect(existsSync(join(serviceDir, "trust-store.json"))).toBe(false);
  });
});
