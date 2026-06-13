import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runCli } from "../../src/runtime/cli.js";
import { startService, TRUST_SENTINEL } from "../../src/service/state.js";
import { createEphemeralCertificateAuthority } from "../../src/proxy/ca.js";
import { writeAuthState } from "../../src/auth/store.js";

const STUB_WORKER_SOURCE = `
const { createServer } = require("node:http");
const { writeFileSync } = require("node:fs");
const runtimePath = process.argv[4];
const server = createServer((_request, response) => {
  response.writeHead(200, { "Content-Type": "application/json" });
  response.end("{\\"ok\\":true}\\n");
});
server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  writeFileSync(
    runtimePath,
    JSON.stringify({
      pid: process.pid,
      proxyUrl: "http://127.0.0.1:" + port,
      healthUrl: "http://127.0.0.1:" + port + "/health",
      sessionDir: "stub-session",
      caPath: "stub-ca.pem",
      startedAt: new Date().toISOString()
    }) + "\\n",
    { encoding: "utf8", mode: 0o600 }
  );
});
process.on("SIGTERM", () => process.exit(0));
process.stdin.on("end", () => process.exit(0));
`;

async function writeStubWorker(home: string): Promise<string> {
  const path = join(home, "stub-service-worker.cjs");
  await writeFile(path, STUB_WORKER_SOURCE, "utf8");
  return path;
}

describe("service mode", () => {
  it("refuses to start before explicit service setup", async () => {
    const home = await tempHome();
    const result = await withEnv(home, () => runCli(["service", "start"]));

    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("run dg setup --service --yes first");
    await expect(access(join(home, ".dg", "state", "service", "service.json"))).rejects.toThrow();
  });

  it("does not create service state for no-op stop, trust uninstall, or service uninstall", async () => {
    const home = await tempHome();
    const stop = await withEnv(home, () => runCli(["service", "stop"]));
    const trust = await withEnv(home, () => runCli(["service", "trust", "uninstall", "--yes"]));
    const uninstall = await withEnv(home, () => runCli(["service", "uninstall", "--yes"]));

    expect(stop.exitCode).toBe(0);
    expect(trust.exitCode).toBe(0);
    expect(uninstall.exitCode).toBe(0);
    await expect(access(join(home, ".dg", "state", "service"))).rejects.toThrow();
    await expect(access(join(home, ".dg", "state", "cleanup-registry.json"))).rejects.toThrow();
  });

  it("starts, reports, restarts, and stops explicit service mode", async () => {
    const home = await tempHome();
    const workerPath = await writeStubWorker(home);
    await withEnv(home, () => writeAuthState({ token: "dg_test_token_abcdefghi" }));
    await withEnv(home, () => runCli(["setup", "--service", "--yes"]));

    const worker = { DG_SERVICE_WORKER_PATH: workerPath };
    const start = await withEnv(home, () => runCli(["service", "start"]), worker);
    const status = await withEnv(home, () => runCli(["service", "status", "--json"]), worker);
    const restart = await withEnv(home, () => runCli(["service", "restart"]), worker);
    const stop = await withEnv(home, () => runCli(["service", "stop"]), worker);
    const parsed = JSON.parse(status.stdout) as {
      readonly configured: boolean;
      readonly running: boolean;
      readonly trustInstalled: boolean;
    };

    expect(start.exitCode).toBe(0);
    expect(start.stdout).toContain("Service started");
    expect(parsed).toMatchObject({
      configured: true,
      running: true,
      trustInstalled: false
    });
    expect(restart.exitCode).toBe(0);
    expect(restart.stdout).toContain("Service restarted");
    expect(stop.exitCode).toBe(0);
    expect(stop.stdout).toContain("Service stopped");
  });

  it("start/stop/restart parse --help and --print and reject unknown flags without mutating", async () => {
    const home = await tempHome();

    const help = await withEnv(home, () => runCli(["service", "start", "--help"]));
    expect(help.exitCode).toBe(0);
    expect(help.stdout).toContain("dg service start");
    expect(help.stdout).toContain("--print");

    const startPrint = await withEnv(home, () => runCli(["service", "start", "--print"]));
    expect(startPrint.exitCode).toBe(0);
    expect(startPrint.stdout).toContain("Dependency Guardian service start plan");
    expect(startPrint.stdout).toContain("No service or trust-store state is changed");

    const stopPrint = await withEnv(home, () => runCli(["service", "stop", "--print"]));
    expect(stopPrint.exitCode).toBe(0);
    expect(stopPrint.stdout).toContain("Dependency Guardian service stop plan");

    const restartPrint = await withEnv(home, () => runCli(["service", "restart", "--print"]));
    expect(restartPrint.exitCode).toBe(0);
    expect(restartPrint.stdout).toContain("Dependency Guardian service restart plan");

    const unknown = await withEnv(home, () => runCli(["service", "start", "--bogus"]));
    expect(unknown.exitCode).toBe(2);
    expect(unknown.stderr).toContain("unknown option '--bogus'");

    await expect(access(join(home, ".dg", "state", "service"))).rejects.toThrow();
  });

  it("prints each trust-install plan line once without a redundant path suffix", async () => {
    const home = await tempHome();
    const trustDir = join(home, "ci-trust");
    await writeActiveServiceRuntime(home);

    const print = await withEnv(
      home,
      () => runCli(["service", "trust", "install", "--print"]),
      {
        DG_SERVICE_TRUST_STORE_BACKEND: "file",
        DG_SERVICE_TRUST_STORE_DIR: trustDir
      }
    );

    expect(print.exitCode).toBe(0);
    expect(print.stdout).toMatch(/^- trust provider: file$/mu);
    expect(print.stdout).not.toContain("trust provider: file: ");
    expect(print.stdout).toMatch(/^- certificate SHA-256 fingerprint: [0-9a-f]{64}$/mu);
    expect(print.stdout).toMatch(/^- requires admin\/root: no$/mu);
  });

  it("fails trust install without an active service CA and records no trust state", async () => {
    const home = await tempHome();
    await withEnv(home, () => writeAuthState({ token: "dg_test_token_abcdefghi" }));
    await withEnv(home, () => runCli(["setup", "--service", "--yes"]));

    const noConsent = await withEnv(home, () => runCli(["service", "trust", "install"]));
    const install = await withEnv(home, () => runCli(["service", "trust", "install", "--yes"]));

    expect(noConsent.exitCode).toBe(2);
    expect(noConsent.stdout).toContain("service trust install plan");
    expect(noConsent.stderr).toContain("requires --yes");
    expect(install.exitCode).toBe(1);
    expect(install.stderr).toContain("requires a running service proxy with an active CA certificate");
    await expect(access(join(home, ".dg", "state", "service", "trust-store.json"))).rejects.toThrow();
  });

  it("installs file-backed service trust and fully reverses the recorded certificate", async () => {
    const home = await tempHome();
    const trustDir = join(home, "ci-trust");
    const caPath = await writeActiveServiceRuntime(home);

    await withEnv(home, () => writeAuthState({ token: "dg_test_token_abcdefghi" }));
    await withEnv(home, () => runCli(["setup", "--service", "--yes"]));
    await writeActiveServiceRuntime(home, caPath);

    const install = await withEnv(
      home,
      () => runCli(["service", "trust", "install", "--yes"]),
      {
        DG_SERVICE_TRUST_STORE_BACKEND: "file",
        DG_SERVICE_TRUST_STORE_DIR: trustDir
      }
    );
    const status = await withEnv(home, () => runCli(["service", "status"]));

    expect(install.exitCode).toBe(0);
    expect(install.stdout).toContain("trust provider: file");
    await expect(readFile(join(home, ".dg", "state", "service", "trust-store.json"), "utf8")).resolves.toContain(TRUST_SENTINEL);
    await expect(access(trustDir)).resolves.toBeUndefined();
    expect(status.stdout).toContain("Trust        ✓ file (");

    const uninstall = await withEnv(
      home,
      () => runCli(["service", "trust", "uninstall", "--yes"]),
      {
        DG_SERVICE_TRUST_STORE_BACKEND: "file",
        DG_SERVICE_TRUST_STORE_DIR: trustDir
      }
    );
    expect(uninstall.exitCode).toBe(0);
    await expect(access(join(home, ".dg", "state", "service", "trust-store.json"))).rejects.toThrow();
  });

  it("uninstalls service and trust state through service and top-level uninstall paths", async () => {
    const home = await tempHome();
    await withEnv(home, () => writeAuthState({ token: "dg_test_token_abcdefghi" }));
    await withEnv(home, () => runCli(["setup", "--service", "--yes"]));
    await withEnv(home, () => runCli(["service", "trust", "install", "--yes"]));

    const topLevel = await withEnv(home, () => runCli(["uninstall", "--service", "--yes"]));
    const second = await withEnv(home, () => runCli(["service", "uninstall", "--yes"]));

    expect(topLevel.exitCode).toBe(0);
    expect(topLevel.stdout).toContain("Service uninstall completed");
    await expect(access(join(home, ".dg", "state", "service"))).rejects.toThrow();
    expect(second.exitCode).toBe(0);
    expect(second.stdout).toContain("No dg-owned service writes were present.");
  });

  it("reports service doctor health without admin or OS trust-store mutation", async () => {
    const home = await tempHome();
    const workerPath = await writeStubWorker(home);
    await withEnv(home, () => writeAuthState({ token: "dg_test_token_abcdefghi" }));
    await withEnv(home, () => runCli(["setup", "--service", "--yes"]));
    await withEnv(home, () => runCli(["service", "start"]), { DG_SERVICE_WORKER_PATH: workerPath });

    const doctor = await withEnv(home, () => runCli(["service", "doctor", "--json"]), { DG_SERVICE_WORKER_PATH: workerPath });
    const parsed = JSON.parse(doctor.stdout) as {
      readonly checks: readonly { readonly name: string; readonly status: string; readonly message: string }[];
    };

    expect(doctor.exitCode).toBe(0);
    expect(parsed.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "configured", status: "pass" }),
        expect.objectContaining({ name: "running", status: "pass" }),
        expect.objectContaining({
          name: "admin",
          status: "pass",
          message: expect.stringContaining("Native service trust-store mutation is consent-gated")
        })
      ])
    );
    await withEnv(home, () => runCli(["service", "stop"]));
  });

  it("fails start loud when the service proxy worker is unavailable", async () => {
    const home = await tempHome();
    await withEnv(home, () => writeAuthState({ token: "dg_test_token_abcdefghi" }));
    await withEnv(home, () => runCli(["setup", "--service", "--yes"]));

    await expect(
      withEnv(home, () => startService(), { DG_SERVICE_WORKER_PATH: join(home, "missing-worker.cjs") })
    ).rejects.toThrow("service proxy worker is unavailable until the CLI package is built");

    const status = await withEnv(home, () => runCli(["service", "status", "--json"]));
    const parsed = JSON.parse(status.stdout) as { readonly running: boolean };
    expect(parsed.running).toBe(false);
  });

  it("detects stale service runtime JSON when the worker is gone or health is unreachable", async () => {
    const deadHome = await tempHome();
    await writeActiveServiceRuntime(deadHome, undefined, {
      pid: 9_999_999,
      healthUrl: "http://127.0.0.1:9/health"
    });
    const deadStatus = await withEnv(deadHome, () => runCli(["service", "status", "--json"]));
    const deadDoctor = await withEnv(deadHome, () => runCli(["service", "doctor", "--json"]));
    const parsedDeadStatus = JSON.parse(deadStatus.stdout) as {
      readonly running: boolean;
      readonly lastError: string;
    };
    const parsedDeadDoctor = JSON.parse(deadDoctor.stdout) as {
      readonly checks: readonly { readonly name: string; readonly status: string; readonly message: string }[];
    };

    expect(parsedDeadStatus.running).toBe(false);
    expect(parsedDeadStatus.lastError).toContain("recorded service worker pid 9999999 is not running");
    expect(parsedDeadDoctor.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "service-proxy",
          status: "fail",
          message: expect.stringContaining("stale service runtime state")
        })
      ])
    );

    const unreachableHome = await tempHome();
    await writeActiveServiceRuntime(unreachableHome, undefined, {
      pid: process.pid,
      healthUrl: "http://127.0.0.1:9/health"
    });
    const unreachableStatus = await withEnv(unreachableHome, () => runCli(["service", "status"]));

    expect(unreachableStatus.stdout).toContain("Running      ⚠ no");
    expect(unreachableStatus.stdout).toContain("health endpoint is unreachable");
  });

  it("warns when recorded service trust drifts from the active CA", async () => {
    const home = await tempHome();
    const trustDir = join(home, "ci-trust");
    const firstCa = await writeActiveServiceRuntime(home);

    await withEnv(home, () => writeAuthState({ token: "dg_test_token_abcdefghi" }));
    await withEnv(home, () => runCli(["setup", "--service", "--yes"]));
    await writeActiveServiceRuntime(home, firstCa, {
      pid: process.pid
    });
    const install = await withEnv(
      home,
      () => runCli(["service", "trust", "install", "--yes"]),
      {
        DG_SERVICE_TRUST_STORE_BACKEND: "file",
        DG_SERVICE_TRUST_STORE_DIR: trustDir
      }
    );
    await writeActiveServiceRuntime(home, join(home, ".dg", "state", "sessions", "service-test-2", "ca", "ca.pem"), {
      pid: process.pid
    });

    const doctor = await withEnv(home, () => runCli(["service", "doctor", "--json"]));
    const status = await withEnv(home, () => runCli(["service", "status", "--json"]));
    const parsedDoctor = JSON.parse(doctor.stdout) as {
      readonly checks: readonly { readonly name: string; readonly status: string; readonly message: string }[];
    };
    const parsedStatus = JSON.parse(status.stdout) as {
      readonly trustDrift: null | { readonly message: string };
    };

    expect(install.exitCode).toBe(0);
    expect(parsedStatus.trustDrift?.message).toContain("does not match active service CA fingerprint");
    expect(parsedDoctor.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "trust-drift",
          status: "warn",
          message: expect.stringContaining("does not match active service CA fingerprint")
        })
      ])
    );
  });

  it("never deletes a sessionsDir sibling named in runtime.json, only true session children", async () => {
    const escapeHome = await tempHome();
    const sibling = join(escapeHome, ".dg", "state", "sessionsEVIL");
    await mkdir(sibling, { recursive: true });
    await writeFile(join(sibling, "marker.txt"), "must survive", "utf8");
    await writeActiveServiceRuntime(escapeHome, undefined, {
      pid: 9_999_999,
      sessionDir: sibling
    });

    const stopEscape = await withEnv(escapeHome, () => runCli(["service", "stop"]));

    expect(stopEscape.exitCode).toBe(0);
    await expect(readFile(join(sibling, "marker.txt"), "utf8")).resolves.toBe("must survive");

    const containedHome = await tempHome();
    const contained = join(containedHome, ".dg", "state", "sessions", "service-test");
    await writeActiveServiceRuntime(containedHome, undefined, {
      pid: 9_999_999,
      sessionDir: contained
    });
    await writeFile(join(contained, "marker.txt"), "session content", "utf8");

    const stopContained = await withEnv(containedHome, () => runCli(["service", "stop"]));

    expect(stopContained.exitCode).toBe(0);
    await expect(access(contained)).rejects.toThrow();
  });
});

async function tempHome(): Promise<string> {
  return mkdtemp(join(tmpdir(), "dg-service-test-"));
}

async function writeActiveServiceRuntime(
  home: string,
  caPath = join(home, ".dg", "state", "sessions", "service-test", "ca", "ca.pem"),
  runtimeOverrides: Partial<{
    readonly pid: number;
    readonly proxyUrl: string;
    readonly healthUrl: string;
    readonly sessionDir: string;
  }> = {}
): Promise<string> {
  createEphemeralCertificateAuthority(caPath);
  const serviceDir = join(home, ".dg", "state", "service");
  const sessionDir = runtimeOverrides.sessionDir ?? join(home, ".dg", "state", "sessions", "service-test");
  const runtime = {
    pid: runtimeOverrides.pid ?? process.pid,
    proxyUrl: runtimeOverrides.proxyUrl ?? "http://127.0.0.1:4567",
    healthUrl: runtimeOverrides.healthUrl ?? "http://127.0.0.1:4567/health",
    sessionDir,
    caPath,
    startedAt: "2026-06-01T00:00:00.000Z"
  };
  await mkdir(serviceDir, {
    recursive: true
  });
  await writeFile(
    join(serviceDir, "service.json"),
    `${JSON.stringify(
      {
        version: 1,
        configured: true,
        running: true,
        trustInstalled: false,
        proxy: runtime,
        policySyncedAt: "2026-06-01T00:00:00.000Z",
        configuredAt: "2026-06-01T00:00:00.000Z",
        startedAt: "2026-06-01T00:00:00.000Z"
      },
      null,
      2
    )}\n`
  );
  await writeFile(join(serviceDir, "runtime.json"), `${JSON.stringify(runtime, null, 2)}\n`);
  return caPath;
}

async function withEnv<T>(home: string, run: () => T | Promise<T>, extra: Record<string, string> = {}): Promise<T> {
  const previous = {
    HOME: process.env.HOME,
    PATH: process.env.PATH,
    SHELL: process.env.SHELL,
    DG_TEST_NODE_VERSION: process.env.DG_TEST_NODE_VERSION,
    DG_SERVICE_TRUST_STORE_BACKEND: process.env.DG_SERVICE_TRUST_STORE_BACKEND,
    DG_SERVICE_TRUST_STORE_DIR: process.env.DG_SERVICE_TRUST_STORE_DIR,
    DG_SERVICE_WORKER_PATH: process.env.DG_SERVICE_WORKER_PATH
  };
  process.env.HOME = home;
  process.env.PATH = `/usr/bin:/bin`;
  process.env.SHELL = "/bin/bash";
  process.env.DG_TEST_NODE_VERSION = "v22.14.0";
  for (const [key, value] of Object.entries(extra)) {
    process.env[key] = value;
  }
  try {
    return await run();
  } finally {
    restoreEnv("HOME", previous.HOME);
    restoreEnv("PATH", previous.PATH);
    restoreEnv("SHELL", previous.SHELL);
    restoreEnv("DG_TEST_NODE_VERSION", previous.DG_TEST_NODE_VERSION);
    restoreEnv("DG_SERVICE_TRUST_STORE_BACKEND", previous.DG_SERVICE_TRUST_STORE_BACKEND);
    restoreEnv("DG_SERVICE_TRUST_STORE_DIR", previous.DG_SERVICE_TRUST_STORE_DIR);
    restoreEnv("DG_SERVICE_WORKER_PATH", previous.DG_SERVICE_WORKER_PATH);
  }
}

function restoreEnv(key: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[key];
  } else {
    process.env[key] = value;
  }
}
