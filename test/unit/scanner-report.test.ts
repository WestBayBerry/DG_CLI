import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../../src/runtime/cli.js";
import { buildScannerReport, scanWorkerTimeoutMs, workerFailure } from "../../src/scan/scanner-report.js";
import type { ScanReport, ScannerError } from "../../src/scan/types.js";

const tempRoots: string[] = [];
const children: ChildProcess[] = [];

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-scanner-scan-"));
  tempRoots.push(root);
  return root;
}

const SERVER_SCRIPT = `
const { createServer } = require("node:http");
const config = JSON.parse(process.argv[1]);
const server = createServer((request, response) => {
  let body = "";
  request.on("data", (chunk) => { body += chunk; });
  request.on("end", () => {
    response.writeHead(config.status ?? 200, { "Content-Type": config.contentType ?? "application/json" });
    response.end(config.body);
  });
});
server.listen(0, "127.0.0.1", () => {
  console.log(String(server.address().port));
});
`;

async function startRawMock(config: { status?: number; contentType?: string; body: string }): Promise<{ url: string }> {
  const child = spawn(process.execPath, ["-e", SERVER_SCRIPT, JSON.stringify(config)], {
    stdio: ["ignore", "pipe", "ignore"]
  });
  children.push(child);
  const port = await new Promise<string>((resolvePort, rejectPort) => {
    const timer = setTimeout(() => rejectPort(new Error("mock server did not start")), 5000);
    child.stdout?.once("data", (data: Buffer) => {
      clearTimeout(timer);
      resolvePort(String(data).trim());
    });
  });
  return { url: `http://127.0.0.1:${port}` };
}

function startMock(verdict: unknown): Promise<{ url: string }> {
  return startRawMock({ body: JSON.stringify(verdict) });
}

async function fixtureProject(root: string, manifestExtras: Record<string, unknown> = {}): Promise<string> {
  const project = join(root, "app");
  await mkdir(project, { recursive: true });
  await writeFile(join(project, "package.json"), JSON.stringify({
    name: "fixture",
    version: "1.0.0",
    dependencies: { "left-pad": "1.3.0" },
    ...manifestExtras
  }));
  await writeFile(join(project, "package-lock.json"), JSON.stringify({
    name: "fixture",
    version: "1.0.0",
    lockfileVersion: 3,
    packages: {
      "": { name: "fixture", version: "1.0.0", dependencies: { "left-pad": "1.3.0" } },
      "node_modules/left-pad": { version: "1.3.0" }
    }
  }));
  return project;
}

async function writeConfig(home: string, baseUrl: string): Promise<void> {
  await mkdir(join(home, ".dg"), { recursive: true });
  await writeFile(join(home, ".dg", "config.json"), JSON.stringify({
    version: 1,
    api: { baseUrl },
    org: { id: "" },
    policy: { mode: "block", trustProjectAllowlists: false, allowForceOverride: true, scriptHardening: false },
    telemetry: { enabled: false },
    webhooks: { enabled: false }
  }));
}

async function withHome<T>(home: string, run: () => T | Promise<T>): Promise<T> {
  const previous = process.env.HOME;
  process.env.HOME = home;
  try {
    return await run();
  } finally {
    if (previous === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previous;
    }
  }
}

type JsonScanOutput = ScanReport & { scannerUnavailable: boolean; status: string };

describe("scanner-backed non-TTY scan", () => {
  afterEach(async () => {
    for (const child of children.splice(0)) {
      child.kill();
    }
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
  });

  it("uses the scanner verdict verbatim for --json output and the exit contract", async () => {
    const root = await tempRoot();
    const project = await fixtureProject(root);
    const mock = await startMock({
      score: 64,
      action: "warn",
      packages: [
        {
          name: "left-pad",
          version: "1.3.0",
          score: 64,
          action: "warn",
          findings: [{ severity: 3, category: "lifecycle", title: "install lifecycle script" }],
          reasons: ["install lifecycle script"],
          cached: false
        }
      ],
      safeVersions: {},
      durationMs: 7
    });
    await writeConfig(root, mock.url);

    const result = await withHome(root, () => runCli(["scan", project, "--json"]));
    const report = JSON.parse(result.stdout) as JsonScanOutput;

    expect(report.scanner?.action).toBe("warn");
    expect(report.status).toBe("warn");
    expect(report.findings[0]?.location).toBe("left-pad@1.3.0");
    expect(report.findings[0]?.severity).toBe("warn");
    expect(result.exitCode).toBe(1);
  });

  it("exits 4 with an analysis_incomplete status when the scanner is unreachable", async () => {
    const root = await tempRoot();
    const project = await fixtureProject(root);
    await writeConfig(root, "http://127.0.0.1:9");

    const result = await withHome(root, () => runCli(["scan", project, "--json"]));
    const report = JSON.parse(result.stdout) as JsonScanOutput;

    expect(report.scanner).toBeUndefined();
    expect(report.status).toBe("analysis_incomplete");
    expect(report.scannerError?.kind).toBe("network");
    expect(result.exitCode).toBe(4);
  });

  it("exits 4 on a persistent 5xx and carries the server classification", async () => {
    const root = await tempRoot();
    const project = await fixtureProject(root);
    const mock = await startRawMock({ status: 503, body: JSON.stringify({ error: "scanner overloaded" }) });
    await writeConfig(root, mock.url);

    const result = await withHome(root, () => runCli(["scan", project, "--json"]));
    const report = JSON.parse(result.stdout) as JsonScanOutput;

    expect(result.exitCode).toBe(4);
    expect(report.status).toBe("analysis_incomplete");
    expect(report.scannerError?.kind).toBe("server");
    expect(report.scannerError?.message).toBe("scanner overloaded");
    expect(report.scannerError?.statusCode).toBe(503);
  });

  it("renders quota exhaustion loudly with the server message and counts", async () => {
    const root = await tempRoot();
    const project = await fixtureProject(root);
    const mock = await startRawMock({
      status: 403,
      body: JSON.stringify({ error: "Free scan limit reached", reason: "monthly_limit", scansUsed: 15, maxScans: 15 })
    });
    await writeConfig(root, mock.url);

    const text = await withHome(root, () => runCli(["scan", project]));
    expect(text.exitCode).toBe(4);
    expect(text.stdout).toContain("server scan failed: Free scan limit reached");
    expect(text.stdout).toContain("scans used: 15 of 15");
    expect(text.stdout).not.toContain("No supported project manifests found.");
    expect(text.stdout).not.toContain("server scan unavailable");

    const json = await withHome(root, () => runCli(["scan", project, "--json"]));
    const report = JSON.parse(json.stdout) as JsonScanOutput;
    expect(json.exitCode).toBe(4);
    expect(report.scannerError).toEqual({
      kind: "quota_exceeded",
      message: "Free scan limit reached",
      statusCode: 403,
      scansUsed: 15,
      scansLimit: 15
    });
  });

  it("exits 4 when the scanner answers with an unparseable body", async () => {
    const root = await tempRoot();
    const project = await fixtureProject(root);
    const mock = await startRawMock({ body: "<html>not json</html>", contentType: "text/html" });
    await writeConfig(root, mock.url);

    const result = await withHome(root, () => runCli(["scan", project, "--json"]));
    const report = JSON.parse(result.stdout) as JsonScanOutput;

    expect(result.exitCode).toBe(4);
    expect(report.scannerError?.kind).toBe("invalid_response");
  });

  it("propagates NDJSON error events including quota fields", async () => {
    const root = await tempRoot();
    const project = await fixtureProject(root);
    const events = [
      { type: "progress", done: 1, total: 1 },
      { type: "error", error: "scan quota exhausted", statusCode: 403, scansUsed: 12, maxScans: 15 }
    ];
    const mock = await startRawMock({
      contentType: "application/x-ndjson",
      body: events.map((event) => JSON.stringify(event)).join("\n") + "\n"
    });
    await writeConfig(root, mock.url);

    const result = await withHome(root, () => runCli(["scan", project, "--json"]));
    const report = JSON.parse(result.stdout) as JsonScanOutput;

    expect(result.exitCode).toBe(4);
    expect(report.scannerError).toEqual({
      kind: "quota_exceeded",
      message: "scan quota exhausted",
      statusCode: 403,
      scansUsed: 12,
      scansLimit: 15
    });
  });

  it("keeps local warn and block verdicts authoritative when the scanner fails", async () => {
    const root = await tempRoot();
    const warnProject = await fixtureProject(root, { scripts: { postinstall: "node install.js" } });
    await writeConfig(root, "http://127.0.0.1:9");
    const warned = await withHome(root, () => runCli(["scan", warnProject, "--json"]));
    const warnReport = JSON.parse(warned.stdout) as JsonScanOutput;
    expect(warned.exitCode).toBe(1);
    expect(warnReport.status).toBe("warn");
    expect(warnReport.scannerError?.kind).toBe("network");

    const blockRoot = await tempRoot();
    const blockProject = await fixtureProject(blockRoot, {
      dependencies: { "left-pad": "1.3.0", remote: "https://registry.example.test/remote.tgz" }
    });
    await writeConfig(blockRoot, "http://127.0.0.1:9");
    const blocked = await withHome(blockRoot, () => runCli(["scan", blockProject, "--json"]));
    const blockReport = JSON.parse(blocked.stdout) as JsonScanOutput;
    expect(blocked.exitCode).toBe(2);
    expect(blockReport.status).toBe("block");
    expect(blockReport.scannerError?.kind).toBe("network");
  });

  it("exits 4 with a parse-error message when the lockfile exists but cannot be parsed", async () => {
    const root = await tempRoot();
    const project = join(root, "app");
    await mkdir(project, { recursive: true });
    await writeFile(join(project, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0" }));
    await writeFile(join(project, "package-lock.json"), "{ not json");
    await writeConfig(root, "http://127.0.0.1:9");

    const result = await withHome(root, () => runCli(["scan", project, "--json"]));
    const report = JSON.parse(result.stdout) as JsonScanOutput;

    expect(result.exitCode).toBe(4);
    expect(report.status).toBe("analysis_incomplete");
    expect(report.scannerError?.kind).toBe("lockfile_unparsed");
    expect(report.scannerError?.message).toMatch(/could not parse lockfile: package-lock\.json: .+/);
    expect(report.scannerError?.message).not.toContain("no packages could be parsed");

    const text = await withHome(root, () => runCli(["scan", project]));
    expect(text.stdout).not.toContain("server scan unavailable");
    expect(text.stdout).toContain("server scan failed:");
  });

  it("delivers a >1MB package payload to the worker without hitting argv limits", async () => {
    const root = await tempRoot();
    const project = join(root, "app");
    await mkdir(project, { recursive: true });
    const packages: Record<string, unknown> = {
      "": { name: "fixture", version: "1.0.0" }
    };
    const filler = "a".repeat(60);
    for (let index = 0; index < 16000; index += 1) {
      packages[`node_modules/pkg-${filler}-${index}`] = { version: "1.0.0" };
    }
    await writeFile(join(project, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0" }));
    await writeFile(join(project, "package-lock.json"), JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      lockfileVersion: 3,
      packages
    }));
    const mock = await startMock({ score: 0, action: "pass", packages: [], safeVersions: {}, durationMs: 1 });
    await writeConfig(root, mock.url);

    const result = await withHome(root, () => runCli(["scan", project, "--json"]));
    const report = JSON.parse(result.stdout) as JsonScanOutput;

    expect(result.exitCode).toBe(0);
    expect(report.status).toBe("pass");
    expect(report.summary.dependencyCount).toBe(16000);
  }, 120000);
});

describe("scanWorkerTimeoutMs", () => {
  it("scales the whole-scan cap with the package count", () => {
    expect(scanWorkerTimeoutMs(0)).toBe(180_000);
    expect(scanWorkerTimeoutMs(1)).toBe(180_000 + Math.ceil(660_000 / 64));
    expect(scanWorkerTimeoutMs(640)).toBe(180_000 + 640 * Math.ceil(660_000 / 64));
  });
});

describe("workerFailure", () => {
  it("maps a spawn timeout to a distinct timeout error", () => {
    const failure = workerFailure(
      { error: Object.assign(new Error("spawnSync ETIMEDOUT"), { code: "ETIMEDOUT" }), status: null, stdout: "", stderr: "" },
      241_000,
      200
    );
    expect(failure?.kind).toBe("timeout");
    expect(failure?.message).toContain("241s");
    expect(failure?.message).toContain("200 packages");
  });

  it("prefers the structured scannerError payload from the worker stdout", () => {
    const reported: ScannerError = { kind: "quota_exceeded", message: "limit", statusCode: 403, scansUsed: 1, scansLimit: 2 };
    const failure = workerFailure(
      { status: 1, stdout: JSON.stringify({ scannerError: reported }), stderr: "" },
      180_000,
      1
    );
    expect(failure).toEqual(reported);
  });

  it("falls back to the first stderr line when the worker crashed without a payload", () => {
    const failure = workerFailure(
      { status: 1, stdout: "", stderr: "TypeError: boom\n  at main\n" },
      180_000,
      1
    );
    expect(failure?.kind).toBe("worker");
    expect(failure?.message).toContain("TypeError: boom");
  });

  it("returns null for a clean worker run", () => {
    expect(workerFailure({ status: 0, stdout: "{}", stderr: "" }, 180_000, 1)).toBeNull();
  });
});

describe("buildScannerReport", () => {
  const localReport: ScanReport = {
    target: ".",
    status: "pass",
    projects: [],
    findings: [],
    errors: [],
    summary: { projectCount: 1, dependencyCount: 0, findingCount: 0, warnCount: 0, blockCount: 0, errorCount: 0 }
  };

  it("maps analysis_incomplete to the unknown status, never deriving from score", () => {
    const report = buildScannerReport(localReport, {
      score: 99,
      action: "analysis_incomplete",
      packages: [],
      safeVersions: {},
      durationMs: 1
    }, 3);
    expect(report.status).toBe("unknown");
    expect(report.summary.dependencyCount).toBe(3);
  });
});
