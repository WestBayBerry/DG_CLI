import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../../src/runtime/cli.js";
import type { ScanReport } from "../../src/scan/types.js";

const tempRoots: string[] = [];
const children: ChildProcess[] = [];

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-decisions-scan-"));
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
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(config.body);
  });
});
server.listen(0, "127.0.0.1", () => {
  console.log(String(server.address().port));
});
`;

async function startMock(verdict: unknown): Promise<{ url: string }> {
  const child = spawn(process.execPath, ["-e", SERVER_SCRIPT, JSON.stringify({ body: JSON.stringify(verdict) })], {
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

function warnVerdict(findings: ReadonlyArray<{ severity: number; category: string }>, action = "warn"): unknown {
  return {
    score: 64,
    action,
    packages: [
      {
        name: "left-pad",
        version: "1.3.0",
        score: 64,
        action,
        findings,
        reasons: ["install lifecycle script"],
        cached: false
      }
    ],
    safeVersions: {},
    durationMs: 7
  };
}

async function fixtureRepo(root: string): Promise<string> {
  spawnSync("git", ["init", "-q"], { cwd: root, encoding: "utf8", env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" } });
  const project = join(root, "app");
  await mkdir(project, { recursive: true });
  await writeFile(join(project, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0", dependencies: { "left-pad": "1.3.0" } }));
  await writeFile(
    join(project, "package-lock.json"),
    JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      lockfileVersion: 3,
      packages: {
        "": { name: "fixture", version: "1.0.0", dependencies: { "left-pad": "1.3.0" } },
        "node_modules/left-pad": { version: "1.3.0" }
      }
    })
  );
  return project;
}

async function writeAcceptance(root: string, findings: Record<string, number>): Promise<void> {
  await writeFile(
    join(root, "dg.json"),
    JSON.stringify({
      version: 1,
      decisions: [
        {
          id: "11112222-3333-4444-5555-666677778888",
          ecosystem: "npm",
          name: "left-pad",
          scope: { kind: "exact", version: "1.3.0" },
          findings,
          reason: "vetted by the team",
          acceptedBy: "alice@example.com",
          acceptedAt: "2026-06-01T00:00:00.000Z"
        }
      ]
    })
  );
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

type JsonScanOutput = ScanReport & { status: string };

describe("dg scan with decision memory", () => {
  afterEach(async () => {
    for (const child of children.splice(0)) {
      child.kill();
    }
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
  });

  it("suppresses an acknowledged warn from display and exit code but keeps full JSON data", async () => {
    const root = await tempRoot();
    const project = await fixtureRepo(root);
    await writeAcceptance(root, { lifecycle: 3 });
    const mock = await startMock(warnVerdict([{ severity: 3, category: "lifecycle" }]));
    await writeConfig(root, mock.url);

    const json = await withHome(root, () => runCli(["scan", project, "--json"]));
    expect(json.exitCode).toBe(0);
    const report = JSON.parse(json.stdout) as JsonScanOutput;
    expect(report.status).toBe("warn");
    expect(report.scanner?.action).toBe("warn");
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.acknowledged?.by).toBe("alice@example.com");
    expect(report.decisions?.acknowledgedCount).toBe(1);
    expect(report.decisions?.effectiveAction).toBe("pass");

    const text = await withHome(root, () => runCli(["scan", project]));
    expect(text.exitCode).toBe(0);
    expect(text.stdout).toContain("Status: pass");
    expect(text.stdout).toContain("Acknowledged: 1 warn verdict accepted in dg.json");
    expect(text.stdout).toContain("dg decisions");
  });

  it("--no-decisions ignores the store and restores the warn exit code", async () => {
    const root = await tempRoot();
    const project = await fixtureRepo(root);
    await writeAcceptance(root, { lifecycle: 3 });
    const mock = await startMock(warnVerdict([{ severity: 3, category: "lifecycle" }]));
    await writeConfig(root, mock.url);

    const result = await withHome(root, () => runCli(["scan", project, "--json", "--no-decisions"]));
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as JsonScanOutput;
    expect(report.decisions).toBeUndefined();
    expect(report.findings[0]?.acknowledged).toBeUndefined();
  });

  it("emits SARIF suppressions for acknowledged findings without dropping rows", async () => {
    const root = await tempRoot();
    const project = await fixtureRepo(root);
    await writeAcceptance(root, { lifecycle: 3 });
    const mock = await startMock(warnVerdict([{ severity: 3, category: "lifecycle" }]));
    await writeConfig(root, mock.url);

    const result = await withHome(root, () => runCli(["scan", project, "--sarif"]));
    expect(result.exitCode).toBe(0);
    const sarif = JSON.parse(result.stdout) as {
      runs: Array<{ results: Array<{ ruleId: string; suppressions?: Array<{ kind: string; justification: string }> }> }>;
    };
    const results = sarif.runs[0]?.results ?? [];
    expect(results).toHaveLength(1);
    expect(results[0]?.suppressions).toEqual([{ kind: "external", justification: "vetted by the team" }]);
  });

  it("a new finding category re-surfaces the warn", async () => {
    const root = await tempRoot();
    const project = await fixtureRepo(root);
    await writeAcceptance(root, { lifecycle: 3 });
    const mock = await startMock(
      warnVerdict([
        { severity: 3, category: "lifecycle" },
        { severity: 4, category: "network_exfil" }
      ])
    );
    await writeConfig(root, mock.url);

    const result = await withHome(root, () => runCli(["scan", project, "--json"]));
    expect(result.exitCode).toBe(1);
    const report = JSON.parse(result.stdout) as JsonScanOutput;
    expect(report.decisions?.acknowledgedCount).toBe(0);
    expect(report.decisions?.packages["left-pad@1.3.0"]?.newFindings).toEqual(["network_exfil:4"]);
  });

  it("a warn-to-block escalation is never suppressed", async () => {
    const root = await tempRoot();
    const project = await fixtureRepo(root);
    await writeAcceptance(root, { lifecycle: 5, malware: 5 });
    const mock = await startMock(warnVerdict([{ severity: 5, category: "malware" }], "block"));
    await writeConfig(root, mock.url);

    const result = await withHome(root, () => runCli(["scan", project, "--json"]));
    expect(result.exitCode).toBe(2);
    const report = JSON.parse(result.stdout) as JsonScanOutput;
    expect(report.decisions?.acknowledgedCount).toBe(0);
    expect(report.decisions?.effectiveAction).toBe("block");
  });
});
