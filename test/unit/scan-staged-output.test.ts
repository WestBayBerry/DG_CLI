import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runScanCommand } from "../../src/scan/command.js";
import type { ScanReport } from "../../src/scan/types.js";
import type { AnalyzeResponse } from "../../src/api/analyze.js";

const mocks = vi.hoisted(() => ({ stagedScanReport: vi.fn() }));

vi.mock("../../src/scan/staged.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/scan/staged.js")>()),
  stagedScanReport: mocks.stagedScanReport
}));

function emptyReport(target: string): ScanReport {
  return {
    target,
    status: "pass",
    projects: [],
    findings: [],
    errors: [],
    summary: { projectCount: 0, dependencyCount: 0, findingCount: 0, warnCount: 0, blockCount: 0, errorCount: 0 }
  };
}

function blockReport(target: string): ScanReport {
  return {
    ...emptyReport(target),
    status: "block",
    findings: [
      {
        id: "scanner-finding",
        severity: "block",
        title: "credential exfiltration",
        message: "credential exfiltration",
        project: "",
        location: "evil@1.0.0"
      }
    ],
    summary: { projectCount: 0, dependencyCount: 1, findingCount: 1, warnCount: 0, blockCount: 1, errorCount: 0 },
    scanner: { action: "block" } as unknown as AnalyzeResponse
  };
}

describe("dg scan --staged machine output", () => {
  let home: string;
  let savedHome: string | undefined;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "dg-staged-out-"));
    savedHome = process.env.HOME;
    process.env.HOME = home;
    mocks.stagedScanReport.mockReset();
  });

  afterEach(async () => {
    if (savedHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = savedHome;
    }
    await rm(home, { recursive: true, force: true });
  });

  it("renders the staged scanner verdict as JSON with the scan exit code", () => {
    mocks.stagedScanReport.mockReturnValue({
      report: emptyReport("/repo"),
      outcome: { kind: "report", report: blockReport("/repo") }
    });

    const result = runScanCommand({ commandPath: ["scan"], args: ["--staged", "--json"] });

    expect(mocks.stagedScanReport).toHaveBeenCalledWith({ targetPath: null, useDecisions: true });
    expect(result.exitCode).toBe(2);
    const json = JSON.parse(result.stdout) as { status: string; findings: Array<{ location: string }> };
    expect(json.status).toBe("block");
    expect(json.findings[0]?.location).toBe("evil@1.0.0");
  });

  it("passes an explicit path argument through to the staged scope", () => {
    mocks.stagedScanReport.mockReturnValue({
      report: emptyReport("/repo"),
      outcome: { kind: "skipped", reason: "no_lockfiles" }
    });

    const result = runScanCommand({ commandPath: ["scan"], args: ["--staged", "--json", "packages/api"] });

    expect(mocks.stagedScanReport).toHaveBeenCalledWith({ targetPath: "packages/api", useDecisions: true });
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({ status: "pass", scannerUnavailable: false });
  });

  it("writes the staged report with --output and keeps the verdict exit code", async () => {
    mocks.stagedScanReport.mockReturnValue({
      report: emptyReport("/repo"),
      outcome: { kind: "report", report: blockReport("/repo") }
    });
    const outputPath = join(home, "staged-report.json");

    const result = runScanCommand({ commandPath: ["scan"], args: ["--staged", "--json", "--output", outputPath] });

    expect(result.exitCode).toBe(2);
    expect(result.stdout).toBe(`Wrote json scan report to ${outputPath}\n`);
    const exported = JSON.parse(await readFile(outputPath, "utf8")) as { status: string };
    expect(exported.status).toBe("block");
  });

  it("renders SARIF for staged scans", () => {
    mocks.stagedScanReport.mockReturnValue({
      report: emptyReport("/repo"),
      outcome: { kind: "report", report: blockReport("/repo") }
    });

    const result = runScanCommand({ commandPath: ["scan"], args: ["--staged", "--sarif"] });

    expect(result.exitCode).toBe(2);
    const sarif = JSON.parse(result.stdout) as { version: string; runs: Array<{ tool: { driver: { name: string } } }> };
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]?.tool.driver.name).toBe("Dependency Guardian");
  });

  it("maps a staged scanner failure to analysis_incomplete and exit 4", () => {
    mocks.stagedScanReport.mockReturnValue({
      report: emptyReport("/repo"),
      outcome: { kind: "failed", error: { kind: "worker", message: "could not read staged changes" } }
    });

    const result = runScanCommand({ commandPath: ["scan"], args: ["--staged", "--json"] });

    expect(result.exitCode).toBe(4);
    const json = JSON.parse(result.stdout) as { status: string; scannerError: { message: string } };
    expect(json.status).toBe("analysis_incomplete");
    expect(json.scannerError.message).toBe("could not read staged changes");
  });

  it("returns staged usage results unchanged", () => {
    mocks.stagedScanReport.mockReturnValue({
      result: { exitCode: 64, stdout: "", stderr: "dg scan --staged: not a git repository.\n" }
    });

    const result = runScanCommand({ commandPath: ["scan"], args: ["--staged", "--json"] });

    expect(result.exitCode).toBe(64);
    expect(result.stderr).toContain("not a git repository");
  });
});
