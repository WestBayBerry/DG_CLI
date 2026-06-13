import { describe, expect, it, vi } from "vitest";
import { runCli } from "../../src/runtime/cli.js";
import { doctorReport } from "../../src/setup/plan.js";

vi.mock("../../src/setup/plan.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/setup/plan.js")>();
  return {
    ...actual,
    doctorReportWithRemote: vi.fn(async () => ({
      version: "0.0.0-test",
      checks: [
        { name: "node", status: "pass" as const, message: "Node 22 ok", group: "environment" as const }
      ]
    }))
  };
});

describe("dg doctor command output", () => {
  it("emits schemaVersion 1 and the producer checks verbatim in JSON output", async () => {
    const result = await runCli(["doctor", "--json"]);
    const report = JSON.parse(result.stdout) as { schemaVersion: number; checks: Array<{ name: string }> };

    expect(result.exitCode).toBe(0);
    expect(report.schemaVersion).toBe(1);
    expect(report.checks.map((check) => check.name)).toEqual(["node"]);
  });

  it("renders the report without a telemetry check anywhere", async () => {
    const result = await runCli(["doctor", "--verbose"]);

    expect(result.exitCode).toBe(0);
    expect(result.stdout.toLowerCase()).not.toContain("telemetry");
  });

  it("doctorReport produces no telemetry check", () => {
    const names = doctorReport().checks.map((check) => check.name);
    expect(names).not.toContain("telemetry");
  });
});
