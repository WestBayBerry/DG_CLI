import React from "react";
import { render } from "ink-testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AnalyzeResponse, ScannerAction } from "../../src/api/analyze.js";
import type { FoundProject, ScanMode } from "../../src/scan-ui/shims.js";
import type { ScanState } from "../../src/scan-ui/hooks/useScan.js";

const hoisted = vi.hoisted(() => ({
  state: { phase: "discovering" } as unknown
}));

vi.mock("../../src/scan-ui/hooks/useScan.js", () => ({
  useScan: () => ({
    state: hoisted.state,
    scanSelectedProjects: () => undefined,
    restartSelection: null
  })
}));

import { App } from "../../src/scan-ui/LegacyApp.js";

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function resultFixture(action: ScannerAction): AnalyzeResponse {
  return {
    score: action === "pass" ? 0 : 80,
    action,
    packages: [
      {
        name: "left-pad",
        version: "1.3.0",
        score: action === "pass" ? 0 : 80,
        action,
        findings: [],
        reasons: [],
        cached: false
      }
    ],
    safeVersions: {},
    durationMs: 100
  };
}

function setState(state: ScanState): void {
  hoisted.state = state;
}

const selectingState: ScanState = {
  phase: "selecting",
  projects: [
    {
      path: "/tmp/app",
      relativePath: "app",
      ecosystem: "npm",
      depFile: "package-lock.json",
      packageCount: 3
    } satisfies FoundProject
  ]
};

describe("App exit codes by policy mode and verdict", () => {
  let previousExitCode: number | string | undefined;

  beforeEach(() => {
    previousExitCode = process.exitCode;
  });

  afterEach(() => {
    process.exitCode = previousExitCode;
  });

  const matrix: ReadonlyArray<readonly [ScanMode, ScannerAction, number]> = [
    ["off", "pass", 0],
    ["off", "warn", 1],
    ["off", "block", 2],
    ["off", "analysis_incomplete", 4],
    ["warn", "pass", 0],
    ["warn", "warn", 1],
    ["warn", "block", 2],
    ["warn", "analysis_incomplete", 4],
    ["block", "pass", 0],
    ["block", "warn", 1],
    ["block", "block", 2],
    ["block", "analysis_incomplete", 4],
    ["strict", "pass", 0],
    ["strict", "warn", 2],
    ["strict", "block", 2],
    ["strict", "analysis_incomplete", 4]
  ];

  for (const [mode, action, expected] of matrix) {
    it(`exits ${expected} for ${action} under policy.mode=${mode}`, async () => {
      setState({ phase: "results", result: resultFixture(action), durationMs: 100, skippedCount: 0 });
      process.exitCode = undefined;

      const view = render(React.createElement(App, { config: { mode } }));
      await sleep(30);
      view.unmount();

      expect(process.exitCode).toBe(expected);
    });
  }
});

describe("App update line", () => {
  const updateLine = "Update available: 2.0.9 → 99.0.0 · run dg update";

  it("shows the update line under the project selector", async () => {
    setState(selectingState);
    const view = render(React.createElement(App, { config: { mode: "warn" }, updateAvailable: updateLine }));
    await sleep(30);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(frame).toContain("Found 1 project");
    expect(frame).toContain(updateLine);
  });

  it("shows the update line during the scanning phase", async () => {
    setState({ phase: "scanning", done: 1, total: 4, batchIndex: 0, batchCount: 1 });
    const view = render(React.createElement(App, { config: { mode: "warn" }, updateAvailable: updateLine }));
    await sleep(30);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(frame).toContain(updateLine);
  });

  it("omits the update line on the full-height results view and without update state", async () => {
    setState({ phase: "results", result: resultFixture("pass"), durationMs: 100, skippedCount: 0 });
    const previousExitCode = process.exitCode;
    const withUpdate = render(React.createElement(App, { config: { mode: "warn" }, updateAvailable: updateLine }));
    await sleep(30);
    const resultsFrame = withUpdate.lastFrame() ?? "";
    withUpdate.unmount();
    process.exitCode = previousExitCode;

    expect(resultsFrame).toContain("Dependency Guardian");
    expect(resultsFrame).not.toContain(updateLine);

    setState(selectingState);
    const withoutUpdate = render(React.createElement(App, { config: { mode: "warn" } }));
    await sleep(30);
    const selectorFrame = withoutUpdate.lastFrame() ?? "";
    withoutUpdate.unmount();

    expect(selectorFrame).toContain("Found 1 project");
    expect(selectorFrame).not.toContain("Update available");
  });
});
