import React from "react";
import { Text } from "ink";
import { render } from "ink-testing-library";
import { afterEach, describe, expect, it, vi } from "vitest";

const hoisted = vi.hoisted(() => ({
  analyzePackages: vi.fn(),
  collectScanPackages: vi.fn(),
  discoverScanProjectsAsync: vi.fn()
}));

vi.mock("../../src/api/analyze.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/api/analyze.js")>();
  return { ...actual, analyzePackages: hoisted.analyzePackages };
});

vi.mock("../../src/scan/collect.js", () => ({
  collectScanPackages: hoisted.collectScanPackages,
  discoverScanProjectsAsync: hoisted.discoverScanProjectsAsync
}));

import { AnalyzeError, type AnalyzeResponse } from "../../src/api/analyze.js";
import { useScan } from "../../src/scan-ui/hooks/useScan.js";
import type { FoundProject } from "../../src/scan-ui/shims.js";

const CONFIG = { mode: "warn" as const };

const project: FoundProject = {
  path: "/tmp/app",
  relativePath: ".",
  ecosystem: "npm",
  depFile: "package-lock.json",
  packageCount: 2
};

function passResponse(names: readonly string[]): AnalyzeResponse {
  return {
    score: 0,
    action: "pass",
    packages: names.map((name) => ({
      name,
      version: "1.0.0",
      score: 0,
      action: "pass" as const,
      findings: [],
      reasons: [],
      cached: true
    })),
    safeVersions: {},
    durationMs: 5
  };
}

function Probe(): React.ReactElement {
  const { state } = useScan(CONFIG);
  if (state.phase === "results") {
    return React.createElement(Text, null, `results:${state.result.packages.length}:${state.result.action}`);
  }
  if (state.phase === "free_cap_reached") {
    return React.createElement(Text, null, `free_cap:${state.scansUsed}/${state.maxScans}:${state.capReason}`);
  }
  if (state.phase === "error") {
    return React.createElement(Text, null, `error:${state.error.message}`);
  }
  if (state.phase === "scanning") {
    return React.createElement(Text, null, `scanning:${state.done}/${state.total}:b${state.batchIndex}/${state.batchCount}`);
  }
  return React.createElement(Text, null, state.phase);
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(predicate: () => boolean, timeoutMs = 3000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error("condition not met in time");
    }
    await sleep(15);
  }
}

function setupDiscovery(byEcosystem: Map<"npm" | "pypi", Array<{ name: string; version: string }>>): void {
  hoisted.discoverScanProjectsAsync.mockResolvedValue([project]);
  hoisted.collectScanPackages.mockReturnValue({ byEcosystem, skipped: 0 });
}

describe("useScan", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("keeps the first ecosystem results when the second ecosystem request fails", async () => {
    setupDiscovery(new Map([
      ["npm", [{ name: "a", version: "1.0.0" }]],
      ["pypi", [{ name: "b", version: "1.0.0" }]]
    ]));
    hoisted.analyzePackages
      .mockResolvedValueOnce(passResponse(["a"]))
      .mockRejectedValueOnce(new AnalyzeError("scanner overloaded", 503));

    const ui = render(React.createElement(Probe));
    await waitFor(() => (ui.lastFrame() ?? "").startsWith("results:"));

    expect(ui.lastFrame()).toBe("results:1:analysis_incomplete");
    expect(hoisted.analyzePackages).toHaveBeenCalledTimes(2);
    ui.unmount();
  });

  it("keeps the second ecosystem results when the first ecosystem request fails", async () => {
    setupDiscovery(new Map([
      ["npm", [{ name: "a", version: "1.0.0" }]],
      ["pypi", [{ name: "b", version: "1.0.0" }]]
    ]));
    hoisted.analyzePackages
      .mockRejectedValueOnce(new AnalyzeError("scanner overloaded", 503))
      .mockResolvedValueOnce(passResponse(["b"]));

    const ui = render(React.createElement(Probe));
    await waitFor(() => (ui.lastFrame() ?? "").startsWith("results:"));

    expect(ui.lastFrame()).toBe("results:1:analysis_incomplete");
    ui.unmount();
  });

  it("starts every ecosystem request in parallel and aggregates progress across them", async () => {
    setupDiscovery(new Map([
      ["npm", [{ name: "a", version: "1.0.0" }, { name: "b", version: "1.0.0" }]],
      ["pypi", [{ name: "c", version: "1.0.0" }]]
    ]));
    type Handle = {
      onProgress: (progress: { done: number; total: number; batchIndex: number; batchCount: number }) => void;
      resolve: (response: AnalyzeResponse) => void;
    };
    const handles = new Map<string, Handle>();
    hoisted.analyzePackages.mockImplementation(
      (_packages: unknown, options: { ecosystem: string; onProgress: Handle["onProgress"] }) =>
        new Promise<AnalyzeResponse>((resolve) => {
          handles.set(options.ecosystem, { onProgress: options.onProgress, resolve });
        })
    );

    const ui = render(React.createElement(Probe));
    await waitFor(() => handles.size === 2);
    expect([...handles.keys()].sort()).toEqual(["npm", "pypi"]);

    const npm = handles.get("npm");
    const pypi = handles.get("pypi");
    if (!npm || !pypi) throw new Error("missing ecosystem handle");

    npm.onProgress({ done: 1, total: 2, batchIndex: 0, batchCount: 1 });
    pypi.onProgress({ done: 1, total: 1, batchIndex: 1, batchCount: 1 });
    await waitFor(() => ui.lastFrame() === "scanning:2/3:b1/2");
    expect(ui.lastFrame()).toBe("scanning:2/3:b1/2");

    npm.resolve(passResponse(["a", "b"]));
    pypi.resolve(passResponse(["c"]));
    await waitFor(() => (ui.lastFrame() ?? "").startsWith("results:"));
    expect(ui.lastFrame()).toBe("results:3:pass");
    ui.unmount();
  });

  it("maps a 403 quota body to the free-cap panel with real numbers", async () => {
    setupDiscovery(new Map([["npm", [{ name: "a", version: "1.0.0" }]]]));
    hoisted.analyzePackages.mockRejectedValueOnce(
      new AnalyzeError("Free scan limit reached", 403, { error: "Free scan limit reached", reason: "monthly_limit", scansUsed: 15, maxScans: 15 })
    );

    const ui = render(React.createElement(Probe));
    await waitFor(() => (ui.lastFrame() ?? "").startsWith("free_cap:"));

    expect(ui.lastFrame()).toBe("free_cap:15/15:monthly_limit");
    ui.unmount();
  });

  it("renders a bare 429 as an error, not a zero-count cap panel", async () => {
    setupDiscovery(new Map([["npm", [{ name: "a", version: "1.0.0" }]]]));
    hoisted.analyzePackages.mockRejectedValueOnce(
      new AnalyzeError("scanner rate limit reached — wait a moment and retry", 429, {})
    );

    const ui = render(React.createElement(Probe));
    await waitFor(() => (ui.lastFrame() ?? "").startsWith("error:"));

    expect(ui.lastFrame()).toBe("error:scanner rate limit reached — wait a moment and retry");
    ui.unmount();
  });

  it("aborts the in-flight analyze request on unmount", async () => {
    setupDiscovery(new Map([["npm", [{ name: "a", version: "1.0.0" }]]]));
    let capturedSignal: AbortSignal | undefined;
    hoisted.analyzePackages.mockImplementationOnce((_packages: unknown, options: { signal?: AbortSignal }) => {
      capturedSignal = options.signal;
      return new Promise(() => undefined);
    });

    const ui = render(React.createElement(Probe));
    await waitFor(() => capturedSignal !== undefined);

    expect(capturedSignal?.aborted).toBe(false);
    ui.unmount();
    await waitFor(() => capturedSignal?.aborted === true);
    expect(capturedSignal?.aborted).toBe(true);
  });
});
