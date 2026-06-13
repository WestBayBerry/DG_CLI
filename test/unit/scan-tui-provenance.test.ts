import React from "react";
import { EventEmitter } from "node:events";
import { render as inkRender } from "ink";
import { describe, expect, it } from "vitest";
import { InteractiveResultsView, provenanceMarker } from "../../src/scan-ui/components/InteractiveResultsView.js";
import type { AnalyzeResponse, ScannerPackageResult, ScannerProvenance } from "../../src/api/analyze.js";
import type { APIPackageResult } from "../../src/scan-ui/api-aliases.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const stripAnsi = (s: string) => s.replace(/\[[0-9;]*m/g, "");

class SizedStdout extends EventEmitter {
  private _lastFrame: string | undefined;
  constructor(public columns: number, public rows: number) {
    super();
  }
  write = (frame: string) => {
    this._lastFrame = frame;
  };
  lastFrame = () => this._lastFrame;
}

class SizedStdin extends EventEmitter {
  isTTY = true;
  private data: string | null = null;
  write = (data: string) => {
    this.data = data;
    this.emit("readable");
    this.emit("data", data);
  };
  setEncoding() {}
  setRawMode() {}
  resume() {}
  pause() {}
  ref() {}
  unref() {}
  read = () => {
    const d = this.data;
    this.data = null;
    return d;
  };
}

function renderSized(tree: React.ReactElement, columns = 110, rows = 40) {
  const stdout = new SizedStdout(columns, rows);
  const stdin = new SizedStdin();
  const instance = inkRender(tree, {
    stdout: stdout as unknown as NodeJS.WriteStream,
    stdin: stdin as unknown as NodeJS.ReadStream,
    debug: true,
    exitOnCtrlC: false,
    patchConsole: false
  });
  return { stdout, stdin, lastFrame: stdout.lastFrame, unmount: instance.unmount };
}

function pkg(
  name: string,
  version: string,
  action: ScannerPackageResult["action"],
  provenance?: ScannerProvenance
): ScannerPackageResult {
  return {
    name,
    version,
    score: action === "block" ? 91 : action === "warn" ? 64 : 0,
    action,
    findings: action === "pass" ? [] : [{ severity: 3, category: "lifecycle", title: "install lifecycle script" }],
    reasons: action === "pass" ? [] : ["install lifecycle script"],
    cached: false,
    license: { spdx: "MIT", raw: "MIT", riskCategory: "permissive", label: "MIT" },
    ...(provenance ? { provenance } : {})
  };
}

function response(packages: ScannerPackageResult[]): AnalyzeResponse {
  const action = packages.some((p) => p.action === "block") ? "block" : packages.some((p) => p.action === "warn") ? "warn" : "pass";
  return {
    score: Math.max(0, ...packages.map((p) => p.score)),
    action,
    packages,
    safeVersions: {},
    durationMs: 1200
  };
}

function renderResults(packages: ScannerPackageResult[]) {
  return renderSized(
    React.createElement(InteractiveResultsView, {
      result: response(packages),
      config: {} as never,
      durationMs: 1200,
      onExit: () => undefined
    })
  );
}

const DOWNGRADED: ScannerProvenance = { status: "none", downgrade: { fromVersion: "1.2.0" } };
const ATTESTED: ScannerProvenance = { status: "attested", predicateType: "https://slsa.dev/provenance/v1" };

describe("provenanceMarker", () => {
  const base = pkg("left-pad", "1.3.0", "warn");
  it("marks a downgraded package and an attested package distinctly", () => {
    expect(stripAnsi(provenanceMarker({ ...base, provenance: DOWNGRADED } as APIPackageResult))).toBe("◇ ");
    expect(stripAnsi(provenanceMarker({ ...base, provenance: ATTESTED } as APIPackageResult))).toBe("◆ ");
  });
  it("stays blank for unknown or absent provenance", () => {
    expect(stripAnsi(provenanceMarker(base as APIPackageResult))).toBe("  ");
    expect(stripAnsi(provenanceMarker({ ...base, provenance: { status: "unknown" } } as APIPackageResult))).toBe("  ");
  });
});

describe("InteractiveResultsView provenance", () => {
  it("shows the downgrade marker on the package row", async () => {
    const view = renderResults([pkg("left-pad", "1.3.0", "warn", DOWNGRADED), pkg("lodash", "4.17.21", "pass")]);
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    expect(frame).toContain("left-pad@1.3.0");
    expect(frame).toContain("◇");
    view.unmount();
  });

  it("shows the attested marker on the package row", async () => {
    const view = renderResults([pkg("old-lib", "0.2.0", "block", ATTESTED)]);
    await sleep(30);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("◆");
    view.unmount();
  });

  it("renders the downgrade alarm in the expanded summary", async () => {
    const view = renderResults([pkg("left-pad", "1.3.0", "warn", DOWNGRADED)]);
    await sleep(30);
    view.stdin.write("\r");
    await sleep(120);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("provenance downgraded — 1.2.0 was attested, 1.3.0 is not");
    view.unmount();
  });

  it("renders the provenance line and downgrade alarm in the detail pane", async () => {
    const view = renderResults([pkg("left-pad", "1.3.0", "warn", DOWNGRADED)]);
    await sleep(30);
    view.stdin.write("\r");
    await sleep(120);
    view.stdin.write("\r");
    await sleep(60);
    const frame = stripAnsi(view.lastFrame() ?? "");
    expect(frame).toContain("Provenance: none");
    expect(frame).toContain("provenance downgraded — 1.2.0 was attested, 1.3.0 is not");
    view.unmount();
  });

  it("labels an attested package in the detail pane with the slsa tag", async () => {
    const view = renderResults([pkg("old-lib", "0.2.0", "block", ATTESTED)]);
    await sleep(30);
    view.stdin.write("\r");
    await sleep(120);
    view.stdin.write("\r");
    await sleep(60);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("Provenance: attested (slsa v1)");
    view.unmount();
  });

  it("omits the provenance line when the server sent no provenance field", async () => {
    const view = renderResults([pkg("left-pad", "1.3.0", "warn")]);
    await sleep(30);
    view.stdin.write("\r");
    await sleep(120);
    view.stdin.write("\r");
    await sleep(60);
    expect(stripAnsi(view.lastFrame() ?? "")).not.toContain("Provenance:");
    view.unmount();
  });
});
