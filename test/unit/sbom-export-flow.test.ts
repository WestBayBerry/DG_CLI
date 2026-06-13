import React from "react";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { render } from "ink-testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildSbomRows, mergeVerdicts, type SbomRow } from "../../src/sbom-ui/inventory.js";
import { createSbomStore } from "../../src/sbom-ui/store.js";
import { SbomApp } from "../../src/sbom-ui/SbomApp.js";
import type { ScannerPackageResult } from "../../src/api/analyze.js";
import type { SbomComponent } from "../../src/sbom/cyclonedx.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const stripAnsi = (s: string) => s.replace(/\[[0-9;]*m/g, "");

function comp(over: Partial<SbomComponent>): SbomComponent {
  return {
    ecosystem: "npm",
    name: "left-pad",
    version: "1.3.0",
    requested: "left-pad",
    sourceKind: "lockfile",
    resolvedUrl: null,
    integrity: null,
    license: null,
    ...over
  } as SbomComponent;
}

function pkg(over: Partial<ScannerPackageResult>): ScannerPackageResult {
  return { name: "left-pad", version: "1.3.0", score: 0, findings: [], reasons: [], cached: false, ...over };
}

function rowsFixture(): readonly SbomRow[] {
  return mergeVerdicts(
    buildSbomRows([
      comp({ name: "alpha", ecosystem: "npm", version: "1.0.0", license: "MIT", integrity: "sha512-x" }),
      comp({ name: "beta", ecosystem: "npm", version: "2.0.0" })
    ]),
    "npm",
    [pkg({ name: "alpha", version: "1.0.0", action: "pass" })]
  );
}

describe("SbomApp export wiring end to end", () => {
  let workdir: string;
  let prevToken: string | undefined;
  let previousExitCode: typeof process.exitCode;

  beforeEach(() => {
    prevToken = process.env.DG_API_TOKEN;
    process.env.DG_API_TOKEN = "test-token-abcdef";
    previousExitCode = process.exitCode;
    workdir = mkdtempSync(join(tmpdir(), "dg-sbom-work-"));
  });

  afterEach(() => {
    if (prevToken === undefined) delete process.env.DG_API_TOKEN;
    else process.env.DG_API_TOKEN = prevToken;
    process.exitCode = previousExitCode;
    rmSync(workdir, { recursive: true, force: true });
  });

  function appInDir() {
    const store = createSbomStore({
      phase: "done",
      rows: rowsFixture(),
      subject: "demo",
      dropped: [],
      scannable: 2,
      scanProgress: 2,
      scanError: null,
      usage: null
    });
    return render(React.createElement(SbomApp, { store, document: "{\"bomFormat\":\"CycloneDX\"}", cwd: workdir }));
  }

  it("e -> Components CSV -> This folder writes the CSV into the working dir", async () => {
    const view = appInDir();
    await sleep(30);

    view.stdin.write("e");
    await sleep(30);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("Components CSV");

    view.stdin.write("j");
    await sleep(30);
    view.stdin.write("\r");
    await sleep(30);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("This folder");

    view.stdin.write("\r");
    await sleep(60);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    const body = readFileSync(join(workdir, "sbom-components.csv"), "utf8");
    expect(body.split("\n")[0]).toBe("name,version,ecosystem,license,verdict");
    expect(body).toContain("alpha,1.0.0,npm,MIT,pass");
    expect(frame).toContain("exported");
  });

  it("e -> CycloneDX JSON -> This folder writes sbom.cdx.json to cwd", async () => {
    const view = appInDir();
    await sleep(30);

    view.stdin.write("e");
    await sleep(30);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("CycloneDX JSON");

    view.stdin.write("\r");
    await sleep(30);
    view.stdin.write("\r");
    await sleep(60);
    view.unmount();

    expect(readdirSync(workdir)).toEqual(["sbom.cdx.json"]);
    expect(readFileSync(join(workdir, "sbom.cdx.json"), "utf8")).toBe("{\"bomFormat\":\"CycloneDX\"}");
  });
});
