import React from "react";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { render } from "ink-testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildSbomRows,
  componentsCsv,
  componentsMarkdown,
  emptyFilterMessage,
  filterRows,
  mergeVerdicts,
  rowKey,
  tallyVerdicts,
  verdictFromResult,
  type SbomRow
} from "../../src/sbom-ui/inventory.js";
import { createSbomStore, type SbomView } from "../../src/sbom-ui/store.js";
import { SbomApp } from "../../src/sbom-ui/SbomApp.js";
import { SbomHeader } from "../../src/sbom-ui/components/SbomHeader.js";
import { SbomList } from "../../src/sbom-ui/components/SbomList.js";
import type { ScannerPackageResult } from "../../src/api/analyze.js";
import type { SbomComponent } from "../../src/sbom/cyclonedx.js";

vi.mock("../../src/api/analyze.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/api/analyze.js")>();
  return { ...actual, analyzePackages: vi.fn() };
});

const { analyzePackages, AnalyzeError } = await import("../../src/api/analyze.js");
const { runSbomScan } = await import("../../src/sbom-ui/run.js");
const analyzeMock = vi.mocked(analyzePackages);

afterEach(() => {
  analyzeMock.mockReset();
});

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

function viewWith(rows: readonly SbomRow[]): SbomView {
  return {
    phase: "inventory",
    rows,
    subject: "demo",
    dropped: [],
    scannable: rows.filter((r) => r.scannable).length,
    scanProgress: 0,
    scanError: null,
    usage: null
  };
}

describe("buildSbomRows", () => {
  it("maps ecosystem, license, hash presence, and scannability, sorted by name", () => {
    const rows = buildSbomRows([
      comp({ name: "zed", ecosystem: "cargo", version: "1.0.0", integrity: "sha256:ab" }),
      comp({ name: "acme", ecosystem: "npm", version: "2.0.0", license: "MIT", integrity: "sha512-x" })
    ]);
    expect(rows.map((r) => r.name)).toEqual(["acme", "zed"]);
    expect(rows[0]).toMatchObject({ ecosystem: "npm", license: "MIT", hasHash: true, scannable: true });
    expect(rows[1]).toMatchObject({ ecosystem: "cargo", license: null, hasHash: true, scannable: false });
  });

  it("treats an unknown ecosystem as other and not scannable", () => {
    const rows = buildSbomRows([comp({ ecosystem: "unknown", name: "x", version: "1.0.0" })]);
    expect(rows[0]?.ecosystem).toBe("other");
    expect(rows[0]?.scannable).toBe(false);
  });
});

describe("verdictFromResult", () => {
  it("prefers provenance-downgrade and cooldown reasons over generic ones", () => {
    expect(verdictFromResult(pkg({ action: "warn", provenance: { status: "none", downgrade: { fromVersion: "0.7.28" } } })))
      .toMatchObject({ action: "warn", reason: "provenance downgraded", provenanceFrom: "0.7.28" });
    expect(verdictFromResult(pkg({ action: "warn", cooldown: { status: "quarantine", ageDays: 2 } })))
      .toMatchObject({ action: "warn", reason: "in cooldown", cooldownAgeDays: 2 });
  });

  it("falls back to the first scanner reason, then a default by action", () => {
    expect(verdictFromResult(pkg({ action: "block", reasons: ["known malware"] }))?.reason).toBe("known malware");
    expect(verdictFromResult(pkg({ action: "pass" }))?.reason).toBe("clean");
    expect(verdictFromResult(pkg({}))).toBeUndefined();
  });
});

describe("mergeVerdicts", () => {
  it("attaches verdicts by ecosystem+name+version, case-insensitively, leaving others untouched", () => {
    const rows = buildSbomRows([
      comp({ name: "React", ecosystem: "npm", version: "18.0.0" }),
      comp({ name: "lodash", ecosystem: "npm", version: "4.17.21" })
    ]);
    const merged = mergeVerdicts(rows, "npm", [pkg({ name: "react", version: "18.0.0", action: "block", reasons: ["malware"] })]);
    expect(merged.find((r) => r.name === "React")?.verdict).toMatchObject({ action: "block" });
    expect(merged.find((r) => r.name === "lodash")?.verdict).toBeUndefined();
  });

  it("returns the original rows when no result carries an action", () => {
    const rows = buildSbomRows([comp({ name: "a", version: "1.0.0" })]);
    expect(mergeVerdicts(rows, "npm", [pkg({ name: "a", version: "1.0.0" })])).toBe(rows);
  });
});

describe("filterRows", () => {
  const rows = mergeVerdicts(
    buildSbomRows([
      comp({ name: "bad", ecosystem: "npm", version: "1.0.0", license: "MIT" }),
      comp({ name: "warned", ecosystem: "npm", version: "1.0.0", license: "MIT" }),
      comp({ name: "nolicense", ecosystem: "npm", version: "1.0.0" })
    ]),
    "npm",
    [pkg({ name: "bad", version: "1.0.0", action: "block" }), pkg({ name: "warned", version: "1.0.0", action: "warn" })]
  );

  it("risky shows only block/warn, block first", () => {
    expect(filterRows(rows, "risky", "").map((r) => r.name)).toEqual(["bad", "warned"]);
  });

  it("unlicensed shows only rows without a license", () => {
    expect(filterRows(rows, "unlicensed", "").map((r) => r.name)).toEqual(["nolicense"]);
  });

  it("search narrows by name within the active filter", () => {
    expect(filterRows(rows, "all", "warn").map((r) => r.name)).toEqual(["warned"]);
  });
});

describe("tallyVerdicts", () => {
  it("counts block/warn/pass and the scanned total", () => {
    const rows = mergeVerdicts(
      buildSbomRows([comp({ name: "a", version: "1.0.0" }), comp({ name: "b", version: "1.0.0" }), comp({ name: "c", version: "1.0.0" })]),
      "npm",
      [pkg({ name: "a", version: "1.0.0", action: "block" }), pkg({ name: "b", version: "1.0.0", action: "pass" })]
    );
    expect(tallyVerdicts(rows)).toEqual({ block: 1, warn: 0, pass: 1, scanned: 2 });
  });
});

describe("runSbomScan", () => {
  it("does nothing but finish when nothing is scannable", async () => {
    const store = createSbomStore(viewWith(buildSbomRows([comp({ name: "crate", ecosystem: "cargo", version: "1.0.0" })])));
    await runSbomScan(store, {});
    expect(analyzeMock).not.toHaveBeenCalled();
    expect(store.get().phase).toBe("done");
  });

  it("streams verdicts and usage into the store, then finishes", async () => {
    analyzeMock.mockResolvedValueOnce({
      score: 0,
      action: "block",
      packages: [pkg({ name: "evil", version: "1.0.0", action: "block", reasons: ["malware"] })],
      safeVersions: {},
      durationMs: 1,
      usage: { used: 5, limit: 100, tier: "free" }
    });
    analyzeMock.mockResolvedValueOnce({ score: 0, action: "pass", packages: [], safeVersions: {}, durationMs: 1 });
    const store = createSbomStore(viewWith(buildSbomRows([comp({ name: "evil", ecosystem: "npm", version: "1.0.0" })])));
    await runSbomScan(store, {});
    expect(store.get().rows[0]?.verdict?.action).toBe("block");
    expect(store.get().usage).toMatchObject({ used: 5, limit: 100 });
    expect(store.get().phase).toBe("done");
    expect(store.get().scanError).toBeNull();
  });

  it("fails open with a friendly reason on an auth error, keeping the inventory", async () => {
    analyzeMock.mockRejectedValueOnce(new AnalyzeError("unauthorized", 401, undefined, "auth"));
    const store = createSbomStore(viewWith(buildSbomRows([comp({ name: "x", ecosystem: "npm", version: "1.0.0" })])));
    await runSbomScan(store, {});
    expect(store.get().scanError).toBe("sign in with dg login to see verdicts");
    expect(store.get().phase).toBe("done");
    expect(store.get().rows).toHaveLength(1);
  });
});

describe("SbomList", () => {
  it("renders verdict glyphs, missing-license and missing-hash markers, and a selection cursor", () => {
    const rows = mergeVerdicts(
      buildSbomRows([
        comp({ name: "blocked", ecosystem: "npm", version: "1.0.0", license: "MIT", integrity: "sha512-x" }),
        comp({ name: "bare", ecosystem: "npm", version: "2.0.0" })
      ]),
      "npm",
      [pkg({ name: "blocked", version: "1.0.0", action: "block" })]
    );
    const { lastFrame, unmount } = render(React.createElement(SbomList, { rows, selected: 0, height: 10, width: 100, emptyMessage: "" }));
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("blocked@1.0.0");
    expect(frame).toContain("✘");
    expect(frame).toContain("no license");
    expect(frame).toContain("no checksum");
    expect(frame).toContain("checksum");
    expect(frame).toContain("›");
  });

  it("shows the provided empty message when there are no rows", () => {
    const { lastFrame, unmount } = render(
      React.createElement(SbomList, { rows: [], selected: 0, height: 10, width: 80, emptyMessage: "nothing flagged — no malware, downgrades, or cooldowns" })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("nothing flagged");
  });
});

describe("emptyFilterMessage", () => {
  const clean = { block: 0, warn: 0, pass: 5, scanned: 5 };
  const none = { block: 0, warn: 0, pass: 0, scanned: 0 };

  it("explains an empty risky filter by scan phase rather than implying a failure", () => {
    expect(emptyFilterMessage("risky", "", "scanning", none, null)).toBe("scanning… nothing flagged yet");
    expect(emptyFilterMessage("risky", "", "done", clean, null)).toBe("nothing flagged — no malware, downgrades, or cooldowns");
    expect(emptyFilterMessage("risky", "", "done", none, null)).toBe("no components were verdict-checked");
    expect(emptyFilterMessage("risky", "", "done", none, "sign in with dg login to see verdicts")).toBe("sign in with dg login to see verdicts");
  });

  it("frames an empty unlicensed filter as good news", () => {
    expect(emptyFilterMessage("unlicensed", "", "done", clean, null)).toBe("every component declares a license");
  });

  it("echoes the search query when nothing matches", () => {
    expect(emptyFilterMessage("all", "  zztop ", "done", clean, null)).toBe('no components match "zztop"');
  });
});

describe("SbomHeader", () => {
  const base = {
    total: 4,
    ecosystems: [["npm", 3], ["cargo", 1]] as Array<[import("../../src/sbom-ui/inventory.js").RowEcosystem, number]>,
    scannable: 3,
    scanProgress: 3,
    usage: null,
    subject: "demo",
    cargoCount: 1
  };

  it("shows the component count and breakdown but no verdict line during inventory", () => {
    const { lastFrame, unmount } = render(
      React.createElement(SbomHeader, { ...base, phase: "inventory", tally: { block: 0, warn: 0, pass: 0, scanned: 0 }, scanError: null })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("4 components");
    expect(frame).toContain("3 npm");
    expect(frame).not.toContain("BLOCK");
  });

  it("shows the verdict rollup and the cargo inventory-only note once done", () => {
    const { lastFrame, unmount } = render(
      React.createElement(SbomHeader, { ...base, phase: "done", tally: { block: 1, warn: 2, pass: 0, scanned: 3 }, scanError: null })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("1 BLOCK");
    expect(frame).toContain("2 WARN");
    expect(frame).toContain("cargo: inventory only");
  });

  it("shows the fail-open reason instead of a verdict line on a scan error", () => {
    const { lastFrame, unmount } = render(
      React.createElement(SbomHeader, {
        ...base,
        phase: "done",
        tally: { block: 0, warn: 0, pass: 0, scanned: 0 },
        scanError: "sign in with dg login to see verdicts"
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("dg login to see verdicts");
  });

  it("renders the dg dependency-graph logo and a tight brand title", () => {
    const { lastFrame, unmount } = render(
      React.createElement(SbomHeader, { ...base, phase: "done", tally: { block: 0, warn: 0, pass: 3, scanned: 3 }, scanError: null })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toMatch(/[⠀-⣿]/);
    expect(frame).toContain("Dependency Guardian");
    expect(frame).not.toContain("software bill of materials");
  });
});

describe("SbomApp", () => {
  it("renders the header, list, and an export/quit footer (not write)", async () => {
    const rows = buildSbomRows([comp({ name: "alpha", ecosystem: "npm", version: "1.0.0", license: "MIT", integrity: "sha512-x" })]);
    const store = createSbomStore({ phase: "done", rows, subject: "demo", dropped: [], scannable: 1, scanProgress: 1, scanError: null, usage: null });
    const { lastFrame, unmount } = render(React.createElement(SbomApp, { store, document: "{}", cwd: "/tmp" }));
    await new Promise((resolve) => setTimeout(resolve, 20));
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("alpha@1.0.0");
    expect(frame).toContain("export");
    expect(frame).toContain("q quit");
    expect(frame).not.toContain("write");
  });
});

describe("SbomApp search", () => {
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
  const stripAnsi = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, "");

  function appWithRows() {
    const rows = buildSbomRows([
      comp({ name: "alpha", ecosystem: "npm", version: "1.0.0", license: "MIT", integrity: "sha512-x" }),
      comp({ name: "beta", ecosystem: "npm", version: "2.0.0", license: "MIT", integrity: "sha512-y" })
    ]);
    const store = createSbomStore({ phase: "done", rows, subject: "demo", dropped: [], scannable: 2, scanProgress: 2, scanError: null, usage: null });
    return render(React.createElement(SbomApp, { store, document: "{}", cwd: "/tmp" }));
  }

  let previousExitCode: typeof process.exitCode;

  beforeEach(() => {
    previousExitCode = process.exitCode;
  });

  afterEach(() => {
    process.exitCode = previousExitCode;
  });

  it("Esc while typing clears the query and restores the full list", async () => {
    const view = appWithRows();
    await sleep(30);
    view.stdin.write("/");
    await sleep(20);
    for (const ch of "alp") view.stdin.write(ch);
    await sleep(30);
    expect(stripAnsi(view.lastFrame() ?? "")).not.toContain("beta@2.0.0");

    view.stdin.write("\u001b");
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("alpha@1.0.0");
    expect(frame).toContain("beta@2.0.0");
    expect(frame).toContain("q quit");
  });

  it("Enter keeps the filter with a visible chip, then Esc clears it without quitting", async () => {
    const view = appWithRows();
    await sleep(30);
    view.stdin.write("/");
    await sleep(20);
    for (const ch of "alp") view.stdin.write(ch);
    await sleep(30);
    view.stdin.write("\r");
    await sleep(30);
    const confirmed = stripAnsi(view.lastFrame() ?? "");
    expect(confirmed).toContain("alpha@1.0.0");
    expect(confirmed).not.toContain("beta@2.0.0");
    expect(confirmed).toContain("/alp");
    expect(confirmed).toContain("1 of 2 components");
    expect(confirmed).toContain("esc clear");

    view.stdin.write("\u001b");
    await sleep(30);
    const cleared = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(process.exitCode).toBe(previousExitCode);
    expect(cleared).toContain("alpha@1.0.0");
    expect(cleared).toContain("beta@2.0.0");
    expect(cleared).not.toContain("esc clear");
  });

  it("ignores non-printable characters in search input", async () => {
    const view = appWithRows();
    await sleep(30);
    view.stdin.write("/");
    await sleep(20);
    view.stdin.write("\u0007");
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("alpha@1.0.0");
    expect(frame).toContain("beta@2.0.0");
  });
});

describe("SbomApp export dialog", () => {
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
  const stripAnsi = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, "");

  let workdir: string;
  let prevToken: string | undefined;

  beforeEach(() => {
    prevToken = process.env.DG_API_TOKEN;
    process.env.DG_API_TOKEN = "test-token-abcdef";
    workdir = mkdtempSync(join(tmpdir(), "dg-sbom-export-"));
  });

  afterEach(() => {
    if (prevToken === undefined) delete process.env.DG_API_TOKEN;
    else process.env.DG_API_TOKEN = prevToken;
    rmSync(workdir, { recursive: true, force: true });
  });

  function appInDir() {
    const rows = mergeVerdicts(
      buildSbomRows([
        comp({ name: "alpha", ecosystem: "npm", version: "1.0.0", license: "MIT", integrity: "sha512-x" }),
        comp({ name: "beta", ecosystem: "npm", version: "2.0.0" })
      ]),
      "npm",
      [pkg({ name: "alpha", version: "1.0.0", action: "pass" })]
    );
    const store = createSbomStore({ phase: "done", rows, subject: "demo", dropped: [], scannable: 2, scanProgress: 2, scanError: null, usage: null });
    return render(React.createElement(SbomApp, { store, document: '{"bomFormat":"CycloneDX"}', cwd: workdir }));
  }

  it("blocks export behind login with the same message scan uses", async () => {
    const prevKey = process.env.DG_API_KEY;
    const prevHome = process.env.HOME;
    const prevXdg = process.env.XDG_CONFIG_HOME;
    delete process.env.DG_API_KEY;
    delete process.env.DG_API_TOKEN;
    process.env.HOME = workdir;
    delete process.env.XDG_CONFIG_HOME;
    try {
      const view = appInDir();
      await sleep(30);
      view.stdin.write("e");
      await sleep(40);
      const frame = stripAnsi(view.lastFrame() ?? "");
      view.unmount();

      expect(frame).toContain("Sign in to export:");
      expect(frame).toContain("dg login");
      expect(frame).not.toContain("CycloneDX JSON");
      expect(readdirSync(workdir).filter((f) => f.endsWith(".json") || f.endsWith(".csv") || f.endsWith(".md"))).toEqual([]);
    } finally {
      if (prevKey === undefined) delete process.env.DG_API_KEY;
      else process.env.DG_API_KEY = prevKey;
      process.env.DG_API_TOKEN = "test-token-abcdef";
      if (prevHome === undefined) delete process.env.HOME;
      else process.env.HOME = prevHome;
      if (prevXdg === undefined) delete process.env.XDG_CONFIG_HOME;
      else process.env.XDG_CONFIG_HOME = prevXdg;
    }
  });

  it("e opens the export menu with the document and component options", async () => {
    const view = appInDir();
    await sleep(30);
    view.stdin.write("e");
    await sleep(40);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("CycloneDX JSON");
    expect(frame).toContain("Components CSV");
    expect(frame).toContain("Components Markdown");
    expect(readdirSync(workdir)).toEqual([]);
  });

  it("Enter on the first option writes the CycloneDX document to sbom.cdx.json in cwd", async () => {
    const view = appInDir();
    await sleep(30);
    view.stdin.write("e");
    await sleep(30);
    view.stdin.write("\r");
    await sleep(30);
    view.stdin.write("\r");
    await sleep(50);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(readFileSync(join(workdir, "sbom.cdx.json"), "utf8")).toBe('{"bomFormat":"CycloneDX"}');
    expect(frame).toContain("exported");
  });

  it("Components CSV writes name,version,ecosystem,license,verdict rows to sbom-components.csv", async () => {
    const view = appInDir();
    await sleep(30);
    view.stdin.write("e");
    await sleep(30);
    view.stdin.write("j");
    await sleep(20);
    view.stdin.write("\r");
    await sleep(30);
    view.stdin.write("\r");
    await sleep(50);
    view.unmount();

    expect(readdirSync(workdir)).toEqual(["sbom-components.csv"]);
    const body = readFileSync(join(workdir, "sbom-components.csv"), "utf8");
    expect(body).toContain("name,version,ecosystem,license,verdict");
    expect(body).toContain("alpha,1.0.0,npm,MIT,pass");
    expect(body).toContain("beta,2.0.0,npm,,");
  });

  it("Esc closes the dialog without writing", async () => {
    const view = appInDir();
    await sleep(30);
    view.stdin.write("e");
    await sleep(30);
    view.stdin.write("\u001b");
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("alpha@1.0.0");
    expect(readdirSync(workdir)).toEqual([]);
  });
});

describe("components renderers", () => {
  const rows = mergeVerdicts(
    buildSbomRows([
      comp({ name: "alpha", ecosystem: "npm", version: "1.0.0", license: "MIT" }),
      comp({ name: 'we,"ird', ecosystem: "cargo", version: "2.0.0" })
    ]),
    "npm",
    [pkg({ name: "alpha", version: "1.0.0", action: "block", reasons: ["malware"] })]
  );

  it("componentsCsv escapes cells and leaves absent license/verdict empty", () => {
    const body = componentsCsv(rows);
    expect(body.split("\n")[0]).toBe("name,version,ecosystem,license,verdict");
    expect(body).toContain("alpha,1.0.0,npm,MIT,block");
    expect(body).toContain('"we,""ird",2.0.0,cargo,,');
  });

  it("componentsMarkdown renders one table row per component", () => {
    const body = componentsMarkdown(rows);
    expect(body).toContain("| Name | Version | Ecosystem | License | Verdict |");
    expect(body).toContain("| alpha | 1.0.0 | npm | MIT | block |");
    expect(body.trimEnd().split("\n")).toHaveLength(2 + rows.length);
  });
});

describe("rowKey", () => {
  it("normalizes case for stable matching against scanner results", () => {
    expect(rowKey("npm", "React", "18.0.0")).toBe("npm:react@18.0.0");
  });
});
