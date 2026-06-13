import React from "react";
import { EventEmitter } from "node:events";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { render as inkRender } from "ink";
import { render } from "ink-testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { InteractiveResultsView } from "../../src/scan-ui/components/InteractiveResultsView.js";
import { ScoreHeader } from "../../src/scan-ui/components/ScoreHeader.js";
import type { AnalyzeResponse } from "../../src/api/analyze.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const stripAnsi = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, "");

class SizedStdout extends EventEmitter {
  frames: string[] = [];
  private _lastFrame: string | undefined;
  constructor(public columns: number, public rows: number) {
    super();
  }
  write = (frame: string) => {
    this.frames.push(frame);
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

function renderSized(tree: React.ReactElement, columns: number, rows: number) {
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

const fixture: AnalyzeResponse = {
  score: 82,
  action: "warn",
  packages: [
    {
      name: "left-pad",
      version: "1.3.0",
      score: 64,
      action: "warn",
      findings: [{ severity: 3, category: "lifecycle", title: "install lifecycle script" }],
      reasons: ["install lifecycle script"],
      cached: false,
      license: { spdx: "MIT", raw: "MIT", riskCategory: "permissive", label: "MIT" }
    },
    {
      name: "old-lib",
      version: "0.2.0",
      score: 91,
      action: "block",
      findings: [{ severity: 5, category: "malware", title: "credential exfiltration" }],
      reasons: ["confirmed malware"],
      cached: false,
      license: { spdx: "GPL-3.0", raw: "GPL-3.0", riskCategory: "strong-copyleft", label: "GPL-3.0" }
    },
    {
      name: "lodash",
      version: "4.17.21",
      score: 0,
      action: "pass",
      findings: [],
      reasons: [],
      cached: true,
      license: { spdx: "MIT", raw: "MIT", riskCategory: "permissive", label: "MIT" }
    }
  ],
  safeVersions: { "old-lib": "0.3.1" },
  durationMs: 1200,
  usage: { used: 1204, limit: 100000, tier: "free" }
};

function renderResults(initialView?: "results" | "licenses") {
  return render(
    React.createElement(InteractiveResultsView, {
      result: fixture,
      config: { mode: "warn" },
      durationMs: 1200,
      onExit: () => undefined,
      ...(initialView ? { initialView } : {})
    })
  );
}

describe("ported InteractiveResultsView", () => {
  it("renders the score header and flagged packages bucketed by scanner action", () => {
    const { lastFrame, unmount } = renderResults();
    const frame = lastFrame() ?? "";
    unmount();

    expect(frame).toContain("Score");
    expect(frame).toContain("82");
    expect(frame).toContain("left-pad");
    expect(frame).toContain("old-lib");
    expect(frame).toContain("3 packages scanned");
    expect(frame).toContain("2 flagged");
    expect(frame).toContain("1 clean");
  });

  it("shows the license overlay grouped by SPDX when opened", () => {
    const { lastFrame, unmount } = renderResults("licenses");
    const frame = lastFrame() ?? "";
    unmount();

    expect(frame).toContain("MIT");
    expect(frame).toContain("GPL-3.0");
  });

  it("opens the license overlay from the keyboard", async () => {
    const view = renderResults();
    await sleep(30);
    view.stdin.write("l");
    await sleep(50);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(frame).toContain("unique across");
  });

  it("license list rows truncate instead of soft-wrapping on narrow terminals", async () => {
    const view = renderSized(
      React.createElement(InteractiveResultsView, {
        result: fixture,
        config: { mode: "warn" },
        durationMs: 1200,
        onExit: () => undefined,
        initialView: "licenses"
      }),
      58,
      24
    );
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("MIT");
    const orphanBarLines = frame.split("\n").filter((line) => line.includes("█") && /^[\s█]+$/.test(line));
    expect(orphanBarLines).toEqual([]);
  });

  it("license drill-in truncates an over-long version to keep one row per package", async () => {
    const longVersionFixture: AnalyzeResponse = {
      score: 0,
      action: "pass",
      packages: [
        {
          name: "left-pad",
          version: "1.3.0-superduperlongprereleasebuildmetadata",
          score: 0,
          action: "pass",
          findings: [],
          reasons: [],
          cached: false,
          license: { spdx: "MIT", raw: "MIT", riskCategory: "permissive", label: "MIT" }
        }
      ],
      safeVersions: {},
      durationMs: 100
    };
    const view = renderSized(
      React.createElement(InteractiveResultsView, {
        result: longVersionFixture,
        config: { mode: "warn" },
        durationMs: 100,
        onExit: () => undefined,
        initialView: "licenses"
      }),
      70,
      24
    );
    await sleep(30);
    view.stdin.write("\r");
    await sleep(40);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("left-pad");
    expect(frame).toContain("1.3.0-superdup…");
    expect(frame).not.toContain("buildmetadata");
  });
});

describe("InteractiveResultsView export + export-menu behavior", () => {
  const bucketFixture: AnalyzeResponse = {
    score: 91,
    action: "block",
    packages: [
      { name: "blocked-pkg", version: "1.0.0", score: 91, action: "block", findings: [{ severity: 5, category: "malware", title: "exfil" }], reasons: ["malware"], cached: false },
      { name: "warned-pkg", version: "1.0.0", score: 70, action: "warn", findings: [{ severity: 3, category: "lifecycle", title: "postinstall" }], reasons: ["lifecycle"], cached: false },
      { name: "pass-zero", version: "1.0.0", score: 0, action: "pass", findings: [], reasons: [], cached: false },
      { name: "pass-nonzero", version: "1.0.0", score: 30, action: "pass", findings: [], reasons: [], cached: false }
    ],
    safeVersions: {},
    durationMs: 500
  };

  let prevToken: string | undefined;
  let workdir: string;
  let cwdSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    prevToken = process.env.DG_API_TOKEN;
    process.env.DG_API_TOKEN = "test-token-abcdef";
    workdir = mkdtempSync(join(tmpdir(), "dg-tui-export-"));
    cwdSpy = vi.spyOn(process, "cwd").mockReturnValue(workdir);
  });

  afterEach(() => {
    cwdSpy.mockRestore();
    if (prevToken === undefined) delete process.env.DG_API_TOKEN;
    else process.env.DG_API_TOKEN = prevToken;
    rmSync(workdir, { recursive: true, force: true });
  });

  it("buckets the export summary by scanner action, counting score>0 passes as clean", async () => {
    const view = render(
      React.createElement(InteractiveResultsView, {
        result: bucketFixture,
        config: { mode: "warn" },
        durationMs: 500,
        onExit: () => undefined
      })
    );
    await sleep(30);
    view.stdin.write("e");
    await sleep(40);
    view.stdin.write("\r");
    await sleep(40);
    view.stdin.write("\r");
    await sleep(60);
    view.unmount();

    const file = readdirSync(workdir).find((f) => f.endsWith(".json"));
    expect(file).toBe("dg-scan.json");
    const payload = JSON.parse(readFileSync(join(workdir, file as string), "utf-8"));

    expect(payload.blocked).toBe(1);
    expect(payload.warned).toBe(1);
    expect(payload.clean).toBe(2);
    expect(payload.passLowRisk).toBe(0);
  });

  it("'q' inside the export menu closes the menu without quitting the TUI", async () => {
    let exited = false;
    const view = render(
      React.createElement(InteractiveResultsView, {
        result: bucketFixture,
        config: { mode: "warn" },
        durationMs: 500,
        onExit: () => { exited = true; }
      })
    );
    await sleep(30);
    view.stdin.write("e");
    await sleep(40);
    expect(view.lastFrame() ?? "").toContain("Format");

    view.stdin.write("q");
    await sleep(40);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(exited).toBe(false);
    expect(readdirSync(workdir).length).toBe(0);
    expect(frame).toContain("blocked-pkg");
  });

  it("renders without crashing when a search filter empties the flagged groups", async () => {
    const view = render(
      React.createElement(InteractiveResultsView, {
        result: bucketFixture,
        config: { mode: "warn" },
        durationMs: 500,
        onExit: () => undefined
      })
    );
    await sleep(30);
    view.stdin.write("/");
    await sleep(20);
    for (const ch of "zzz-no-match") view.stdin.write(ch);
    await sleep(40);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(frame).not.toContain("blocked-pkg");
    expect(frame.length).toBeGreaterThan(0);
  });

  it("keeps the navigate footer and does not quit after Enter on a non-matching search", async () => {
    let exited = false;
    const view = render(
      React.createElement(InteractiveResultsView, {
        result: bucketFixture,
        config: { mode: "warn" },
        durationMs: 500,
        onExit: () => { exited = true; }
      })
    );
    await sleep(30);
    view.stdin.write("/");
    await sleep(20);
    for (const ch of "zzz-no-match") view.stdin.write(ch);
    await sleep(30);
    view.stdin.write("\r");
    await sleep(30);
    view.stdin.write("\r");
    await sleep(40);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(exited).toBe(false);
    expect(frame).toContain("navigate");
    expect(frame).toContain("blocked-pkg");
  });

  it("clears the export toast timer on unmount so quit is not delayed", async () => {
    const setSpy = vi.spyOn(globalThis, "setTimeout");
    const clearSpy = vi.spyOn(globalThis, "clearTimeout");
    try {
      const view = render(
        React.createElement(InteractiveResultsView, {
          result: bucketFixture,
          config: { mode: "warn" },
          durationMs: 500,
          onExit: () => undefined
        })
      );
      await sleep(30);
      view.stdin.write("e");
      await sleep(40);
      view.stdin.write("\r");
      await sleep(40);
      view.stdin.write("\r");
      await sleep(60);

      const toastIdx = setSpy.mock.calls.findIndex((c) => c[1] === 4000);
      expect(toastIdx).toBeGreaterThanOrEqual(0);
      const handle = setSpy.mock.results[toastIdx]?.value;
      expect(handle).toBeDefined();

      view.unmount();
      await sleep(10);
      expect(clearSpy.mock.calls.some((c) => c[0] === handle)).toBe(true);
    } finally {
      setSpy.mockRestore();
      clearSpy.mockRestore();
    }
  });
});

describe("all-packages search", () => {
  const groupedFixture: AnalyzeResponse = {
    score: 70,
    action: "warn",
    packages: ["evil-a", "evil-b", "evil-c", "evil-target"].map((name) => ({
      name,
      version: "1.0.0",
      score: 70,
      action: "warn" as const,
      findings: [{ severity: 3 as const, category: "lifecycle", title: "postinstall" }],
      reasons: ["lifecycle"],
      cached: false
    })),
    safeVersions: {},
    durationMs: 100
  };

  it("finds a clean package and renders it as a Pass row", async () => {
    const view = renderResults();
    await sleep(30);
    view.stdin.write("/");
    await sleep(20);
    for (const ch of "lodash") view.stdin.write(ch);
    await sleep(40);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("lodash@4.17.21");
    expect(frame).toContain("Pass");
    expect(frame).toContain("Search Results");
    expect(frame).toContain("1 of 3 packages");
    expect(frame).not.toContain("old-lib");
  });

  it("narrows a grouped row to the matching member", async () => {
    const view = render(
      React.createElement(InteractiveResultsView, {
        result: groupedFixture,
        config: { mode: "warn" },
        durationMs: 100,
        onExit: () => undefined
      })
    );
    await sleep(30);
    view.stdin.write("/");
    await sleep(20);
    for (const ch of "target") view.stdin.write(ch);
    await sleep(40);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("evil-target@1.0.0");
    expect(frame).not.toContain("similar");
    expect(frame).not.toContain("evil-a@");
  });

  it("keeps a visible filter chip after Enter confirms and clears it with Esc without onBack", async () => {
    const view = renderResults();
    await sleep(30);
    view.stdin.write("/");
    await sleep(20);
    for (const ch of "lodash") view.stdin.write(ch);
    await sleep(30);
    view.stdin.write("\r");
    await sleep(40);
    const confirmed = stripAnsi(view.lastFrame() ?? "");
    expect(confirmed).toContain("/ lodash");
    expect(confirmed).toContain("clear");

    view.stdin.write("\u001b");
    await sleep(40);
    const cleared = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(cleared).toContain("navigate");
    expect(cleared).not.toContain("Search Results");
    expect(cleared).toContain("old-lib");
  });

  it("uses the all-packages empty state copy", async () => {
    const view = renderResults();
    await sleep(30);
    view.stdin.write("/");
    await sleep(20);
    for (const ch of "zzz") view.stdin.write(ch);
    await sleep(40);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain('No packages match "zzz"');
    expect(frame).not.toContain("No flagged packages match");
  });

  it("advertises the all-packages search scope in the help overlay", async () => {
    const view = renderResults();
    await sleep(30);
    view.stdin.write("?");
    await sleep(40);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("Search all scanned packages");
  });
});

describe("expansion keyed by group", () => {
  it("keeps the expanded row attached to its package across search filtering", async () => {
    const view = renderResults();
    await sleep(30);
    view.stdin.write("j");
    await sleep(20);
    view.stdin.write("\r");
    await sleep(250);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("install lifecycle script");

    view.stdin.write("/");
    await sleep(20);
    for (const ch of "left") view.stdin.write(ch);
    await sleep(40);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("install lifecycle script");
    expect(frame).not.toContain("old-lib");
  });

  it("does not transfer expansion to whatever lands at the old index after filtering", async () => {
    const view = renderResults();
    await sleep(30);
    view.stdin.write("\r");
    await sleep(250);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("credential exfiltration");

    view.stdin.write("/");
    await sleep(20);
    for (const ch of "left") view.stdin.write(ch);
    await sleep(40);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("left-pad@1.3.0");
    expect(frame).not.toContain("credential exfiltration");
    expect(frame).not.toContain("install lifecycle script");
  });

  it("shows the yanked reason in the summary expansion", async () => {
    const yankedFixture: AnalyzeResponse = {
      score: 91,
      action: "block",
      packages: [
        { name: "bad-pkg", version: "1.0.0", score: 91, action: "block", findings: [{ severity: 5, category: "malware", title: "exfil" }], reasons: ["malware"], cached: false },
        { name: "yanked-pkg", version: "2.0.0", score: 0, action: "analysis_incomplete", findings: [{ id: "analysis_incomplete", severity: 1, title: "Version unpublished/yanked from registry" }], reasons: ["Version unpublished/yanked from registry"], cached: false }
      ],
      safeVersions: {},
      durationMs: 100
    };
    const view = render(
      React.createElement(InteractiveResultsView, {
        result: yankedFixture,
        config: { mode: "warn" },
        durationMs: 100,
        onExit: () => undefined
      })
    );
    await sleep(30);
    view.stdin.write("j");
    await sleep(20);
    view.stdin.write("\r");
    await sleep(250);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("Version unpublished/yanked from registry");
  });
});

describe("detail pane", () => {
  it("opens on second Enter with verdict, findings, and safe version, Esc returns to the list", async () => {
    const view = renderSized(
      React.createElement(InteractiveResultsView, {
        result: fixture,
        config: { mode: "warn" },
        durationMs: 1200,
        onExit: () => undefined
      }),
      100,
      40
    );
    await sleep(30);
    view.stdin.write("\r");
    await sleep(250);
    view.stdin.write("\r");
    await sleep(60);
    const detail = stripAnsi(view.lastFrame() ?? "");
    expect(detail).toContain("Verdict");
    expect(detail).toContain("Block");
    expect(detail).toContain("v0.2.0");
    expect(detail).toContain("score 91");
    expect(detail).toContain("credential exfiltration");
    expect(detail).toContain("Safe version: old-lib@0.3.1");

    view.stdin.write("\u001b");
    await sleep(60);
    const list = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(list).toContain("Flagged Packages");
  });

  it("opens for a clean package found via search", async () => {
    const view = renderSized(
      React.createElement(InteractiveResultsView, {
        result: fixture,
        config: { mode: "warn" },
        durationMs: 1200,
        onExit: () => undefined
      }),
      100,
      40
    );
    await sleep(30);
    view.stdin.write("/");
    await sleep(20);
    for (const ch of "lodash") view.stdin.write(ch);
    await sleep(30);
    view.stdin.write("\r");
    await sleep(40);
    view.stdin.write("\r");
    await sleep(250);
    view.stdin.write("\r");
    await sleep(60);
    const detail = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(detail).toContain("Verdict");
    expect(detail).toContain("Pass");
    expect(detail).toContain("lodash@4.17.21");
    expect(detail).toContain("No findings");
  });
});

describe("layout degradation", () => {
  it("aligns the name column across Unverified and Block badges", async () => {
    const badgeFixture: AnalyzeResponse = {
      score: 91,
      action: "block",
      packages: [
        { name: "bad-pkg", version: "1.0.0", score: 91, action: "block", findings: [{ severity: 5, category: "malware", title: "exfil" }], reasons: ["malware"], cached: false },
        { name: "yanked-pkg", version: "2.0.0", score: 0, action: "analysis_incomplete", findings: [{ id: "analysis_incomplete", severity: 1, title: "Version unpublished/yanked from registry" }], reasons: ["Version unpublished/yanked from registry"], cached: false }
      ],
      safeVersions: {},
      durationMs: 100
    };
    const { lastFrame, unmount } = render(
      React.createElement(InteractiveResultsView, {
        result: badgeFixture,
        config: { mode: "warn" },
        durationMs: 100,
        onExit: () => undefined
      })
    );
    await sleep(30);
    const lines = stripAnsi(lastFrame() ?? "").split("\n");
    unmount();

    const blockLine = lines.find((l) => l.includes("bad-pkg@"));
    const yankedLine = lines.find((l) => l.includes("yanked-pkg@"));
    expect(blockLine).toBeDefined();
    expect(yankedLine).toBeDefined();
    expect((blockLine as string).indexOf("bad-pkg@")).toBe((yankedLine as string).indexOf("yanked-pkg@"));
  });

  it("never emits a line wider than a 48-col terminal", async () => {
    const longFixture: AnalyzeResponse = {
      score: 91,
      action: "block",
      packages: [
        {
          name: "extremely-long-package-name-that-overflows-the-whole-terminal-width",
          version: "1.0.0-beta.huge.12345",
          score: 91,
          action: "block",
          findings: [{ severity: 5, category: "malware", title: "a very long finding title that would definitely soft-wrap on a narrow terminal without truncation" }],
          reasons: ["malware"],
          cached: false,
          license: { spdx: "BSD-3-Clause", raw: "BSD-3-Clause", riskCategory: "permissive", label: "BSD-3-Clause" }
        }
      ],
      safeVersions: {},
      durationMs: 100,
      usage: { used: 1204, limit: 100000, tier: "free" }
    };
    const view = renderSized(
      React.createElement(InteractiveResultsView, {
        result: longFixture,
        config: { mode: "warn" },
        durationMs: 100,
        onExit: () => undefined
      }),
      48,
      30
    );
    await sleep(30);
    view.stdin.write("\r");
    await sleep(250);
    const lines = stripAnsi(view.lastFrame() ?? "").split("\n");
    view.unmount();

    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) {
      expect(line.length).toBeLessThanOrEqual(48);
    }
  });

  it("shows the logo at 80 cols and hides it at 70 cols", async () => {
    const headerProps = { score: 82, action: "warn" as const, compact: false, total: 3, flagged: 2, clean: 1 };
    const wide = renderSized(React.createElement(ScoreHeader, headerProps), 80, 30);
    await sleep(20);
    const wideFrame = wide.lastFrame() ?? "";
    wide.unmount();
    expect(wideFrame).toMatch(/[⠀-⣿]/);

    const narrow = renderSized(React.createElement(ScoreHeader, headerProps), 70, 30);
    await sleep(20);
    const narrowFrame = narrow.lastFrame() ?? "";
    narrow.unmount();
    expect(narrowFrame).not.toMatch(/[⠀-⣿]/);
  });

  it("keeps the full header with logo on a short terminal when everything fits", async () => {
    const short = renderSized(
      React.createElement(InteractiveResultsView, {
        result: fixture,
        config: { mode: "warn" },
        durationMs: 1200,
        onExit: () => undefined
      }),
      100,
      18
    );
    await sleep(30);
    const shortFrame = short.lastFrame() ?? "";
    short.unmount();

    expect(shortFrame).toMatch(/[⠀-⣿]/);
    expect(shortFrame.split("\n").length).toBeLessThanOrEqual(18);
  });

  it("collapses chrome and drops the logo only when the list needs the rows", async () => {
    const crowdedFixture: AnalyzeResponse = {
      ...fixture,
      packages: Array.from({ length: 20 }, (_, i) => ({
        name: `flagged-pkg-${i}`,
        version: "1.0.0",
        score: 40 + i,
        action: "warn" as const,
        findings: [{ severity: 3, category: "lifecycle", title: "install lifecycle script" }],
        reasons: ["install lifecycle script"],
        cached: false
      }))
    };

    const short = renderSized(
      React.createElement(InteractiveResultsView, {
        result: crowdedFixture,
        config: { mode: "warn" },
        durationMs: 1200,
        onExit: () => undefined
      }),
      100,
      18
    );
    await sleep(30);
    const shortFrame = short.lastFrame() ?? "";
    short.unmount();

    expect(shortFrame).not.toMatch(/[⠀-⣿]/);
    expect(shortFrame.split("\n").length).toBeLessThanOrEqual(18);

    const tall = renderSized(
      React.createElement(InteractiveResultsView, {
        result: crowdedFixture,
        config: { mode: "warn" },
        durationMs: 1200,
        onExit: () => undefined
      }),
      100,
      30
    );
    await sleep(30);
    const tallFrame = tall.lastFrame() ?? "";
    tall.unmount();

    expect(tallFrame).toMatch(/[⠀-⣿]/);
    expect(tallFrame.split("\n").length).toBeLessThanOrEqual(30);
  });
});


describe("InteractiveResultsView acknowledged section", () => {
  const decisions = {
    file: "/repo/dg.json",
    acknowledgedCount: 1,
    effectiveAction: "block" as const,
    packages: {
      "left-pad@1.3.0": {
        ecosystem: "npm" as const,
        acknowledged: {
          decisionId: "11112222-3333-4444-5555-666677778888",
          by: "alice@example.com",
          at: "2026-06-01T00:00:00.000Z",
          reason: "vetted"
        }
      },
      "old-lib@0.2.0": { ecosystem: "npm" as const }
    }
  };

  function renderWithDecisions() {
    return render(
      React.createElement(InteractiveResultsView, {
        result: fixture,
        config: { mode: "warn" },
        durationMs: 1200,
        onExit: () => undefined,
        decisions
      })
    );
  }

  it("collapses acknowledged warns into the section with the who/when line", () => {
    const { lastFrame, unmount } = renderWithDecisions();
    const frame = stripAnsi(lastFrame() ?? "");
    unmount();

    expect(frame).toContain("Acknowledged (1) · dg.json");
    expect(frame).not.toContain("\\u00b7");
    expect(frame).toContain("dg.json");
    expect(frame).toContain("accepted by alice@example.com on 2026-06-01");
    expect(frame).toContain("left-pad@1.3.0");
    expect(frame).toContain("old-lib");
    expect(frame).toContain("1/1");
  });

  it("renders the mandatory one-line footer naming the count and the file", () => {
    const { lastFrame, unmount } = renderWithDecisions();
    const frame = stripAnsi(lastFrame() ?? "");
    unmount();

    expect(frame).toContain("1 acknowledged warn");
    expect(frame).toContain("review with 'dg decisions'");
  });

  it("a block stays in the flagged list even when a forged entry targets it", () => {
    const forged = {
      ...decisions,
      acknowledgedCount: 1,
      packages: {
        ...decisions.packages,
        "old-lib@0.2.0": { ecosystem: "npm" as const }
      }
    };
    const view = render(
      React.createElement(InteractiveResultsView, {
        result: fixture,
        config: { mode: "warn" },
        durationMs: 1200,
        onExit: () => undefined,
        decisions: forged
      })
    );
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("Block");
    expect(frame).toContain("old-lib");
  });

  it("renders no acknowledged chrome without decisions", () => {
    const { lastFrame, unmount } = renderResults();
    const frame = stripAnsi(lastFrame() ?? "");
    unmount();

    expect(frame).not.toContain("Acknowledged");
    expect(frame).not.toContain("dg.json");
  });

  it("search still finds acknowledged packages", async () => {
    const view = renderWithDecisions();
    await sleep(30);
    view.stdin.write("/");
    await sleep(20);
    for (const ch of "left-pad") view.stdin.write(ch);
    await sleep(40);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("left-pad");
    expect(frame).toContain("Search Results");
  });
});
