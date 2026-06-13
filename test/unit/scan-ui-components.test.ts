import React from "react";
import { render } from "ink-testing-library";
import { describe, expect, it } from "vitest";
import { ErrorView } from "../../src/scan-ui/components/ErrorView.js";
import { ProgressBar } from "../../src/scan-ui/components/ProgressBar.js";
import { ScoreHeader } from "../../src/scan-ui/components/ScoreHeader.js";
import { Spinner } from "../../src/scan-ui/components/Spinner.js";
import { packageBadge, resolveResultsLayout } from "../../src/scan-ui/components/InteractiveResultsView.js";
import { groupPackages } from "../../src/scan-ui/format-helpers.js";
import type { APIPackageResult } from "../../src/scan-ui/api-aliases.js";

function incompletePkg(title: string, reasons: string[]): APIPackageResult {
  return {
    name: "event-stream",
    version: "3.3.6",
    score: 0,
    action: "analysis_incomplete",
    findings: [{ id: "analysis_incomplete", severity: 1, title }],
    reasons,
    cached: false
  };
}

describe("packageBadge", () => {
  it("labels a yanked/unpublished version 'Unverified', not a bland 'Unknown'", () => {
    const pkg = incompletePkg("Version unpublished/yanked from registry", ["Version unpublished/yanked from registry"]);
    expect(packageBadge(pkg).label).toBe("Unverified");
  });

  it("keeps 'Unknown' for a genuine scan-timeout incomplete", () => {
    const pkg = incompletePkg("partial_analysis", []);
    expect(packageBadge(pkg).label).toBe("Unknown");
  });

  it("badges block/warn/pass from the scanner action unchanged", () => {
    expect(packageBadge({ ...incompletePkg("", []), action: "block" }).label).toBe("Block");
    expect(packageBadge({ ...incompletePkg("", []), action: "warn" }).label).toBe("Warn");
    expect(packageBadge({ ...incompletePkg("", []), action: "pass" }).label).toBe("Pass");
  });
});

describe("groupPackages", () => {
  it("never collapses a block verdict into a findingless incomplete group", () => {
    const mk = (name: string, action: APIPackageResult["action"]): APIPackageResult => ({
      name,
      version: "1.0.0",
      score: 0,
      action,
      findings: [],
      reasons: [],
      cached: false
    });
    const groups = groupPackages(
      [mk("yanked-a", "analysis_incomplete"), mk("yanked-b", "analysis_incomplete"), mk("policy-block-c", "block")],
      "fingerprint"
    );
    const blockGroup = groups.find((group) => group.packages.some((pkg) => pkg.name === "policy-block-c"));
    expect(blockGroup).toBeDefined();
    expect(blockGroup?.packages.every((pkg) => pkg.action === "block")).toBe(true);
  });
});

describe("ported legacy TUI components", () => {
  it("ScoreHeader renders score, counts, usage and the braille graph", () => {
    const { lastFrame, unmount } = render(
      React.createElement(ScoreHeader, {
        score: 82,
        action: "warn",
        compact: false,
        total: 248,
        flagged: 3,
        clean: 245,
        scanUsage: "1,204 / 100,000 packages this month"
      })
    );
    const frame = lastFrame() ?? "";
    unmount();

    expect(frame).toContain("Dependency Guardian");
    expect(frame).toContain("Score");
    expect(frame).toContain("82");
    expect(frame).toContain("248 packages scanned");
    expect(frame).toContain("3 flagged");
    expect(frame).toContain("245 clean");
    expect(frame).toContain("1,204 / 100,000 packages this month");
    expect(frame).toMatch(/[⠀-⣿]/);
  });

  it("ScoreHeader drops the logo and spacers in compact mode", () => {
    const { lastFrame, unmount } = render(
      React.createElement(ScoreHeader, {
        score: 82,
        action: "warn",
        compact: true,
        total: 248,
        flagged: 3,
        clean: 245,
        scanUsage: "1,204 / 100,000 packages this month"
      })
    );
    const frame = lastFrame() ?? "";
    unmount();

    expect(frame).toContain("248 packages scanned");
    expect(frame).not.toMatch(/[⠀-⣿]/);
  });

  it("ScoreHeader reports all clean when nothing is flagged", () => {
    const { lastFrame, unmount } = render(
      React.createElement(ScoreHeader, {
        score: 0,
        action: "pass",
        compact: false,
        total: 10,
        flagged: 0,
        clean: 10
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("all clean");
  });

  describe("resolveResultsLayout", () => {
    const base = {
      logoRows: 7,
      ackSectionLines: 0,
      hasGroups: true,
      hasUsage: true,
      extraLines: 0
    };

    it("keeps the full header with logo on a short terminal when everything fits", () => {
      const layout = resolveResultsLayout({ ...base, termRows: 18, listRows: 1 });
      expect(layout.compact).toBe(false);
      expect(layout.availableRows).toBeGreaterThanOrEqual(1);
    });

    it("goes compact on a short terminal when the list needs the rows", () => {
      const layout = resolveResultsLayout({ ...base, termRows: 18, listRows: 40 });
      expect(layout.compact).toBe(true);
    });

    it("never goes compact at 24 rows or taller", () => {
      const layout = resolveResultsLayout({ ...base, termRows: 24, listRows: 200 });
      expect(layout.compact).toBe(false);
    });

    it("stays full at the exact-fit boundary and flips one row past it", () => {
      const fullChrome = 15;
      const termRows = 23;
      const fits = resolveResultsLayout({ ...base, termRows, listRows: termRows - fullChrome });
      const overflows = resolveResultsLayout({ ...base, termRows, listRows: termRows - fullChrome + 1 });
      expect(fits.compact).toBe(false);
      expect(fits.availableRows).toBe(termRows - fullChrome);
      expect(overflows.compact).toBe(true);
    });

    it("reserves scroll-indicator rows only when the list overflows", () => {
      const compactChrome = 9;
      const termRows = 23;
      const maxList = termRows - compactChrome;
      const scrolling = resolveResultsLayout({ ...base, termRows, listRows: maxList + 10 });
      expect(scrolling.compact).toBe(true);
      expect(scrolling.availableRows).toBe(maxList - 2);
    });

    it("floors availableRows at 5 on tiny terminals", () => {
      const layout = resolveResultsLayout({ ...base, termRows: 10, listRows: 30 });
      expect(layout.availableRows).toBe(5);
    });

    it("counts ack and extra lines against the fit budget", () => {
      const withoutAck = resolveResultsLayout({ ...base, termRows: 20, listRows: 5 });
      const withAck = resolveResultsLayout({ ...base, termRows: 20, listRows: 5, ackSectionLines: 4 });
      expect(withoutAck.compact).toBe(false);
      expect(withAck.compact).toBe(true);
    });
  });

  it("ProgressBar renders the count and bar", () => {
    const { lastFrame, unmount } = render(
      React.createElement(ProgressBar, {
        value: 5,
        total: 10,
        label: "left-pad"
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("5/10");
    expect(frame).toContain("left-pad");
  });

  it("Spinner renders its label", () => {
    const { lastFrame, unmount } = render(React.createElement(Spinner, { label: "Searching for dependencies" }));
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("Searching for dependencies");
  });

  it("ErrorView renders the message and a status-specific hint", () => {
    const error = Object.assign(new Error("Forbidden"), { statusCode: 401 });
    const { lastFrame, unmount } = render(React.createElement(ErrorView, { error }));
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("Error");
    expect(frame).toContain("Forbidden");
    expect(frame).toContain("dg login");
  });
});
