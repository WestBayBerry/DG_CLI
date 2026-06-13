import React from "react";
import { render } from "ink-testing-library";
import { describe, expect, it } from "vitest";
import { LiveInstall } from "../../src/install-ui/LiveInstall.js";

describe("LiveInstall ultra-minimal UI", () => {
  it("shows a live verifying line with the in-flight package", () => {
    const { lastFrame, unmount } = render(
      React.createElement(LiveInstall, {
        view: { phase: "scanning", total: 4, verified: 1, flagged: 0, current: "numpy 2.4.6" }
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("DG verifying 4 packages…");
    expect(frame).toContain("numpy 2.4.6");
  });

  it("shows a bounded verifying line once the resolved total is known", () => {
    const { lastFrame, unmount } = render(
      React.createElement(LiveInstall, {
        view: { phase: "scanning", total: 2, verified: 1, flagged: 0, resolvedTotal: 3 }
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("DG verifying 2/3…");
  });

  it("drops the stale denominator once more artifacts than resolved appear", () => {
    const { lastFrame, unmount } = render(
      React.createElement(LiveInstall, {
        view: { phase: "scanning", total: 5, verified: 4, flagged: 0, resolvedTotal: 4 }
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("DG verifying 5 packages…");
    expect(frame).not.toContain("5/5");
  });

  it("collapses to a single clean summary line when done", () => {
    const { lastFrame, unmount } = render(
      React.createElement(LiveInstall, {
        view: { phase: "done", total: 4, verified: 4, flagged: 0 }
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("✓");
    expect(frame).toContain("DG verified 4 packages — clean");
    expect(frame).not.toMatch(/─{10,}/);
  });

  it("singularizes one package", () => {
    const { lastFrame, unmount } = render(
      React.createElement(LiveInstall, {
        view: { phase: "done", total: 1, verified: 1, flagged: 0 }
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("DG verified 1 package — clean");
  });

  it("reports flagged packages in the summary", () => {
    const { lastFrame, unmount } = render(
      React.createElement(LiveInstall, {
        view: { phase: "done", total: 3, verified: 2, flagged: 1 }
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("⚠");
    expect(frame).toContain("DG verified 3 packages — 1 flagged");
  });

  it("renders a block panel with package, reason and next step", () => {
    const { lastFrame, unmount } = render(
      React.createElement(LiveInstall, {
        view: {
          phase: "done",
          total: 1,
          verified: 0,
          flagged: 0,
          blocked: {
            kind: "blocked",
            packageName: "pypi:evil-pkg@9.9.9",
            headline: "confirmed malware",
            reason: "remote code execution in install hook",
            nextStep: "Do not install. Remove the dependency or pin a known-safe version."
          }
        }
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("✘");
    expect(frame).toContain("DG blocked install — confirmed malware");
    expect(frame).toContain("pypi:evil-pkg@9.9.9");
    expect(frame).toContain("remote code execution in install hook");
    expect(frame).toContain("Next:");
  });

  it("renders a could-not-verify panel distinctly from a malware block", () => {
    const { lastFrame, unmount } = render(
      React.createElement(LiveInstall, {
        view: {
          phase: "done",
          total: 1,
          verified: 0,
          flagged: 0,
          blocked: {
            kind: "unverified",
            packageName: "pypi:numpy@2.4.6",
            headline: "scanner timed out",
            reason: "This operation was aborted",
            override: "re-run with --dg-force-install"
          }
        }
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("could not verify pypi:numpy@2.4.6");
    expect(frame).not.toContain("blocked install");
    expect(frame).toContain("Override:");
  });

  it("shows the startup spinner immediately while the proxy is coming up", () => {
    const { lastFrame, unmount } = render(
      React.createElement(LiveInstall, {
        view: { phase: "scanning", total: 0, verified: 0, flagged: 0 }
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("DG starting protection…");
    expect(frame).not.toContain("0 packages");
  });

  it("switches to the counted verifying line once the first package is fetched", () => {
    const { lastFrame, unmount } = render(
      React.createElement(LiveInstall, {
        view: { phase: "scanning", total: 1, verified: 0, flagged: 0 }
      })
    );
    const frame = lastFrame() ?? "";
    unmount();
    expect(frame).toContain("DG verifying 1 package…");
  });

  it("renders nothing for a cache-only run that fetched nothing", () => {
    const { lastFrame, unmount } = render(
      React.createElement(LiveInstall, {
        view: { phase: "done", total: 0, verified: 0, flagged: 0 }
      })
    );
    const frame = (lastFrame() ?? "").trim();
    unmount();
    expect(frame).toBe("");
  });
});
