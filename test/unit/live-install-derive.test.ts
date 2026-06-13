import { describe, expect, it } from "vitest";
import { deriveLiveView, runWithProductionProxyLive } from "../../src/launcher/run.js";
import type { ProxySessionState } from "../../src/proxy/server.js";
import type { EnforcementDecision } from "../../src/proxy/enforcement.js";

describe("runWithProductionProxyLive guards", () => {
  it("rejects streaming output callbacks (would contend with Ink for the TTY)", async () => {
    const plan = { classification: { manager: "npm" }, realBinary: { path: "/bin/true" }, startsProxy: true, childEnv: {} } as never;
    await expect(
      runWithProductionProxyLive(plan, ["install", "x"], { onStdout: () => undefined } as never, () => undefined)
    ).rejects.toThrow(/streaming output callbacks are not supported/);
    await expect(
      runWithProductionProxyLive(plan, ["install", "x"], { onStderr: () => undefined } as never, () => undefined)
    ).rejects.toThrow(/streaming output callbacks are not supported/);
  });
});

function baseState(overrides: Partial<ProxySessionState>): ProxySessionState {
  return {
    ready: true,
    port: 1234,
    decisions: [],
    inflight: [],
    hashes: [],
    identities: [],
    events: [],
    ...overrides
  };
}

function decision(action: EnforcementDecision["action"], cause: EnforcementDecision["cause"], packageName: string, reason: string): EnforcementDecision {
  return { action, cause, packageName, reason } as EnforcementDecision;
}

describe("deriveLiveView (live install state → view)", () => {
  it("reports the in-flight package and a growing total while scanning", () => {
    const view = deriveLiveView(
      baseState({
        decisions: [decision("pass", "pass", "pypi:pandas@3.0.3", "clean")],
        inflight: ["pypi:numpy@2.4.6"]
      }),
      "scanning"
    );
    expect(view).toMatchObject({ phase: "scanning", total: 2, verified: 1, flagged: 0, current: "pypi:numpy@2.4.6" });
    expect(view.blocked).toBeUndefined();
  });

  it("counts verified and flagged at done and names the flagged packages", () => {
    const view = deriveLiveView(
      baseState({
        decisions: [
          decision("pass", "pass", "a@1", "clean"),
          decision("pass", "pass", "b@1", "clean"),
          decision("warn", "warn", "c@1", "flagged for review")
        ]
      }),
      "done"
    );
    expect(view).toMatchObject({ phase: "done", total: 3, verified: 2, flagged: 1 });
    expect(view.flaggedItems).toEqual([{ packageName: "c@1", reason: "flagged for review" }]);
  });

  it("labels override-allowed and quota warns distinctly (never as a benign reason)", () => {
    const overridden = {
      action: "warn", cause: "malware", packageName: "evil@1", reason: "rce in install hook",
      forceOverride: { allowed: true, reason: "user override" }
    } as EnforcementDecision;
    const quota = {
      action: "warn", cause: "quota-exceeded", packageName: "big@1",
      reason: "over monthly quota — installed unverified per your dashboard setting"
    } as EnforcementDecision;
    const view = deriveLiveView(baseState({ decisions: [overridden, quota] }), "done");
    expect(view.flagged).toBe(2);
    expect(view.flaggedItems).toEqual([
      { packageName: "evil@1", reason: "installed despite block (--dg-force-install)" },
      { packageName: "big@1", reason: "installed unverified (over quota)" }
    ]);
  });

  it("maps a malware decision to a blocked panel", () => {
    const view = deriveLiveView(
      baseState({ decisions: [decision("block", "malware", "pypi:evil@1.0.0", "rce in install hook")] }),
      "done"
    );
    expect(view.blocked?.kind).toBe("blocked");
    expect(view.blocked?.headline).toBe("confirmed malware");
    expect(view.blocked?.packageName).toBe("pypi:evil@1.0.0");
  });

  it("maps a scanner timeout to a could-not-verify panel (never malware)", () => {
    const view = deriveLiveView(
      baseState({ decisions: [decision("block", "api-timeout", "pypi:numpy@2.4.6", "This operation was aborted")] }),
      "done"
    );
    expect(view.blocked?.kind).toBe("unverified");
    expect(view.blocked?.headline).toBe("scanner timed out");
    expect(view.blocked?.override).toContain("--dg-force-install");
  });

  it("is empty before any package is fetched", () => {
    const view = deriveLiveView(baseState({}), "scanning");
    expect(view).toMatchObject({ total: 0, verified: 0, flagged: 0 });
    expect(view.current).toBeUndefined();
  });
});
