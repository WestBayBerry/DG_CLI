import { describe, expect, it } from "vitest";
import { describeBlockedInstall, renderInstallDecision } from "../../src/install-ui/block-render.js";
import type { EnforcementDecision } from "../../src/proxy/enforcement.js";

function decision(overrides: Partial<EnforcementDecision>): EnforcementDecision {
  return {
    action: "block",
    cause: "malware",
    packageName: "left-pad@1.3.0",
    policyMode: "block",
    reason: "credential exfiltration",
    ...overrides
  };
}

describe("renderInstallDecision", () => {
  it("renders a clean pass as a single verified line", () => {
    const out = renderInstallDecision(decision({ action: "pass", cause: "pass", reason: "verdict pass" }));
    expect(out).toBe("✓ DG verified left-pad@1.3.0 — clean\n");
  });

  it("renders a warn as a flagged line with the reason", () => {
    const out = renderInstallDecision(decision({ action: "warn", cause: "warn", reason: "install lifecycle script" }));
    expect(out).toContain("⚠ DG flagged left-pad@1.3.0 (warn)");
    expect(out).toContain("install lifecycle script");
  });

  it("renders a verified-bad block as the 5-part explanation", () => {
    const out = renderInstallDecision(decision({
      cause: "malware",
      dashboardUrl: "https://dash.example/p/left-pad"
    }));
    expect(out).toContain("✘ DG blocked install — confirmed malware");
    expect(out).toContain("credential exfiltration");
    expect(out).toContain("Evidence: https://dash.example/p/left-pad");
    expect(out).toContain("Override: re-run with --dg-force-install");
    expect(out).toContain("Next:");
  });

  it("renders a degraded cause as could-not-verify, never as a verdict", () => {
    const out = renderInstallDecision(decision({ cause: "api-timeout", reason: "verdict lookup timed out" }));
    expect(out).toContain("? DG could not verify left-pad@1.3.0 — scanner timed out");
    expect(out).not.toContain("DG blocked install");
  });

  it("renders an anonymous registry check as a sign-in gate, not scanner-unavailable", () => {
    const out = renderInstallDecision(decision({
      cause: "needs-login",
      unauthenticated: true,
      reason: "Checking a package from the registry before it installs requires sign-in."
    }));
    expect(out).toContain("sign-in required");
    expect(out).not.toContain("scanner unavailable");
    expect(out).toContain("Run 'dg login'");
    expect(out).not.toContain("Auth: local policy only");
  });

  it("shows policy-denied override when force was refused", () => {
    const out = renderInstallDecision(decision({
      cause: "policy",
      forceOverride: { allowed: false, reason: "force override is disabled by policy" }
    }));
    expect(out).toContain("Override: not allowed by your policy");
  });

  it("renders a granted force override as an install-despite-block notice", () => {
    const out = renderInstallDecision(decision({
      action: "warn",
      forceOverride: { allowed: true, reason: "developer override via --dg-force-install" }
    }));
    expect(out).toContain("⚠ DG override — installing left-pad@1.3.0 despite block (--dg-force-install)");
  });

  it("renders an over-quota block as the short two-line form with the reset date", () => {
    const out = renderInstallDecision(decision({
      cause: "quota-exceeded",
      resetsAt: "2026-07-01T00:00:00.000Z",
      reason: "You've reached your monthly scan limit."
    }));
    expect(out).toBe("Quota hit — resets 07/01\nOverride:  --dg-force-install\n");
    expect(out).not.toContain("could not verify");
    expect(out).not.toContain("Next:");
  });

  it("renders over-quota with pass behavior as an installed-unverified warning", () => {
    const out = renderInstallDecision(decision({
      action: "warn",
      cause: "quota-exceeded",
      resetsAt: "2026-07-01T00:00:00.000Z"
    }));
    expect(out).toBe("⚠ Over quota — installed left-pad@1.3.0 unverified (resets 07/01)\n");
  });

  it("renders the over-quota block without a date when the server sent none", () => {
    const out = renderInstallDecision(decision({ cause: "quota-exceeded" }));
    expect(out).toBe("Quota hit\nOverride:  --dg-force-install\n");
  });

  it("renders a cooldown block as a quarantine with age, window, eligible date, and the override line", () => {
    const out = renderInstallDecision(decision({
      packageName: "left-pad@2.0.1",
      cause: "cooldown",
      reason: "published 3h ago — younger than your 24h cooldown",
      dashboardUrl: "https://dash.example/p/npm/left-pad@2.0.1",
      cooldown: { requiredDays: 1, ageDays: 0.125, publishedAt: "2026-06-10T09:00:00.000Z", eligibleAt: "2026-06-11T09:00:00.000Z" }
    }));
    expect(out).toContain("? DG quarantined left-pad@2.0.1 — release too new (cooldown)");
    expect(out).toContain("published 3h ago; your cooldown is 24h (eligible 06/11)");
    expect(out).toContain("Override: re-run with --dg-force-install");
    expect(out).toContain("Next: Wait it out (see holds: dg cooldown), pin an older version, or exempt it: dg cooldown exempt <name>");
    expect(out).not.toContain("DG blocked install");
    expect(out).not.toContain("malware");
  });

  it("renders an unknown-publish-time cooldown block without an age line", () => {
    const out = renderInstallDecision(decision({
      cause: "cooldown",
      reason: "publish time could not be determined — your 24h cooldown policy blocks unverifiable release ages",
      cooldown: { requiredDays: 1 }
    }));
    expect(out).toContain("publish time unknown; your cooldown is 24h");
    expect(out).not.toContain("published ");
  });

  it("summarizes a cooldown block as unverified (never malware framing) with the cooldown next step", () => {
    const summary = describeBlockedInstall(decision({
      cause: "cooldown",
      reason: "published 3h ago — younger than your 24h cooldown",
      cooldown: { requiredDays: 1, ageDays: 0.125 }
    }));
    expect(summary.kind).toBe("unverified");
    expect(summary.headline).toBe("release too new (cooldown)");
    expect(summary.override).toBe("re-run with --dg-force-install");
    expect(summary.nextStep).toContain("dg cooldown exempt");
  });
});
