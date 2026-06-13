import { describe, expect, it } from "vitest";
import { applyDecisions, findingFingerprint, matchDecision } from "../../src/decisions/apply.js";
import { effectiveScanAction } from "../../src/scan-ui/shims.js";
import type { DecisionEntry, DgFile } from "../../src/project/dgfile.js";
import type { ScannerPackageResult } from "../../src/api/analyze.js";

function entry(over: Partial<DecisionEntry> = {}): DecisionEntry {
  return {
    id: "decision-1",
    ecosystem: "npm",
    name: "left-pad",
    scope: { kind: "exact", version: "1.3.0" },
    findings: { lifecycle: 3 },
    reason: "accepted",
    acceptedBy: "alice",
    acceptedAt: "2026-06-01T00:00:00.000Z",
    ...over
  };
}

function pkg(over: Partial<ScannerPackageResult> = {}): ScannerPackageResult {
  return {
    name: "left-pad",
    version: "1.3.0",
    score: 64,
    action: "warn",
    findings: [{ severity: 3, category: "lifecycle" }],
    reasons: ["install lifecycle script"],
    cached: false,
    ...over
  };
}

function store(entries: DecisionEntry[], readable = true): DgFile {
  return { path: "/repo/dg.json", exists: true, readable, raw: {}, decisions: entries };
}

const now = new Date("2026-06-10T00:00:00.000Z");

describe("matchDecision invalidation matrix", () => {
  it("never acknowledges a block, even with a fully covering any-scope entry", () => {
    const match = matchDecision(pkg({ action: "block" }), "npm", [entry({ scope: { kind: "any" }, findings: { lifecycle: 5, malware: 5 } })], now);
    expect(match.acknowledged).toBe(false);
  });

  it("never acknowledges analysis_incomplete", () => {
    const match = matchDecision(pkg({ action: "analysis_incomplete" }), "npm", [entry({ scope: { kind: "any" } })], now);
    expect(match.acknowledged).toBe(false);
  });

  it("acknowledges a warn whose fingerprint is fully covered", () => {
    const match = matchDecision(pkg(), "npm", [entry()], now);
    expect(match.acknowledged).toBe(true);
  });

  it("re-surfaces on a NEW finding category at the same version", () => {
    const match = matchDecision(
      pkg({ findings: [{ severity: 3, category: "lifecycle" }, { severity: 4, category: "network_exfil" }] }),
      "npm",
      [entry()],
      now
    );
    expect(match.acknowledged).toBe(false);
    expect(match.acknowledged === false && match.newFindings).toEqual(["network_exfil:4"]);
  });

  it("re-surfaces on a severity escalation within an accepted category", () => {
    const match = matchDecision(pkg({ findings: [{ severity: 4, category: "lifecycle" }] }), "npm", [entry()], now);
    expect(match.acknowledged).toBe(false);
    expect(match.acknowledged === false && match.newFindings).toEqual(["lifecycle:4"]);
  });

  it("stays acknowledged when severity drops within an accepted category", () => {
    const match = matchDecision(pkg({ findings: [{ severity: 2, category: "lifecycle" }] }), "npm", [entry()], now);
    expect(match.acknowledged).toBe(true);
  });

  it("ignores score-only changes — the fingerprint excludes score", () => {
    const match = matchDecision(pkg({ score: 99 }), "npm", [entry()], now);
    expect(match.acknowledged).toBe(true);
  });

  it("does not match an exact entry against another version", () => {
    const match = matchDecision(pkg({ version: "1.4.0" }), "npm", [entry()], now);
    expect(match.acknowledged).toBe(false);
    expect(match.acknowledged === false && match.newFindings).toBeUndefined();
  });

  it("matches an any-scope entry across versions", () => {
    const match = matchDecision(pkg({ version: "9.9.9" }), "npm", [entry({ scope: { kind: "any" } })], now);
    expect(match.acknowledged).toBe(true);
  });

  it("keys on ecosystem — a pypi entry never covers the npm package of the same name", () => {
    const match = matchDecision(pkg(), "npm", [entry({ ecosystem: "pypi" })], now);
    expect(match.acknowledged).toBe(false);
  });

  it("ignores expired entries and honors future expiries", () => {
    expect(matchDecision(pkg(), "npm", [entry({ expiresAt: "2026-06-09T00:00:00.000Z" })], now).acknowledged).toBe(false);
    expect(matchDecision(pkg(), "npm", [entry({ expiresAt: "2027-01-01T00:00:00.000Z" })], now).acknowledged).toBe(true);
  });

  it("treats an unparseable expiry as expired (fail open)", () => {
    expect(matchDecision(pkg(), "npm", [entry({ expiresAt: "next tuesday-ish" })], now).acknowledged).toBe(false);
  });

  it("covers an action-only warn (no findings) with an empty fingerprint entry", () => {
    const match = matchDecision(pkg({ findings: [], score: 0 }), "npm", [entry({ findings: {} })], now);
    expect(match.acknowledged).toBe(true);
  });

  it("an empty-fingerprint entry stops covering once any real finding appears", () => {
    const match = matchDecision(pkg(), "npm", [entry({ findings: {} })], now);
    expect(match.acknowledged).toBe(false);
    expect(match.acknowledged === false && match.newFindings).toEqual(["lifecycle:3"]);
  });
});

describe("findingFingerprint", () => {
  it("keeps the max severity per category", () => {
    expect(
      findingFingerprint([
        { severity: 2, category: "lifecycle" },
        { severity: 4, category: "lifecycle" },
        { severity: 3, category: "network_exfil" }
      ])
    ).toEqual({ lifecycle: 4, network_exfil: 3 });
  });

  it("falls back to id, then unknown, when the wire omits category", () => {
    expect(findingFingerprint([{ severity: 3, id: "raw-id" }, { severity: 2 }])).toEqual({ "raw-id": 3, unknown: 2 });
  });
});

describe("applyDecisions effective action", () => {
  const eco = () => "npm" as const;

  it("downgrades to pass when every warn is acknowledged", () => {
    const applied = applyDecisions([pkg()], eco, store([entry()]), "warn", now);
    expect(applied.acknowledgedCount).toBe(1);
    expect(applied.effectiveAction).toBe("pass");
    expect(applied.packages["left-pad@1.3.0"]?.acknowledged?.by).toBe("alice");
  });

  it("stays warn while any warn is unacknowledged", () => {
    const applied = applyDecisions(
      [pkg(), pkg({ name: "other-pkg", findings: [{ severity: 4, category: "network_exfil" }] })],
      eco,
      store([entry()]),
      "warn",
      now
    );
    expect(applied.acknowledgedCount).toBe(1);
    expect(applied.effectiveAction).toBe("warn");
  });

  it("never downgrades a block aggregate", () => {
    const applied = applyDecisions(
      [pkg(), pkg({ name: "evil", action: "block", findings: [{ severity: 5, category: "malware" }] })],
      eco,
      store([entry(), entry({ id: "d2", name: "evil", scope: { kind: "any" }, findings: { malware: 5 } })]),
      "block",
      now
    );
    expect(applied.effectiveAction).toBe("block");
    expect(applied.packages["evil@1.3.0"]?.acknowledged).toBeUndefined();
  });

  it("keeps the raw action when nothing is acknowledged", () => {
    const applied = applyDecisions([pkg({ findings: [{ severity: 5, category: "lifecycle" }] })], eco, store([entry()]), "warn", now);
    expect(applied.acknowledgedCount).toBe(0);
    expect(applied.effectiveAction).toBe("warn");
  });

  it("treats a package with an unknown ecosystem as unacknowledged", () => {
    const applied = applyDecisions([pkg()], () => undefined, store([entry()]), "warn", now);
    expect(applied.acknowledgedCount).toBe(0);
    expect(applied.effectiveAction).toBe("warn");
  });

  it("acknowledges nothing through an unreadable store", () => {
    const applied = applyDecisions([pkg()], eco, store([entry()], false), "warn", now);
    expect(applied.acknowledgedCount).toBe(0);
    expect(applied.effectiveAction).toBe("warn");
  });

  it("surfaces analysis_incomplete that was masked behind acknowledged warns", () => {
    const applied = applyDecisions(
      [pkg(), pkg({ name: "mystery", action: "analysis_incomplete", findings: [] })],
      eco,
      store([entry()]),
      "warn",
      now
    );
    expect(applied.effectiveAction).toBe("analysis_incomplete");
  });
});

describe("effectiveScanAction (exit-code seam)", () => {
  it("uses the effective action outside strict mode", () => {
    expect(effectiveScanAction("warn", "pass", "block")).toBe("pass");
    expect(effectiveScanAction("warn", "pass", "warn")).toBe("pass");
  });

  it("strict mode ignores decision memory", () => {
    expect(effectiveScanAction("warn", "pass", "strict")).toBe("warn");
  });

  it("falls back to the raw action without decisions", () => {
    expect(effectiveScanAction("warn", undefined, "block")).toBe("warn");
  });
});
