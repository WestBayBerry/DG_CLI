import { describe, expect, it } from "vitest";
import { provenanceLabel, provenanceDowngradeLine } from "../../src/presentation/provenance.js";
import { renderTextReport } from "../../src/scan/render.js";
import type { ScanReport } from "../../src/scan/types.js";
import type { AnalyzeResponse, ScannerProvenance } from "../../src/api/analyze.js";

describe("provenanceLabel", () => {
  it("labels a slsa attestation with its version tag", () => {
    expect(provenanceLabel({ status: "attested", predicateType: "https://slsa.dev/provenance/v1" })).toBe("attested (slsa v1)");
  });

  it("labels an attestation without a recognized predicate as plain attested", () => {
    expect(provenanceLabel({ status: "attested" })).toBe("attested");
    expect(provenanceLabel({ status: "attested", predicateType: "https://example.com/other" })).toBe("attested");
  });

  it("labels none and unknown honestly — never the word verified", () => {
    expect(provenanceLabel({ status: "none" })).toBe("none");
    expect(provenanceLabel({ status: "unknown" })).toBe("unknown (not yet checked)");
    for (const status of ["attested", "none", "unknown"] as const) {
      expect(provenanceLabel({ status })).not.toContain("verified");
    }
  });
});

describe("provenanceDowngradeLine", () => {
  it("spells out the downgrade pair", () => {
    const prov: ScannerProvenance = { status: "none", downgrade: { fromVersion: "1.2.0" } };
    expect(provenanceDowngradeLine("1.3.0", prov)).toBe("provenance downgraded — 1.2.0 was attested, 1.3.0 is not");
  });

  it("returns null without a downgrade", () => {
    expect(provenanceDowngradeLine("1.3.0", { status: "none" })).toBeNull();
    expect(provenanceDowngradeLine("1.3.0", { status: "attested" })).toBeNull();
  });
});

function scannerResponse(provenance: ScannerProvenance | undefined): AnalyzeResponse {
  return {
    score: 0,
    action: "pass",
    packages: [
      {
        name: "left-pad",
        version: "1.3.0",
        score: 0,
        action: "pass",
        findings: [],
        reasons: [],
        cached: false,
        ...(provenance ? { provenance } : {})
      }
    ],
    safeVersions: {},
    durationMs: 5
  };
}

function reportWith(scanner: AnalyzeResponse): ScanReport {
  return {
    target: ".",
    status: "pass",
    projects: [],
    findings: [],
    errors: [],
    summary: { projectCount: 1, dependencyCount: 1, findingCount: 0, warnCount: 0, blockCount: 0, errorCount: 0 },
    scanner
  };
}

describe("renderTextReport provenance downgrades", () => {
  it("prints one line per downgraded package after the Scanner line", () => {
    const text = renderTextReport(reportWith(scannerResponse({ status: "none", downgrade: { fromVersion: "1.2.0" } })), 100);
    expect(text).toContain("Provenance downgrades: left-pad@1.3.0 (was attested at 1.2.0)");
  });

  it("prints nothing when no package was downgraded", () => {
    const attested = renderTextReport(reportWith(scannerResponse({ status: "attested" })), 100);
    expect(attested).not.toContain("Provenance downgrades");
    const absent = renderTextReport(reportWith(scannerResponse(undefined)), 100);
    expect(absent).not.toContain("Provenance downgrades");
  });
});
