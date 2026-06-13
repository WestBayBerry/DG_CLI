import type { ScannerProvenance } from "../api/analyze.js";

export function provenanceLabel(provenance: ScannerProvenance): string {
  if (provenance.status === "attested") {
    const tag = slsaTag(provenance.predicateType);
    return tag ? `attested (${tag})` : "attested";
  }
  if (provenance.status === "none") {
    return "none";
  }
  return "unknown (not yet checked)";
}

export function provenanceDowngradeLine(version: string, provenance: ScannerProvenance): string | null {
  if (!provenance.downgrade) {
    return null;
  }
  return `provenance downgraded — ${provenance.downgrade.fromVersion} was attested, ${version} is not`;
}

function slsaTag(predicateType: string | undefined): string | null {
  if (!predicateType) {
    return null;
  }
  const match = /slsa\.dev\/provenance\/(v[0-9][0-9.]*)/.exec(predicateType);
  return match ? `slsa ${match[1]}` : null;
}
