import type { ScannerAction, ScannerFinding, ScannerPackageResult } from "../api/analyze.js";
import type { DecisionEcosystem, DecisionEntry, DgFile } from "../project/dgfile.js";

export type DecisionAcknowledgement = {
  readonly decisionId: string;
  readonly by: string;
  readonly at: string;
  readonly reason: string;
};

export type DecisionMatch =
  | { readonly acknowledged: true; readonly entry: DecisionEntry }
  | { readonly acknowledged: false; readonly newFindings?: readonly string[] };

export type PackageAnnotation = {
  readonly ecosystem: DecisionEcosystem;
  readonly acknowledged?: DecisionAcknowledgement;
  readonly newFindings?: readonly string[];
};

export type AppliedDecisions = {
  readonly file: string;
  readonly acknowledgedCount: number;
  readonly effectiveAction: ScannerAction;
  readonly packages: Readonly<Record<string, PackageAnnotation>>;
};

export function packageKey(name: string, version: string): string {
  return `${name}@${version}`;
}

export function findingCategory(finding: ScannerFinding): string {
  return finding.category ?? finding.id ?? "unknown";
}

export function findingFingerprint(findings: readonly ScannerFinding[]): Record<string, number> {
  const fingerprint: Record<string, number> = {};
  for (const finding of findings) {
    const category = findingCategory(finding);
    fingerprint[category] = Math.max(fingerprint[category] ?? 0, finding.severity);
  }
  return fingerprint;
}

export function matchDecision(
  pkg: Pick<ScannerPackageResult, "name" | "version" | "action" | "findings">,
  ecosystem: DecisionEcosystem,
  entries: readonly DecisionEntry[],
  now = new Date()
): DecisionMatch {
  if ((pkg.action ?? "pass") !== "warn") {
    return { acknowledged: false };
  }
  const fingerprint = findingFingerprint(pkg.findings);
  let nearestUncovered: string[] | undefined;
  for (const entry of entries) {
    if (entry.ecosystem !== ecosystem || entry.name !== pkg.name) {
      continue;
    }
    if (!scopeMatches(entry, pkg.version)) {
      continue;
    }
    if (isExpired(entry, now)) {
      continue;
    }
    const uncovered = uncoveredFindings(fingerprint, entry.findings);
    if (uncovered.length === 0) {
      return { acknowledged: true, entry };
    }
    if (!nearestUncovered || uncovered.length < nearestUncovered.length) {
      nearestUncovered = uncovered;
    }
  }
  return nearestUncovered ? { acknowledged: false, newFindings: nearestUncovered } : { acknowledged: false };
}

export function applyDecisions(
  packages: readonly ScannerPackageResult[],
  ecosystemOf: (pkg: ScannerPackageResult) => DecisionEcosystem | undefined,
  file: DgFile,
  rawAction: ScannerAction,
  now = new Date()
): AppliedDecisions {
  const annotations: Record<string, PackageAnnotation> = {};
  let acknowledgedCount = 0;
  let worst = 0;
  for (const pkg of packages) {
    const action = pkg.action ?? "pass";
    if (action === "pass") {
      continue;
    }
    const ecosystem = ecosystemOf(pkg);
    if (!ecosystem) {
      worst = Math.max(worst, actionSeverity(action));
      continue;
    }
    const match = file.readable ? matchDecision(pkg, ecosystem, file.decisions, now) : { acknowledged: false as const };
    const key = packageKey(pkg.name, pkg.version);
    if (match.acknowledged) {
      acknowledgedCount += 1;
      annotations[key] = {
        ecosystem,
        acknowledged: {
          decisionId: match.entry.id,
          by: match.entry.acceptedBy,
          at: match.entry.acceptedAt,
          reason: match.entry.reason
        }
      };
    } else {
      annotations[key] = {
        ecosystem,
        ...(match.newFindings ? { newFindings: match.newFindings } : {})
      };
      worst = Math.max(worst, actionSeverity(action));
    }
  }
  const effectiveAction =
    acknowledgedCount === 0 || worst >= actionSeverity(rawAction) ? rawAction : actionFromSeverity(worst);
  return {
    file: file.path,
    acknowledgedCount,
    effectiveAction,
    packages: annotations
  };
}

const ACTION_SEVERITY: Record<ScannerAction, number> = {
  pass: 0,
  analysis_incomplete: 1,
  warn: 2,
  block: 3
};

function actionSeverity(action: ScannerAction): number {
  return ACTION_SEVERITY[action] ?? 0;
}

function actionFromSeverity(severity: number): ScannerAction {
  if (severity >= 3) {
    return "block";
  }
  if (severity === 2) {
    return "warn";
  }
  if (severity === 1) {
    return "analysis_incomplete";
  }
  return "pass";
}

function scopeMatches(entry: DecisionEntry, version: string): boolean {
  if (entry.scope.kind === "any") {
    return true;
  }
  return entry.scope.version === version;
}

function isExpired(entry: DecisionEntry, now: Date): boolean {
  if (!entry.expiresAt) {
    return false;
  }
  const expiry = Date.parse(entry.expiresAt);
  return !Number.isFinite(expiry) || expiry <= now.getTime();
}

function uncoveredFindings(fingerprint: Readonly<Record<string, number>>, accepted: Readonly<Record<string, number>>): string[] {
  const uncovered: string[] = [];
  for (const [category, severity] of Object.entries(fingerprint)) {
    const acceptedSeverity = accepted[category];
    if (acceptedSeverity === undefined || severity > acceptedSeverity) {
      uncovered.push(`${category}:${severity}`);
    }
  }
  return uncovered.sort();
}
