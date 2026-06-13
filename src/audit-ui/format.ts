import type { Role } from "../presentation/theme.js";
import type { AuditFinding } from "../audit/detectors.js";

export const WARN_GLYPH = "⚠︎";

export type SeverityKind = "block" | "warn" | "note";

export function severityKind(severity: number): SeverityKind {
  if (severity >= 4) return "block";
  if (severity === 3) return "warn";
  return "note";
}

export function severityGlyph(severity: number): string {
  const kind = severityKind(severity);
  return kind === "block" ? "✘" : kind === "warn" ? WARN_GLYPH : "·";
}

export function severityRole(severity: number): Role {
  const kind = severityKind(severity);
  return kind === "block" ? "block" : kind === "warn" ? "warn" : "muted";
}

export type VerdictAction = "block" | "warn" | "pass";

export function verdictGlyph(action: VerdictAction): string {
  return action === "block" ? "✘" : action === "warn" ? WARN_GLYPH : "✓";
}

export function countSummary(findings: readonly AuditFinding[]): string {
  const blocking = findings.filter((finding) => finding.severity >= 4).length;
  const warnings = findings.filter((finding) => finding.severity === 3).length;
  const notes = findings.filter((finding) => finding.severity < 3).length;
  return (
    [
      blocking ? `${blocking} blocking` : "",
      warnings ? `${warnings} warning${warnings === 1 ? "" : "s"}` : "",
      notes ? `${notes} note${notes === 1 ? "" : "s"}` : ""
    ]
      .filter(Boolean)
      .join(" · ") || "no issues"
  );
}
