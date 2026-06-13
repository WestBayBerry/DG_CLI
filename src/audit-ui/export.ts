import { findingLocation, type AuditFinding } from "../audit/detectors.js";
import type { DeepResult } from "../audit/deep.js";
import { deepSummary } from "../audit/deep.js";
import { severityKind, WARN_GLYPH } from "./format.js";

export type AuditExportFormat = "json" | "md" | "txt";

export interface AuditExportInput {
  readonly target: string;
  readonly artifact: string;
  readonly ecosystem: string;
  readonly action: "block" | "warn" | "pass";
  readonly fileCount: number;
  readonly publishSetSource: string;
  readonly findings: readonly AuditFinding[];
  readonly deep: DeepResult;
}

function countSummaryLine(findings: readonly AuditFinding[]): string {
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

function buildJson(input: AuditExportInput): string {
  const report = {
    target: input.target,
    artifact: input.artifact,
    ecosystem: input.ecosystem,
    action: input.action,
    fileCount: input.fileCount,
    publishSetSource: input.publishSetSource,
    findings: input.findings,
    deep: input.deep
  };
  return `${JSON.stringify(report, null, 2)}\n`;
}

function buildMd(input: AuditExportInput): string {
  const lines: string[] = [
    `# Dependency Guardian — audit of ${input.artifact}`,
    "",
    `**Verdict:** ${input.action.toUpperCase()}  ·  ${input.ecosystem}`,
    `**Files:** ${input.fileCount}  ·  ${countSummaryLine(input.findings)}`,
    input.publishSetSource === "fallback" ? "**Publish set approximated**" : "",
    `**Deep behavioral scan:** ${deepSummary(input.deep)}`
  ].filter((line, index) => line !== "" || index === 1);

  if (input.findings.length === 0) {
    lines.push("", "> No findings — the publish set is clean.", "");
    return `${lines.join("\n")}\n`;
  }

  lines.push("", "| Severity | Location | Title | Evidence | Recommendation |", "|---|---|---|---|---|");
  for (const finding of input.findings) {
    const kind = severityKind(finding.severity);
    const sev = kind === "block" ? "BLOCK" : kind === "warn" ? "WARN" : "NOTE";
    const cell = (value: string): string => value.replace(/\|/g, "\\|").replace(/\n/g, " ");
    lines.push(`| ${sev} | ${cell(findingLocation(finding))} | ${cell(finding.title)} | ${cell(finding.evidence)} | ${cell(finding.recommendation)} |`);
  }
  lines.push("");
  return `${lines.join("\n")}\n`;
}

function buildTxt(input: AuditExportInput): string {
  const glyph = input.action === "block" ? "✘" : input.action === "warn" ? WARN_GLYPH : "✓";
  const fallback = input.publishSetSource === "fallback" ? " · publish set approximated" : "";
  const lines: string[] = [
    `${glyph} ${input.action.toUpperCase()}   ${input.artifact} · ${input.ecosystem}`,
    `${countSummaryLine(input.findings)} in ${input.fileCount} file${input.fileCount === 1 ? "" : "s"}${fallback}`,
    ""
  ];

  for (const finding of input.findings) {
    const kind = severityKind(finding.severity);
    const tag = kind === "block" ? "✘" : kind === "warn" ? WARN_GLYPH : "·";
    lines.push(`  ${tag} ${findingLocation(finding)}`);
    lines.push(`     ${finding.title}`);
    if (finding.evidence && finding.evidence !== `path: ${finding.location}` && finding.evidence !== finding.location) {
      lines.push(`     ${finding.evidence}`);
    }
    lines.push(`     → ${finding.recommendation}`);
    lines.push("");
  }

  lines.push(`  Deep behavioral scan · ${deepSummary(input.deep)}`);
  return `${lines.join("\n")}\n`;
}

export function buildExport(input: AuditExportInput, format: AuditExportFormat): { body: string; ext: AuditExportFormat } {
  if (format === "json") return { body: buildJson(input), ext: "json" };
  if (format === "md") return { body: buildMd(input), ext: "md" };
  return { body: buildTxt(input), ext: "txt" };
}
