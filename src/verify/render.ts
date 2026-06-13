import { createTheme, type Role, type ScannerAction, type Theme } from "../presentation/theme.js";
import { packagePageUrl } from "../presentation/package-page.js";
import { sanitizeDeep } from "../security/sanitize.js";
import type { VerifyFinding, VerifyReport } from "./types.js";

const STATUS_ROLE: Record<VerifyReport["status"], Role> = {
  pass: "pass",
  warn: "warn",
  block: "block",
  unknown: "unknown",
  error: "block"
};

const STATUS_ACTION: Record<VerifyReport["status"], ScannerAction> = {
  pass: "pass",
  warn: "warn",
  block: "block",
  unknown: "analysis_incomplete",
  error: "block"
};

export function renderVerifyText(report: VerifyReport, theme: Theme = createTheme(false), verbose = false): string {
  const safe = sanitizeDeep(report);
  return verbose ? renderVerifyVerbose(safe, theme) : renderVerifyCompact(safe, theme);
}

function renderVerifyCompact(report: VerifyReport, theme: Theme): string {
  const badge = report.status === "error" ? theme.paint("block", "✘ ERROR") : theme.badge(STATUS_ACTION[report.status]);
  const phrase = summaryPhrase(report);
  const lines = [phrase ? `${badge}  ${targetLabel(report)} — ${phrase}` : `${badge}  ${targetLabel(report)}`];

  if (report.sha256) {
    lines.push(theme.paint("muted", `  sha256 ${shortSha(report.sha256)}`));
  }

  for (const finding of report.findings) {
    const glyph = theme.paint(finding.severity === "block" ? "block" : "warn", finding.severity === "block" ? "✘" : "⚠");
    lines.push(`  ${glyph} ${finding.id}  ${finding.message}`);
  }

  for (const error of report.errors) {
    lines.push(`  ${theme.paint("block", "✘")} ${error}`);
  }

  const page = packageReportUrl(report);
  if (page) {
    lines.push(theme.paint("muted", `  → ${page}`));
  }

  return `${lines.join("\n")}\n`;
}

function packageReportUrl(report: VerifyReport): string | null {
  if (report.packages.length !== 1) {
    return null;
  }
  const identity = report.packages[0]!;
  return packagePageUrl(identity.ecosystem, identity.name);
}

function targetLabel(report: VerifyReport): string {
  if (report.packages.length === 1) {
    const identity = report.packages[0]!;
    const version = identity.version ? `@${identity.version}` : "";
    return `${identity.name}${version} (${identity.ecosystem})`;
  }
  if (report.workspaceScan) {
    const count = report.workspaceScan.summary.projectCount;
    return `${report.target} (${count} project${plural(count)})`;
  }
  if (report.preflight && report.preflight.packageCount > 1) {
    return `${report.target} (${report.preflight.packageCount} packages)`;
  }
  return report.target;
}

function summaryPhrase(report: VerifyReport): string {
  const { findingCount, warnCount, blockCount } = report.summary;
  if (report.status === "error") {
    return report.errors.length > 0 ? "verification failed" : "verification error";
  }
  if (findingCount === 0 && report.errors.length === 0) {
    return "";
  }
  if (blockCount > 0) {
    return `${blockCount} blocking finding${plural(blockCount)}${warnCount > 0 ? `, ${warnCount} warn` : ""}`;
  }
  if (warnCount > 0) {
    return `${warnCount} advisory finding${plural(warnCount)}`;
  }
  return "see details";
}

function shortSha(sha: string): string {
  return sha.length > 12 ? `${sha.slice(0, 4)}…${sha.slice(-4)}` : sha;
}

function plural(count: number): string {
  return count === 1 ? "" : "s";
}

function renderVerifyVerbose(report: VerifyReport, theme: Theme): string {
  const lines = [
    "Dependency Guardian verify",
    `Target: ${report.target}`,
    `Input: ${report.inputKind}`,
    `Status: ${theme.paint(STATUS_ROLE[report.status], report.status)}`,
    `SHA-256: ${report.sha256 ?? "not applicable"}`,
    `Findings: ${report.summary.findingCount} (${report.summary.warnCount} warn, ${report.summary.blockCount} block)`,
    ""
  ];

  if (report.archive) {
    lines.push(`Archive entries: ${report.archive.entryCount}`);
    lines.push(`Package manifests: ${report.archive.packageManifestCount}`);
    lines.push(`Unpacked bytes: ${report.archive.unpackedSizeBytes ?? "unknown"}`);
    lines.push("");
  }

  if (report.workspaceScan) {
    lines.push(`Projects: ${report.workspaceScan.summary.projectCount}`);
    lines.push(`Dependencies: ${report.workspaceScan.summary.dependencyCount}`);
    lines.push("");
  }

  if (report.preflight) {
    lines.push(`Packages: ${report.preflight.packageCount}`);
    lines.push(`Identity source: ${report.preflight.identitySource}`);
    lines.push(`Advisory: ${report.preflight.message}`);
    lines.push("");
  }

  if (report.packages.length > 0) {
    lines.push("Package identities:");
    for (const identity of report.packages) {
      const version = identity.version ? `@${identity.version}` : "";
      const integrity = identity.integrity ? " integrity" : " no-integrity";
      const license = identity.license ? ` license=${identity.license}` : "";
      lines.push(`- ${identity.ecosystem}:${identity.name}${version} (${identity.sourceKind}${integrity}${license})`);
    }
    lines.push("");
  }

  if (report.findings.length === 0 && report.errors.length === 0) {
    lines.push(report.preflight ? "No advisory preflight issues found." : "No local verification issues found.");
  }

  for (const finding of report.findings) {
    lines.push(`${theme.paint(finding.severity === "block" ? "block" : "warn", finding.severity.toUpperCase())} ${finding.id} ${finding.location}: ${finding.message}`);
  }

  for (const error of report.errors) {
    lines.push(`ERROR ${error}`);
  }

  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd()}\n`;
}

export function renderVerifyJson(report: VerifyReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function renderVerifySarif(report: VerifyReport): string {
  const rules = uniqueFindings(report.findings).map((finding) => ({
    id: finding.id,
    name: finding.title,
    shortDescription: {
      text: finding.title
    },
    fullDescription: {
      text: finding.message
    },
    defaultConfiguration: {
      level: finding.severity === "block" ? "error" : "warning"
    }
  }));

  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Dependency Guardian",
            informationUri: "https://westbayberry.com",
            rules
          }
        },
        results: report.findings.map((finding) => ({
          ruleId: finding.id,
          level: finding.severity === "block" ? "error" : "warning",
          message: {
            text: finding.message
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: artifactUri(finding.location)
                }
              }
            }
          ]
        }))
      }
    ]
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

function artifactUri(location: string): string {
  return location.replace(/:\d+$/, "");
}

function uniqueFindings(findings: readonly VerifyFinding[]): VerifyFinding[] {
  const seen = new Set<string>();
  const unique: VerifyFinding[] = [];
  for (const finding of findings) {
    if (seen.has(finding.id)) {
      continue;
    }
    seen.add(finding.id);
    unique.push(finding);
  }
  return unique;
}
