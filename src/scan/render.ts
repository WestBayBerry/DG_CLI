import type { ScannerPackageResult } from "../api/analyze.js";
import { createTheme, type Role, type Theme } from "../presentation/theme.js";
import { packagePageUrl } from "../presentation/package-page.js";
import { sanitizeDeep } from "../security/sanitize.js";
import type { ScanFinding, ScanReport } from "./types.js";

const DETAIL_PROJECT_LIMIT = 8;
const CLEAN_PROJECT_PREVIEW_LIMIT = 5;
const FINDING_GROUP_PREVIEW_LIMIT = 3;

const SCAN_STATUS_ROLE: Record<ScanReport["status"], Role> = {
  pass: "pass",
  warn: "warn",
  block: "block",
  unknown: "unknown",
  error: "block"
};

export function displayScanStatus(report: ScanReport): string {
  return report.scannerError && report.status === "unknown" ? "analysis_incomplete" : report.status;
}

export type ScannerSkipNotice = "no_lockfile" | "empty_lockfile";

const SCANNER_SKIP_MESSAGES: Record<ScannerSkipNotice, string> = {
  no_lockfile: "no lockfile found — server verification skipped (local heuristics only)",
  empty_lockfile: "lockfile contains no scannable packages — server verification skipped (local heuristics only)"
};

export function renderTextReport(rawReport: ScanReport, terminalWidth = terminalWidthFromEnv(), theme: Theme = createTheme(false), scannerNotice?: ScannerSkipNotice): string {
  const report = sanitizeDeep(rawReport);
  const width = Math.max(48, Math.min(terminalWidth, 140));
  const cleanProjects = report.projects.filter((project) => project.findings.length === 0);
  const findingProjects = report.projects.filter((project) => project.findings.length > 0);
  const shouldCollapseProjects = report.projects.length > DETAIL_PROJECT_LIMIT;
  const acknowledgedCount = report.decisions?.acknowledgedCount ?? 0;
  const activeFindings = report.findings.filter((finding) => !finding.acknowledged);
  const lines = [
    "Dependency Guardian scan",
    `Target: ${report.target}`,
    `Scanning: checked ${report.summary.projectCount} project manifest${report.summary.projectCount === 1 ? "" : "s"}.`,
    `Status: ${paintEffectiveStatus(report, theme)}`,
    `Projects: ${report.summary.projectCount}`,
    `Dependencies: ${report.summary.dependencyCount}`,
    `Findings: ${report.summary.findingCount} (${report.summary.warnCount} warn, ${report.summary.blockCount} block)${acknowledgedCount > 0 ? ` · ${acknowledgedCount} acknowledged` : ""}`,
    ...(acknowledgedCount > 0
      ? [`Acknowledged: ${acknowledgedCount} warn verdict${acknowledgedCount === 1 ? "" : "s"} accepted in dg.json — run 'dg decisions' to review`]
      : []),
    ...(report.scanner
      ? [`Scanner: score ${report.scanner.score}, ${report.scanner.packages.length} packages verified`]
      : []),
    ...(report.scanner ? provenanceDowngradeLines(report.scanner.packages, theme) : []),
    ""
  ];

  if (report.scannerError) {
    const scannerError = report.scannerError;
    lines.push(theme.paint(scannerError.kind === "quota_exceeded" ? "warn" : "block", `server scan failed: ${scannerError.message}`));
    if (scannerError.scansUsed !== undefined || scannerError.scansLimit !== undefined) {
      lines.push(`scans used: ${scannerError.scansUsed ?? "?"} of ${scannerError.scansLimit ?? "?"}`);
    }
    lines.push("local heuristics only — no server verdict (run 'dg doctor' to diagnose)");
    lines.push("");
  } else if (scannerNotice) {
    lines.push(SCANNER_SKIP_MESSAGES[scannerNotice]);
    lines.push("");
  }

  if (report.projects.length === 0 && report.errors.length === 0 && !report.scanner && !report.scannerError) {
    lines.push("No supported project manifests found.");
  }

  if (findingProjects.length > 0) {
    lines.push("Finding groups:");
    for (const group of groupFindings(activeFindings)) {
      const severityLabel = theme.paint(group.severity === "block" ? "block" : "warn", group.severity.toUpperCase());
      lines.push(`  ${severityLabel} ${group.id}: ${group.count} finding${group.count === 1 ? "" : "s"} across ${group.projectCount} project${group.projectCount === 1 ? "" : "s"}`);
      for (const finding of group.examples) {
        lines.push(...wrapLine("    example: ", `${finding.project} at ${finding.location}: ${finding.message}`, width));
      }
      if (group.hiddenCount > 0) {
        lines.push(`    ${group.hiddenCount} more hidden by default.`);
      }
    }
    lines.push("");
  }

  if (shouldCollapseProjects) {
    if (findingProjects.length > 0) {
      lines.push(`Projects with findings: ${findingProjects.length}`);
      for (const project of findingProjects.slice(0, CLEAN_PROJECT_PREVIEW_LIMIT)) {
        const version = project.version ? `@${project.version}` : "";
        lines.push(`  ${project.name}${version} (${project.manifestPath}) findings:${project.findings.length}`);
      }
      if (findingProjects.length > CLEAN_PROJECT_PREVIEW_LIMIT) {
        lines.push(`  ${findingProjects.length - CLEAN_PROJECT_PREVIEW_LIMIT} more projects with findings hidden by default.`);
      }
    }
    if (cleanProjects.length > 0) {
      const preview = cleanProjects.slice(0, CLEAN_PROJECT_PREVIEW_LIMIT).map((project) => project.name).join(", ");
      const suffix = cleanProjects.length > CLEAN_PROJECT_PREVIEW_LIMIT ? `, plus ${cleanProjects.length - CLEAN_PROJECT_PREVIEW_LIMIT} more` : "";
      lines.push(`Clean projects collapsed: ${cleanProjects.length}${preview.length > 0 ? ` (${preview}${suffix})` : ""}.`);
    }
    lines.push(`For full project detail, run: dg scan ${quoteTarget(report.target)} in a terminal (opens the interactive view) or dg scan ${quoteTarget(report.target)} --json`);
    lines.push("");
  } else {
    for (const project of report.projects) {
      lines.push(...formatProject(project, width));
      lines.push("");
    }
  }

  lines.push(...packagePageLines(report, theme));

  for (const error of report.errors) {
    lines.push(...wrapLine(`ERROR ${error.location}: `, error.message, width));
  }

  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd()}\n`;
}

function packagePageLines(report: ScanReport, theme: Theme): string[] {
  const urls: string[] = [];
  const seen = new Set<string>();
  for (const pkg of report.scanner?.packages ?? []) {
    const action = pkg.action ?? "pass";
    if (action !== "block" && action !== "warn") {
      continue;
    }
    const url = packagePageUrl(pkg.ecosystem ?? "", pkg.name);
    if (url && !seen.has(url)) {
      seen.add(url);
      urls.push(url);
    }
  }
  if (urls.length === 0) {
    return [];
  }
  return ["Full report for each flagged package:", ...urls.map((url) => `  ${theme.paint("muted", url)}`), ""];
}

function provenanceDowngradeLines(packages: readonly ScannerPackageResult[], theme: Theme): string[] {
  return packages
    .filter((pkg) => pkg.provenance?.downgrade)
    .map((pkg) => theme.paint("warn", `Provenance downgrades: ${pkg.name}@${pkg.version} (was attested at ${pkg.provenance!.downgrade!.fromVersion})`));
}

function paintEffectiveStatus(report: ScanReport, theme: Theme): string {
  if (report.scanner && report.decisions && !report.scannerError) {
    const action = report.decisions.effectiveAction;
    if (action === "analysis_incomplete") {
      return theme.paint("unknown", "analysis_incomplete");
    }
    return theme.paint(SCAN_STATUS_ROLE[action], action);
  }
  return theme.paint(SCAN_STATUS_ROLE[report.status], displayScanStatus(report));
}

function formatProject(project: ScanReport["projects"][number], width: number): string[] {
  const lines: string[] = [];
    const version = project.version ? `@${project.version}` : "";
    const license = project.license ?? "unknown";
    lines.push(`${project.name}${version} (${project.manifestPath})`);
    lines.push(`  license: ${license}`);
    lines.push(`  dependencies: ${project.dependencyCount}`);
    if (project.findings.length === 0) {
      lines.push("  result: pass");
    } else {
      for (const finding of project.findings) {
        lines.push(...formatFinding(finding, width));
      }
    }
  return lines;
}

export function renderJsonReport(report: ScanReport, scannerUnavailable = false, nothingToScan = false): string {
  return `${JSON.stringify({ schemaVersion: 1, ...report, status: nothingToScan ? "nothing_to_scan" : displayScanStatus(report), scannerUnavailable }, null, 2)}\n`;
}

export function renderSarifReport(report: ScanReport): string {
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
          ],
          ...(finding.acknowledged
            ? {
                suppressions: [
                  {
                    kind: "external",
                    justification: finding.acknowledged.reason || `accepted by ${finding.acknowledged.by}`
                  }
                ]
              }
            : {})
        }))
      }
    ]
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

function artifactUri(location: string): string {
  return location.replace(/:\d+$/u, "");
}

function uniqueFindings(findings: readonly ScanFinding[]): ScanFinding[] {
  const seen = new Set<string>();
  const unique: ScanFinding[] = [];
  for (const finding of findings) {
    if (seen.has(finding.id)) {
      continue;
    }
    seen.add(finding.id);
    unique.push(finding);
  }
  return unique;
}

function formatFinding(finding: ScanFinding, width: number): string[] {
  const prefix = `  ${finding.severity.toUpperCase()} ${finding.id} ${finding.location}: `;
  return wrapLine(prefix, finding.message, width);
}

type FindingGroup = {
  id: string;
  severity: ScanFinding["severity"];
  count: number;
  projectCount: number;
  examples: ScanFinding[];
  hiddenCount: number;
};

function groupFindings(findings: readonly ScanFinding[]): FindingGroup[] {
  const groups = new Map<string, { findings: ScanFinding[]; projects: Set<string> }>();
  for (const finding of findings) {
    const key = `${finding.severity}:${finding.id}`;
    const group = groups.get(key) ?? {
      findings: [],
      projects: new Set<string>()
    };
    group.findings.push(finding);
    group.projects.add(finding.project);
    groups.set(key, group);
  }

  return [...groups.entries()]
    .map(([key, group]) => {
      const [severity, id] = key.split(":") as [ScanFinding["severity"], string];
      return {
        id,
        severity,
        count: group.findings.length,
        projectCount: group.projects.size,
        examples: group.findings.slice(0, FINDING_GROUP_PREVIEW_LIMIT),
        hiddenCount: Math.max(0, group.findings.length - FINDING_GROUP_PREVIEW_LIMIT)
      };
    })
    .sort((left, right) => {
      if (left.severity !== right.severity) {
        return left.severity === "block" ? -1 : 1;
      }
      return left.id.localeCompare(right.id);
    });
}

function quoteTarget(target: string): string {
  if (/^[A-Za-z0-9_./:-]+$/u.test(target)) {
    return target;
  }
  return JSON.stringify(target);
}

function wrapLine(prefix: string, text: string, width: number): string[] {
  if (prefix.length > width - 16) {
    return [
      prefix.trimEnd(),
      ...wrapLine("    ", text, width)
    ];
  }

  const available = Math.max(16, width - prefix.length);
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = "";

  for (const word of words) {
    if (current.length === 0) {
      current = word;
      continue;
    }
    if (current.length + 1 + word.length > available) {
      lines.push(current);
      current = word;
      continue;
    }
    current = `${current} ${word}`;
  }

  if (current.length > 0) {
    lines.push(current);
  }

  if (lines.length === 0) {
    return [prefix.trimEnd()];
  }

  const continuation = " ".repeat(Math.min(prefix.length, width - available));
  return lines.map((line, index) => `${index === 0 ? prefix : continuation}${line}`);
}

function terminalWidthFromEnv(): number {
  const override = process.env.NODE_ENV === "test" ? process.env.DG_TEST_TERMINAL_WIDTH : undefined;
  const value = override ?? String(process.stdout.columns ?? 100);
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 100;
}
