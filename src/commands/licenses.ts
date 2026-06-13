import { readdirSync, statSync } from "node:fs";
import { launchScanTui, shouldLaunchScanTui } from "../scan-ui/launch.js";
import { writeReportAtomic } from "../util/report-writer.js";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { scanProject } from "../scan/discovery.js";
import { isSupportedLockfilePath, verifyLockfile } from "../verify/preflight.js";
import type { VerifyPackageIdentity } from "../verify/types.js";
import type { CommandResult, CommandSpec } from "./types.js";
import { EXIT_ANALYSIS_INCOMPLETE, EXIT_USAGE_VERDICT } from "./types.js";

type LicenseFormat = "text" | "json" | "csv" | "markdown";
type LicenseRisk =
  | "network-copyleft"
  | "no-license"
  | "permissive"
  | "strong-copyleft"
  | "unknown"
  | "unlicensed"
  | "weak-copyleft";

type LicenseEntry = {
  ecosystem: "cargo" | "npm" | "pypi" | "unknown";
  license: string | null;
  location: string;
  name: string;
  risk: LicenseRisk;
  source: "lockfile" | "manifest";
  version: string | null;
};

type LicenseReport = {
  target: string;
  status: "pass" | "block";
  entries: readonly LicenseEntry[];
  policy: {
    deniedLicenses: readonly string[];
    failOn: readonly LicenseRisk[];
  };
  summary: {
    packageCount: number;
    blockedCount: number;
    byRisk: Record<LicenseRisk, number>;
  };
};

type ParsedLicensesArgs = {
  deniedLicenses: string[];
  failOn: LicenseRisk[];
  format: LicenseFormat;
  outputPath: string | null;
  target: string;
};

const LICENSE_RISKS: readonly LicenseRisk[] = [
  "network-copyleft",
  "no-license",
  "permissive",
  "strong-copyleft",
  "unknown",
  "unlicensed",
  "weak-copyleft"
];

const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  "coverage",
  "dist",
  "node_modules",
  "vendor"
]);

const MAX_DISCOVERY_DEPTH = 8;

export const licensesCommand: CommandSpec = {
  name: "licenses",
  summary: "Report dependency licenses and policy results.",
  usage: "dg licenses [path] [--json|--csv|--markdown] [--fail-on <risk[,risk...]>]",
  args: [{ name: "[path]", summary: "Project directory to report on (default: current directory)." }],
  flags: [
    { flag: "--json", summary: "JSON output." },
    { flag: "--csv", summary: "CSV output." },
    { flag: "--markdown", summary: "Markdown table output." },
    { flag: "--output", value: "<path>", summary: "Write the report to a file (alias -o)." },
    { flag: "--fail-on", value: "<risk[,risk...]>", summary: "Exit non-zero on these risks: permissive, weak-copyleft, strong-copyleft, network-copyleft, no-license, unlicensed, unknown." },
    { flag: "--deny-license", value: "<id>", summary: "Fail if this SPDX license appears (repeatable)." }
  ],
  examples: ["dg licenses", "dg licenses --markdown -o licenses.md", "dg licenses --fail-on strong-copyleft,network-copyleft"],
  details: [
    "Reports project and lockfile license metadata without running package managers or package code.",
    "License exports support text, JSON, CSV, and Markdown. Exit codes: 0 pass, 2 policy block, 4 report error, 64 usage error."
  ],
  handler: (context) => runLicensesCommand(context.args)
};

async function runLicensesCommand(args: readonly string[]): Promise<CommandResult> {
  const parsed = parseLicensesArgs(args);
  if ("error" in parsed) {
    return usageError(parsed.error);
  }

  if (
    parsed.deniedLicenses.length === 0 &&
    parsed.failOn.length === 0 &&
    shouldLaunchScanTui({
      targetPath: parsed.target,
      format: parsed.format,
      outputPath: parsed.outputPath ?? undefined
    })
  ) {
    try {
      await launchScanTui("licenses");
    } catch (error) {
      return {
        exitCode: EXIT_ANALYSIS_INCOMPLETE,
        stdout: "",
        stderr: `dg licenses TUI failed: ${error instanceof Error ? error.message : "unknown error"}\n`
      };
    }
    return {
      exitCode: typeof process.exitCode === "number" ? process.exitCode : 0,
      stdout: "",
      stderr: ""
    };
  }

  let report: LicenseReport;
  let skippedDirectories: readonly string[];
  try {
    ({ report, skippedDirectories } = buildLicenseReport(parsed));
  } catch (error) {
    return {
      exitCode: EXIT_ANALYSIS_INCOMPLETE,
      stdout: "",
      stderr: `dg licenses failed: ${error instanceof Error ? error.message : "unknown license error"}\n`
    };
  }

  const notices = skippedDirectories.map((directory) => `dg licenses: skipped unreadable directory ${directory}\n`).join("");
  const rendered = renderLicenseReport(report, parsed.format);
  if (parsed.outputPath) {
    try {
      writeReportAtomic(resolve(parsed.outputPath), rendered);
    } catch (error) {
      return {
        exitCode: EXIT_ANALYSIS_INCOMPLETE,
        stdout: "",
        stderr: `dg licenses could not write ${parsed.outputPath}: ${error instanceof Error ? error.message : "unknown write error"}\n`
      };
    }
    return {
      exitCode: exitCodeForReport(report),
      stdout: `Wrote ${parsed.format} license report to ${parsed.outputPath}\n`,
      stderr: notices
    };
  }

  return {
    exitCode: exitCodeForReport(report),
    stdout: rendered,
    stderr: notices
  };
}

function parseLicensesArgs(args: readonly string[]): ParsedLicensesArgs | { error: string } {
  let format: LicenseFormat = "text";
  let outputPath: string | null = null;
  let target = ".";
  let sawTarget = false;
  const deniedLicenses: string[] = [];
  const failOn: LicenseRisk[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg) {
      return { error: "empty argument" };
    }
    if (arg === "--json" || arg === "--csv" || arg === "--markdown") {
      if (format !== "text") {
        return { error: "choose only one output format" };
      }
      format = arg === "--json" ? "json" : arg === "--csv" ? "csv" : "markdown";
      continue;
    }
    if (arg === "--output" || arg === "-o") {
      const next = args[index + 1];
      if (!next) {
        return { error: `${arg} requires a path` };
      }
      outputPath = next;
      index += 1;
      continue;
    }
    if (arg === "--fail-on") {
      const next = args[index + 1];
      if (!next) {
        return { error: "--fail-on requires a comma-separated risk list" };
      }
      const parsed = parseRiskList(next);
      if ("error" in parsed) {
        return parsed;
      }
      failOn.push(...parsed.risks);
      index += 1;
      continue;
    }
    if (arg.startsWith("--fail-on=")) {
      const parsed = parseRiskList(arg.slice("--fail-on=".length));
      if ("error" in parsed) {
        return parsed;
      }
      failOn.push(...parsed.risks);
      continue;
    }
    if (arg === "--deny-license") {
      const next = args[index + 1];
      if (!next) {
        return { error: "--deny-license requires a license id" };
      }
      deniedLicenses.push(next);
      index += 1;
      continue;
    }
    if (arg.startsWith("-")) {
      return { error: `unknown option '${arg}'` };
    }
    if (sawTarget) {
      return { error: "licenses accepts at most one path" };
    }
    target = arg;
    sawTarget = true;
  }

  return {
    deniedLicenses,
    failOn: uniqueRisks(failOn),
    format,
    outputPath,
    target
  };
}

function parseRiskList(value: string): { risks: LicenseRisk[] } | { error: string } {
  const risks: LicenseRisk[] = [];
  for (const raw of value.split(",")) {
    const risk = raw.trim();
    if (!isLicenseRisk(risk)) {
      return { error: `unknown license risk '${risk}'` };
    }
    risks.push(risk);
  }
  return { risks };
}

function buildLicenseReport(parsed: ParsedLicensesArgs): { report: LicenseReport; skippedDirectories: readonly string[] } {
  const targetPath = resolve(parsed.target);
  const targetInfo = statSync(targetPath);
  const root = targetInfo.isFile() ? dirname(targetPath) : targetPath;
  const unreadable: string[] = [];
  const lockfiles = targetInfo.isFile() && isSupportedLockfilePath(targetPath)
    ? [targetPath]
    : discoverLockfiles(root, unreadable);
  const entries = dedupeEntries([
    ...manifestLicenseEntries(parsed.target),
    ...lockfiles.flatMap((lockfile) => lockfileLicenseEntries(root, lockfile))
  ]);
  const denied = new Set(parsed.deniedLicenses.map(normalizeLicense));
  const failOn = new Set(parsed.failOn);
  const blocked = entries.filter((entry) => {
    const normalizedLicense = normalizeLicense(entry.license ?? "");
    return (entry.license ? denied.has(normalizedLicense) : false) || failOn.has(entry.risk);
  });
  const byRisk = Object.fromEntries(LICENSE_RISKS.map((risk) => [risk, 0])) as Record<LicenseRisk, number>;
  for (const entry of entries) {
    byRisk[entry.risk] += 1;
  }

  return {
    report: {
      target: displayPath(process.cwd(), targetPath),
      status: blocked.length > 0 ? "block" : "pass",
      entries,
      policy: {
        deniedLicenses: [...denied].sort(),
        failOn: [...failOn].sort()
      },
      summary: {
        packageCount: entries.length,
        blockedCount: blocked.length,
        byRisk
      }
    },
    skippedDirectories: unreadable.map((directory) => displayPath(root, directory)).sort()
  };
}

function manifestLicenseEntries(target: string): LicenseEntry[] {
  const report = scanProject({
    targetPath: target
  });
  return report.projects.map((project) => ({
    ecosystem: ecosystemForManifest(project.manifestPath),
    license: project.license,
    location: project.manifestPath,
    name: project.name,
    risk: classifyLicense(project.license),
    source: "manifest",
    version: project.version
  }));
}

const MANIFEST_ECOSYSTEMS: Record<string, LicenseEntry["ecosystem"]> = {
  "package.json": "npm",
  "pyproject.toml": "pypi",
  "setup.py": "pypi",
  "setup.cfg": "pypi",
  "Cargo.toml": "cargo"
};

function ecosystemForManifest(manifestPath: string): LicenseEntry["ecosystem"] {
  return MANIFEST_ECOSYSTEMS[basename(manifestPath)] ?? "unknown";
}

function lockfileLicenseEntries(root: string, lockfile: string): LicenseEntry[] {
  const report = verifyLockfile(lockfile);
  return report.packages.map((identity) => licenseEntryFromIdentity(root, lockfile, identity));
}

function licenseEntryFromIdentity(root: string, lockfile: string, identity: VerifyPackageIdentity): LicenseEntry {
  return {
    ecosystem: identity.ecosystem,
    license: identity.license,
    location: displayPath(root, lockfile),
    name: identity.name,
    risk: classifyLicense(identity.license),
    source: "lockfile",
    version: identity.version
  };
}

function discoverLockfiles(root: string, unreadable: string[]): string[] {
  const lockfiles: string[] = [];
  walk(root, 0, lockfiles, unreadable);
  return lockfiles.sort((left, right) => displayPath(root, left).localeCompare(displayPath(root, right)));
}

function walk(directory: string, depth: number, lockfiles: string[], unreadable: string[]): void {
  if (depth > MAX_DISCOVERY_DEPTH) {
    return;
  }
  let entries;
  try {
    entries = readdirSync(directory, {
      withFileTypes: true
    }).sort((left, right) => left.name.localeCompare(right.name));
  } catch {
    unreadable.push(directory);
    return;
  }
  for (const entry of entries) {
    const absolutePath = resolve(directory, entry.name);
    if (entry.isDirectory()) {
      if (!IGNORED_DIRECTORIES.has(entry.name)) {
        walk(absolutePath, depth + 1, lockfiles, unreadable);
      }
      continue;
    }
    if (entry.isFile() && isSupportedLockfilePath(absolutePath)) {
      lockfiles.push(absolutePath);
    }
  }
}

function classifyLicense(license: string | null): LicenseRisk {
  if (!license) {
    return "no-license";
  }
  const normalized = normalizeLicense(license);
  if (normalized === "UNLICENSED" || normalized === "NOASSERTION") {
    return "unlicensed";
  }
  if (/\bAGPL\b/u.test(normalized)) {
    return "network-copyleft";
  }
  if (/\bGPL\b/u.test(normalized)) {
    return "strong-copyleft";
  }
  if (/\bLGPL\b|\bMPL\b|\bEPL\b|\bCDDL\b/u.test(normalized)) {
    return "weak-copyleft";
  }
  if (/\bMIT\b|\bISC\b|\bBSD\b|\bAPACHE\b|\b0BSD\b/u.test(normalized)) {
    return "permissive";
  }
  return "unknown";
}

function renderLicenseReport(report: LicenseReport, format: LicenseFormat): string {
  if (format === "json") {
    return `${JSON.stringify({ schemaVersion: 1, ...report }, null, 2)}\n`;
  }
  if (format === "csv") {
    return renderCsv(report);
  }
  if (format === "markdown") {
    return renderMarkdown(report);
  }
  return renderText(report);
}

function renderText(report: LicenseReport): string {
  const lines = [
    "Dependency Guardian licenses",
    `Target: ${report.target}`,
    `Status: ${report.status}`,
    `Packages: ${report.summary.packageCount}`,
    `Policy blocks: ${report.summary.blockedCount}`,
    ""
  ];
  if (report.entries.length === 0) {
    lines.push("No license metadata found.");
  } else {
    for (const entry of report.entries) {
      const version = entry.version ? `@${entry.version}` : "";
      lines.push(`- ${entry.ecosystem}:${entry.name}${version} license=${entry.license ?? "none"} risk=${entry.risk} source=${entry.source} location=${entry.location}`);
    }
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

function renderCsv(report: LicenseReport): string {
  const rows = [
    ["ecosystem", "name", "version", "license", "risk", "source", "location"],
    ...report.entries.map((entry) => [
      entry.ecosystem,
      entry.name,
      entry.version ?? "",
      entry.license ?? "",
      entry.risk,
      entry.source,
      entry.location
    ])
  ];
  return `${rows.map((row) => row.map(csvCell).join(",")).join("\n")}\n`;
}

function renderMarkdown(report: LicenseReport): string {
  const lines = [
    "# Dependency Guardian licenses",
    "",
    `- Target: ${report.target}`,
    `- Status: ${report.status}`,
    `- Packages: ${report.summary.packageCount}`,
    `- Policy blocks: ${report.summary.blockedCount}`,
    "",
    "| Ecosystem | Package | Version | License | Risk | Source |",
    "| --- | --- | --- | --- | --- | --- |"
  ];
  for (const entry of report.entries) {
    lines.push(`| ${markdownCell(entry.ecosystem)} | ${markdownCell(entry.name)} | ${markdownCell(entry.version ?? "")} | ${markdownCell(entry.license ?? "")} | ${markdownCell(entry.risk)} | ${markdownCell(entry.source)} |`);
  }
  return `${lines.join("\n")}\n`;
}

function exitCodeForReport(report: LicenseReport): number {
  return report.status === "block" ? 2 : 0;
}

function usageError(message: string): CommandResult {
  return {
    exitCode: EXIT_USAGE_VERDICT,
    stdout: "",
    stderr: `dg licenses: ${message}. Usage: dg licenses [path] [--json|--csv|--markdown] [--output <path>] [--fail-on <risk[,risk...]>] [--deny-license <id>]\n`
  };
}

function dedupeEntries(entries: readonly LicenseEntry[]): LicenseEntry[] {
  const seen = new Set<string>();
  const deduped: LicenseEntry[] = [];
  for (const entry of entries) {
    const key = `${entry.ecosystem}|${entry.name}|${entry.version ?? ""}|${entry.license ?? ""}|${entry.source}|${entry.location}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(entry);
    }
  }
  return deduped.sort((left, right) => `${left.ecosystem}:${left.name}`.localeCompare(`${right.ecosystem}:${right.name}`));
}

function uniqueRisks(risks: readonly LicenseRisk[]): LicenseRisk[] {
  return [...new Set(risks)].sort();
}

function isLicenseRisk(value: string): value is LicenseRisk {
  return LICENSE_RISKS.includes(value as LicenseRisk);
}

function normalizeLicense(value: string): string {
  return value.trim().toUpperCase().replace(/\s+/gu, "-");
}

function displayPath(root: string, path: string): string {
  const relativePath = relative(root, path);
  const display = relativePath.length === 0 ? "." : relativePath;
  return display.split(sep).join("/");
}

function csvCell(value: string): string {
  return /[",\n\r]/u.test(value) ? `"${value.replace(/"/gu, "\"\"")}"` : value;
}

function markdownCell(value: string): string {
  return value.replace(/\|/gu, "\\|");
}
