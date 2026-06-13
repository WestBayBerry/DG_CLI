import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { AnalyzeResponse, ScannerAction, ScannerPackageResult } from "../api/analyze.js";
import { applyDecisions, packageKey } from "../decisions/apply.js";
import type { DecisionEcosystem, DgFile } from "../project/dgfile.js";
import { sanitize } from "../security/sanitize.js";
import { collectScanPackages, discoverScanProjects, type LockfileProject } from "./collect.js";
import type { ScanFinding, ScanReport, ScanStatus, ScannerError } from "./types.js";

const WORKER_TIMEOUT_BASE_MS = 180_000;
const SERVER_PER_PACKAGE_WORST_CASE_MS = 660_000;
const SERVER_SCAN_CONCURRENCY = 64;
const WORKER_MAX_BUFFER = 64 * 1024 * 1024;

export function scanWorkerTimeoutMs(packageCount: number): number {
  return WORKER_TIMEOUT_BASE_MS + packageCount * Math.ceil(SERVER_PER_PACKAGE_WORST_CASE_MS / SERVER_SCAN_CONCURRENCY);
}

export type ScannerSkipReason = "no_lockfiles" | "no_packages";

export type ScannerScanOutcome =
  | { kind: "report"; report: ScanReport }
  | { kind: "skipped"; reason: ScannerSkipReason }
  | { kind: "failed"; error: ScannerError };

export function runScannerScan(
  targetPath: string,
  localReport: ScanReport,
  env: NodeJS.ProcessEnv = process.env,
  decisionsFile: DgFile | null = null
): ScannerScanOutcome {
  const projects = discoverScanProjects(resolve(targetPath));
  if (projects.length === 0) {
    return { kind: "skipped", reason: "no_lockfiles" };
  }
  const collected = collectScanPackages(projects);
  const groups = [...collected.byEcosystem.entries()].map(([ecosystem, packages]) => ({ ecosystem, packages }));
  const total = groups.reduce((sum, group) => sum + group.packages.length, 0);
  if (total === 0) {
    if (collected.skipped > 0) {
      return { kind: "failed", error: lockfileParseError(projects, collected) };
    }
    return { kind: "skipped", reason: "no_packages" };
  }

  const workerPath = [
    fileURLToPath(new URL("./analyze-worker.js", import.meta.url)),
    fileURLToPath(new URL("../../dist/scan/analyze-worker.js", import.meta.url))
  ].find((candidate) => existsSync(candidate));
  if (!workerPath) {
    return {
      kind: "failed",
      error: { kind: "worker", message: "scanner worker is missing — reinstall @westbayberry/dg" }
    };
  }
  const timeoutMs = scanWorkerTimeoutMs(total);
  const worker = spawnSync(process.execPath, [workerPath], {
    encoding: "utf8",
    env,
    input: JSON.stringify({ scanId: randomUUID(), groups }),
    maxBuffer: WORKER_MAX_BUFFER,
    timeout: timeoutMs
  });
  const failure = workerFailure(worker, timeoutMs, total);
  if (failure) {
    return { kind: "failed", error: failure };
  }

  let response: AnalyzeResponse;
  try {
    response = JSON.parse(worker.stdout) as AnalyzeResponse;
  } catch {
    return {
      kind: "failed",
      error: { kind: "invalid_response", message: "scanner worker returned unreadable output" }
    };
  }
  const ecosystems = new Map<string, DecisionEcosystem>();
  for (const group of groups) {
    for (const pkg of group.packages) {
      ecosystems.set(packageKey(pkg.name, pkg.version), group.ecosystem);
    }
  }
  const report = buildScannerReport(localReport, response, total, ecosystems);
  if (!decisionsFile?.readable) {
    return { kind: "report", report };
  }
  return { kind: "report", report: annotateReportWithDecisions(report, decisionsFile, ecosystems) };
}

export function tryScannerScan(
  targetPath: string,
  localReport: ScanReport,
  env: NodeJS.ProcessEnv = process.env,
  decisionsFile: DgFile | null = null
): ScanReport | null {
  const outcome = runScannerScan(targetPath, localReport, env, decisionsFile);
  return outcome.kind === "report" ? outcome.report : null;
}

export function annotateReportWithDecisions(
  report: ScanReport,
  decisionsFile: DgFile,
  ecosystems: ReadonlyMap<string, DecisionEcosystem>
): ScanReport {
  if (!report.scanner || !decisionsFile.readable) {
    return report;
  }
  const applied = applyDecisions(
    report.scanner.packages,
    (pkg) => ecosystems.get(packageKey(pkg.name, pkg.version)),
    decisionsFile,
    report.scanner.action
  );
  const findings = report.findings.map((finding) => {
    const acknowledged = applied.packages[finding.location]?.acknowledged;
    return acknowledged && finding.severity === "warn" ? { ...finding, acknowledged } : finding;
  });
  return {
    ...report,
    findings,
    summary: { ...report.summary, acknowledgedCount: applied.acknowledgedCount },
    decisions: applied
  };
}

type WorkerResult = {
  error?: (Error & { code?: string }) | undefined;
  status: number | null;
  stdout: string | null;
  stderr: string | null;
};

export function workerFailure(worker: WorkerResult, timeoutMs: number, packageCount: number): ScannerError | null {
  if (worker.error?.code === "ETIMEDOUT") {
    return {
      kind: "timeout",
      message: `server scan timed out after ${Math.round(timeoutMs / 1000)}s without finishing ${packageCount} package${packageCount === 1 ? "" : "s"}`
    };
  }
  if (worker.error) {
    return { kind: "worker", message: `scanner worker failed to start: ${worker.error.message}` };
  }
  if (worker.status === 0 && worker.stdout) {
    return null;
  }
  const reported = parseWorkerError(worker.stdout);
  if (reported) {
    return reported;
  }
  const stderrLine = (worker.stderr ?? "").trim().split("\n")[0] ?? "";
  return {
    kind: "worker",
    message: stderrLine ? `scanner worker failed: ${sanitize(stderrLine)}` : "scanner worker exited without a result"
  };
}

function parseWorkerError(stdout: string | null): ScannerError | null {
  if (!stdout) {
    return null;
  }
  try {
    const parsed = JSON.parse(stdout) as { scannerError?: ScannerError };
    if (parsed.scannerError && typeof parsed.scannerError.message === "string" && typeof parsed.scannerError.kind === "string") {
      return parsed.scannerError;
    }
  } catch {
    return null;
  }
  return null;
}

function lockfileParseError(
  projects: readonly LockfileProject[],
  collected: ReturnType<typeof collectScanPackages>
): ScannerError {
  const parseErrors = collected.parseErrors;
  const detail = parseErrors
    .map((entry) => [entry.file, entry.reason].filter(Boolean).join(": "))
    .filter((line) => line.length > 0)
    .join("; ");
  const lockfiles = [...new Set(projects.map((project) => project.depFile))].join(", ");
  return {
    kind: "lockfile_unparsed",
    message: detail
      ? `could not parse lockfile${parseErrors.length === 1 ? "" : "s"}: ${detail}`
      : `found ${projects.length} lockfile${projects.length === 1 ? "" : "s"} (${lockfiles}) but no packages could be parsed`
  };
}

export function buildScannerReport(
  localReport: ScanReport,
  response: AnalyzeResponse,
  analyzedCount: number,
  ecosystems?: ReadonlyMap<string, string>
): ScanReport {
  const packages = ecosystems
    ? response.packages.map((pkg) => {
        const ecosystem = ecosystems.get(packageKey(pkg.name, pkg.version));
        return ecosystem ? { ...pkg, ecosystem } : pkg;
      })
    : response.packages;
  const findings = packages
    .filter((pkg) => (pkg.action ?? "pass") !== "pass")
    .map((pkg) => scannerFinding(pkg));
  const warnCount = findings.filter((finding) => finding.severity === "warn").length;
  const blockCount = findings.filter((finding) => finding.severity === "block").length;

  return {
    target: localReport.target,
    status: statusFromAction(response.action),
    projects: localReport.projects.map((project) => ({ ...project, findings: [] })),
    findings,
    errors: localReport.errors,
    summary: {
      projectCount: localReport.summary.projectCount,
      dependencyCount: analyzedCount,
      findingCount: findings.length,
      warnCount,
      blockCount,
      errorCount: localReport.summary.errorCount
    },
    scanner: { ...response, packages }
  };
}

function scannerFinding(pkg: ScannerPackageResult): ScanFinding {
  const action = pkg.action ?? "pass";
  const top = pkg.findings[0];
  return {
    id: top?.category ?? top?.id ?? "scanner-finding",
    severity: action === "block" ? "block" : "warn",
    title: top?.title ?? pkg.reasons[0] ?? `scanner ${action} verdict`,
    message: pkg.reasons.join("; ") || top?.title || `scanner returned ${action} (score ${pkg.score})`,
    project: "",
    location: `${pkg.name}@${pkg.version}`
  };
}

function statusFromAction(action: ScannerAction): ScanStatus {
  if (action === "analysis_incomplete") {
    return "unknown";
  }
  return action;
}
