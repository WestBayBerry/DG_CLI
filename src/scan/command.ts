import { statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { writeReportAtomic } from "../util/report-writer.js";
import { findProjectRoot, loadDgFile, warnUnreadableDgFile, type DgFile } from "../project/dgfile.js";
import { scanProject } from "./discovery.js";
import { renderJsonReport, renderSarifReport, renderTextReport, type ScannerSkipNotice } from "./render.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme } from "../presentation/theme.js";
import { launchScanTui, shouldLaunchScanTui } from "../scan-ui/launch.js";
import { runScannerScan, type ScannerScanOutcome } from "./scanner-report.js";
import { runStagedScan, stagedScanReport } from "./staged.js";
import { scanExitCode } from "../scan-ui/shims.js";
import { loadUserConfig } from "../config/settings.js";
import type { CommandContext, CommandResult } from "../commands/types.js";
import { EXIT_ANALYSIS_INCOMPLETE, EXIT_NOTHING_TO_SCAN, EXIT_USAGE_VERDICT } from "../commands/types.js";
import type { ScanFormat, ScanReport, ScannerError } from "./types.js";

export function runScanCommand(context: CommandContext): CommandResult {
  const parsed = parseScanArgs(context.args);
  if ("error" in parsed) {
    return usageError(parsed.error);
  }

  const stagedTarget = parsed.sawTarget ? parsed.targetPath : null;
  const machineOutput = parsed.format !== "text" || parsed.outputPath !== null;

  if (parsed.staged && !machineOutput) {
    return runStagedScan({ hook: parsed.hook, targetPath: stagedTarget, useDecisions: !parsed.noDecisions });
  }

  let report: ScanReport;
  let outcome: ScannerScanOutcome;
  if (parsed.staged) {
    const staged = stagedScanReport({ targetPath: stagedTarget, useDecisions: !parsed.noDecisions });
    if ("result" in staged) {
      return staged.result;
    }
    report = staged.report;
    outcome = staged.outcome;
  } else {
    if (
      shouldLaunchScanTui({
        targetPath: parsed.targetPath,
        format: parsed.format,
        outputPath: parsed.outputPath ?? undefined
      })
    ) {
      void launchScanTui().catch((error: unknown) => {
        process.stderr.write(`dg scan TUI failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
        process.exitCode = 1;
      });
      return {
        exitCode: 0,
        stdout: "",
        stderr: ""
      };
    }

    try {
      report = scanProject({
        targetPath: parsed.targetPath
      });
    } catch (error) {
      return {
        exitCode: EXIT_ANALYSIS_INCOMPLETE,
        stdout: "",
        stderr: `dg scan failed: ${error instanceof Error ? error.message : "unknown scan error"}\n`
      };
    }

    outcome = runScannerScan(parsed.targetPath, report, process.env, parsed.noDecisions ? null : loadScanDecisions(parsed.targetPath));
  }

  if (outcome.kind === "report") {
    report = outcome.report;
  } else if (outcome.kind === "failed") {
    report = degradeReport(report, outcome.error);
  }
  const skipNotice = skipNoticeFor(outcome, report);
  const scannerUnavailable = !report.scanner && report.summary.projectCount > 0;
  const nothingToScan =
    !parsed.staged &&
    !report.scanner &&
    !report.scannerError &&
    report.summary.projectCount === 0 &&
    report.summary.errorCount === 0;
  const exitCode = nothingToScan ? EXIT_NOTHING_TO_SCAN : exitCodeForReport(report);

  const rendered = renderReport(report, parsed.format, scannerUnavailable, skipNotice, nothingToScan);
  if (parsed.outputPath) {
    try {
      writeReportAtomic(resolve(parsed.outputPath), rendered);
    } catch (error) {
      return {
        exitCode: EXIT_ANALYSIS_INCOMPLETE,
        stdout: "",
        stderr: `dg scan could not write ${parsed.outputPath}: ${error instanceof Error ? error.message : "unknown write error"}\n`
      };
    }

    return {
      exitCode,
      stdout: `Wrote ${parsed.format} scan report to ${parsed.outputPath}\n`,
      stderr: ""
    };
  }

  return {
    exitCode,
    stdout: rendered,
    stderr: ""
  };
}

type ParsedScanArgs = {
  format: ScanFormat;
  outputPath: string | null;
  targetPath: string;
  sawTarget: boolean;
  staged: boolean;
  hook: boolean;
  noDecisions: boolean;
};

function parseScanArgs(args: readonly string[]): ParsedScanArgs | { error: string } {
  let format: ScanFormat = "text";
  let outputPath: string | null = null;
  let targetPath = ".";
  let sawTarget = false;
  let staged = false;
  let hook = false;
  let noDecisions = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg) {
      return { error: "empty argument" };
    }
    if (arg === "--staged") {
      staged = true;
      continue;
    }
    if (arg === "--hook") {
      hook = true;
      continue;
    }
    if (arg === "--no-decisions") {
      noDecisions = true;
      continue;
    }
    if (arg === "--json") {
      if (format !== "text") {
        return { error: "choose only one output format" };
      }
      format = "json";
      continue;
    }
    if (arg === "--sarif") {
      if (format !== "text") {
        return { error: "choose only one output format" };
      }
      format = "sarif";
      continue;
    }
    if (arg === "--output" || arg === "-o") {
      const next = args[index + 1];
      if (!next || next.startsWith("-")) {
        return { error: `${arg} requires a path` };
      }
      outputPath = next;
      index += 1;
      continue;
    }
    if (arg.startsWith("-")) {
      return { error: `unknown option '${arg}'` };
    }
    if (sawTarget) {
      return { error: "scan accepts at most one path" };
    }
    targetPath = arg;
    sawTarget = true;
  }

  return {
    format,
    outputPath,
    targetPath,
    sawTarget,
    staged,
    hook,
    noDecisions
  };
}

function usageError(message: string): CommandResult {
  return {
    exitCode: EXIT_USAGE_VERDICT,
    stdout: "",
    stderr: `dg scan: ${message}. Usage: dg scan [path] [--json|--sarif] [--output <path>] [--no-decisions]\n`
  };
}

function loadScanDecisions(targetPath: string, env: NodeJS.ProcessEnv = process.env): DgFile | null {
  let dir = resolve(targetPath);
  try {
    if (!statSync(dir).isDirectory()) {
      dir = dirname(dir);
    }
  } catch {
    return null;
  }
  const root = findProjectRoot(dir, env);
  if (!root) {
    return null;
  }
  const file = loadDgFile(root);
  warnUnreadableDgFile(file);
  return file.readable ? file : null;
}

function degradeReport(report: ScanReport, error: ScannerError): ScanReport {
  const status = report.status === "block" || report.status === "warn" ? report.status : "unknown";
  return { ...report, status, scannerError: error };
}

function skipNoticeFor(outcome: ScannerScanOutcome, report: ScanReport): ScannerSkipNotice | undefined {
  if (outcome.kind !== "skipped") {
    return undefined;
  }
  if (outcome.reason === "no_lockfiles") {
    return report.summary.projectCount > 0 ? "no_lockfile" : undefined;
  }
  return "empty_lockfile";
}

function renderReport(report: ScanReport, format: ScanFormat, scannerUnavailable: boolean, skipNotice: ScannerSkipNotice | undefined, nothingToScan: boolean): string {
  if (format === "json") {
    return renderJsonReport(report, scannerUnavailable, nothingToScan);
  }
  if (format === "sarif") {
    return renderSarifReport(report);
  }
  return renderTextReport(report, undefined, createTheme(resolvePresentation().color), skipNotice);
}

function exitCodeForReport(report: ScanReport): number {
  if (report.scanner) {
    const mode = loadUserConfig().policy.mode;
    const action = mode === "strict" ? report.scanner.action : report.decisions?.effectiveAction ?? report.scanner.action;
    return scanExitCode(action, mode);
  }
  if (report.status === "block") {
    return 2;
  }
  if (report.status === "warn") {
    return 1;
  }
  if (report.status === "error" || report.status === "unknown") {
    return 4;
  }
  return 0;
}

