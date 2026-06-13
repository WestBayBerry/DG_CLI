import type { CommandSpec } from "./types.js";
import { EXIT_ANALYSIS_INCOMPLETE, EXIT_UNAVAILABLE, EXIT_USAGE_VERDICT } from "./types.js";
import { writeFileSync } from "node:fs";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { renderVerifyJson, renderVerifySarif, renderVerifyText } from "../verify/render.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme } from "../presentation/theme.js";
import { verifyLocalTarget } from "../verify/local.js";
import { isSupportedLockfilePath, verifyLockfile, verifyPackageSpec } from "../verify/preflight.js";
import type { VerifyFormat, VerifyReport } from "../verify/types.js";

export const verifyCommand: CommandSpec = {
  name: "verify",
  summary: "Verify a package spec, lockfile, or local artifact.",
  usage: "dg verify <registry:package[@version]|path|lockfile> [--verbose] [--json|--sarif] [--output <path>]",
  args: [
    { name: "<target>", summary: "registry:package[@version] (npm:react), a local path, an artifact (.tgz/.whl), or a lockfile." }
  ],
  flags: [
    { flag: "--verbose", summary: "Show every finding, not just the top ones (alias -v)." },
    { flag: "--json", summary: "Machine-readable JSON report." },
    { flag: "--sarif", summary: "SARIF report for code-scanning tools." },
    { flag: "--output", value: "<path>", summary: "Write the report to a file instead of stdout (alias -o)." }
  ],
  examples: ["dg verify npm:react", "dg verify pypi:requests@2.31.0", "dg verify ./pkg.tgz --verbose", "dg verify package-lock.json --json"],
  details: [
    "dg verify npm:react (or pypi:requests, with an optional @version — defaults to latest) runs a real scanner check on a published package before you install it. Signed-out runs show the verdict and top reasons; dg login unlocks full findings, license info, --json, and --output.",
    "Local paths, workspaces, tgz/zip/wheel artifacts, and lockfiles are verified offline as advisory preflight (free); proxy enforcement remains authoritative for network artifact fetches."
  ],
  handler: (context) => {
    const parsed = parseVerifyArgs(context.args);
    if ("error" in parsed) {
      return {
        exitCode: EXIT_USAGE_VERDICT,
        stdout: "",
        stderr: `dg verify: ${parsed.error}. Usage: dg verify <spec|path|lockfile> [--verbose] [--json|--sarif] [--output <path>]\n`
      };
    }

    let report: VerifyReport;
    try {
      report = verifyTarget(parsed);
    } catch (error) {
      return {
        exitCode: EXIT_UNAVAILABLE,
        stdout: "",
        stderr: `dg verify could not verify ${parsed.target}: ${error instanceof Error ? error.message : "unknown verify error"}\n`
      };
    }

    const rendered = renderVerifyReport(report, parsed.format, parsed.verbose);
    if (parsed.outputPath) {
      try {
        writeFileSync(resolve(parsed.outputPath), rendered, "utf8");
      } catch (error) {
        return {
          exitCode: EXIT_ANALYSIS_INCOMPLETE,
          stdout: "",
          stderr: `dg verify could not write ${parsed.outputPath}: ${error instanceof Error ? error.message : "unknown write error"}\n`
        };
      }

      return {
        exitCode: exitCodeForReport(report),
        stdout: `Wrote ${parsed.format} verify report to ${parsed.outputPath}\n`,
        stderr: ""
      };
    }

    return {
      exitCode: exitCodeForReport(report),
      stdout: rendered,
      stderr: ""
    };
  }
};

type ParsedVerifyArgs = {
  format: VerifyFormat;
  outputPath: string | null;
  target: string;
  verbose: boolean;
};

function parseVerifyArgs(args: readonly string[]): ParsedVerifyArgs | { error: string } {
  let format: VerifyFormat = "text";
  let outputPath: string | null = null;
  let target: string | null = null;
  let verbose = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg) {
      return { error: "empty argument" };
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
    if (arg === "--verbose" || arg === "-v") {
      verbose = true;
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
    if (arg.startsWith("-")) {
      return { error: `unknown option '${arg}'` };
    }
    if (target) {
      return { error: "verify accepts exactly one target" };
    }
    target = arg;
  }

  if (!target) {
    return { error: "missing target" };
  }

  return {
    format,
    outputPath,
    target,
    verbose
  };
}

function verifyTarget(parsed: ParsedVerifyArgs): VerifyReport {
  if (isSupportedLockfilePath(parsed.target)) {
    return verifyLockfile(parsed.target);
  }
  if (existsSync(resolve(parsed.target))) {
    return verifyLocalTarget(parsed.target);
  }
  return verifyPackageSpec(parsed.target);
}

function renderVerifyReport(report: VerifyReport, format: VerifyFormat, verbose: boolean): string {
  if (format === "json") {
    return renderVerifyJson(report);
  }
  if (format === "sarif") {
    return renderVerifySarif(report);
  }
  return renderVerifyText(report, createTheme(resolvePresentation().color), verbose);
}

function exitCodeForReport(report: VerifyReport): number {
  if (report.status === "block") {
    return 2;
  }
  if (report.status === "error") {
    return EXIT_ANALYSIS_INCOMPLETE;
  }
  return report.status === "warn" ? 1 : 0;
}
