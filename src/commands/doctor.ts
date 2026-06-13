import type { CommandSpec } from "./types.js";
import { EXIT_USAGE, type CommandResult } from "./types.js";
import { doctorReportWithRemote, renderDoctorReport } from "../setup/plan.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme } from "../presentation/theme.js";

export const doctorCommand: CommandSpec = {
  name: "doctor",
  summary: "Inspect local dg health and setup state.",
  usage: "dg doctor [--verbose] [--json]",
  flags: [
    { flag: "--verbose", summary: "List every check, including passing and gated ones (alias -v)." },
    { flag: "--json", summary: "Machine-readable check results." }
  ],
  examples: ["dg doctor", "dg doctor --verbose"],
  details: [
    "Checks runtime, package, config, auth, PATH, package-manager resolution, stale state, optional support gates, service state, and next fix commands.",
    "Groups checks and collapses passing ones; --verbose lists every check including gated/remote surfaces."
  ],
  handler: (context) => doctorHandler(context.args)
};

async function doctorHandler(args: readonly string[]): Promise<CommandResult> {
  const json = args.includes("--json");
  const verbose = args.includes("--verbose") || args.includes("-v");
  const unknown = args.find((arg) => arg !== "--json" && arg !== "--verbose" && arg !== "-v");
  if (unknown) {
    return {
      exitCode: EXIT_USAGE,
      stdout: "",
      stderr: `dg doctor: unknown option '${unknown}'. Run 'dg doctor --help'.\n`
    };
  }

  const report = await doctorReportWithRemote();
  const hasFailure = report.checks.some((check) => check.status === "fail");
  const theme = createTheme(resolvePresentation().color);

  return {
    exitCode: hasFailure ? 1 : 0,
    stdout: json ? `${JSON.stringify({ schemaVersion: 1, ...report }, null, 2)}\n` : renderDoctorReport(report, theme, verbose),
    stderr: ""
  };
}
