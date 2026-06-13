import type { CommandSpec } from "./types.js";
import { runScanCommand } from "../scan/command.js";

export const scanCommand: CommandSpec = {
  name: "scan",
  summary: "Scan a project and show Dependency Guardian findings.",
  usage: "dg scan [path] [--json|--sarif] [--output <path>]",
  args: [{ name: "[path]", summary: "Project directory or a package.json to scan (default: current directory)." }],
  flags: [
    { flag: "--json", summary: "Machine-readable JSON report." },
    { flag: "--sarif", summary: "SARIF report for code-scanning tools." },
    { flag: "--output", value: "<path>", summary: "Write the report to a file instead of stdout (alias -o)." },
    { flag: "--staged", summary: "Scan only the git-staged lockfile changes (what dg guard-commit runs)." },
    { flag: "--no-decisions", summary: "Ignore acceptances remembered in dg.json (see dg decisions)." }
  ],
  examples: ["dg scan", "dg scan ./packages/api", "dg scan --json -o scan.json", "dg scan --staged"],
  details: [
    "Reads lockfiles, scores each dependency through the scanner, and never changes project files. In a terminal it opens the full-screen results browser; piped or with --json/--sarif it prints machine output. Exit codes: 0 clean, 1 warn, 2 block, 4 analysis incomplete, 10 nothing to scan, 64 usage error."
  ],
  handler: runScanCommand
};
