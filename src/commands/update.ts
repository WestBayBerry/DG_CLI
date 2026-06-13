import { spawnSync } from "node:child_process";
import { toolInvocation } from "../util/external-tool.js";
import type { CommandResult, CommandSpec } from "./types.js";
import { EXIT_USAGE } from "./types.js";
import { dgVersion } from "./version.js";

type ParsedUpdateArgs = {
  format: "text" | "json";
};

type UpdateReport = {
  currentVersion: string;
  latestVersion: string | null;
  packageName: string;
  status: "available" | "current" | "unknown";
  updateCommand: string | null;
};

const PACKAGE_NAME = "@westbayberry/dg";
const VERSION_PATTERN = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/u;

export const updateCommand: CommandSpec = {
  name: "update",
  summary: "Check for dg CLI updates.",
  usage: "dg update [--json]",
  aliases: ["upgrade"],
  flags: [{ flag: "--json", summary: "Machine-readable update info." }],
  examples: ["dg update"],
  details: [
    "Checks the latest published dg version and prints the exact package-manager command to run.",
    "The command does not run package managers, edit setup state, or mutate the installed npm package."
  ],
  handler: (context) => runUpdateCommand(context.args, context.commandPath[0] ?? "update")
};

function runUpdateCommand(args: readonly string[], commandName: string): CommandResult {
  const parsed = parseUpdateArgs(args);
  if ("error" in parsed) {
    return usageError(commandName, parsed.error);
  }

  const latestVersion = readLatestVersion();
  const report = buildUpdateReport(latestVersion);
  if (parsed.format === "json") {
    return {
      exitCode: report.status === "unknown" ? 1 : 0,
      stdout: `${JSON.stringify({ schemaVersion: 1, ...report }, null, 2)}\n`,
      stderr: ""
    };
  }

  return {
    exitCode: report.status === "unknown" ? 1 : 0,
    stdout: renderUpdateText(report),
    stderr: ""
  };
}

function parseUpdateArgs(args: readonly string[]): ParsedUpdateArgs | { error: string } {
  let format: "text" | "json" = "text";
  for (const arg of args) {
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
    if (arg === "--yes" || arg === "-y") {
      return { error: "--yes is not supported because dg update does not self-mutate; run the printed command explicitly" };
    }
    if (arg.startsWith("-")) {
      return { error: `unknown option '${arg}'` };
    }
    return { error: "update does not accept positional arguments" };
  }
  return {
    format
  };
}

export function readLatestVersion(timeoutMs = 5000): string | null {
  const injected = process.env.NODE_ENV === "test" ? process.env.DG_UPDATE_LATEST_VERSION : undefined;
  if (injected) {
    return validVersion(injected);
  }
  const invocation = toolInvocation("npm", ["view", PACKAGE_NAME, "version", "--json"]);
  if (!invocation) {
    return null;
  }
  const result = spawnSync(invocation.command, [...invocation.args], {
    encoding: "utf8",
    env: {
      ...process.env,
      npm_config_ignore_scripts: "true"
    },
    timeout: timeoutMs,
    windowsVerbatimArguments: invocation.windowsVerbatimArguments
  });
  if (result.status !== 0) {
    return null;
  }
  const raw = result.stdout.trim();
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    return typeof parsed === "string" ? validVersion(parsed) : null;
  } catch {
    return validVersion(raw.replace(/^"|"$/gu, ""));
  }
}

function validVersion(value: string): string | null {
  return VERSION_PATTERN.test(value) ? value : null;
}

function buildUpdateReport(latestVersion: string | null): UpdateReport {
  if (!latestVersion) {
    return {
      currentVersion: dgVersion(),
      latestVersion: null,
      packageName: PACKAGE_NAME,
      status: "unknown",
      updateCommand: null
    };
  }
  const available = compareVersions(latestVersion, dgVersion()) > 0;
  return {
    currentVersion: dgVersion(),
    latestVersion,
    packageName: PACKAGE_NAME,
    status: available ? "available" : "current",
    updateCommand: available ? `npm install -g ${PACKAGE_NAME}@${latestVersion}` : null
  };
}

function renderUpdateText(report: UpdateReport): string {
  const lines = [
    "Dependency Guardian update",
    `Current version: ${report.currentVersion}`
  ];
  if (report.status === "unknown") {
    lines.push("Latest version: unknown");
    lines.push("Status: registry metadata unavailable");
    lines.push("No install command was run.");
    return `${lines.join("\n")}\n`;
  }
  lines.push(`Latest version: ${report.latestVersion}`);
  lines.push(`Status: ${report.status}`);
  if (report.updateCommand) {
    lines.push(`Run: ${report.updateCommand}`);
  } else {
    lines.push("No update needed.");
  }
  lines.push("No package manager was executed.");
  return `${lines.join("\n")}\n`;
}

type ParsedVersion = {
  release: number[];
  prerelease: string[];
};

export function compareVersions(left: string, right: string): number {
  const leftVersion = parseVersion(left);
  const rightVersion = parseVersion(right);
  const length = Math.max(leftVersion.release.length, rightVersion.release.length);
  for (let index = 0; index < length; index += 1) {
    const diff = (leftVersion.release[index] ?? 0) - (rightVersion.release[index] ?? 0);
    if (diff !== 0) {
      return diff;
    }
  }
  return comparePrerelease(leftVersion.prerelease, rightVersion.prerelease);
}

function parseVersion(version: string): ParsedVersion {
  const core = version.replace(/^v/u, "").split("+", 1)[0] ?? "";
  const dashIndex = core.indexOf("-");
  const releaseText = dashIndex === -1 ? core : core.slice(0, dashIndex);
  const prereleaseText = dashIndex === -1 ? "" : core.slice(dashIndex + 1);
  const release = releaseText
    .split(".")
    .map((part) => Number.parseInt(part, 10))
    .filter((part) => Number.isFinite(part));
  const prerelease = prereleaseText ? prereleaseText.split(".") : [];
  return { release, prerelease };
}

function comparePrerelease(left: string[], right: string[]): number {
  if (left.length === 0 && right.length === 0) {
    return 0;
  }
  if (left.length === 0) {
    return 1;
  }
  if (right.length === 0) {
    return -1;
  }
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const leftId = left[index];
    const rightId = right[index];
    if (leftId === undefined) {
      return -1;
    }
    if (rightId === undefined) {
      return 1;
    }
    const diff = comparePrereleaseIdentifier(leftId, rightId);
    if (diff !== 0) {
      return diff;
    }
  }
  return 0;
}

function comparePrereleaseIdentifier(left: string, right: string): number {
  const leftNumeric = /^\d+$/u.test(left);
  const rightNumeric = /^\d+$/u.test(right);
  if (leftNumeric && rightNumeric) {
    return Number.parseInt(left, 10) - Number.parseInt(right, 10);
  }
  if (leftNumeric) {
    return -1;
  }
  if (rightNumeric) {
    return 1;
  }
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function usageError(commandName: string, message: string): CommandResult {
  return {
    exitCode: EXIT_USAGE,
    stdout: "",
    stderr: `dg ${commandName}: ${message}. Usage: dg ${commandName} [--json]\n`
  };
}
