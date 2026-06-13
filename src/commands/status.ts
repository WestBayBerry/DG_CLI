import { authStatus, displayTier, readAuthState } from "../auth/store.js";
import { envAuthToken } from "../auth/env-token.js";
import { fetchAccountStatus } from "../auth/device-login.js";
import { formatUsage } from "../scan-ui/format-helpers.js";
import { loadUserConfig } from "../config/settings.js";
import { describeCooldownSettings } from "../policy/cooldown.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme, type Theme } from "../presentation/theme.js";
import { currentShellActivation, doctorReport } from "../setup/plan.js";
import { gitHookStatusState, type GuardStatusState } from "../setup/git-hook.js";
import type { CommandResult, CommandSpec } from "./types.js";
import { EXIT_USAGE } from "./types.js";

export const statusCommand: CommandSpec = {
  name: "status",
  summary: "Show what dg protects on this machine right now.",
  usage: "dg status [--json]",
  flags: [{ flag: "--json", summary: "Machine-readable status snapshot." }],
  examples: ["dg status", "dg status --json"],
  details: [
    "A quick snapshot: account connection, bare-command protection, commit guard (inside a repo), and the active policy.",
    "For full diagnostics with fix commands, run 'dg doctor'."
  ],
  handler: (context) => runStatusCommand(context.args)
};

type StatusUsage =
  | { state: "ok"; used: number; limit: number | null }
  | { state: "anonymous" }
  | { state: "unavailable" };

type StatusReport = {
  account: { connected: boolean; tokenPreview: string; email?: string; tier?: string };
  usage: StatusUsage;
  protection: { shims: boolean; path: boolean; configured: boolean };
  reloadHint: string;
  commitGuard: GuardStatusState;
  policy: { mode: string; trustProjectAllowlists: boolean };
  cooldown: string;
};

export const STATUS_USAGE_TIMEOUT_MS = 2_500;

export type StatusIo = {
  readonly fetchImpl?: typeof fetch;
  readonly usageTimeoutMs?: number;
};

export async function runStatusCommand(args: readonly string[], io: StatusIo = {}): Promise<CommandResult> {
  const json = args.includes("--json");
  const unknown = args.find((arg) => arg !== "--json");
  if (unknown) {
    return {
      exitCode: EXIT_USAGE,
      stdout: "",
      stderr: `dg status: unknown option '${unknown}'. Run 'dg status --help'.\n`
    };
  }

  const report = await buildStatusReport(io);
  if (json) {
    return {
      exitCode: 0,
      stdout: `${JSON.stringify(report, null, 2)}\n`,
      stderr: ""
    };
  }
  return {
    exitCode: 0,
    stdout: renderStatus(report, createTheme(resolvePresentation().color)),
    stderr: ""
  };
}

async function buildStatusReport(io: StatusIo): Promise<StatusReport> {
  const checks = doctorReport().checks;
  const checkPassed = (name: string): boolean => checks.find((check) => check.name === name)?.status === "pass";
  const auth = safeAuthStatus();
  const config = loadUserConfig();
  return {
    account: auth,
    usage: await fetchStatusUsage(auth.connected, io),
    protection: { shims: checkPassed("shims"), path: checkPassed("path"), configured: checkPassed("shell-rc") },
    reloadHint: currentShellActivation(),
    commitGuard: safeCommitGuard(),
    policy: { mode: config.policy.mode, trustProjectAllowlists: config.policy.trustProjectAllowlists },
    cooldown: describeCooldownSettings(config, process.env)
  };
}

async function fetchStatusUsage(connected: boolean, io: StatusIo): Promise<StatusUsage> {
  const token = connected ? resolveStatusToken() : undefined;
  if (!token) {
    return { state: "anonymous" };
  }
  const account = await fetchAccountStatus(
    token,
    process.env,
    io.fetchImpl ?? fetch,
    io.usageTimeoutMs ?? STATUS_USAGE_TIMEOUT_MS
  );
  if (!account || account.scansUsed === null) {
    return { state: "unavailable" };
  }
  return { state: "ok", used: account.scansUsed, limit: account.scansLimit };
}

function resolveStatusToken(): string | undefined {
  try {
    return envAuthToken(process.env) ?? readAuthState()?.token;
  } catch {
    return undefined;
  }
}

function safeCommitGuard(): GuardStatusState {
  try {
    return gitHookStatusState();
  } catch {
    return "not-a-repo";
  }
}

function safeAuthStatus(): StatusReport["account"] {
  try {
    const status = authStatus();
    return {
      connected: status.authenticated,
      tokenPreview: status.tokenPreview,
      ...(status.email ? { email: status.email } : {}),
      ...(status.tier ? { tier: status.tier } : {})
    };
  } catch {
    return { connected: false, tokenPreview: "" };
  }
}

function renderStatus(report: StatusReport, theme: Theme): string {
  const account = report.account.connected
    ? report.account.email && report.account.tier
      ? `${theme.paint("pass", "✓")} ${report.account.email} · ${displayTier(report.account.tier)} plan`
      : `${theme.paint("pass", "✓")} connected (${report.account.tokenPreview})`
    : `${theme.paint("warn", "⚠")} not connected — run ${theme.paint("accent", "dg login")}`;
  const bare = report.protection.shims && report.protection.path
    ? `${theme.paint("pass", "✓")} bare npm/pip installs are protected`
    : report.protection.shims && report.protection.configured
      ? `${theme.paint("muted", "○")} configured — run ${theme.paint("accent", report.reloadHint)} to activate this shell ${theme.paint("muted", "(already active in new terminals)")}`
      : `${theme.paint("warn", "⚠")} not set up — run ${theme.paint("accent", "dg setup")}, or prefix commands with ${theme.paint("accent", "dg")}`;
  const lines = [
    "Dependency Guardian status",
    "",
    `  Account      ${account}`,
    `  Usage        ${usageLine(report, theme)}`,
    `  Installs     ${bare}`
  ];
  const guard = commitGuardLine(report.commitGuard, theme);
  if (guard) {
    lines.push(`  Commit guard ${guard}`);
  }
  lines.push(`  Policy       ${report.policy.mode} mode; project allowlists ${report.policy.trustProjectAllowlists ? "trusted" : "untrusted"}`);
  lines.push(`  Cooldown     ${report.cooldown === "off" ? "off — new releases install immediately" : `${report.cooldown} release-age gate on new installs`}`);
  lines.push("");
  lines.push(`Full diagnostics: ${theme.paint("accent", "dg doctor")}`);
  return `${lines.join("\n")}\n`;
}

function usageLine(report: StatusReport, theme: Theme): string {
  if (report.usage.state === "anonymous") {
    return theme.paint("muted", "sign in to see usage");
  }
  if (report.usage.state === "unavailable") {
    return theme.paint("muted", "unavailable offline");
  }
  return formatUsage({ used: report.usage.used, limit: report.usage.limit, tier: report.account.tier ?? "" }).text;
}

function commitGuardLine(state: GuardStatusState, theme: Theme): string | null {
  if (state === "not-a-repo") {
    return null;
  }
  if (state === "active") {
    return `${theme.paint("pass", "✓")} this repo's commits are scanned`;
  }
  if (state === "dead") {
    return `${theme.paint("warn", "⚠")} installed but git isn't using it — run ${theme.paint("accent", "dg guard-commit --check")}`;
  }
  return `${theme.paint("warn", "⚠")} off — run ${theme.paint("accent", "dg guard-commit")}`;
}
