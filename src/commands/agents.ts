import { homedir } from "node:os";
import {
  AGENT_IDS,
  AGENTS,
  agentLabel,
  collectAgentOffers,
  getAgent,
  isAgentId,
  resolveAgentHookContext,
} from "../agents/registry.js";
import { AgentHookError } from "../agents/persistence.js";
import type { AgentId } from "../agents/types.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme, type Theme } from "../presentation/theme.js";
import { tildifyPath as tildify } from "../setup/plan.js";
import type { CommandContext, CommandResult, CommandSpec } from "./types.js";
import { EXIT_USAGE } from "./types.js";

const VERBS = ["on", "off", "--check", "--print"] as const;
type AgentsVerb = (typeof VERBS)[number];

const LEGACY_VERB_MAP: Record<string, AgentsVerb> = {
  install: "on",
  on: "on",
  off: "off",
  remove: "off",
  uninstall: "off",
  "--check": "--check",
  "--print": "--print",
};

interface ParsedAgentsArgs {
  readonly verb: AgentsVerb | "status";
  readonly agents: readonly AgentId[];
  readonly recordFixture: boolean;
}

function parseAgentsArgs(args: readonly string[]): ParsedAgentsArgs | { readonly error: string } {
  if (args.length === 0) {
    return { verb: "status", agents: [], recordFixture: false };
  }
  let rest = [...args];
  let verb: AgentsVerb | null = null;
  const first = rest[0] ?? "";
  if (isAgentId(first)) {
    const legacy = rest[1] ?? "install";
    const mapped = LEGACY_VERB_MAP[legacy];
    if (!mapped || rest.length > 3 || (rest.length === 3 && (rest[2] !== "--record-fixture" || mapped !== "on"))) {
      return { error: `unknown subcommand '${rest[1] ?? ""}'. Use: dg agents [on|off|--check|--print] [agent]` };
    }
    return { verb: mapped, agents: [first], recordFixture: rest[2] === "--record-fixture" };
  }
  if ((VERBS as readonly string[]).includes(first)) {
    verb = first as AgentsVerb;
    rest = rest.slice(1);
  } else {
    return { error: `unknown subcommand '${first}'. Use: dg agents [on|off|--check|--print] [agent]` };
  }
  const agents: AgentId[] = [];
  let recordFixture = false;
  for (const arg of rest) {
    if (arg === "--record-fixture") {
      recordFixture = true;
      continue;
    }
    if (!isAgentId(arg)) {
      return { error: `unknown agent '${arg}'. Agents: ${AGENT_IDS.join(", ")}` };
    }
    agents.push(arg);
  }
  if (recordFixture && verb !== "on") {
    return { error: "--record-fixture only applies to 'dg agents on'" };
  }
  return { verb, agents, recordFixture };
}

interface AgentRow {
  readonly agent: AgentId;
  readonly state: "protected" | "detected" | "not found" | "unsupported";
  readonly detail: string;
}

function agentRow(agent: AgentId, home: string, env: NodeJS.ProcessEnv): AgentRow {
  const integration = AGENTS[agent];
  if (!integration.detect(home)) {
    return { agent, state: "not found", detail: "" };
  }
  const probe = integration.probeHookSupport(home);
  if (!probe.supported) {
    return { agent, state: "unsupported", detail: probe.detail };
  }
  const ctx = resolveAgentHookContext(agent, { env, home });
  const hooked = integration.verify(ctx).find((check) => check.name === integration.isInstalledCheckName)?.ok ?? false;
  if (hooked) {
    return { agent, state: "protected", detail: tildify(ctx.settingsPath, home) };
  }
  return { agent, state: "detected", detail: `dg agents on ${agent}` };
}

function renderStatusCard(rows: readonly AgentRow[], theme: Theme): string {
  const accent = (text: string): string => theme.paint("accent", text);
  const muted = (text: string): string => theme.paint("muted", text);
  const glyph = (state: AgentRow["state"]): string => {
    if (state === "protected") {
      return theme.paint("pass", "✓");
    }
    if (state === "detected") {
      return accent("·");
    }
    if (state === "unsupported") {
      return theme.paint("warn", "✗");
    }
    return muted("–");
  };
  const labelWidth = Math.max(...rows.map((row) => agentLabel(row.agent).length));
  const stateWidth = Math.max(...rows.map((row) => row.state.length));
  const lines = [
    "",
    `  ${accent("AI agents")} ${muted("— installs route through dg before fetching")}`,
    ""
  ];
  for (const row of rows) {
    const label = agentLabel(row.agent).padEnd(labelWidth);
    const state = row.state === "protected" ? theme.paint("pass", row.state.padEnd(stateWidth)) : muted(row.state.padEnd(stateWidth));
    const detail = row.state === "detected" ? accent(row.detail) : muted(row.detail);
    lines.push(`  ${glyph(row.state)} ${label}  ${state}  ${detail}`.trimEnd());
  }
  lines.push("", `  ${muted("protect all:")} ${accent("dg agents on")} ${muted("·")} ${muted("remove:")} ${accent("dg agents off")}`, "");
  return lines.join("\n");
}

async function applyAgents(targets: readonly AgentId[], env: NodeJS.ProcessEnv, home: string, theme: Theme, recordFixture: boolean): Promise<CommandResult> {
  const accent = (text: string): string => theme.paint("accent", text);
  const muted = (text: string): string => theme.paint("muted", text);
  const lines: string[] = [];
  let failures = 0;
  for (const agent of targets) {
    const integration = AGENTS[agent];
    const probe = integration.probeHookSupport(home);
    if (!probe.supported) {
      failures += 1;
      lines.push(`  ${theme.paint("warn", `✗ ${integration.label}`)} ${muted(`— ${probe.detail}. The dg PATH shim still covers installs typed in its terminal.`)}`);
      continue;
    }
    const ctx = resolveAgentHookContext(agent, { env, home });
    const dgCommand = recordFixture ? `${ctx.dgCommand} --record-fixture` : ctx.dgCommand;
    try {
      await integration.apply({ ...ctx, dgCommand });
      lines.push(`  ${theme.paint("pass", `✓ ${integration.label} installs route through dg`)} ${muted(`(${tildify(ctx.settingsPath, home)})`)}`);
      if (integration.maturity === "unverified") {
        lines.push(`  ${muted(`  hook installed from ${integration.label}'s documented schema; payload format not yet verified against a live ${integration.label} run`)}`);
      }
      if (integration.postInstallNote) {
        lines.push(`  ${muted(`  ${integration.postInstallNote}`)}`);
      }
    } catch (error) {
      failures += 1;
      const message = error instanceof AgentHookError ? error.message : error instanceof Error ? error.message : "agent hook error";
      lines.push(`  ${theme.paint("warn", `✗ ${integration.label}`)} ${muted(`— ${message}`)}`);
    }
  }
  if (lines.length === 0) {
    return { exitCode: 0, stdout: `  ${muted("No unprotected agents detected.")} ${muted("See")} ${accent("dg agents")}\n`, stderr: "" };
  }
  lines.push(`  ${muted("Reverse:")} ${accent("dg agents off")}`);
  return { exitCode: failures > 0 && failures === targets.length ? 1 : 0, stdout: `${lines.join("\n")}\n`, stderr: "" };
}

async function removeAgents(targets: readonly AgentId[], env: NodeJS.ProcessEnv, home: string, theme: Theme): Promise<CommandResult> {
  const muted = (text: string): string => theme.paint("muted", text);
  const lines: string[] = [];
  for (const agent of targets) {
    const integration = AGENTS[agent];
    const ctx = resolveAgentHookContext(agent, { env, home });
    try {
      const result = await integration.remove(ctx);
      lines.push(
        result.removed
          ? `  ${theme.paint("pass", `✓ ${integration.label} hook removed`)} ${muted(`(${tildify(ctx.settingsPath, home)})`)}`
          : `  ${muted(`· ${integration.label} — no dg hook was installed`)}`,
      );
    } catch (error) {
      const message = error instanceof AgentHookError ? error.message : error instanceof Error ? error.message : "agent hook error";
      lines.push(`  ${theme.paint("warn", `✗ ${integration.label}`)} ${muted(`— ${message}`)}`);
    }
  }
  if (lines.length === 0) {
    lines.push(`  ${muted("No agent hooks to remove.")}`);
  }
  return { exitCode: 0, stdout: `${lines.join("\n")}\n`, stderr: "" };
}

function checkAgents(targets: readonly AgentId[], env: NodeJS.ProcessEnv, home: string): CommandResult {
  const lines: string[] = [];
  let allOk = true;
  for (const agent of targets) {
    const ctx = resolveAgentHookContext(agent, { env, home });
    const checks = getAgent(agent).verify(ctx);
    lines.push(`${agentLabel(agent)}:`);
    for (const check of checks) {
      lines.push(`  ${check.ok ? "✓" : "✗"} ${check.name}: ${check.detail}`);
      allOk = allOk && check.ok;
    }
  }
  return { exitCode: allOk ? 0 : 1, stdout: `${lines.join("\n")}\n`, stderr: "" };
}

function printAgents(targets: readonly AgentId[], env: NodeJS.ProcessEnv, home: string): CommandResult {
  const lines: string[] = [];
  for (const agent of targets) {
    const integration = AGENTS[agent];
    const ctx = resolveAgentHookContext(agent, { env, home });
    const probe = integration.probeHookSupport(home);
    lines.push(
      `dg agents on ${agent} would write a dg hook to:`,
      `  ${ctx.settingsPath}`,
      "running:",
      `  ${ctx.dgCommand}`,
      `probe: ${probe.supported ? "supported" : "unsupported"} — ${probe.detail}`,
      `Reverse with: dg agents off ${agent}  (or dg uninstall)`,
    );
  }
  return { exitCode: 0, stdout: `${lines.join("\n")}\n`, stderr: "" };
}

export async function runAgentsCommand(args: readonly string[], env: NodeJS.ProcessEnv = process.env, home?: string): Promise<CommandResult> {
  const parsed = parseAgentsArgs(args);
  if ("error" in parsed) {
    return { exitCode: EXIT_USAGE, stdout: "", stderr: `dg agents: ${parsed.error}\n` };
  }
  const resolvedHome = home ?? env.HOME ?? homedir();
  const theme = createTheme(resolvePresentation().color);
  if (parsed.verb === "status") {
    const rows = AGENT_IDS.map((agent) => agentRow(agent, resolvedHome, env));
    return { exitCode: 0, stdout: `${renderStatusCard(rows, theme)}\n`, stderr: "" };
  }
  if (parsed.verb === "on") {
    const targets = parsed.agents.length > 0 ? parsed.agents : collectAgentOffers({ env, home: resolvedHome }).map((offer) => offer.agent);
    return applyAgents(targets, env, resolvedHome, theme, parsed.recordFixture);
  }
  if (parsed.verb === "off") {
    const targets = parsed.agents.length > 0
      ? parsed.agents
      : AGENT_IDS.filter((agent) => agentRow(agent, resolvedHome, env).state === "protected");
    return removeAgents(targets, env, resolvedHome, theme);
  }
  const targets = parsed.agents.length > 0
    ? parsed.agents
    : AGENT_IDS.filter((agent) => AGENTS[agent].detect(resolvedHome));
  if (targets.length === 0) {
    return { exitCode: 1, stdout: "", stderr: "dg agents: no AI agents detected on this machine.\n" };
  }
  return parsed.verb === "--check" ? checkAgents(targets, env, resolvedHome) : printAgents(targets, env, resolvedHome);
}

async function handle({ args }: CommandContext): Promise<CommandResult> {
  return runAgentsCommand(args);
}

export const agentsCommand: CommandSpec = {
  name: "agents",
  aliases: ["hook"],
  summary: "Route AI coding agents' package installs through dg's firewall",
  usage: "dg agents [on|off|--check|--print] [agent ...]",
  details: [
    "Bare 'dg agents' shows every supported agent and whether its installs are protected.",
    "'dg agents on' installs a native pre-command hook into every detected agent (or name one, e.g. 'dg agents on claude-code') so the shell installs it runs are checked by dg and blocked before a malicious package is fetched. Reversible via 'dg agents off' or 'dg uninstall'.",
  ],
  args: [{ name: "agent", summary: AGENT_IDS.join(" | ") }],
  examples: ["dg agents", "dg agents on", "dg agents on claude-code", "dg agents --check", "dg agents off"],
  handler: handle,
};
