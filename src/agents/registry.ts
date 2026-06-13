import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { resolveDgPaths, type CleanupRegistryEntry } from "../state/index.js";
import { claudeCodeIntegration } from "./claude-code.js";
import { codexIntegration } from "./codex.js";
import { copilotCliIntegration } from "./copilot-cli.js";
import { cursorIntegration } from "./cursor.js";
import { geminiIntegration } from "./gemini.js";
import { LEGACY_AGENT_HOOK_SENTINEL } from "./persistence.js";
import { windsurfIntegration } from "./windsurf.js";
import type {
  AgentHookApplyResult,
  AgentHookCheck,
  AgentHookContext,
  AgentId,
  AgentIntegration,
  ProbeResult,
} from "./types.js";

export const AGENTS: Readonly<Record<AgentId, AgentIntegration>> = {
  "claude-code": claudeCodeIntegration,
  codex: codexIntegration,
  cursor: cursorIntegration,
  "copilot-cli": copilotCliIntegration,
  gemini: geminiIntegration,
  windsurf: windsurfIntegration,
};

export const AGENT_IDS: readonly AgentId[] = Object.keys(AGENTS) as AgentId[];

export function isAgentId(value: string): value is AgentId {
  return value in AGENTS;
}

export function getAgent(id: AgentId): AgentIntegration {
  return AGENTS[id];
}

export function agentLabel(id: string): string {
  return isAgentId(id) ? AGENTS[id].label : id;
}

export function agentHookSignature(agent: AgentId): string {
  return `hook-exec ${agent}`;
}

export function defaultDgCommand(agent: AgentId): string {
  let bin = process.argv[1] ?? "dg";
  try {
    bin = realpathSync(bin);
  } catch {
    // keep argv[1]; the hook still resolves via PATH as a fallback
  }
  // Absolute node + script path so the agent's non-interactive subprocess
  // can't lose it to a PATH change (the whole point of the hook).
  return `${process.execPath} ${bin} ${agentHookSignature(agent)}`;
}

export interface ResolveAgentHookOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly home?: string;
  readonly dgCommand?: string;
}

export function resolveAgentHookContext(agent: AgentId, options: ResolveAgentHookOptions = {}): AgentHookContext {
  const env = options.env ?? process.env;
  const home = options.home ?? env.HOME ?? homedir();
  return {
    agent,
    settingsPath: AGENTS[agent].configPath(home),
    dgCommand: options.dgCommand ?? defaultDgCommand(agent),
    paths: resolveDgPaths(env),
  };
}

export function applyAgentHook(ctx: AgentHookContext): Promise<AgentHookApplyResult> {
  return AGENTS[ctx.agent].apply(ctx);
}

export function removeAgentHookForAgent(ctx: AgentHookContext): Promise<{ removed: boolean }> {
  return AGENTS[ctx.agent].remove(ctx);
}

export function verifyAgentHook(ctx: AgentHookContext): AgentHookCheck[] {
  return AGENTS[ctx.agent].verify(ctx);
}

function agentFromSentinel(sentinel: string | undefined): AgentId | null {
  if (!sentinel || sentinel === LEGACY_AGENT_HOOK_SENTINEL) {
    return "claude-code";
  }
  if (!sentinel.startsWith(`${LEGACY_AGENT_HOOK_SENTINEL}:`)) {
    return null;
  }
  const id = sentinel.slice(LEGACY_AGENT_HOOK_SENTINEL.length + 1);
  return isAgentId(id) ? id : null;
}

export function reverseAgentHookEntry(
  entry: CleanupRegistryEntry,
  removed: string[],
  missing: string[],
  warnings: string[],
): void {
  const agent = agentFromSentinel(entry.sentinel);
  if (!agent) {
    warnings.push(`${entry.path}: unrecognized agent hook entry (${entry.sentinel ?? "no sentinel"}); left untouched`);
    return;
  }
  AGENTS[agent].reverseEntry(entry, removed, missing, warnings);
}

export interface AgentOffer {
  readonly agent: AgentId;
  readonly label: string;
  readonly ctx: AgentHookContext;
  readonly probe: ProbeResult;
}

export interface AgentSkip {
  readonly agent: AgentId;
  readonly label: string;
  readonly detail: string;
}

export function collectAgentSkips(options?: { readonly home?: string; readonly env?: NodeJS.ProcessEnv }): AgentSkip[] {
  const skips: AgentSkip[] = [];
  const env = options?.env ?? process.env;
  const home = options?.home ?? env.HOME ?? homedir();
  for (const agent of AGENT_IDS) {
    try {
      const integration = AGENTS[agent];
      if (!integration.detect(home)) {
        continue;
      }
      const probe = integration.probeHookSupport(home);
      if (!probe.supported) {
        skips.push({ agent, label: integration.label, detail: probe.detail });
      }
    } catch {
      continue;
    }
  }
  return skips;
}

export function collectAgentOffers(options?: { readonly home?: string; readonly env?: NodeJS.ProcessEnv }): AgentOffer[] {
  const offers: AgentOffer[] = [];
  const env = options?.env ?? process.env;
  const home = options?.home ?? env.HOME ?? homedir();
  for (const agent of AGENT_IDS) {
    try {
      const integration = AGENTS[agent];
      if (!integration.detect(home)) {
        continue;
      }
      const probe = integration.probeHookSupport(home);
      if (!probe.supported) {
        continue;
      }
      const ctx = resolveAgentHookContext(agent, options ?? {});
      const hooked = integration.verify(ctx).find((check) => check.name === integration.isInstalledCheckName)?.ok ?? false;
      if (!hooked) {
        offers.push({ agent, label: integration.label, ctx, probe });
      }
    } catch {
      continue;
    }
  }
  return offers;
}
