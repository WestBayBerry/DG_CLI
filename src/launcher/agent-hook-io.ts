import { agentCheckCommand, ESCALATE, formatScreenedNote, type AgentVerdict } from "./agent-check.js";
import { getAgent } from "../agents/registry.js";
import { redactSecrets } from "./output-redaction.js";
import type { AgentId } from "../agents/types.js";

export interface HookExecResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode: number;
}

export interface HookExecDeps {
  readonly env?: NodeJS.ProcessEnv;
  readonly fetchImpl?: typeof fetch;
}

export async function runAgentHookExec(agent: AgentId, stdin: string, deps: HookExecDeps = {}): Promise<HookExecResult> {
  const integration = getAgent(agent);
  const parsed = integration.parseInput(stdin);
  if (!parsed) {
    // Unreadable payload -> fail closed (deny) so a malformed hook input can
    // never slip an install through unverified.
    const verdict: AgentVerdict = { decision: "deny", reason: `dg hook: could not read the tool command, so the install is blocked. ${ESCALATE}` };
    const emitted = integration.emitDecision(verdict);
    return { stdout: emitted.stdout, stderr: "dg hook: malformed hook payload\n", exitCode: emitted.exitCode };
  }
  let verdict: AgentVerdict;
  try {
    verdict = await agentCheckCommand({
      commandLine: parsed.command,
      ...(parsed.cwd ? { cwd: parsed.cwd } : {}),
      ...(deps.env ? { env: deps.env } : {}),
      ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
    });
  } catch {
    // Any failure computing the verdict must fail closed: an unhandled throw
    // would otherwise exit non-zero with no decision, which most agents read
    // as allow.
    verdict = { decision: "deny", reason: `dg hook: the firewall check failed, so the install is blocked. ${ESCALATE}` };
  }
  const emitted = integration.emitDecision(verdict);
  const stderr = allowStderr(verdict);
  return { stdout: emitted.stdout, stderr, exitCode: emitted.exitCode };
}

function allowStderr(verdict: AgentVerdict): string {
  if (verdict.decision !== "allow") {
    return `  ${redactSecrets(verdict.reason ?? "DG firewall")}\n`;
  }
  const note = verdict.screened ? formatScreenedNote(verdict.screened) : "";
  return note ? `  ${redactSecrets(note)}\n` : "";
}
