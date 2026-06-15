import { join } from "node:path";
import type { AgentVerdict } from "../launcher/agent-check.js";
import type { AgentIntegration, EmittedDecision, ParsedHookInput, ProbeDeps, ProbeResult } from "./types.js";
import { dirExists, ownedJsonHook, probeMinCliVersion, type Json } from "./persistence.js";

function configPath(home: string): string {
  return join(home, ".codex", "hooks.json");
}

function parseInput(stdin: string): ParsedHookInput | null {
  try {
    const obj = JSON.parse(stdin) as { tool_input?: { command?: unknown }; cwd?: unknown };
    const command = obj.tool_input?.command;
    if (typeof command !== "string") {
      return null;
    }
    return typeof obj.cwd === "string" ? { command, cwd: obj.cwd } : { command };
  } catch {
    return null;
  }
}

function emitDecision(verdict: AgentVerdict): EmittedDecision {
  if (verdict.decision === "allow") {
    return { stdout: "", exitCode: 0 };
  }
  const reason = verdict.reason ?? "Dependency Guardian firewall";
  const suffix = verdict.decision === "ask" ? " (dg flagged this for human review — not auto-approved)" : "";
  return {
    stdout: JSON.stringify({ decision: "block", reason: `${reason}${suffix}` }),
    exitCode: 0,
  };
}

function renderHookFile(dgCommand: string): Json {
  return {
    hooks: {
      PreToolUse: [
        {
          matcher: "Bash",
          hooks: [{ type: "command", command: dgCommand, timeout: 60, statusMessage: "Dependency Guardian install check" }],
        },
      ],
    },
  };
}

function probeHookSupport(home: string, deps?: ProbeDeps): ProbeResult {
  if (!dirExists(join(home, ".codex"))) {
    return { supported: false, detail: "~/.codex not found (is Codex CLI installed?)" };
  }
  return probeMinCliVersion("codex", "0.124.0", "Codex CLI", deps);
}

export const codexIntegration: AgentIntegration = {
  id: "codex",
  label: "Codex CLI",
  kind: "owned-json",
  maturity: "verified",
  minVersion: "0.124.0",
  postInstallNote: "Codex asks to trust new hooks: approve the dg hook when Codex prompts on its next start.",
  configPath,
  detect: (home) => dirExists(join(home, ".codex")),
  probeHookSupport,
  parseInput,
  emitDecision,
  ...ownedJsonHook({
    agent: "codex",
    checkName: "dg PreToolUse hook",
    render: renderHookFile,
  }),
};
