import { join } from "node:path";
import type { AgentVerdict } from "../launcher/agent-check.js";
import type { AgentIntegration, EmittedDecision, ParsedHookInput, ProbeDeps, ProbeResult } from "./types.js";
import { dirExists, mergedJsonHook, probeMinCliVersion, type Json } from "./persistence.js";

const SIGNATURE = "hook-exec gemini";

function configPath(home: string): string {
  return join(home, ".gemini", "settings.json");
}

function isDgGroup(group: unknown): boolean {
  if (typeof group !== "object" || group === null) {
    return false;
  }
  const hooks = (group as { hooks?: unknown }).hooks;
  if (!Array.isArray(hooks)) {
    return false;
  }
  return hooks.some(
    (h) =>
      typeof h === "object" &&
      h !== null &&
      typeof (h as { command?: unknown }).command === "string" &&
      (h as { command: string }).command.includes(SIGNATURE),
  );
}

// No timeout field: gemini reads it in MILLISECONDS (default 60000); the
// Claude-style seconds value 60 made gemini kill the hook at 60ms and run
// the command ungated (gemini fails open on hook timeout).
function dgGroup(dgCommand: string): Json {
  return { matcher: "run_shell_command", hooks: [{ type: "command", command: dgCommand }] };
}

function insertHook(settings: Json, dgCommand: string): Json {
  const next: Json = { ...settings };
  const hooks: Json = typeof next.hooks === "object" && next.hooks !== null ? { ...(next.hooks as Json) } : {};
  const pre = Array.isArray(hooks.BeforeTool) ? (hooks.BeforeTool as unknown[]) : [];
  hooks.BeforeTool = [...pre.filter((g) => !isDgGroup(g)), dgGroup(dgCommand)];
  next.hooks = hooks;
  return next;
}

function removeHook(settings: Json): { settings: Json; changed: boolean; empty: boolean } {
  const next: Json = { ...settings };
  if (typeof next.hooks !== "object" || next.hooks === null) {
    return { settings: next, changed: false, empty: Object.keys(next).length === 0 };
  }
  const hooks: Json = { ...(next.hooks as Json) };
  const pre = Array.isArray(hooks.BeforeTool) ? (hooks.BeforeTool as unknown[]) : [];
  const withoutDg = pre.filter((g) => !isDgGroup(g));
  const changed = withoutDg.length !== pre.length;
  if (withoutDg.length > 0) {
    hooks.BeforeTool = withoutDg;
  } else {
    delete hooks.BeforeTool;
  }
  if (Object.keys(hooks).length > 0) {
    next.hooks = hooks;
  } else {
    delete next.hooks;
  }
  return { settings: next, changed, empty: Object.keys(next).length === 0 };
}

function hasDgHook(settings: Json): boolean {
  const hooks = (settings.hooks as Json | undefined)?.BeforeTool;
  return Array.isArray(hooks) && hooks.some((g) => isDgGroup(g));
}

function parseInput(stdin: string): ParsedHookInput | null {
  try {
    const obj = JSON.parse(stdin) as {
      tool_args?: { command?: unknown };
      tool_input?: { command?: unknown };
      cwd?: unknown;
    };
    const command = obj.tool_args?.command ?? obj.tool_input?.command;
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
    return { stdout: "{}", exitCode: 0 };
  }
  const reason = verdict.reason ?? "Dependency Guardian firewall";
  return {
    stdout: JSON.stringify({ decision: "block", reason }),
    exitCode: 0,
  };
}

function probeHookSupport(home: string, deps?: ProbeDeps): ProbeResult {
  if (!dirExists(join(home, ".gemini"))) {
    return { supported: false, detail: "~/.gemini not found (is Gemini CLI installed?)" };
  }
  return probeMinCliVersion("gemini", "0.26.0", "Gemini CLI", deps);
}

export const geminiIntegration: AgentIntegration = {
  id: "gemini",
  label: "Gemini CLI",
  kind: "merged-json",
  maturity: "verified",
  minVersion: "0.26.0",
  configPath,
  detect: (home) => dirExists(join(home, ".gemini")),
  probeHookSupport,
  parseInput,
  emitDecision,
  ...mergedJsonHook({
    checkName: "dg BeforeTool hook",
    insert: insertHook,
    remove: removeHook,
    isInstalled: hasDgHook,
  }),
};
