import { join } from "node:path";
import { formatScreenedNote, type AgentVerdict } from "../launcher/agent-check.js";
import type { AgentIntegration, EmittedDecision, ParsedHookInput } from "./types.js";
import { dirExists, mergedJsonHook, LEGACY_AGENT_HOOK_SENTINEL, type Json } from "./persistence.js";

const SIGNATURE = "hook-exec claude-code";

function configPath(home: string): string {
  return join(home, ".claude", "settings.json");
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

function dgGroup(dgCommand: string): Json {
  return { matcher: "Bash", hooks: [{ type: "command", command: dgCommand, timeout: 60 }] };
}

// Idempotently insert the dg PreToolUse group, preserving every other key the
// user has in their settings (round-trips unknown keys).
export function insertDgHook(settings: Json, dgCommand: string): Json {
  const next: Json = { ...settings };
  const hooks: Json = typeof next.hooks === "object" && next.hooks !== null ? { ...(next.hooks as Json) } : {};
  const pre = Array.isArray(hooks.PreToolUse) ? (hooks.PreToolUse as unknown[]) : [];
  hooks.PreToolUse = [...pre.filter((g) => !isDgGroup(g)), dgGroup(dgCommand)];
  next.hooks = hooks;
  return next;
}

export function removeDgHook(settings: Json): { settings: Json; changed: boolean; empty: boolean } {
  const next: Json = { ...settings };
  if (typeof next.hooks !== "object" || next.hooks === null) {
    return { settings: next, changed: false, empty: Object.keys(next).length === 0 };
  }
  const hooks: Json = { ...(next.hooks as Json) };
  const pre = Array.isArray(hooks.PreToolUse) ? (hooks.PreToolUse as unknown[]) : [];
  const withoutDg = pre.filter((g) => !isDgGroup(g));
  const changed = withoutDg.length !== pre.length;
  if (withoutDg.length > 0) {
    hooks.PreToolUse = withoutDg;
  } else {
    delete hooks.PreToolUse;
  }
  if (Object.keys(hooks).length > 0) {
    next.hooks = hooks;
  } else {
    delete next.hooks;
  }
  return { settings: next, changed, empty: Object.keys(next).length === 0 };
}

function hasDgHook(settings: Json): boolean {
  const hooks = (settings.hooks as Json | undefined)?.PreToolUse;
  return Array.isArray(hooks) && hooks.some((g) => isDgGroup(g));
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

// Claude Code PreToolUse contract: emit a decision only to deny/ask; stay
// silent ({}) on allow so we never override the user's normal permission flow.
function emitDecision(verdict: AgentVerdict): EmittedDecision {
  if (verdict.decision === "allow") {
    const note = verdict.screened ? formatScreenedNote(verdict.screened) : "";
    if (note) {
      return {
        stdout: JSON.stringify({
          hookSpecificOutput: { hookEventName: "PreToolUse", additionalContext: note },
        }),
        exitCode: 0,
      };
    }
    return { stdout: "{}", exitCode: 0 };
  }
  return {
    stdout: JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: verdict.decision,
        ...(verdict.reason ? { permissionDecisionReason: verdict.reason } : {}),
      },
    }),
    exitCode: 0,
  };
}

export const claudeCodeIntegration: AgentIntegration = {
  id: "claude-code",
  label: "Claude Code",
  kind: "merged-json",
  maturity: "verified",
  minVersion: null,
  configPath,
  detect: (home) => dirExists(join(home, ".claude")),
  probeHookSupport: (home) => ({
    supported: true,
    detail: dirExists(join(home, ".claude"))
      ? "Claude Code settings directory found"
      : "settings hooks are supported by every Claude Code version; ~/.claude will be created",
  }),
  parseInput,
  emitDecision,
  ...mergedJsonHook({
    checkName: "dg PreToolUse hook",
    legacySentinels: [LEGACY_AGENT_HOOK_SENTINEL],
    insert: insertDgHook,
    remove: removeDgHook,
    isInstalled: hasDgHook,
  }),
};
