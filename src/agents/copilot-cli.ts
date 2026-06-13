import { join } from "node:path";
import type { AgentVerdict } from "../launcher/agent-check.js";
import type { AgentIntegration, EmittedDecision, ParsedHookInput, ProbeDeps, ProbeResult } from "./types.js";
import { dirExists, mergedJsonHook, probeMinCliVersion, type Json } from "./persistence.js";

const SIGNATURE = "hook-exec copilot-cli";

function configPath(home: string): string {
  return join(home, ".copilot", "settings.json");
}

function isDgEntry(entry: unknown): boolean {
  return (
    typeof entry === "object" &&
    entry !== null &&
    typeof (entry as { command?: unknown }).command === "string" &&
    (entry as { command: string }).command.includes(SIGNATURE)
  );
}

// Native camelCase event contract (PascalCase keys switch copilot into its
// VS Code snake_case compat mode, a different payload shape). toolName for
// the shell tool is "bash" — the UI's "shell" label is display-only.
function dgEntry(dgCommand: string): Json {
  return { type: "command", matcher: "bash", command: dgCommand, timeoutSec: 60 };
}

export function insertDgHook(settings: Json, dgCommand: string): Json {
  const next: Json = { ...settings };
  const hooks: Json = typeof next.hooks === "object" && next.hooks !== null ? { ...(next.hooks as Json) } : {};
  const pre = Array.isArray(hooks.preToolUse) ? (hooks.preToolUse as unknown[]) : [];
  hooks.preToolUse = [...pre.filter((e) => !isDgEntry(e)), dgEntry(dgCommand)];
  next.hooks = hooks;
  return next;
}

export function removeDgHook(settings: Json): { settings: Json; changed: boolean; empty: boolean } {
  const next: Json = { ...settings };
  if (typeof next.hooks !== "object" || next.hooks === null) {
    return { settings: next, changed: false, empty: Object.keys(next).length === 0 };
  }
  const hooks: Json = { ...(next.hooks as Json) };
  const pre = Array.isArray(hooks.preToolUse) ? (hooks.preToolUse as unknown[]) : [];
  const withoutDg = pre.filter((e) => !isDgEntry(e));
  const changed = withoutDg.length !== pre.length;
  if (withoutDg.length > 0) {
    hooks.preToolUse = withoutDg;
  } else {
    delete hooks.preToolUse;
  }
  if (Object.keys(hooks).length > 0) {
    next.hooks = hooks;
  } else {
    delete next.hooks;
  }
  return { settings: next, changed, empty: Object.keys(next).length === 0 };
}

function hasDgHook(settings: Json): boolean {
  const hooks = (settings.hooks as Json | undefined)?.preToolUse;
  return Array.isArray(hooks) && hooks.some((e) => isDgEntry(e));
}

function toolArgsObject(raw: unknown): Json | null {
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw) as unknown;
      return typeof parsed === "object" && parsed !== null ? (parsed as Json) : null;
    } catch {
      return null;
    }
  }
  return typeof raw === "object" && raw !== null ? (raw as Json) : null;
}

function parseInput(stdin: string): ParsedHookInput | null {
  try {
    const obj = JSON.parse(stdin) as { toolArgs?: unknown; cwd?: unknown };
    const args = toolArgsObject(obj.toolArgs);
    const command = args?.command;
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
  return {
    stdout: JSON.stringify({
      permissionDecision: verdict.decision,
      ...(verdict.reason ? { permissionDecisionReason: verdict.reason } : {}),
    }),
    exitCode: 0,
  };
}

function probeHookSupport(home: string, deps?: ProbeDeps): ProbeResult {
  if (!dirExists(join(home, ".copilot"))) {
    return { supported: false, detail: "~/.copilot not found (is GitHub Copilot CLI installed?)" };
  }
  return probeMinCliVersion("copilot", "1.0.61", "GitHub Copilot CLI", deps);
}

export const copilotCliIntegration: AgentIntegration = {
  id: "copilot-cli",
  label: "GitHub Copilot CLI",
  kind: "merged-json",
  maturity: "verified",
  minVersion: "1.0.61",
  configPath,
  detect: (home) => dirExists(join(home, ".copilot")),
  probeHookSupport,
  parseInput,
  emitDecision,
  ...mergedJsonHook({
    checkName: "dg preToolUse hook",
    insert: insertDgHook,
    remove: removeDgHook,
    isInstalled: hasDgHook,
  }),
};
