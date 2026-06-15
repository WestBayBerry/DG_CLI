import { join } from "node:path";
import { formatScreenedNote, type AgentVerdict } from "../launcher/agent-check.js";
import type { AgentIntegration, EmittedDecision, ParsedHookInput, ProbeResult } from "./types.js";
import { dirExists, mergedJsonHook, readSettings, type Json } from "./persistence.js";

const SIGNATURE = "hook-exec cursor";

function configPath(home: string): string {
  return join(home, ".cursor", "hooks.json");
}

function isDgEntry(entry: unknown): boolean {
  return (
    typeof entry === "object" &&
    entry !== null &&
    typeof (entry as { command?: unknown }).command === "string" &&
    (entry as { command: string }).command.includes(SIGNATURE)
  );
}

function hookList(settings: Json): unknown[] {
  const hooks = settings.hooks;
  if (typeof hooks !== "object" || hooks === null) {
    return [];
  }
  const list = (hooks as Json).beforeShellExecution;
  return Array.isArray(list) ? list : [];
}

function insertHook(settings: Json, dgCommand: string): Json {
  const next: Json = { ...settings };
  const hooks: Json = typeof next.hooks === "object" && next.hooks !== null ? { ...(next.hooks as Json) } : {};
  const list = Array.isArray(hooks.beforeShellExecution) ? (hooks.beforeShellExecution as unknown[]) : [];
  hooks.beforeShellExecution = [...list.filter((entry) => !isDgEntry(entry)), { command: dgCommand }];
  next.hooks = hooks;
  if (next.version === undefined) {
    next.version = 1;
  }
  return next;
}

function effectivelyEmpty(obj: Json): boolean {
  const keys = Object.keys(obj);
  return keys.length === 0 || (keys.length === 1 && keys[0] === "version");
}

function removeHook(settings: Json): { settings: Json; changed: boolean; empty: boolean } {
  const next: Json = { ...settings };
  if (typeof next.hooks !== "object" || next.hooks === null) {
    return { settings: next, changed: false, empty: effectivelyEmpty(next) };
  }
  const hooks: Json = { ...(next.hooks as Json) };
  const list = Array.isArray(hooks.beforeShellExecution) ? (hooks.beforeShellExecution as unknown[]) : [];
  const withoutDg = list.filter((entry) => !isDgEntry(entry));
  const changed = withoutDg.length !== list.length;
  if (withoutDg.length > 0) {
    hooks.beforeShellExecution = withoutDg;
  } else {
    delete hooks.beforeShellExecution;
  }
  if (Object.keys(hooks).length > 0) {
    next.hooks = hooks;
  } else {
    delete next.hooks;
  }
  return { settings: next, changed, empty: effectivelyEmpty(next) };
}

function hasDgHook(settings: Json): boolean {
  return hookList(settings).some((entry) => isDgEntry(entry));
}

function parseInput(stdin: string): ParsedHookInput | null {
  try {
    const obj = JSON.parse(stdin) as { command?: unknown; cwd?: unknown };
    if (typeof obj.command !== "string") {
      return null;
    }
    return typeof obj.cwd === "string" ? { command: obj.command, cwd: obj.cwd } : { command: obj.command };
  } catch {
    return null;
  }
}

function emitDecision(verdict: AgentVerdict): EmittedDecision {
  if (verdict.decision === "allow") {
    const note = verdict.screened ? formatScreenedNote(verdict.screened) : "";
    return {
      stdout: JSON.stringify(note ? { permission: "allow", agent_message: note } : { permission: "allow" }),
      exitCode: 0,
    };
  }
  const reason = verdict.reason ?? "Dependency Guardian firewall";
  return {
    stdout: JSON.stringify({ permission: verdict.decision, user_message: reason, agent_message: reason }),
    exitCode: 0,
  };
}

function probeHookSupport(home: string): ProbeResult {
  if (!dirExists(join(home, ".cursor"))) {
    return { supported: false, detail: "~/.cursor not found (is Cursor installed?)" };
  }
  try {
    readSettings(configPath(home));
  } catch {
    return { supported: false, detail: `${configPath(home)} exists but is not a JSON object dg can merge into` };
  }
  return { supported: true, detail: "requires Cursor 1.7+; dg cannot read your Cursor version from disk" };
}

export const cursorIntegration: AgentIntegration = {
  id: "cursor",
  label: "Cursor",
  kind: "merged-json",
  maturity: "verified",
  minVersion: "1.7",
  configPath,
  detect: (home) => dirExists(join(home, ".cursor")),
  probeHookSupport,
  parseInput,
  emitDecision,
  ...mergedJsonHook({
    checkName: "dg beforeShellExecution hook",
    insert: insertHook,
    remove: removeHook,
    isInstalled: hasDgHook,
  }),
};
