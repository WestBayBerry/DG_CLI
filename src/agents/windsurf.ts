import { join } from "node:path";
import type { AgentVerdict } from "../launcher/agent-check.js";
import type { AgentIntegration, EmittedDecision, ParsedHookInput, ProbeResult } from "./types.js";
import { dirExists, mergedJsonHook, type Json } from "./persistence.js";

const SIGNATURE = "hook-exec windsurf";

function configPath(home: string): string {
  return join(home, ".codeium", "windsurf", "hooks.json");
}

function isDgEntry(entry: unknown): boolean {
  return (
    typeof entry === "object" &&
    entry !== null &&
    typeof (entry as { command?: unknown }).command === "string" &&
    (entry as { command: string }).command.includes(SIGNATURE)
  );
}

function insertHook(settings: Json, dgCommand: string): Json {
  const next: Json = { ...settings };
  const hooks: Json = typeof next.hooks === "object" && next.hooks !== null ? { ...(next.hooks as Json) } : {};
  const list = Array.isArray(hooks.pre_run_command) ? (hooks.pre_run_command as unknown[]) : [];
  hooks.pre_run_command = [...list.filter((entry) => !isDgEntry(entry)), { command: dgCommand }];
  next.hooks = hooks;
  return next;
}

function removeHook(settings: Json): { settings: Json; changed: boolean; empty: boolean } {
  const next: Json = { ...settings };
  if (typeof next.hooks !== "object" || next.hooks === null) {
    return { settings: next, changed: false, empty: Object.keys(next).length === 0 };
  }
  const hooks: Json = { ...(next.hooks as Json) };
  const list = Array.isArray(hooks.pre_run_command) ? (hooks.pre_run_command as unknown[]) : [];
  const withoutDg = list.filter((entry) => !isDgEntry(entry));
  const changed = withoutDg.length !== list.length;
  if (withoutDg.length > 0) {
    hooks.pre_run_command = withoutDg;
  } else {
    delete hooks.pre_run_command;
  }
  if (Object.keys(hooks).length > 0) {
    next.hooks = hooks;
  } else {
    delete next.hooks;
  }
  return { settings: next, changed, empty: Object.keys(next).length === 0 };
}

function hasDgHook(settings: Json): boolean {
  const hooks = (settings.hooks as Json | undefined)?.pre_run_command;
  return Array.isArray(hooks) && hooks.some((entry) => isDgEntry(entry));
}

function parseInput(stdin: string): ParsedHookInput | null {
  try {
    const obj = JSON.parse(stdin) as { tool_info?: { command_line?: unknown; cwd?: unknown } };
    const command = obj.tool_info?.command_line;
    if (typeof command !== "string") {
      return null;
    }
    const cwd = obj.tool_info?.cwd;
    return typeof cwd === "string" ? { command, cwd } : { command };
  } catch {
    return null;
  }
}

function emitDecision(verdict: AgentVerdict): EmittedDecision {
  if (verdict.decision === "allow") {
    return { stdout: "", exitCode: 0 };
  }
  const reason = verdict.reason ?? "Dependency Guardian firewall";
  const suffix = verdict.decision === "ask" ? " (flagged for review — run the install in a terminal to decide)" : "";
  return { stdout: `${reason}${suffix}\n`, exitCode: 2 };
}

function probeHookSupport(home: string): ProbeResult {
  if (!dirExists(join(home, ".codeium", "windsurf"))) {
    return { supported: false, detail: "~/.codeium/windsurf not found (is Windsurf installed?)" };
  }
  return { supported: true, detail: "Windsurf config directory found; dg cannot read the app version from disk" };
}

export const windsurfIntegration: AgentIntegration = {
  id: "windsurf",
  label: "Windsurf",
  kind: "merged-json",
  maturity: "unverified",
  minVersion: null,
  configPath,
  detect: (home) => dirExists(join(home, ".codeium", "windsurf")),
  probeHookSupport,
  parseInput,
  emitDecision,
  ...mergedJsonHook({
    checkName: "dg pre_run_command hook",
    insert: insertHook,
    remove: removeHook,
    isInstalled: hasDgHook,
  }),
};
