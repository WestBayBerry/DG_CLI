import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { codexIntegration } from "../../src/agents/codex.js";
import {
  applyAgentHook,
  removeAgentHookForAgent,
  resolveAgentHookContext,
  verifyAgentHook,
} from "../../src/agents/registry.js";
import { agentHookSentinel } from "../../src/agents/persistence.js";

describe("codex integration", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-codex-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  function ctx() {
    return resolveAgentHookContext("codex", { env: { HOME: home }, home, dgCommand: "/abs/dg hook-exec codex" });
  }

  it("parses the Claude-shaped payload and fails closed on malformed input", () => {
    expect(codexIntegration.parseInput(JSON.stringify({ tool_input: { command: "npm i x" }, cwd: "/w" }))).toEqual({ command: "npm i x", cwd: "/w" });
    expect(codexIntegration.parseInput("not json")).toBeNull();
    expect(codexIntegration.parseInput(JSON.stringify({ tool_input: {} }))).toBeNull();
  });

  it("emits empty allow and the flat block decision codex consumes, for deny and ask alike", () => {
    expect(codexIntegration.emitDecision({ decision: "allow" })).toEqual({ stdout: "", exitCode: 0 });
    const deny = JSON.parse(codexIntegration.emitDecision({ decision: "deny", reason: "blocked" }).stdout) as Record<string, string>;
    expect(deny.decision).toBe("block");
    expect(deny.reason).toBe("blocked");
    const ask = JSON.parse(codexIntegration.emitDecision({ decision: "ask", reason: "flagged" }).stdout) as Record<string, string>;
    expect(ask.decision).toBe("block");
    expect(ask.reason).toContain("flagged for review");
  });

  it("probes the codex CLI version and refuses below 0.124.0 or when unknown", () => {
    expect(codexIntegration.probeHookSupport(home).supported).toBe(false);
    mkdirSync(join(home, ".codex"), { recursive: true });
    expect(codexIntegration.probeHookSupport(home, { execVersion: () => null }).supported).toBe(false);
    expect(codexIntegration.probeHookSupport(home, { execVersion: () => "codex 0.123.9" }).supported).toBe(false);
    expect(codexIntegration.probeHookSupport(home, { execVersion: () => "codex 0.124.0" }).supported).toBe(true);
    expect(codexIntegration.probeHookSupport(home, { execVersion: () => "1.2.0" }).supported).toBe(true);
  });

  it("writes a dg-owned hooks.json layer and round-trips install/verify/remove", async () => {
    const c = ctx();
    const applied = await applyAgentHook(c);
    expect(applied.created).toBe(true);
    const written = JSON.parse(readFileSync(c.settingsPath, "utf8")) as { dgSentinel: string; hooks: { PreToolUse: unknown[] } };
    expect(written.dgSentinel).toBe(agentHookSentinel("codex"));
    expect(written.hooks.PreToolUse).toHaveLength(1);
    expect(verifyAgentHook(c).every((check) => check.ok)).toBe(true);

    const removed = await removeAgentHookForAgent(c);
    expect(removed.removed).toBe(true);
    expect(existsSync(c.settingsPath)).toBe(false);
  });

  it("refuses to overwrite a foreign ~/.codex/hooks.json", async () => {
    const c = ctx();
    mkdirSync(join(home, ".codex"), { recursive: true });
    writeFileSync(c.settingsPath, JSON.stringify({ hooks: { PreToolUse: [] } }), "utf8");
    await expect(applyAgentHook(c)).rejects.toThrow(/not written by dg/);
    const untouched = JSON.parse(readFileSync(c.settingsPath, "utf8")) as { dgSentinel?: string };
    expect(untouched.dgSentinel).toBeUndefined();
  });

  it("remove leaves a foreign file alone", async () => {
    const c = ctx();
    mkdirSync(join(home, ".codex"), { recursive: true });
    writeFileSync(c.settingsPath, JSON.stringify({ theirs: true }), "utf8");
    const removed = await removeAgentHookForAgent(c);
    expect(removed.removed).toBe(false);
    expect(existsSync(c.settingsPath)).toBe(true);
  });
});
