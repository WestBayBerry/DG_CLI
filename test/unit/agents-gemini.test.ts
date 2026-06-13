import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { geminiIntegration } from "../../src/agents/gemini.js";
import {
  applyAgentHook,
  removeAgentHookForAgent,
  resolveAgentHookContext,
  verifyAgentHook,
} from "../../src/agents/registry.js";

describe("gemini integration", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-gemini-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  function ctx() {
    return resolveAgentHookContext("gemini", { env: { HOME: home }, home, dgCommand: "/abs/dg hook-exec gemini" });
  }

  it("parses tool_args.command with a tool_input fallback and fails closed otherwise", () => {
    expect(geminiIntegration.parseInput(JSON.stringify({ tool_args: { command: "npm i x" }, cwd: "/w" }))).toEqual({ command: "npm i x", cwd: "/w" });
    expect(geminiIntegration.parseInput(JSON.stringify({ tool_input: { command: "npm i x" } }))).toEqual({ command: "npm i x" });
    expect(geminiIntegration.parseInput(JSON.stringify({ tool_args: {} }))).toBeNull();
    expect(geminiIntegration.parseInput("nope")).toBeNull();
  });

  it("emits silent allow and a block decision for deny and ask alike (no ask channel)", () => {
    expect(geminiIntegration.emitDecision({ decision: "allow" })).toEqual({ stdout: "{}", exitCode: 0 });
    const deny = JSON.parse(geminiIntegration.emitDecision({ decision: "deny", reason: "blocked" }).stdout) as Record<string, string>;
    expect(deny.decision).toBe("block");
    expect(deny.reason).toBe("blocked");
    const ask = JSON.parse(geminiIntegration.emitDecision({ decision: "ask", reason: "flagged" }).stdout) as Record<string, string>;
    expect(ask.decision).toBe("block");
  });

  it("merges a BeforeTool group into settings.json preserving user keys and groups", async () => {
    const c = ctx();
    mkdirSync(join(home, ".gemini"), { recursive: true });
    writeFileSync(
      c.settingsPath,
      JSON.stringify({ theme: "dark", hooks: { BeforeTool: [{ matcher: "run_shell_command", hooks: [{ type: "command", command: "/their/hook" }] }] } }),
      "utf8",
    );
    await applyAgentHook(c);
    const merged = JSON.parse(readFileSync(c.settingsPath, "utf8")) as {
      theme: string;
      hooks: { BeforeTool: { hooks: { command: string }[] }[] };
    };
    expect(merged.theme).toBe("dark");
    expect(merged.hooks.BeforeTool).toHaveLength(2);
    expect(verifyAgentHook(c).every((check) => check.ok)).toBe(true);

    await removeAgentHookForAgent(c);
    const final = JSON.parse(readFileSync(c.settingsPath, "utf8")) as { theme: string; hooks: { BeforeTool: unknown[] } };
    expect(final.theme).toBe("dark");
    expect(final.hooks.BeforeTool).toHaveLength(1);
    expect(existsSync(c.settingsPath)).toBe(true);
  });

  it("probes the gemini CLI version and refuses below 0.26.0", () => {
    expect(geminiIntegration.probeHookSupport(home).supported).toBe(false);
    mkdirSync(join(home, ".gemini"), { recursive: true });
    expect(geminiIntegration.probeHookSupport(home, { execVersion: () => "0.25.9" }).supported).toBe(false);
    expect(geminiIntegration.probeHookSupport(home, { execVersion: () => "0.26.0" }).supported).toBe(true);
    expect(geminiIntegration.probeHookSupport(home, { execVersion: () => null }).supported).toBe(false);
  });
});
