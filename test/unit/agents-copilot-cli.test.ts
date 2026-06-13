import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { copilotCliIntegration } from "../../src/agents/copilot-cli.js";
import {
  applyAgentHook,
  removeAgentHookForAgent,
  resolveAgentHookContext,
  verifyAgentHook,
} from "../../src/agents/registry.js";

describe("copilot-cli integration", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-copilot-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  function ctx() {
    return resolveAgentHookContext("copilot-cli", { env: { HOME: home }, home, dgCommand: "/abs/dg hook-exec copilot-cli" });
  }

  it("parses toolArgs as an object and as a JSON string (double-parse quirk)", () => {
    expect(copilotCliIntegration.parseInput(JSON.stringify({ toolArgs: { command: "npm i x" }, cwd: "/w" }))).toEqual({ command: "npm i x", cwd: "/w" });
    expect(copilotCliIntegration.parseInput(JSON.stringify({ toolArgs: "{\"command\":\"npm i x\"}" }))).toEqual({ command: "npm i x" });
    expect(copilotCliIntegration.parseInput(JSON.stringify({ toolArgs: "not json" }))).toBeNull();
    expect(copilotCliIntegration.parseInput(JSON.stringify({ toolArgs: {} }))).toBeNull();
    expect(copilotCliIntegration.parseInput("garbage")).toBeNull();
  });

  it("emits silent allow, native permissionDecision on deny and ask", () => {
    expect(copilotCliIntegration.emitDecision({ decision: "allow" })).toEqual({ stdout: "{}", exitCode: 0 });
    const deny = JSON.parse(copilotCliIntegration.emitDecision({ decision: "deny", reason: "blocked" }).stdout) as Record<string, string>;
    expect(deny.permissionDecision).toBe("deny");
    expect(deny.permissionDecisionReason).toBe("blocked");
    const ask = JSON.parse(copilotCliIntegration.emitDecision({ decision: "ask", reason: "flagged" }).stdout) as Record<string, string>;
    expect(ask.permissionDecision).toBe("ask");
    expect(ask.permissionDecisionReason).toBe("flagged");
  });

  it("merges into ~/.copilot/settings.json preserving the user's keys and hooks", async () => {
    const c = ctx();
    mkdirSync(dirname(c.settingsPath), { recursive: true });
    writeFileSync(
      c.settingsPath,
      JSON.stringify({ theme: "dark", hooks: { preToolUse: [{ type: "command", command: "echo mine" }] } }),
      "utf8",
    );

    await applyAgentHook(c);
    const written = JSON.parse(readFileSync(c.settingsPath, "utf8")) as {
      theme: string;
      hooks: { preToolUse: { command: string; matcher?: string }[] };
    };
    expect(written.theme).toBe("dark");
    expect(written.hooks.preToolUse).toHaveLength(2);
    expect(written.hooks.preToolUse[1]?.command).toContain("hook-exec copilot-cli");
    expect(written.hooks.preToolUse[1]?.matcher).toBe("bash");
    expect(verifyAgentHook(c).every((check) => check.ok)).toBe(true);

    await removeAgentHookForAgent(c);
    const after = JSON.parse(readFileSync(c.settingsPath, "utf8")) as { theme: string; hooks: { preToolUse: { command: string }[] } };
    expect(after.theme).toBe("dark");
    expect(after.hooks.preToolUse).toHaveLength(1);
    expect(after.hooks.preToolUse[0]?.command).toBe("echo mine");
  });

  it("probes the .copilot dir and requires copilot >= 1.0.61 via the injected version check", () => {
    expect(copilotCliIntegration.probeHookSupport(home, { execVersion: () => "GitHub Copilot CLI 1.0.61." }).supported).toBe(false);
    mkdirSync(join(home, ".copilot"), { recursive: true });
    expect(copilotCliIntegration.probeHookSupport(home, { execVersion: () => null }).supported).toBe(false);
    expect(copilotCliIntegration.probeHookSupport(home, { execVersion: () => "GitHub Copilot CLI 1.0.60." }).supported).toBe(false);
    expect(copilotCliIntegration.probeHookSupport(home, { execVersion: () => "GitHub Copilot CLI 1.0.61." }).supported).toBe(true);
  });
});
