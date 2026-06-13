import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { windsurfIntegration } from "../../src/agents/windsurf.js";
import {
  applyAgentHook,
  removeAgentHookForAgent,
  resolveAgentHookContext,
  verifyAgentHook,
} from "../../src/agents/registry.js";

describe("windsurf integration", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-windsurf-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  function ctx() {
    return resolveAgentHookContext("windsurf", { env: { HOME: home }, home, dgCommand: "/abs/dg hook-exec windsurf" });
  }

  it("parses tool_info.command_line and fails closed otherwise", () => {
    expect(windsurfIntegration.parseInput(JSON.stringify({ tool_info: { command_line: "npm i x", cwd: "/w" } }))).toEqual({ command: "npm i x", cwd: "/w" });
    expect(windsurfIntegration.parseInput(JSON.stringify({ tool_info: { command_line: "npm i x" } }))).toEqual({ command: "npm i x" });
    expect(windsurfIntegration.parseInput(JSON.stringify({ tool_info: {} }))).toBeNull();
    expect(windsurfIntegration.parseInput("nope")).toBeNull();
  });

  it("blocks via exit code 2 for deny AND ask, stays silent on allow", () => {
    expect(windsurfIntegration.emitDecision({ decision: "allow" })).toEqual({ stdout: "", exitCode: 0 });
    const deny = windsurfIntegration.emitDecision({ decision: "deny", reason: "DG blocked install — evil@1" });
    expect(deny.exitCode).toBe(2);
    expect(deny.stdout).toContain("evil@1");
    const ask = windsurfIntegration.emitDecision({ decision: "ask", reason: "DG flagged" });
    expect(ask.exitCode).toBe(2);
    expect(ask.stdout).toContain("flagged for review");
  });

  it("merges a pre_run_command entry preserving sibling hooks and removes only its own", async () => {
    const c = ctx();
    mkdirSync(join(home, ".codeium", "windsurf"), { recursive: true });
    writeFileSync(
      c.settingsPath,
      JSON.stringify({ hooks: { pre_run_command: [{ command: "/their/hook" }], post_write: [{ command: "/their/fmt" }] } }),
      "utf8",
    );
    await applyAgentHook(c);
    const merged = JSON.parse(readFileSync(c.settingsPath, "utf8")) as {
      hooks: { pre_run_command: { command: string }[]; post_write: unknown[] };
    };
    expect(merged.hooks.pre_run_command).toHaveLength(2);
    expect(merged.hooks.post_write).toHaveLength(1);
    expect(verifyAgentHook(c).every((check) => check.ok)).toBe(true);

    await removeAgentHookForAgent(c);
    const final = JSON.parse(readFileSync(c.settingsPath, "utf8")) as { hooks: { pre_run_command: { command: string }[] } };
    expect(final.hooks.pre_run_command).toHaveLength(1);
    expect(final.hooks.pre_run_command[0]?.command).toBe("/their/hook");
  });

  it("creates and fully reverses a fresh hooks.json", async () => {
    const c = ctx();
    const applied = await applyAgentHook(c);
    expect(applied.created).toBe(true);
    await removeAgentHookForAgent(c);
    expect(existsSync(c.settingsPath)).toBe(false);
  });

  it("detects only when the nested windsurf config dir exists", () => {
    expect(windsurfIntegration.detect(home)).toBe(false);
    expect(windsurfIntegration.probeHookSupport(home).supported).toBe(false);
    mkdirSync(join(home, ".codeium", "windsurf"), { recursive: true });
    expect(windsurfIntegration.detect(home)).toBe(true);
    expect(windsurfIntegration.probeHookSupport(home).supported).toBe(true);
  });
});
