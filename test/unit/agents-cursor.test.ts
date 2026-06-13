import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cursorIntegration } from "../../src/agents/cursor.js";
import {
  applyAgentHook,
  removeAgentHookForAgent,
  resolveAgentHookContext,
  verifyAgentHook,
} from "../../src/agents/registry.js";

describe("cursor integration", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-cursor-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  function ctx() {
    return resolveAgentHookContext("cursor", { env: { HOME: home }, home, dgCommand: "/abs/dg hook-exec cursor" });
  }

  it("parses the top-level command payload and fails closed otherwise", () => {
    expect(cursorIntegration.parseInput(JSON.stringify({ command: "npm i x", cwd: "/w" }))).toEqual({ command: "npm i x", cwd: "/w" });
    expect(cursorIntegration.parseInput(JSON.stringify({ command: "npm i x" }))).toEqual({ command: "npm i x" });
    expect(cursorIntegration.parseInput("nope")).toBeNull();
    expect(cursorIntegration.parseInput(JSON.stringify({ cmd: "x" }))).toBeNull();
  });

  it("emits the cursor permission shape for every decision", () => {
    expect(JSON.parse(cursorIntegration.emitDecision({ decision: "allow" }).stdout)).toEqual({ permission: "allow" });
    const deny = JSON.parse(cursorIntegration.emitDecision({ decision: "deny", reason: "blocked: evil" }).stdout) as Record<string, string>;
    expect(deny.permission).toBe("deny");
    expect(deny.user_message).toBe("blocked: evil");
    expect(deny.agent_message).toBe("blocked: evil");
    const ask = JSON.parse(cursorIntegration.emitDecision({ decision: "ask" }).stdout) as Record<string, string>;
    expect(ask.permission).toBe("ask");
  });

  it("merges into hooks.json preserving sibling hooks and removes only its own entry", async () => {
    const c = ctx();
    mkdirSync(join(home, ".cursor"), { recursive: true });
    writeFileSync(
      c.settingsPath,
      JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: "/their/hook" }], afterFileEdit: [{ command: "/their/format" }] } }),
      "utf8",
    );
    await applyAgentHook(c);
    const merged = JSON.parse(readFileSync(c.settingsPath, "utf8")) as {
      hooks: { beforeShellExecution: { command: string }[]; afterFileEdit: unknown[] };
    };
    expect(merged.hooks.beforeShellExecution).toHaveLength(2);
    expect(merged.hooks.beforeShellExecution.at(-1)?.command).toContain("hook-exec cursor");
    expect(merged.hooks.afterFileEdit).toHaveLength(1);
    expect(verifyAgentHook(c).every((check) => check.ok)).toBe(true);

    await removeAgentHookForAgent(c);
    const final = JSON.parse(readFileSync(c.settingsPath, "utf8")) as { hooks: { beforeShellExecution: { command: string }[] } };
    expect(final.hooks.beforeShellExecution).toHaveLength(1);
    expect(final.hooks.beforeShellExecution[0]?.command).toBe("/their/hook");
  });

  it("creates and fully reverses a fresh hooks.json", async () => {
    const c = ctx();
    const applied = await applyAgentHook(c);
    expect(applied.created).toBe(true);
    expect(JSON.parse(readFileSync(c.settingsPath, "utf8")).version).toBe(1);
    await removeAgentHookForAgent(c);
    expect(existsSync(c.settingsPath)).toBe(false);
  });

  it("never deletes the user's own version key when removing the dg hook", async () => {
    const c = ctx();
    mkdirSync(join(home, ".cursor"), { recursive: true });
    writeFileSync(c.settingsPath, JSON.stringify({ version: 1 }), "utf8");
    await applyAgentHook(c);
    await removeAgentHookForAgent(c);
    expect(existsSync(c.settingsPath)).toBe(true);
    expect(JSON.parse(readFileSync(c.settingsPath, "utf8"))).toEqual({ version: 1 });
  });

  it("probes dir presence and rejects an unmergeable hooks.json", () => {
    expect(cursorIntegration.probeHookSupport(home).supported).toBe(false);
    mkdirSync(join(home, ".cursor"), { recursive: true });
    expect(cursorIntegration.probeHookSupport(home).supported).toBe(true);
    writeFileSync(join(home, ".cursor", "hooks.json"), "[1,2,3]", "utf8");
    expect(cursorIntegration.probeHookSupport(home).supported).toBe(false);
  });
});
