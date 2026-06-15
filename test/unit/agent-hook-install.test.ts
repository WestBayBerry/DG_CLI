import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  applyAgentHook,
  removeAgentHookForAgent,
  resolveAgentHookContext,
  verifyAgentHook,
} from "../../src/agents/registry.js";
import { insertDgHook, removeDgHook } from "../../src/agents/claude-code.js";
import type { AgentHookContext } from "../../src/agents/types.js";

describe("agent-hook JSON merge (pure)", () => {
  it("inserts the dg PreToolUse group, preserving other keys", () => {
    const out = insertDgHook(
      { model: "opus", hooks: { PostToolUse: [{ matcher: "X" }] } },
      "/abs/dg hook-exec claude-code",
    ) as any;
    expect(out.model).toBe("opus");
    expect(out.hooks.PostToolUse).toBeDefined();
    expect(out.hooks.PreToolUse).toHaveLength(1);
    expect(out.hooks.PreToolUse[0].hooks[0].command).toContain("hook-exec claude-code");
  });

  it("is idempotent — re-insert replaces, never duplicates", () => {
    let s: any = {};
    s = insertDgHook(s, "/abs/dg hook-exec claude-code");
    s = insertDgHook(s, "/abs/dg hook-exec claude-code");
    expect(s.hooks.PreToolUse.filter((g: any) => g.hooks[0].command.includes("hook-exec claude-code"))).toHaveLength(1);
  });

  it("preserves a user's own PreToolUse entry alongside dg, and removes only dg", () => {
    const userGroup = { matcher: "Bash", hooks: [{ type: "command", command: "echo user" }] };
    let s: any = { hooks: { PreToolUse: [userGroup] } };
    s = insertDgHook(s, "/abs/dg hook-exec claude-code");
    expect(s.hooks.PreToolUse).toHaveLength(2);
    const r = removeDgHook(s) as any;
    expect(r.changed).toBe(true);
    expect(r.settings.hooks.PreToolUse).toHaveLength(1);
    expect(r.settings.hooks.PreToolUse[0].hooks[0].command).toBe("echo user");
  });

  it("reports empty when dg was the only content", () => {
    const s = insertDgHook({}, "/abs/dg hook-exec claude-code");
    const r = removeDgHook(s);
    expect(r.changed).toBe(true);
    expect(r.empty).toBe(true);
  });
});

describe("agent-hook install/remove (temp HOME)", () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-agenthook-"));
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  function ctx(): AgentHookContext {
    return resolveAgentHookContext("claude-code", { env: { HOME: home }, home, dgCommand: `${process.execPath} hook-exec claude-code` });
  }

  it("installs into a fresh HOME and fully reverses (file dg-created -> removed)", async () => {
    const c = ctx();
    await applyAgentHook(c);
    expect(existsSync(c.settingsPath)).toBe(true);
    expect(verifyAgentHook(c).every((x) => x.ok)).toBe(true);
    await removeAgentHookForAgent(c);
    expect(existsSync(c.settingsPath)).toBe(false);
  });

  it("preserves the user's existing settings on install and on remove", async () => {
    const c = ctx();
    mkdirSync(join(home, ".claude"), { recursive: true });
    writeFileSync(
      c.settingsPath,
      JSON.stringify({ model: "opus", hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo mine" }] }] } }),
    );
    await applyAgentHook(c);
    const after = JSON.parse(readFileSync(c.settingsPath, "utf8"));
    expect(after.model).toBe("opus");
    expect(after.hooks.PreToolUse).toHaveLength(2);
    await removeAgentHookForAgent(c);
    const final = JSON.parse(readFileSync(c.settingsPath, "utf8"));
    expect(final.model).toBe("opus");
    expect(final.hooks.PreToolUse).toHaveLength(1);
    expect(final.hooks.PreToolUse[0].hooks[0].command).toBe("echo mine");
    expect(existsSync(c.settingsPath)).toBe(true);
  });

  it("refuses to replace a symlinked settings.json and leaves the link intact", async () => {
    const c = ctx();
    mkdirSync(join(home, ".claude"), { recursive: true });
    const linkTarget = join(home, "dotfiles-settings.json");
    writeFileSync(linkTarget, "{}\n");
    symlinkSync(linkTarget, c.settingsPath);

    await expect(applyAgentHook(c)).rejects.toThrow(/symlink/);
    expect(lstatSync(c.settingsPath).isSymbolicLink()).toBe(true);
    expect(readFileSync(linkTarget, "utf8")).toBe("{}\n");
  });
});
