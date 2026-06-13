import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runAgentsCommand } from "../../src/commands/agents.js";
import { routeCommand } from "../../src/commands/router.js";

describe("dg agents", () => {
  let home: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-agents-cmd-"));
    env = { HOME: home };
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  function settingsPath(): string {
    return join(home, ".claude", "settings.json");
  }

  it("renders the status card with a not-found agent", async () => {
    const result = await runAgentsCommand([], env, home);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("AI agents");
    expect(result.stdout).toContain("Claude Code");
    expect(result.stdout).toContain("not found");
    expect(result.stdout).toContain("dg agents on");
  });

  it("walks detected → protected through the card as the hook is applied", async () => {
    mkdirSync(join(home, ".claude"), { recursive: true });
    const detected = await runAgentsCommand([], env, home);
    expect(detected.stdout).toContain("detected");
    expect(detected.stdout).toContain("dg agents on claude-code");

    const applied = await runAgentsCommand(["on"], env, home);
    expect(applied.exitCode).toBe(0);
    expect(applied.stdout).toContain("✓ Claude Code installs route through dg");
    expect(applied.stdout).toContain("settings.json");
    expect(existsSync(settingsPath())).toBe(true);

    const after = await runAgentsCommand([], env, home);
    expect(after.stdout).toContain("protected");
  });

  it("applies nothing and says so when no agents are detected", async () => {
    const result = await runAgentsCommand(["on"], env, home);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("No unprotected agents detected");
    expect(existsSync(settingsPath())).toBe(false);
  });

  it("on/off round-trips a named agent with per-agent outcome lines", async () => {
    mkdirSync(join(home, ".claude"), { recursive: true });
    await runAgentsCommand(["on", "claude-code"], env, home);
    const parsed = JSON.parse(readFileSync(settingsPath(), "utf8")) as { hooks: { PreToolUse: unknown[] } };
    expect(parsed.hooks.PreToolUse).toHaveLength(1);

    const off = await runAgentsCommand(["off", "claude-code"], env, home);
    expect(off.exitCode).toBe(0);
    expect(off.stdout).toContain("✓ Claude Code hook removed");
    expect(existsSync(settingsPath())).toBe(false);

    const again = await runAgentsCommand(["off", "claude-code"], env, home);
    expect(again.stdout).toContain("no dg hook was installed");
  });

  it("--check reports per-check lines and exit 1 when not installed", async () => {
    mkdirSync(join(home, ".claude"), { recursive: true });
    const before = await runAgentsCommand(["--check"], env, home);
    expect(before.exitCode).toBe(1);
    expect(before.stdout).toContain("Claude Code:");

    await runAgentsCommand(["on"], env, home);
    const after = await runAgentsCommand(["--check", "claude-code"], env, home);
    expect(after.exitCode).toBe(0);
    expect(after.stdout).toContain("✓ dg PreToolUse hook: installed");
  });

  it("--print previews the write without applying it", async () => {
    mkdirSync(join(home, ".claude"), { recursive: true });
    const result = await runAgentsCommand(["--print", "claude-code"], env, home);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("would write a dg hook");
    expect(result.stdout).toContain("hook-exec claude-code");
    expect(existsSync(settingsPath())).toBe(false);
  });

  it("accepts the legacy hook grammar: agent first, verb second", async () => {
    mkdirSync(join(home, ".claude"), { recursive: true });
    const installed = await runAgentsCommand(["claude-code", "install"], env, home);
    expect(installed.exitCode).toBe(0);
    expect(existsSync(settingsPath())).toBe(true);
    const off = await runAgentsCommand(["claude-code", "off"], env, home);
    expect(off.exitCode).toBe(0);
    expect(existsSync(settingsPath())).toBe(false);
  });

  it("rejects unknown agents and unknown verbs", async () => {
    const badAgent = await runAgentsCommand(["on", "clippy"], env, home);
    expect(badAgent.exitCode).toBe(2);
    expect(badAgent.stderr).toContain("unknown agent 'clippy'");

    const badVerb = await runAgentsCommand(["explode"], env, home);
    expect(badVerb.exitCode).toBe(2);
    expect(badVerb.stderr).toContain("unknown subcommand 'explode'");
  });

  it("routes 'dg hook' as a working alias", async () => {
    const result = await routeCommand(["hook"]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("AI agents");
  });

  it("does not list the hook alias in root help", async () => {
    const help = await routeCommand(["--help-all"]);
    expect(help.stdout).toContain("agents");
    expect(help.stdout).not.toMatch(/^\s{2}hook\s/m);
  });
});
