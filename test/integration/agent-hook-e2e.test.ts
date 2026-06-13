import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AGENT_IDS, AGENTS } from "../../src/agents/registry.js";

const DG = resolve(dirname(fileURLToPath(import.meta.url)), "../../dist/bin/dg.js");
const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), "../fixtures/agent-hooks");

function run(args: string[], home: string, input = ""): { status: number; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [DG, ...args], {
    env: { ...process.env, HOME: home },
    input,
    encoding: "utf8",
  });
  return { status: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

describe("agent hook e2e (built binary)", () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-hook-e2e-"));
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("hook-exec returns {} for a passthrough command, exit 0, no network", () => {
    const r = run(["hook-exec", "claude-code"], home, JSON.stringify({ tool_input: { command: "npm ls" } }));
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toBe("{}");
  });

  it("install -> --check -> off lifecycle writes and reverses the PreToolUse hook", () => {
    const settings = join(home, ".claude", "settings.json");
    expect(run(["hook", "claude-code", "install"], home).status).toBe(0);
    expect(existsSync(settings)).toBe(true);
    const parsed = JSON.parse(readFileSync(settings, "utf8"));
    expect(parsed.hooks.PreToolUse[0].hooks[0].command).toContain("hook-exec claude-code");
    expect(run(["hook", "claude-code", "--check"], home).status).toBe(0);
    expect(run(["hook", "claude-code", "off"], home).status).toBe(0);
    expect(existsSync(settings)).toBe(false);
  });

  it("off preserves the user's own settings + PreToolUse hook", () => {
    const settings = join(home, ".claude", "settings.json");
    mkdirSync(join(home, ".claude"), { recursive: true });
    writeFileSync(
      settings,
      JSON.stringify({ model: "x", hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo mine" }] }] } }),
    );
    run(["hook", "claude-code", "install"], home);
    expect(JSON.parse(readFileSync(settings, "utf8")).hooks.PreToolUse).toHaveLength(2);
    run(["hook", "claude-code", "off"], home);
    const final = JSON.parse(readFileSync(settings, "utf8"));
    expect(final.model).toBe("x");
    expect(final.hooks.PreToolUse).toHaveLength(1);
    expect(final.hooks.PreToolUse[0].hooks[0].command).toBe("echo mine");
    expect(existsSync(settings)).toBe(true);
  });

  it("every probe-supported agent round-trips on -> --check -> off through the built binary", () => {
    const usable = AGENT_IDS.filter((agent) => {
      mkdirSync(dirname(AGENTS[agent].configPath(home)), { recursive: true });
      return AGENTS[agent].probeHookSupport(home).supported;
    });
    expect(usable).toContain("claude-code");
    for (const agent of usable) {
      const on = run(["agents", "on", agent], home);
      expect(on.status, `${agent} on failed: ${on.stdout}${on.stderr}`).toBe(0);
      expect(existsSync(AGENTS[agent].configPath(home)), `${agent} wrote no config`).toBe(true);
      const check = run(["agents", "--check", agent], home);
      expect(check.status, `${agent} --check failed: ${check.stdout}`).toBe(0);
    }
    for (const agent of usable) {
      expect(run(["agents", "off", agent], home).status).toBe(0);
      expect(run(["agents", "--check", agent], home).status, `${agent} still verified after off`).toBe(1);
    }
  });

  it("hook-exec exits cleanly for every agent's synthetic passthrough payload", () => {
    for (const agent of AGENT_IDS) {
      const fixture = JSON.parse(
        readFileSync(join(FIXTURES, agent, "synthetic", "minimal.json"), "utf8"),
      ) as { payload: unknown };
      const passthrough = JSON.stringify(fixture.payload).replace(/(npm install left-pad|pip install requests)/, "npm ls");
      const r = run(["hook-exec", agent], home, passthrough);
      expect(r.status, `${agent} hook-exec failed: ${r.stderr}`).toBe(0);
    }
  });

  it("dg uninstall reverses the agent hook and preserves the user's hook", () => {
    const settings = join(home, ".claude", "settings.json");
    mkdirSync(join(home, ".claude"), { recursive: true });
    writeFileSync(
      settings,
      JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo mine" }] }] } }),
    );
    run(["hook", "claude-code", "install"], home);
    run(["uninstall", "--yes"], home);
    const final = JSON.parse(readFileSync(settings, "utf8"));
    expect(final.hooks.PreToolUse).toHaveLength(1);
    expect(final.hooks.PreToolUse[0].hooks[0].command).toBe("echo mine");
  });
});
