import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const checkMock = vi.fn();
vi.mock("../../src/launcher/agent-check.js", () => ({
  agentCheckCommand: (...a: unknown[]) => checkMock(...a),
}));

import { runAgentHookExec } from "../../src/launcher/agent-hook-io.js";
import {
  AGENT_IDS,
  AGENTS,
  applyAgentHook,
  collectAgentOffers,
  removeAgentHookForAgent,
  resolveAgentHookContext,
  reverseAgentHookEntry,
  verifyAgentHook,
} from "../../src/agents/registry.js";
import { LEGACY_AGENT_HOOK_SENTINEL, agentHookSentinel } from "../../src/agents/persistence.js";
import { readCleanupRegistry, recordCleanupEntry, resolveDgPaths } from "../../src/state/index.js";
import type { AgentId } from "../../src/agents/types.js";

const FIXTURES_ROOT = fileURLToPath(new URL("../fixtures/agent-hooks", import.meta.url));

interface FixtureFile {
  readonly expectedCommand: string;
  readonly payload: unknown;
}

function fixturePaths(agent: AgentId, kind: "live" | "synthetic"): string[] {
  const dir = join(FIXTURES_ROOT, agent, kind);
  if (!existsSync(dir)) {
    return [];
  }
  return readdirSync(dir)
    .filter((name) => name.endsWith(".json") && name !== "meta.json")
    .map((name) => join(dir, name));
}

describe("agent registry maturity gate", () => {
  it("marks an agent verified only when a live fixture and meta.json exist", () => {
    for (const agent of AGENT_IDS) {
      const live = fixturePaths(agent, "live");
      const meta = join(FIXTURES_ROOT, agent, "live", "meta.json");
      if (AGENTS[agent].maturity === "verified") {
        expect(live.length, `${agent} is verified but has no live fixture`).toBeGreaterThan(0);
        expect(existsSync(meta), `${agent} is verified but has no live/meta.json`).toBe(true);
      } else {
        expect(live.length, `${agent} has live fixtures but is still marked unverified`).toBe(0);
      }
    }
  });
});

describe("fixture replay through runAgentHookExec", () => {
  beforeEach(() => checkMock.mockReset());

  it("parses every fixture and emits the agent's blocking shape on deny", async () => {
    for (const agent of AGENT_IDS) {
      const files = [...fixturePaths(agent, "live"), ...fixturePaths(agent, "synthetic")];
      expect(files.length, `${agent} has no fixtures at all`).toBeGreaterThan(0);
      for (const file of files) {
        const fixture = JSON.parse(readFileSync(file, "utf8")) as FixtureFile;
        const stdin = typeof fixture.payload === "string" ? fixture.payload : JSON.stringify(fixture.payload);
        const parsed = AGENTS[agent].parseInput(stdin);
        expect(parsed?.command, `${file} did not parse`).toBe(fixture.expectedCommand);

        checkMock.mockResolvedValue({ decision: "deny", reason: "DG blocked install" });
        const result = await runAgentHookExec(agent, stdin);
        const emitted = AGENTS[agent].emitDecision({ decision: "deny", reason: "DG blocked install" });
        expect(result.stdout).toBe(emitted.stdout);
        expect(result.exitCode).toBe(emitted.exitCode);
      }
    }
  });
});

describe("sentinel migration (claude-code legacy entries)", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-sentinel-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  function ctx() {
    return resolveAgentHookContext("claude-code", { env: { HOME: home }, home, dgCommand: "/abs/dg hook-exec claude-code" });
  }

  it("re-install upgrades a legacy registry entry without duplicating it", async () => {
    const c = ctx();
    await recordCleanupEntry(c.paths, {
      kind: "agent-hook",
      path: c.settingsPath,
      mode: "mode1",
      sentinel: LEGACY_AGENT_HOOK_SENTINEL,
    });
    await applyAgentHook(c);
    const reg = await readCleanupRegistry(c.paths);
    const hookEntries = reg.entries.filter((entry) => entry.kind === "agent-hook" && entry.path === c.settingsPath);
    expect(hookEntries).toHaveLength(1);
    expect(hookEntries[0]?.sentinel).toBe(agentHookSentinel("claude-code"));
  });

  it("remove drops both suffixed and legacy entries", async () => {
    const c = ctx();
    await applyAgentHook(c);
    await recordCleanupEntry(c.paths, {
      kind: "agent-hook",
      path: c.settingsPath,
      mode: "mode1",
      sentinel: LEGACY_AGENT_HOOK_SENTINEL,
    });
    await removeAgentHookForAgent(c);
    const reg = await readCleanupRegistry(c.paths);
    expect(reg.entries.filter((entry) => entry.kind === "agent-hook")).toHaveLength(0);
  });

  it("reverseAgentHookEntry treats a bare legacy sentinel as claude-code", async () => {
    const c = ctx();
    await applyAgentHook(c);
    const removed: string[] = [];
    const missing: string[] = [];
    const warnings: string[] = [];
    reverseAgentHookEntry(
      { kind: "agent-hook", path: c.settingsPath, mode: "mode1", sentinel: LEGACY_AGENT_HOOK_SENTINEL, installedAt: "2026-01-01T00:00:00.000Z", owner: "dg" },
      removed,
      missing,
      warnings,
    );
    expect(removed).toEqual([c.settingsPath]);
    expect(warnings).toEqual([]);
  });

  it("reverseAgentHookEntry leaves an unrecognized sentinel untouched with a warning", () => {
    const path = join(home, ".future-agent", "hooks.json");
    mkdirSync(join(home, ".future-agent"), { recursive: true });
    writeFileSync(path, "{}\n");
    const removed: string[] = [];
    const missing: string[] = [];
    const warnings: string[] = [];
    reverseAgentHookEntry(
      { kind: "agent-hook", path, mode: "mode1", sentinel: "dg-agent-hook-v1:future-agent", installedAt: "2026-01-01T00:00:00.000Z", owner: "dg" },
      removed,
      missing,
      warnings,
    );
    expect(removed).toEqual([]);
    expect(warnings).toHaveLength(1);
    expect(existsSync(path)).toBe(true);
  });
});

describe("collectAgentOffers", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-offers-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("collects every detected, probe-supported, unhooked agent", async () => {
    expect(collectAgentOffers({ home, env: { HOME: home } })).toEqual([]);
    mkdirSync(join(home, ".claude"), { recursive: true });
    const offers = collectAgentOffers({ home, env: { HOME: home } });
    expect(offers).toHaveLength(1);
    expect(offers[0]?.agent).toBe("claude-code");
    expect(offers[0]?.label).toBe("Claude Code");
    expect(offers[0]?.probe.supported).toBe(true);

    await applyAgentHook(offers[0]!.ctx);
    expect(collectAgentOffers({ home, env: { HOME: home } })).toEqual([]);
  });
});

describe("cross-agent isolation", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-isolation-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("removing one agent's hook leaves the other verified, and uninstall reverses both", async () => {
    const claude = resolveAgentHookContext("claude-code", { env: { HOME: home }, home, dgCommand: "/abs/dg hook-exec claude-code" });
    const codex = resolveAgentHookContext("codex", { env: { HOME: home }, home, dgCommand: "/abs/dg hook-exec codex" });
    await applyAgentHook(claude);
    await applyAgentHook(codex);
    expect(verifyAgentHook(claude).every((check) => check.ok)).toBe(true);
    expect(verifyAgentHook(codex).every((check) => check.ok)).toBe(true);

    await removeAgentHookForAgent(codex);
    expect(existsSync(codex.settingsPath)).toBe(false);
    expect(verifyAgentHook(claude).every((check) => check.ok)).toBe(true);

    await applyAgentHook(codex);
    const reg = await readCleanupRegistry(claude.paths);
    const removed: string[] = [];
    const missing: string[] = [];
    const warnings: string[] = [];
    for (const entry of reg.entries.filter((candidate) => candidate.kind === "agent-hook")) {
      reverseAgentHookEntry(entry, removed, missing, warnings);
    }
    expect(removed.sort()).toEqual([claude.settingsPath, codex.settingsPath].sort());
    expect(warnings).toEqual([]);
    expect(existsSync(claude.settingsPath)).toBe(false);
    expect(existsSync(codex.settingsPath)).toBe(false);
  });
});

describe("fs safety on agent config writes", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-fs-safety-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("refuses to write through a world-writable settings file", async () => {
    const c = resolveAgentHookContext("claude-code", { env: { HOME: home }, home, dgCommand: "/abs/dg hook-exec claude-code" });
    mkdirSync(join(home, ".claude"), { recursive: true });
    writeFileSync(c.settingsPath, "{}\n");
    chmodSync(c.settingsPath, 0o602);
    await expect(applyAgentHook(c)).rejects.toThrow(/world-writable/);
  });

  it("still verifies and round-trips through the registry helpers", async () => {
    const c = resolveAgentHookContext("claude-code", { env: { HOME: home }, home, dgCommand: "/abs/dg hook-exec claude-code" });
    await applyAgentHook(c);
    expect(verifyAgentHook(c).every((check) => check.ok)).toBe(true);
    const paths = resolveDgPaths({ HOME: home });
    const reg = await readCleanupRegistry(paths);
    expect(reg.entries.some((entry) => entry.sentinel === agentHookSentinel("claude-code"))).toBe(true);
  });
});
