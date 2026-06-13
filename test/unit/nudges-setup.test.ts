import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { maybeSetupNudge, nudgeStatePath } from "../../src/runtime/nudges.js";

const NOW = new Date("2026-06-12T12:00:00.000Z");

describe("post-install setup nudge", () => {
  let home: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-nudge-setup-"));
    env = { HOME: home };
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("fires once ever, then stays silent", () => {
    const first = maybeSetupNudge("npm", { env, stderrIsTTY: true, now: NOW });
    expect(first).toContain("dg setup");
    expect(first).toContain("Make this automatic");
    const state = JSON.parse(readFileSync(nudgeStatePath(env), "utf8")) as { setupNudgedAt?: string };
    expect(state.setupNudgedAt).toBe(NOW.toISOString());

    expect(maybeSetupNudge("npm", { env, stderrIsTTY: true, now: NOW })).toBe("");
  });

  it("stays silent when the shim for this manager is installed", () => {
    mkdirSync(join(home, ".dg", "shims"), { recursive: true });
    writeFileSync(join(home, ".dg", "shims", "npm"), "#!/bin/sh\n");
    expect(maybeSetupNudge("npm", { env, stderrIsTTY: true, now: NOW })).toBe("");
  });

  it("stays silent when invoked through a dg shim", () => {
    expect(maybeSetupNudge("npm", { env: { ...env, DG_SHIM_ACTIVE: "npm:123" }, stderrIsTTY: true, now: NOW })).toBe("");
  });

  it("stays silent without a TTY and in CI", () => {
    expect(maybeSetupNudge("npm", { env, stderrIsTTY: false, now: NOW })).toBe("");
    expect(maybeSetupNudge("npm", { env: { ...env, CI: "1" }, stderrIsTTY: true, now: NOW })).toBe("");
  });

  it("leaves the other nudge state fields alone", () => {
    mkdirSync(join(home, ".dg", "state"), { recursive: true });
    writeFileSync(nudgeStatePath(env), JSON.stringify({ updateCheckedAt: "2026-06-01T00:00:00.000Z", loginNudgedAt: "2026-06-02T00:00:00.000Z" }), "utf8");
    maybeSetupNudge("npm", { env, stderrIsTTY: true, now: NOW });
    const state = JSON.parse(readFileSync(nudgeStatePath(env), "utf8")) as Record<string, string>;
    expect(state.updateCheckedAt).toBe("2026-06-01T00:00:00.000Z");
    expect(state.loginNudgedAt).toBe("2026-06-02T00:00:00.000Z");
    expect(state.setupNudgedAt).toBe(NOW.toISOString());
  });
});
