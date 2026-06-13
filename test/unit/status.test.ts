import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runCli } from "../../src/runtime/cli.js";
import { writeAuthState } from "../../src/auth/store.js";
import { runStatusCommand } from "../../src/commands/status.js";

function stubUsageFetch(body: unknown): ReturnType<typeof vi.fn> {
  const impl = vi.fn(async () => ({ ok: true, json: async () => body }));
  vi.stubGlobal("fetch", impl);
  return impl;
}

describe("dg status (value-level)", () => {
  let home: string;
  let savedHome: string | undefined;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "dg-status-"));
    savedHome = process.env.HOME;
    process.env.HOME = home;
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    if (savedHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = savedHome;
    }
    await rm(home, { recursive: true, force: true });
  });

  it("shows disconnected + unprotected state on a fresh machine, with the right next steps", async () => {
    const result = await runCli(["status"]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("not connected");
    expect(result.stdout).toContain("dg login");
    expect(result.stdout).toContain("not set up");
    expect(result.stdout).toContain("dg setup");
    expect(result.stdout).toContain("block mode");
  });

  it("does not tell you to run dg setup again once the shims exist (reload, not re-setup)", async () => {
    const { applySetupPlanWithLock, buildSetupPlan } = await import("../../src/setup/plan.js");
    applySetupPlanWithLock(buildSetupPlan({ shell: "bash" }));
    const line = (await runCli(["status"])).stdout.split("\n").find((l) => l.includes("Installs"));
    expect(line).toBeDefined();
    // shims now exist but are not on this process's PATH → guide to activate, never "run dg setup"
    expect(line).not.toContain("run dg setup");
    expect(line).toContain("active in new terminals");
    // configured-but-not-loaded reads as a calm one-step state, not a warning
    expect(line).toContain("configured");
    expect(line).not.toContain("⚠");
    expect(line).toContain("to activate this shell");
  });

  it("--json reflects the actual state (not just shape)", async () => {
    const result = await runCli(["status", "--json"]);
    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.stdout) as {
      account: { connected: boolean };
      protection: { shims: boolean; path: boolean };
      policy: { mode: string };
      cooldown: string;
    };
    expect(report.account.connected).toBe(false);
    expect(report.protection.shims).toBe(false);
    expect(report.policy.mode).toBe("block");
    expect(report.cooldown).toBe("24h");
  });

  it("shows the effective cooldown line (default 24h, off when disabled)", async () => {
    const defaultResult = await runCli(["status"]);
    expect(defaultResult.stdout).toContain("Cooldown     24h release-age gate on new installs");

    const { updateUserConfig, setConfigValue } = await import("../../src/config/settings.js");
    updateUserConfig((config) => setConfigValue(config, "cooldown.age", "0"));
    const offResult = await runCli(["status"]);
    expect(offResult.stdout).toContain("Cooldown     off — new releases install immediately");
  });

  it("shows connected once an auth token is present", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    stubUsageFetch({ tier: "free", scansUsed: 3, scansLimit: 100 });
    const result = await runCli(["status"]);
    expect(result.stdout).toContain("✓ connected");
    expect(result.stdout).not.toContain("not connected");
    const json = JSON.parse((await runCli(["status", "--json"])).stdout) as { account: { connected: boolean } };
    expect(json.account.connected).toBe(true);
  });

  it("shows the account email and plan when the login cached them", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi", email: "user@example.com", tier: "pro" });
    stubUsageFetch({ tier: "pro", scansUsed: 3, scansLimit: 100 });
    const result = await runCli(["status"]);
    const line = result.stdout.split("\n").find((l) => l.includes("Account"));
    expect(line).toContain("user@example.com · Pro plan");
    expect(line).not.toContain("connected (");
    const json = JSON.parse((await runCli(["status", "--json"])).stdout) as { account: { email?: string; tier?: string } };
    expect(json.account.email).toBe("user@example.com");
    expect(json.account.tier).toBe("pro");
  });

  it("renders the scan-footer usage format for an authenticated account", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi", email: "user@example.com", tier: "pro" });
    const fetchImpl = stubUsageFetch({ tier: "pro", scansUsed: 11229, scansLimit: 50000 });
    const result = await runCli(["status"]);
    const line = result.stdout.split("\n").find((l) => l.includes("Usage"));
    expect(line).toContain("11,229 / 50,000 packages this month");
    const [url, init] = fetchImpl.mock.calls[0] as [string, { headers: Record<string, string> }];
    expect(url).toContain("/v1/auth/status");
    expect(init.headers.Authorization).toBe("Bearer dg_test_token_abcdefghi");
    const json = JSON.parse((await runCli(["status", "--json"])).stdout) as {
      usage: { state: string; used: number; limit: number | null };
    };
    expect(json.usage).toEqual({ state: "ok", used: 11229, limit: 50000 });
  });

  it("tells anonymous devices to sign in for usage without any network call", async () => {
    const fetchImpl = vi.fn();
    vi.stubGlobal("fetch", fetchImpl);
    const result = await runCli(["status"]);
    expect(result.exitCode).toBe(0);
    const line = result.stdout.split("\n").find((l) => l.includes("Usage"));
    expect(line).toContain("sign in to see usage");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("degrades to 'unavailable offline' when the usage fetch fails", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi", email: "user@example.com", tier: "pro" });
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("network down");
    }));
    const result = await runCli(["status"]);
    expect(result.exitCode).toBe(0);
    const line = result.stdout.split("\n").find((l) => l.includes("Usage"));
    expect(line).toContain("unavailable offline");
  });

  it("never hangs on a stalled usage endpoint — the short timeout degrades it", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi", email: "user@example.com", tier: "pro" });
    const hangingFetch = ((_url: string, init?: { signal?: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      })) as unknown as typeof fetch;
    const result = await runStatusCommand([], { fetchImpl: hangingFetch, usageTimeoutMs: 50 });
    expect(result.exitCode).toBe(0);
    const line = result.stdout.split("\n").find((l) => l.includes("Usage"));
    expect(line).toContain("unavailable offline");
  });

  it("collapses install protection into one honest line (no redundant Prefix mode)", async () => {
    const result = await runCli(["status"]);
    expect(result.stdout).not.toContain("Prefix mode");
    const line = result.stdout.split("\n").find((l) => l.includes("Installs"));
    expect(line).toBeDefined();
    // fresh machine: not set up, and it offers the dg-prefix alternative
    expect(line).toContain("not set up");
    expect(line).toContain("dg");
  });

  it("rejects an unknown flag", async () => {
    const result = await runCli(["status", "--bogus"]);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("unknown option");
  });
});
