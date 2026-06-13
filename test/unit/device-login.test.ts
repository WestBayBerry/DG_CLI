import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  assertTrustedVerifyUrl,
  createAuthSession,
  fetchAccountStatus,
  maybeDeviceLogin,
  pollAuthSession,
  resolveWebBase,
  runDeviceLogin
} from "../../src/auth/device-login.js";

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body
  } as unknown as Response;
}

describe("device login (browser flow)", () => {
  let home: string;
  let savedHome: string | undefined;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "dg-login-test-"));
    savedHome = process.env.HOME;
    process.env.HOME = home;
  });

  afterEach(async () => {
    if (savedHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = savedHome;
    }
    await rm(home, { recursive: true, force: true });
  });

  it("opens the browser, polls, and stores the returned key", async () => {
    const opened: string[] = [];
    let polls = 0;
    const fetchImpl = (async (url: string | URL) => {
      const target = String(url);
      if (target.endsWith("/cli/auth/sessions")) {
        return jsonResponse({ session_id: "sess1", verify_url: "https://westbayberry.com/cli/auth/sess1", expires_in: 600 });
      }
      if (target.endsWith("/v1/auth/status")) {
        return jsonResponse({ tier: "team" });
      }
      polls += 1;
      if (polls === 1) {
        return jsonResponse({ status: "pending" });
      }
      return jsonResponse({ status: "complete", api_key: "dg_live_abcdefghijklmnop", email: "dev@example.com" });
    }) as typeof fetch;

    const result = await runDeviceLogin({
      env: { HOME: home },
      fetchImpl,
      open: (url) => opened.push(url),
      sleep: async () => {},
      now: () => 0,
      confirm: () => {},
      stderr: { write: () => true }
    });

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Logged in as dev@example.com");
    expect(opened).toEqual(["https://westbayberry.com/cli/auth/sess1"]);
    const auth = JSON.parse(await readFile(join(home, ".dg", "auth.json"), "utf8")) as { token: string; email: string; tier: string };
    expect(auth.token).toBe("dg_live_abcdefghijklmnop");
    expect(auth.email).toBe("dev@example.com");
    expect(auth.tier).toBe("team");
  });

  it("shows the account plan on the success line when /v1/auth/status returns a tier", async () => {
    const fetchImpl = (async (url: string | URL) => {
      const target = String(url);
      if (target.endsWith("/cli/auth/sessions")) {
        return jsonResponse({ session_id: "sessP", verify_url: "https://westbayberry.com/cli/auth/sessP", expires_in: 600 });
      }
      if (target.endsWith("/v1/auth/status")) {
        return jsonResponse({ tier: "pro" });
      }
      return jsonResponse({ status: "complete", api_key: "dg_live_pro_token_xyz", email: "pro@example.com" });
    }) as typeof fetch;

    const result = await runDeviceLogin({
      env: { HOME: home },
      fetchImpl,
      open: () => {},
      sleep: async () => {},
      now: () => 0,
      confirm: () => {},
      stderr: { write: () => true }
    });

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Logged in as pro@example.com");
    expect(result.stdout).toContain("Pro plan");
  });

  it("still succeeds (email only) when the tier lookup fails", async () => {
    const fetchImpl = (async (url: string | URL) => {
      const target = String(url);
      if (target.endsWith("/cli/auth/sessions")) {
        return jsonResponse({ session_id: "sessF", verify_url: "https://westbayberry.com/cli/auth/sessF", expires_in: 600 });
      }
      if (target.endsWith("/v1/auth/status")) {
        return jsonResponse({ error: "boom" }, 500);
      }
      return jsonResponse({ status: "complete", api_key: "dg_live_tok", email: "x@example.com" });
    }) as typeof fetch;

    const result = await runDeviceLogin({
      env: { HOME: home },
      fetchImpl,
      open: () => {},
      sleep: async () => {},
      now: () => 0,
      confirm: () => {},
      stderr: { write: () => true }
    });

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Logged in as x@example.com");
    expect(result.stdout).not.toContain("plan");
  });

  it("reports an expired login link without writing auth state", async () => {
    const fetchImpl = (async (url: string | URL) => {
      if (String(url).endsWith("/cli/auth/sessions")) {
        return jsonResponse({ session_id: "sess2", verify_url: "https://westbayberry.com/cli/auth/sess2", expires_in: 600 });
      }
      return jsonResponse({ status: "expired" });
    }) as typeof fetch;

    const result = await runDeviceLogin({
      env: { HOME: home },
      fetchImpl,
      open: () => {},
      sleep: async () => {},
      now: () => 0,
      confirm: () => {},
      stderr: { write: () => true }
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("expired");
    await expect(readFile(join(home, ".dg", "auth.json"), "utf8")).rejects.toThrow();
  });

  it("times out waiting for browser approval", async () => {
    let nowMs = 0;
    const fetchImpl = (async (url: string | URL) => {
      if (String(url).endsWith("/cli/auth/sessions")) {
        return jsonResponse({ session_id: "sess3", verify_url: "https://westbayberry.com/cli/auth/sess3", expires_in: 600 });
      }
      return jsonResponse({ status: "pending" });
    }) as typeof fetch;

    const result = await runDeviceLogin({
      env: { HOME: home },
      fetchImpl,
      open: () => {},
      sleep: async () => {
        nowMs += 60_000;
      },
      now: () => nowMs,
      confirm: () => {},
      stderr: { write: () => true }
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("timed out");
    await expect(readFile(join(home, ".dg", "auth.json"), "utf8")).rejects.toThrow();
  });

  it("reports a clean error when the login session cannot be created", async () => {
    const fetchImpl = (async () => jsonResponse({}, 500)) as typeof fetch;
    const result = await runDeviceLogin({
      env: { HOME: home },
      fetchImpl,
      open: () => {},
      sleep: async () => {},
      now: () => 0,
      confirm: () => {},
      stderr: { write: () => true }
    });
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("could not start login");
  });

  it("refuses a verify_url on a host that is not the auth base or a subdomain of it", async () => {
    const fetchImpl = (async () =>
      jsonResponse({ session_id: "sessX", verify_url: "https://evil.example.test/cli/auth/sessX", expires_in: 600 })) as typeof fetch;
    await expect(createAuthSession("https://westbayberry.com", fetchImpl)).rejects.toThrow(/untrusted host/);
  });

  it("accepts a verify_url on a subdomain of the auth base", async () => {
    const fetchImpl = (async () =>
      jsonResponse({ session_id: "sessY", verify_url: "https://auth.westbayberry.com/cli/auth/sessY", expires_in: 600 })) as typeof fetch;
    const session = await createAuthSession("https://westbayberry.com", fetchImpl);
    expect(session.verifyUrl).toBe("https://auth.westbayberry.com/cli/auth/sessY");
  });

  it("keeps polling on transient 5xx and only resolves on a real status", async () => {
    let polls = 0;
    const fetchImpl = (async () => {
      polls += 1;
      if (polls <= 2) {
        return jsonResponse({}, 503);
      }
      return jsonResponse({ status: "complete", api_key: "dg_live_5xx", email: "ops@example.com" });
    }) as typeof fetch;

    const first = await pollAuthSession("https://westbayberry.com", "sess5xx", fetchImpl);
    expect(first.status).toBe("pending");
    const second = await pollAuthSession("https://westbayberry.com", "sess5xx", fetchImpl);
    expect(second.status).toBe("pending");
    const third = await pollAuthSession("https://westbayberry.com", "sess5xx", fetchImpl);
    expect(third).toMatchObject({ status: "complete", apiKey: "dg_live_5xx" });
  });

  it("treats a 4xx token poll as an expired session", async () => {
    const fetchImpl = (async () => jsonResponse({}, 404)) as typeof fetch;
    const result = await pollAuthSession("https://westbayberry.com", "sess404", fetchImpl);
    expect(result.status).toBe("expired");
  });

  it("does not hijack login in CI / non-interactive shells (token path)", async () => {
    // vitest runs without a TTY, mirroring CI — the browser flow must defer
    // so `dg login --token` / DG_API_TOKEN remain the headless path.
    expect((await maybeDeviceLogin(["login"])).handled).toBe(false);
    expect((await maybeDeviceLogin(["login", "--token", "dg_live_x"])).handled).toBe(false);
    expect((await maybeDeviceLogin(["login", "--token=dg_live_x"])).handled).toBe(false);
    expect((await maybeDeviceLogin(["login", "junk-arg"])).handled).toBe(false);
    expect((await maybeDeviceLogin(["login", "--wat"])).handled).toBe(false);
    expect((await maybeDeviceLogin(["scan"])).handled).toBe(false);
  });

  it("polls through a transient 502 then a 200 pending and only resolves on the 200 complete", async () => {
    let polls = 0;
    const fetchImpl = (async () => {
      polls += 1;
      if (polls === 1) {
        return jsonResponse({}, 502);
      }
      if (polls === 2) {
        return jsonResponse({ status: "pending" });
      }
      return jsonResponse({ status: "complete", api_key: "dg_live_502", email: "ops502@example.com" });
    }) as typeof fetch;

    const onError = await pollAuthSession("https://westbayberry.com", "sess502", fetchImpl);
    expect(onError.status).toBe("pending");
    expect(onError.apiKey).toBeUndefined();

    const onPending = await pollAuthSession("https://westbayberry.com", "sess502", fetchImpl);
    expect(onPending.status).toBe("pending");
    expect(onPending.apiKey).toBeUndefined();

    const onComplete = await pollAuthSession("https://westbayberry.com", "sess502", fetchImpl);
    expect(onComplete).toMatchObject({ status: "complete", apiKey: "dg_live_502", email: "ops502@example.com" });
    expect(polls).toBe(3);
  });

  it("treats the --token=VALUE form as headless, exactly like --token VALUE", async () => {
    const spaced = await maybeDeviceLogin(["login", "--token", "dg_live_spaced"]);
    const equals = await maybeDeviceLogin(["login", "--token=dg_live_equals"]);
    expect(equals.handled).toBe(false);
    expect(equals.handled).toBe(spaced.handled);
    expect(equals.result).toEqual({ exitCode: 0, stdout: "", stderr: "" });
  });

  it("refuses a verify_url whose host does not match the resolved web base", async () => {
    const webBase = resolveWebBase({ DG_AUTH_BASE: "https://stage.westbayberry.com" });
    expect(webBase).toBe("https://stage.westbayberry.com");

    const matching = `${webBase}/cli/auth/ok`;
    expect(assertTrustedVerifyUrl(matching, webBase)).toBe(matching);

    expect(() => assertTrustedVerifyUrl("https://westbayberry.com/cli/auth/no", webBase)).toThrow(/untrusted host/);

    const mismatchedFetch = (async () =>
      jsonResponse({ session_id: "sessZ", verify_url: "https://attacker.westbayberry.com.evil.test/cli/auth/sessZ", expires_in: 600 })) as typeof fetch;
    await expect(createAuthSession(webBase, mismatchedFetch)).rejects.toThrow(/untrusted host/);
  });

  it("accepts an http auth-base override only for localhost", () => {
    expect(resolveWebBase({ HOME: home, DG_AUTH_BASE: "http://localhost:8787" })).toBe("http://localhost:8787");
    expect(resolveWebBase({ HOME: home, DG_AUTH_BASE: "ftp://localhost" })).toBe("https://westbayberry.com");
    expect(resolveWebBase({ HOME: home, DG_AUTH_BASE: "gopher://127.0.0.1" })).toBe("https://westbayberry.com");
  });

  it("exposes tier, name, and usage numbers from /v1/auth/status", async () => {
    const fetchImpl = (async () => jsonResponse({ tier: "Pro", name: "Ada", scansUsed: 11229, scansLimit: 50000 })) as typeof fetch;
    const status = await fetchAccountStatus("dg_live_abcdefghijklmnop", { HOME: home }, fetchImpl);
    expect(status).toEqual({ tier: "pro", name: "Ada", scansUsed: 11229, scansLimit: 50000 });
  });

  it("returns null name and usage fields when /v1/auth/status omits or garbles them", async () => {
    const partial = (async () => jsonResponse({ tier: "free", name: "   ", scansUsed: "many" })) as typeof fetch;
    const status = await fetchAccountStatus("dg_live_abcdefghijklmnop", { HOME: home }, partial);
    expect(status).toEqual({ tier: "free", name: null, scansUsed: null, scansLimit: null });

    const failed = (async () => jsonResponse({}, 503)) as typeof fetch;
    expect(await fetchAccountStatus("dg_live_abcdefghijklmnop", { HOME: home }, failed)).toBeNull();

    const offline = (async () => {
      throw new Error("network down");
    }) as typeof fetch;
    expect(await fetchAccountStatus("dg_live_abcdefghijklmnop", { HOME: home }, offline)).toBeNull();
  });

  it("aborts the usage lookup after the caller's timeout instead of hanging", async () => {
    const hanging = ((_url: string | URL, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      })) as typeof fetch;
    expect(await fetchAccountStatus("dg_live_abcdefghijklmnop", { HOME: home }, hanging, 25)).toBeNull();
  });
});
