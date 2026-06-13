import { access, chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { auditLogPath, recordAuditEvent } from "../../src/audit/events.js";
import { loadUserConfig, setConfigValue, saveUserConfig } from "../../src/config/settings.js";
import {
  applyForceOverride,
  evaluatePackagePolicy,
  resolveEffectivePolicy
} from "../../src/policy/evaluate.js";
import { runCli } from "../../src/runtime/cli.js";
import { resolveDgPaths } from "../../src/state/index.js";

describe("auth and config commands", () => {
  it("logs in with a redacted token and removes only auth state on logout", async () => {
    const home = await tempHome();
    const token = "dg_test_token_1234567890";
    await withEnv(home, () => runCli(["config", "set", "api.baseUrl", "https://api.example.test"]));
    const login = await withEnv(home, () => runCli(["login", "--token", token]));

    expect(login.exitCode).toBe(0);
    expect(login.stdout).toContain("Logged in to https://api.example.test");
    expect(login.stdout).toContain("dg_t...7890");
    expect(login.stdout).not.toContain(token);

    const authPath = join(home, ".dg", "auth.json");
    await expect(readFile(authPath, "utf8")).resolves.toContain(token);

    const logout = await withEnv(home, () => runCli(["logout"]));
    expect(logout.exitCode).toBe(0);
    expect(logout.stdout).toContain("Logged out.");
    await expect(access(authPath)).rejects.toThrow();
    await expect(readFile(join(home, ".dg", "config.json"), "utf8")).resolves.toContain("api.example.test");

    const again = await withEnv(home, () => runCli(["logout", "--yes"]));
    expect(again.exitCode).toBe(0);
    expect(again.stdout).toContain("Already logged out.");
  });

  it("rejects positional login arguments naming the accepted forms", async () => {
    const home = await tempHome();
    const junk = await withEnv(home, () => runCli(["login", "wat"]));

    expect(junk.exitCode).toBe(2);
    expect(junk.stderr).toContain("unexpected argument 'wat'");
    expect(junk.stderr).toContain("dg login --token <key>");
  });

  it("names DG_API_KEY and DG_API_TOKEN in the logout env notice", async () => {
    const home = await tempHome();
    const keyOnly = await withEnv(home, async () => {
      process.env.DG_API_KEY = "dg_live_env_key_123";
      try {
        return await runCli(["logout", "--yes"]);
      } finally {
        delete process.env.DG_API_KEY;
      }
    });
    const both = await withEnv(home, async () => {
      process.env.DG_API_KEY = "dg_live_env_key_123";
      process.env.DG_API_TOKEN = "dg_live_env_token_456";
      try {
        return await runCli(["logout", "--yes"]);
      } finally {
        delete process.env.DG_API_KEY;
        delete process.env.DG_API_TOKEN;
      }
    });
    const neither = await withEnv(home, () => runCli(["logout", "--yes"]));

    expect(keyOnly.exitCode).toBe(0);
    expect(keyOnly.stdout).toContain("DG_API_KEY is still set");
    expect(both.stdout).toContain("DG_API_KEY and DG_API_TOKEN are still set");
    expect(neither.stdout).not.toContain("still set");
  });

  it("exits 70 when auth state cannot be written or removed", async () => {
    const home = await tempHome();
    await withEnv(home, () => runCli(["login", "--token", "dg_test_token_1234567890"]));
    const dgDir = join(home, ".dg");
    await chmod(dgDir, 0o500);
    try {
      const logout = await withEnv(home, () => runCli(["logout", "--yes"]));
      const login = await withEnv(home, () => runCli(["login", "--token", "dg_test_token_0987654321"]));

      expect(logout.exitCode).toBe(70);
      expect(logout.stderr).toContain("could not remove the local auth token");
      expect(login.exitCode).toBe(70);
      expect(login.stderr).toContain("could not save auth state");
    } finally {
      await chmod(dgDir, 0o700);
    }
  });

  it("sets, gets, lists, and unsets trusted user-global config keys", async () => {
    const home = await tempHome();
    const set = await withEnv(home, () => runCli(["config", "set", "policy.mode", "strict"]));
    const get = await withEnv(home, () => runCli(["config", "get", "policy.mode"]));
    const list = await withEnv(home, () => runCli(["config", "list", "--json"]));
    const unset = await withEnv(home, () => runCli(["config", "unset", "policy.mode"]));
    const unknown = await withEnv(home, () => runCli(["config", "set", "project.allowlist", "true"]));

    expect(set).toEqual({
      exitCode: 0,
      stdout: "policy.mode=strict\n",
      stderr: ""
    });
    expect(get.stdout).toBe("strict\n");
    expect(JSON.parse(list.stdout)).toMatchObject({
      "policy.mode": "strict",
      "policy.trustProjectAllowlists": "false",
      "audit.upload": "false"
    });
    expect(Object.keys(JSON.parse(list.stdout) as Record<string, string>)).not.toContain("telemetry.enabled");
    expect(Object.keys(JSON.parse(list.stdout) as Record<string, string>)).not.toContain("webhooks.enabled");
    expect(unset.stdout).toBe("policy.mode=block\n");
    expect(unknown.exitCode).toBe(2);
    expect(unknown.stderr).toContain("unknown config key");
  });
});

describe("policy trust model", () => {
  it("applies policy modes and org-over-user source priority", async () => {
    const home = await tempHome();
    await withEnv(home, () => runCli(["config", "set", "policy.mode", "warn"]));
    const userPolicy = resolveEffectivePolicy({
      userConfig: await withEnv(home, () => loadUserConfig())
    });
    const orgPolicy = resolveEffectivePolicy({
      userConfig: await withEnv(home, () => loadUserConfig()),
      orgPolicy: {
        mode: "strict"
      }
    });

    expect(evaluatePackagePolicy({ verdict: "block", packageName: "left-pad", policy: userPolicy }).action).toBe("warn");
    expect(evaluatePackagePolicy({ verdict: "warn", packageName: "left-pad", policy: orgPolicy }).action).toBe("block");
    expect(orgPolicy.source).toBe("org");
  });

  it("ignores project-local allowlists by default and accepts them only when trusted globally", async () => {
    const home = await tempHome();
    const basePolicy = resolveEffectivePolicy({
      userConfig: await withEnv(home, () => loadUserConfig())
    });
    const allowlists = [
      {
        packageName: "left-pad",
        reason: "fixture suppresses malware",
        trustedBy: "project" as const
      }
    ];
    const ignored = evaluatePackagePolicy({
      verdict: "block",
      packageName: "left-pad",
      policy: basePolicy,
      allowlists
    });

    await withEnv(home, () => {
      const config = setConfigValue(loadUserConfig(), "policy.trustProjectAllowlists", "true");
      saveUserConfig(config);
    });
    const trustedPolicy = resolveEffectivePolicy({
      userConfig: await withEnv(home, () => loadUserConfig())
    });
    const accepted = evaluatePackagePolicy({
      verdict: "block",
      packageName: "left-pad",
      policy: trustedPolicy,
      allowlists
    });

    expect(ignored.action).toBe("block");
    expect(accepted.action).toBe("pass");
    expect(accepted.reason).toContain("project allowlist");
  });

  it("honors policy denial and records audit events on force install", async () => {
    const home = await tempHome();
    const paths = resolveDgPaths({
      HOME: home
    });
    const policy = resolveEffectivePolicy({
      userConfig: await withEnv(home, () => loadUserConfig())
    });

    const denied = await withEnv(home, () =>
      applyForceOverride({
        packageName: "left-pad",
        currentAction: "block",
        force: true,
        policy: {
          ...policy,
          allowForceOverride: false
        }
      })
    );
    const allowed = await withEnv(home, () =>
      applyForceOverride(
        {
          packageName: "left-pad",
          currentAction: "block",
          force: true,
          policy,
          now: new Date("2026-06-01T12:00:00.000Z")
        },
        {
          HOME: home
        }
      )
    );

    expect(denied.allowed).toBe(false);
    expect(denied.reason).toContain("disabled by policy");
    expect(allowed).toEqual({
      allowed: true,
      reason: "developer override via --dg-force-install",
      auditRecorded: true
    });
    await withEnv(home, () => {
      expect(
        recordAuditEvent({
          type: "install.blocked",
          packageName: "blocked-package",
          reason: "confirmed malware",
          policyMode: "block",
          createdAt: "2026-06-01T12:01:00.000Z"
        })
      ).toBe(true);
    });
    const audit = await readFile(auditLogPath(paths), "utf8");
    expect(audit).toContain("install.force_override");
    expect(audit).toContain("install.blocked");
    await expect(access(join(paths.stateDir, "webhooks.jsonl"))).rejects.toThrow();
  });

  it("reports a degraded force override instead of throwing when audit state is unwritable", async () => {
    const home = await tempHome();
    const paths = resolveDgPaths({ HOME: home });
    await mkdir(join(paths.stateDir, ".."), { recursive: true });
    await writeFile(paths.stateDir, "not a directory", "utf8");
    const policy = resolveEffectivePolicy({});

    const result = applyForceOverride(
      {
        packageName: "left-pad",
        currentAction: "block",
        force: true,
        policy: { ...policy, allowForceOverride: true }
      },
      { HOME: home }
    );

    expect(result.allowed).toBe(true);
    expect(result.auditRecorded).toBe(false);
  });

  it("keeps script hardening in the effective org policy", () => {
    const policy = resolveEffectivePolicy({
      orgPolicy: {
        mode: "strict"
      }
    });

    expect(policy.scriptHardening).toBe(true);
    expect(policy.mode).toBe("strict");
  });
});

describe("removed config keys", () => {
  it("rejects telemetry.enabled and webhooks.enabled as unknown config keys", async () => {
    const home = await tempHome();
    for (const key of ["telemetry.enabled", "webhooks.enabled"]) {
      const result = await withEnv(home, () => runCli(["config", "set", key, "true"]));
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain("unknown config key");
    }
  });
});

const tempHomes: string[] = [];

afterAll(async () => {
  await Promise.all(tempHomes.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function tempHome(): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), "dg-auth-policy-test-"));
  tempHomes.push(home);
  await mkdir(home, {
    recursive: true
  });
  return home;
}

async function withEnv<T>(home: string, run: () => T | Promise<T>): Promise<T> {
  const previous = {
    HOME: process.env.HOME,
    PATH: process.env.PATH,
    SHELL: process.env.SHELL,
    DG_API_TOKEN: process.env.DG_API_TOKEN,
    DG_TEST_NODE_VERSION: process.env.DG_TEST_NODE_VERSION
  };
  process.env.HOME = home;
  process.env.PATH = `${join(home, ".dg", "shims")}:/usr/bin:/bin`;
  process.env.SHELL = "/bin/bash";
  process.env.DG_TEST_NODE_VERSION = "v22.14.0";
  delete process.env.DG_API_TOKEN;
  try {
    return await run();
  } finally {
    restoreEnv("HOME", previous.HOME);
    restoreEnv("PATH", previous.PATH);
    restoreEnv("SHELL", previous.SHELL);
    restoreEnv("DG_API_TOKEN", previous.DG_API_TOKEN);
    restoreEnv("DG_TEST_NODE_VERSION", previous.DG_TEST_NODE_VERSION);
  }
}

function restoreEnv(key: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[key];
  } else {
    process.env[key] = value;
  }
}
