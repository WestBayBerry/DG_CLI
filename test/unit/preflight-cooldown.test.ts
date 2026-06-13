import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { setConfigValue, updateUserConfig } from "../../src/config/settings.js";
import { resolvePreflightCooldown } from "../../src/launcher/install-preflight.js";

const homes: string[] = [];

afterEach(async () => {
  for (const home of homes.splice(0)) {
    await rm(home, { recursive: true, force: true });
  }
});

async function configuredHome(...kv: Array<[string, string]>): Promise<{ HOME: string }> {
  const home = await mkdtemp(join(tmpdir(), "dg-preflight-cooldown-"));
  homes.push(home);
  const env = { HOME: home };
  updateUserConfig((config) => kv.reduce((acc, [key, value]) => setConfigValue(acc, key, value), config), env);
  return env;
}

describe("resolvePreflightCooldown gates each ecosystem against its own window", () => {
  it("keeps npm cooldown on even when pypi cooldown is off (the agent-hook fail-open)", async () => {
    const env = await configuredHome(["cooldown.age", "0"], ["cooldown.npm.age", "7d"], ["cooldown.pypi.age", "0"]);
    expect(resolvePreflightCooldown(env, "npm")?.param.minAgeDays).toBe(7);
    expect(resolvePreflightCooldown(env, "npm")?.ecosystem).toBe("npm");
    expect(resolvePreflightCooldown(env, "pypi")).toBeUndefined();
  });

  it("resolves each ecosystem's own window rather than a single shared one", async () => {
    const env = await configuredHome(["cooldown.npm.age", "7d"], ["cooldown.pypi.age", "2d"]);
    expect(resolvePreflightCooldown(env, "npm")?.param.minAgeDays).toBe(7);
    expect(resolvePreflightCooldown(env, "pypi")?.param.minAgeDays).toBe(2);
  });
});
