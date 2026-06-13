import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ConfigError,
  DEFAULT_CONFIG,
  getConfigValue,
  loadUserConfig,
  setConfigValue,
  unsetConfigValue,
  updateUserConfig
} from "../../src/config/settings.js";

const distSettingsUrl = new URL("../../dist/config/settings.js", import.meta.url).href;

describe("user config strict type validation", () => {
  let home: string;
  let env: { HOME: string };

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "dg-config-settings-test-"));
    env = { HOME: home };
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  async function writeConfig(content: string): Promise<void> {
    await mkdir(join(home, ".dg"), { recursive: true });
    await writeFile(join(home, ".dg", "config.json"), content, "utf8");
  }

  const rejectionMatrix: ReadonlyArray<{
    readonly name: string;
    readonly content: string;
    readonly messageIncludes: readonly string[];
  }> = [
    {
      name: "string boolean for policy.trustProjectAllowlists",
      content: '{"policy":{"trustProjectAllowlists":"false"}}',
      messageIncludes: ["policy.trustProjectAllowlists", "boolean"]
    },
    {
      name: "string boolean for policy.allowForceOverride",
      content: '{"policy":{"allowForceOverride":"true"}}',
      messageIncludes: ["policy.allowForceOverride", "boolean"]
    },
    {
      name: "string boolean for audit.upload",
      content: '{"audit":{"upload":"true"}}',
      messageIncludes: ["audit.upload", "boolean"]
    },
    {
      name: "numeric org.id",
      content: '{"org":{"id":7}}',
      messageIncludes: ["org.id", "string"]
    },
    {
      name: "numeric api.baseUrl",
      content: '{"api":{"baseUrl":9}}',
      messageIncludes: ["api.baseUrl", "string"]
    },
    {
      name: "array policy section",
      content: '{"policy":[]}',
      messageIncludes: ["policy", "object"]
    },
    {
      name: "string gitHook section",
      content: '{"gitHook":"block"}',
      messageIncludes: ["gitHook", "object"]
    },
    {
      name: "invalid scriptGate.mode value",
      content: '{"scriptGate":{"mode":"loud"}}',
      messageIncludes: ["scriptGate.mode", "observe, enforce, off"]
    },
    {
      name: "string boolean for scriptGate.observe",
      content: '{"scriptGate":{"observe":"true"}}',
      messageIncludes: ["scriptGate.observe", "boolean"]
    },
    {
      name: "array root",
      content: "[]",
      messageIncludes: ["config", "object", "array"]
    },
    {
      name: "null root",
      content: "null",
      messageIncludes: ["config", "object", "null"]
    },
    {
      name: "string root",
      content: '"block"',
      messageIncludes: ["config", "object"]
    }
  ];

  for (const rejection of rejectionMatrix) {
    it(`rejects ${rejection.name} with a field-level message`, async () => {
      await writeConfig(rejection.content);
      let caught: unknown;
      try {
        loadUserConfig(env);
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(ConfigError);
      const message = (caught as ConfigError).message;
      for (const fragment of rejection.messageIncludes) {
        expect(message).toContain(fragment);
      }
      expect(message).not.toContain("Cannot read properties");
    });
  }

  it("loads JSON booleans with their actual values", async () => {
    await writeConfig('{"policy":{"trustProjectAllowlists":false},"audit":{"upload":true}}');
    const config = loadUserConfig(env);
    expect(config.policy.trustProjectAllowlists).toBe(false);
    expect(config.audit.upload).toBe(true);
    expect(config.policy.allowForceOverride).toBe(DEFAULT_CONFIG.policy.allowForceOverride);
  });

  it("keeps loading configs that still contain the removed telemetry and webhooks keys", async () => {
    await writeConfig('{"policy":{"mode":"strict"},"telemetry":{"enabled":true},"webhooks":{"enabled":false}}');
    const config = loadUserConfig(env);
    expect(config.policy.mode).toBe("strict");
    expect(config).not.toHaveProperty("telemetry");
    expect(config).not.toHaveProperty("webhooks");
  });

  it("tolerates junk values under removed legacy keys", async () => {
    await writeConfig('{"telemetry":{"enabled":1},"webhooks":"yes","audit":{"upload":true}}');
    const config = loadUserConfig(env);
    expect(config.audit.upload).toBe(true);
  });

  it("names the field when dg config set receives a non-boolean value", () => {
    expect(() => setConfigValue(DEFAULT_CONFIG, "audit.upload", "yes")).toThrow("audit.upload must be true or false");
    expect(() => setConfigValue(DEFAULT_CONFIG, "policy.trustProjectAllowlists", "0")).toThrow(
      "policy.trustProjectAllowlists must be true or false"
    );
  });

  it("restricts api.baseUrl to http/https even for localhost", () => {
    expect(setConfigValue(DEFAULT_CONFIG, "api.baseUrl", "http://localhost:3000").api.baseUrl).toBe("http://localhost:3000");
    expect(setConfigValue(DEFAULT_CONFIG, "api.baseUrl", "http://127.0.0.1:3000").api.baseUrl).toBe("http://127.0.0.1:3000");
    expect(() => setConfigValue(DEFAULT_CONFIG, "api.baseUrl", "ftp://localhost")).toThrow(ConfigError);
    expect(() => setConfigValue(DEFAULT_CONFIG, "api.baseUrl", "gopher://127.0.0.1")).toThrow("must use https");
    expect(() => setConfigValue(DEFAULT_CONFIG, "api.baseUrl", "http://example.com")).toThrow("must use https");
  });

  it("updateUserConfig persists the applied change under the config lock", () => {
    const next = updateUserConfig((config) => setConfigValue(config, "audit.upload", "true"), env);
    expect(next.audit.upload).toBe(true);
    expect(loadUserConfig(env).audit.upload).toBe(true);
  });

  it("does not lose concurrent config writes from separate processes", async () => {
    for (let round = 0; round < 5; round++) {
      const raceHome = await mkdtemp(join(tmpdir(), "dg-config-race-"));
      await Promise.all([
        runConfigSetChild(raceHome, "policy.scriptHardening", "true"),
        runConfigSetChild(raceHome, "cooldown.onUnknown", "block"),
        runConfigSetChild(raceHome, "gitHook.onWarn", "allow"),
        runConfigSetChild(raceHome, "audit.upload", "true")
      ]);
      const config = loadUserConfig({ HOME: raceHome });
      expect(config.policy.scriptHardening).toBe(true);
      expect(config.cooldown.onUnknown).toBe("block");
      expect(config.gitHook.onWarn).toBe("allow");
      expect(config.audit.upload).toBe(true);
      await rm(raceHome, { recursive: true, force: true });
    }
  }, 60_000);
});

describe("script gate config keys", () => {
  let home: string;
  let env: { HOME: string };

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "dg-config-scriptgate-"));
    env = { HOME: home };
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  async function writeConfig(content: string): Promise<void> {
    await mkdir(join(home, ".dg"), { recursive: true });
    await writeFile(join(home, ".dg", "config.json"), content, "utf8");
  }

  it("defaults to observe mode without dg.json creation", () => {
    const config = loadUserConfig(env);
    expect(config.scriptGate.mode).toBe("observe");
    expect(config.scriptGate.observe).toBe(false);
    expect(getConfigValue(DEFAULT_CONFIG, "scriptGate.mode")).toBe("observe");
    expect(getConfigValue(DEFAULT_CONFIG, "scriptGate.observe")).toBe("false");
  });

  it("round-trips scriptGate keys through set, get, and unset", () => {
    const withMode = setConfigValue(DEFAULT_CONFIG, "scriptGate.mode", "enforce");
    expect(withMode.scriptGate.mode).toBe("enforce");
    expect(getConfigValue(withMode, "scriptGate.mode")).toBe("enforce");
    expect(unsetConfigValue(withMode, "scriptGate.mode").scriptGate.mode).toBe("observe");

    const withObserve = setConfigValue(DEFAULT_CONFIG, "scriptGate.observe", "true");
    expect(withObserve.scriptGate.observe).toBe(true);
    expect(() => setConfigValue(DEFAULT_CONFIG, "scriptGate.mode", "loud")).toThrow("observe, enforce, off");
    expect(() => setConfigValue(DEFAULT_CONFIG, "scriptGate.observe", "yes")).toThrow("scriptGate.observe must be true or false");
  });

  it("migrates legacy policy.scriptHardening=true to scriptGate.mode=enforce", async () => {
    await writeConfig('{"policy":{"scriptHardening":true}}');
    expect(loadUserConfig(env).scriptGate.mode).toBe("enforce");
  });

  it("lets an explicit scriptGate.mode win over the scriptHardening migration", async () => {
    await writeConfig('{"policy":{"scriptHardening":true},"scriptGate":{"mode":"off"}}');
    expect(loadUserConfig(env).scriptGate.mode).toBe("off");
  });

  it("leaves the default observe mode when scriptHardening is false", async () => {
    await writeConfig('{"policy":{"scriptHardening":false}}');
    expect(loadUserConfig(env).scriptGate.mode).toBe("observe");
  });
});

function runConfigSetChild(homeDir: string, key: string, value: string): Promise<void> {
  const script =
    "import(process.argv[1]).then((settings) => { settings.updateUserConfig((config) => settings.setConfigValue(config, process.argv[2], process.argv[3])); }).catch((error) => { console.error(error); process.exit(1); });";
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["-e", script, distSettingsUrl, key, value], {
      env: {
        ...process.env,
        HOME: homeDir,
        XDG_CONFIG_HOME: "",
        XDG_STATE_HOME: "",
        XDG_CACHE_HOME: ""
      },
      stdio: ["ignore", "ignore", "pipe"]
    });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`config child exited ${code}: ${stderr}`));
      }
    });
  });
}
