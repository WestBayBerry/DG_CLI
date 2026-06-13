import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthError, authPath, authStatus, readAuthState, readAuthStateOrWarn, writeAuthState } from "../../src/auth/store.js";
import { loadUserConfig } from "../../src/config/settings.js";
import { resolveDgPaths } from "../../src/state/index.js";

const distAuthUrl = new URL("../../dist/auth/store.js", import.meta.url).href;
const distSettingsUrl = new URL("../../dist/config/settings.js", import.meta.url).href;

describe("auth store email/tier persistence", () => {
  let home: string;
  let env: { HOME: string };

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "dg-auth-store-test-"));
    env = { HOME: home };
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("round-trips email, tier, and name through write and read", () => {
    writeAuthState({ token: "dg_live_round_trip_token", email: "dev@example.com", tier: "pro", name: "Ada" }, env);

    const state = readAuthState(env);
    expect(state?.email).toBe("dev@example.com");
    expect(state?.tier).toBe("pro");
    expect(state?.name).toBe("Ada");

    const status = authStatus(env);
    expect(status.email).toBe("dev@example.com");
    expect(status.tier).toBe("pro");
    expect(status.name).toBe("Ada");
  });

  it("yields undefined email and tier when reading a legacy state file without them", async () => {
    const path = authPath(resolveDgPaths(env));
    await mkdir(join(home, ".dg"), { recursive: true });
    await writeFile(
      path,
      `${JSON.stringify(
        {
          version: 1,
          token: "dg_live_legacy_token_value",
          tokenPreview: "dg_l...alue",
          apiBaseUrl: "https://api.westbayberry.com",
          orgId: "",
          loggedInAt: "2026-01-01T00:00:00.000Z"
        },
        null,
        2
      )}\n`,
      "utf8"
    );

    const state = readAuthState(env);
    expect(state?.token).toBe("dg_live_legacy_token_value");
    expect(state?.email).toBeUndefined();
    expect(state?.tier).toBeUndefined();

    const status = authStatus(env);
    expect(status.email).toBeUndefined();
    expect(status.tier).toBeUndefined();
  });

  it("does not persist empty email, tier, or name strings", async () => {
    writeAuthState({ token: "dg_live_empty_fields_token", email: "", tier: "", name: "" }, env);

    const persisted = JSON.parse(await readFile(authPath(resolveDgPaths(env)), "utf8")) as Record<string, unknown>;
    expect(persisted.email).toBeUndefined();
    expect(persisted.tier).toBeUndefined();
    expect(persisted.name).toBeUndefined();

    const state = readAuthState(env);
    expect(state?.email).toBeUndefined();
    expect(state?.tier).toBeUndefined();
    expect(state?.name).toBeUndefined();
  });
});

describe("corrupt auth state handling", () => {
  let home: string;
  let env: { HOME: string };

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "dg-auth-corrupt-test-"));
    env = { HOME: home };
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  async function writeCorruptAuth(): Promise<string> {
    const path = authPath(resolveDgPaths(env));
    await mkdir(join(home, ".dg"), { recursive: true });
    await writeFile(path, "{not json", "utf8");
    return path;
  }

  it("readAuthState rejects a corrupt file with an AuthError naming the path", async () => {
    const path = await writeCorruptAuth();
    let caught: unknown;
    try {
      readAuthState(env);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(AuthError);
    expect((caught as AuthError).message).toContain(path);
  });

  it("readAuthStateOrWarn warns once on stderr naming the file and continues anonymous", async () => {
    const path = await writeCorruptAuth();
    const warnings: string[] = [];
    const stderr = {
      write: (text: string) => warnings.push(text)
    };

    expect(readAuthStateOrWarn(env, { stderr })).toBeUndefined();
    expect(readAuthStateOrWarn(env, { stderr })).toBeUndefined();

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(path);
    expect(warnings[0]).toContain("dg login");
  });

  it("readAuthStateOrWarn returns a valid state without warning", () => {
    writeAuthState({ token: "dg_live_valid_token_value" }, env);
    const warnings: string[] = [];

    const state = readAuthStateOrWarn(env, {
      stderr: {
        write: (text: string) => warnings.push(text)
      }
    });

    expect(state?.token).toBe("dg_live_valid_token_value");
    expect(warnings).toEqual([]);
  });
});

describe("auth and config write serialization", () => {
  it("does not lose a concurrent config update racing a login write", async () => {
    for (let round = 0; round < 5; round++) {
      const raceHome = await mkdtemp(join(tmpdir(), "dg-auth-race-"));
      await Promise.all([
        runChild(
          raceHome,
          "import(process.argv[1]).then((auth) => { auth.writeAuthState({ token: process.argv[2] }); }).catch((error) => { console.error(error); process.exit(1); });",
          [distAuthUrl, "dg_live_concurrent_token"]
        ),
        runChild(
          raceHome,
          "import(process.argv[1]).then((settings) => { settings.updateUserConfig((config) => settings.setConfigValue(config, process.argv[2], process.argv[3])); }).catch((error) => { console.error(error); process.exit(1); });",
          [distSettingsUrl, "audit.upload", "true"]
        )
      ]);

      expect(loadUserConfig({ HOME: raceHome }).audit.upload).toBe(true);
      expect(readAuthState({ HOME: raceHome })?.token).toBe("dg_live_concurrent_token");
      await rm(raceHome, { recursive: true, force: true });
    }
  }, 60_000);
});

function runChild(homeDir: string, script: string, args: readonly string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["-e", script, ...args], {
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
        reject(new Error(`child exited ${code}: ${stderr}`));
      }
    });
  });
}
