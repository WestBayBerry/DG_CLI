import { existsSync, mkdtempSync, mkdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { prepareCargoHome, userCargoHome } from "../../src/launcher/cargo-cache.js";

const made: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "dg-cargo-"));
  made.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of made.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("userCargoHome", () => {
  it("honors an explicit CARGO_HOME", () => {
    expect(userCargoHome({ CARGO_HOME: "/opt/cargo" })).toBe("/opt/cargo");
  });

  it("falls back to ~/.cargo when CARGO_HOME is unset or blank", () => {
    expect(userCargoHome({})).toBe(join(homedir(), ".cargo"));
    expect(userCargoHome({ CARGO_HOME: "   " })).toBe(join(homedir(), ".cargo"));
  });
});

describe("prepareCargoHome", () => {
  it("creates the throwaway home and links the user's registry config and credentials", () => {
    const source = tempDir();
    writeFileSync(join(source, "config.toml"), "[registry]\ndefault = \"corp\"\n", "utf8");
    writeFileSync(join(source, "credentials.toml"), "[registries.corp]\ntoken = \"secret\"\n", "utf8");
    const cacheDir = join(tempDir(), "pm-cache");

    const linked = prepareCargoHome(cacheDir, source);

    expect(existsSync(cacheDir)).toBe(true);
    expect(linked.slice().sort()).toEqual(["config.toml", "credentials.toml"]);
    expect(readFileSync(join(cacheDir, "config.toml"), "utf8")).toContain("default = \"corp\"");
    expect(readFileSync(join(cacheDir, "credentials.toml"), "utf8")).toContain("token = \"secret\"");
    expect(readlinkSync(join(cacheDir, "config.toml"))).toBe(join(source, "config.toml"));
  });

  it("does not link the crate cache, so it stays empty and forces a re-fetch", () => {
    const source = tempDir();
    mkdirSync(join(source, "registry"), { recursive: true });
    writeFileSync(join(source, "registry", "cached.crate"), "bytes", "utf8");
    const cacheDir = join(tempDir(), "pm-cache");

    prepareCargoHome(cacheDir, source);

    expect(existsSync(join(cacheDir, "registry"))).toBe(false);
  });

  it("links the legacy extension-less config and credentials names too", () => {
    const source = tempDir();
    writeFileSync(join(source, "config"), "legacy", "utf8");
    writeFileSync(join(source, "credentials"), "legacy-token", "utf8");
    const cacheDir = join(tempDir(), "pm-cache");

    const linked = prepareCargoHome(cacheDir, source);

    expect(linked.slice().sort()).toEqual(["config", "credentials"]);
  });

  it("skips entries the user does not have", () => {
    const source = tempDir();
    writeFileSync(join(source, "config.toml"), "x", "utf8");
    const cacheDir = join(tempDir(), "pm-cache");

    expect(prepareCargoHome(cacheDir, source)).toEqual(["config.toml"]);
  });

  it("never overwrites an entry already present in the cache dir", () => {
    const source = tempDir();
    writeFileSync(join(source, "config.toml"), "from-user", "utf8");
    const cacheDir = join(tempDir(), "pm-cache");
    mkdirSync(cacheDir, { recursive: true });
    writeFileSync(join(cacheDir, "config.toml"), "pre-existing", "utf8");

    const linked = prepareCargoHome(cacheDir, source);

    expect(linked).toEqual([]);
    expect(readFileSync(join(cacheDir, "config.toml"), "utf8")).toBe("pre-existing");
  });

  it("is a no-op-safe when the user has no cargo home at all", () => {
    const missing = join(tempDir(), "nonexistent-cargo");
    const cacheDir = join(tempDir(), "pm-cache");

    expect(prepareCargoHome(cacheDir, missing)).toEqual([]);
    expect(existsSync(cacheDir)).toBe(true);
  });
});
