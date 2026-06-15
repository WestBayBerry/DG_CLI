import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ConfigError,
  DEFAULT_CONFIG,
  getConfigValue,
  loadUserConfig,
  setConfigValue,
  unsetConfigValue
} from "../../src/config/settings.js";
import {
  cooldownRequestParam,
  describeCooldownSettings,
  durationToDays,
  effectiveCooldownAge,
  formatCooldownDuration,
  formatPackageAge,
  isCooldownExempt,
  isCooldownExemptByDgFile
} from "../../src/policy/cooldown.js";
import type { CooldownExemption } from "../../src/project/dgfile.js";
import { enforceProtectedInstall } from "../../src/proxy/enforcement.js";
import { evaluatePackagePolicy, resolveEffectivePolicy } from "../../src/policy/evaluate.js";
import { classifyPackageManagerInvocation } from "../../src/launcher/classify.js";

describe("cargo exemption name normalization", () => {
  const stored: CooldownExemption[] = [
    { ecosystem: "cargo", name: "My_Crate", reason: "", acceptedBy: "t", acceptedAt: "2026-01-01T00:00:00.000Z" }
  ];

  it("matches case- and separator-insensitively (crates.io folds - and _)", () => {
    expect(isCooldownExemptByDgFile("my-crate", "cargo", stored)).toBe(true);
    expect(isCooldownExemptByDgFile("MY_CRATE", "cargo", stored)).toBe(true);
    expect(isCooldownExemptByDgFile("unrelated", "cargo", stored)).toBe(false);
  });

  it("folds cargo names in the config glob list too", () => {
    expect(isCooldownExempt("my-crate", "My_Crate", "cargo")).toBe(true);
    expect(isCooldownExempt("my-thing", "my_*", "cargo")).toBe(true);
  });
});

describe("cooldown config keys", () => {
  it("ships on by default at 24h with fail-closed unknowns", () => {
    expect(DEFAULT_CONFIG.cooldown.age).toBe("24h");
    expect(DEFAULT_CONFIG.cooldown.onUnknown).toBe("block");
    expect(DEFAULT_CONFIG.cooldown.npmAge).toBe("");
    expect(DEFAULT_CONFIG.cooldown.pypiAge).toBe("");
    expect(DEFAULT_CONFIG.cooldown.cargoAge).toBe("");
    expect(DEFAULT_CONFIG.cooldown.exempt).toBe("");
  });

  it("sets and gets every cooldown key", () => {
    let config = setConfigValue(DEFAULT_CONFIG, "cooldown.age", "7d");
    config = setConfigValue(config, "cooldown.npm.age", "48h");
    config = setConfigValue(config, "cooldown.pypi.age", "14d");
    config = setConfigValue(config, "cooldown.cargo.age", "0");
    config = setConfigValue(config, "cooldown.onUnknown", "block");
    config = setConfigValue(config, "cooldown.exempt", "@myorg/*, typescript");
    expect(getConfigValue(config, "cooldown.age")).toBe("7d");
    expect(getConfigValue(config, "cooldown.npm.age")).toBe("48h");
    expect(getConfigValue(config, "cooldown.pypi.age")).toBe("14d");
    expect(getConfigValue(config, "cooldown.cargo.age")).toBe("0");
    expect(getConfigValue(config, "cooldown.onUnknown")).toBe("block");
    expect(getConfigValue(config, "cooldown.exempt")).toBe("@myorg/*,typescript");
  });

  it("accepts 0 and off as disable spellings and normalizes off to 0", () => {
    expect(setConfigValue(DEFAULT_CONFIG, "cooldown.age", "0").cooldown.age).toBe("0");
    expect(setConfigValue(DEFAULT_CONFIG, "cooldown.age", "off").cooldown.age).toBe("0");
  });

  it("rejects malformed durations, units, and exempt patterns with field-level errors", () => {
    expect(() => setConfigValue(DEFAULT_CONFIG, "cooldown.age", "1w")).toThrow(ConfigError);
    expect(() => setConfigValue(DEFAULT_CONFIG, "cooldown.age", "24")).toThrow("cooldown.age must be a duration like 24h or 7d");
    expect(() => setConfigValue(DEFAULT_CONFIG, "cooldown.age", "")).toThrow(ConfigError);
    expect(() => setConfigValue(DEFAULT_CONFIG, "cooldown.age", "-3d")).toThrow(ConfigError);
    expect(() => setConfigValue(DEFAULT_CONFIG, "cooldown.npm.age", "soon")).toThrow("cooldown.npm.age");
    expect(() => setConfigValue(DEFAULT_CONFIG, "cooldown.onUnknown", "maybe")).toThrow("cooldown.onUnknown must be one of: allow, block");
    expect(() => setConfigValue(DEFAULT_CONFIG, "cooldown.exempt", "ok-name,$(rm -rf)")).toThrow("cooldown.exempt");
  });

  it("allows empty per-ecosystem overrides (inherit) but not an empty global age", () => {
    expect(setConfigValue(DEFAULT_CONFIG, "cooldown.npm.age", "").cooldown.npmAge).toBe("");
    expect(() => setConfigValue(DEFAULT_CONFIG, "cooldown.age", " ")).toThrow(ConfigError);
  });

  it("unset restores the 24h default", () => {
    const off = setConfigValue(DEFAULT_CONFIG, "cooldown.age", "0");
    expect(unsetConfigValue(off, "cooldown.age").cooldown.age).toBe("24h");
  });
});

describe("cooldown config file round-trip", () => {
  let home: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "dg-cooldown-config-"));
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("loads a persisted cooldown section and rejects malformed values at load time", async () => {
    await mkdir(join(home, ".dg"), { recursive: true });
    await writeFile(
      join(home, ".dg", "config.json"),
      JSON.stringify({ cooldown: { age: "7d", pypiAge: "14d", onUnknown: "block", exempt: "left-pad" } }),
      "utf8"
    );
    const config = loadUserConfig({ HOME: home });
    expect(config.cooldown.age).toBe("7d");
    expect(config.cooldown.pypiAge).toBe("14d");
    expect(config.cooldown.npmAge).toBe("");
    expect(config.cooldown.onUnknown).toBe("block");
    expect(config.cooldown.exempt).toBe("left-pad");

    await writeFile(join(home, ".dg", "config.json"), JSON.stringify({ cooldown: { age: "1 week" } }), "utf8");
    expect(() => loadUserConfig({ HOME: home })).toThrow(ConfigError);
  });

  it("defaults the cooldown section when an older config file omits it", async () => {
    await mkdir(join(home, ".dg"), { recursive: true });
    await writeFile(join(home, ".dg", "config.json"), JSON.stringify({ policy: { mode: "block" } }), "utf8");
    const config = loadUserConfig({ HOME: home });
    expect(config.cooldown.age).toBe("24h");
    expect(config.cooldown.onUnknown).toBe("block");
  });
});

describe("effective cooldown resolution", () => {
  it("converts durations to fractional days", () => {
    expect(durationToDays("24h")).toBe(1);
    expect(durationToDays("36h")).toBe(1.5);
    expect(durationToDays("7d")).toBe(7);
    expect(durationToDays("0")).toBe(0);
    expect(durationToDays("")).toBe(0);
  });

  it("prefers per-ecosystem overrides over the global age", () => {
    const config = setConfigValue(setConfigValue(DEFAULT_CONFIG, "cooldown.pypi.age", "14d"), "cooldown.age", "24h");
    expect(effectiveCooldownAge(config, {}, "npm")).toBe("24h");
    expect(effectiveCooldownAge(config, {}, "pypi")).toBe("14d");
    expect(effectiveCooldownAge(config, {}, "cargo")).toBe("24h");
  });

  it("DG_COOLDOWN_AGE overrides everything; malformed values are ignored", () => {
    const config = setConfigValue(DEFAULT_CONFIG, "cooldown.pypi.age", "14d");
    expect(effectiveCooldownAge(config, { DG_COOLDOWN_AGE: "0" }, "pypi")).toBe("0");
    expect(effectiveCooldownAge(config, { DG_COOLDOWN_AGE: "3d" }, "npm")).toBe("3d");
    expect(effectiveCooldownAge(config, { DG_COOLDOWN_AGE: "banana" }, "pypi")).toBe("14d");
  });

  it("builds the request param only when the window is positive and the package is not exempt", () => {
    expect(cooldownRequestParam(DEFAULT_CONFIG, {}, "npm", "left-pad")).toEqual({ minAgeDays: 1, onUnknown: "block" });
    const off = setConfigValue(DEFAULT_CONFIG, "cooldown.age", "0");
    expect(cooldownRequestParam(off, {}, "npm", "left-pad")).toBeUndefined();
    const exempted = setConfigValue(DEFAULT_CONFIG, "cooldown.exempt", "left-pad");
    expect(cooldownRequestParam(exempted, {}, "npm", "left-pad")).toBeUndefined();
    expect(cooldownRequestParam(exempted, {}, "npm", "right-pad")).toEqual({ minAgeDays: 1, onUnknown: "block" });
    expect(cooldownRequestParam(DEFAULT_CONFIG, { DG_COOLDOWN_AGE: "0" }, "npm", "left-pad")).toBeUndefined();
  });

  it("matches exempt patterns exactly and by scope glob, with pypi name normalization", () => {
    expect(isCooldownExempt("typescript", "@myorg/*,typescript")).toBe(true);
    expect(isCooldownExempt("@myorg/utils", "@myorg/*")).toBe(true);
    expect(isCooldownExempt("@otherorg/utils", "@myorg/*")).toBe(false);
    expect(isCooldownExempt("typescript-eslint", "typescript")).toBe(false);
    expect(isCooldownExempt("My_Package", "my-package", "pypi")).toBe(true);
    expect(isCooldownExempt("my.package", "my-package", "pypi")).toBe(true);
    expect(isCooldownExempt("anything", "")).toBe(false);
  });

  it("honors dg.json cooldown exemptions, expiry, ecosystem, and pypi normalization", () => {
    const now = new Date("2026-06-10T00:00:00.000Z");
    const exempt = (over: Partial<CooldownExemption> = {}): CooldownExemption => ({
      ecosystem: "npm",
      name: "left-pad",
      reason: "",
      acceptedBy: "alice",
      acceptedAt: "2026-06-01T00:00:00.000Z",
      ...over
    });
    expect(isCooldownExemptByDgFile("left-pad", "npm", [exempt()], now)).toBe(true);
    expect(isCooldownExemptByDgFile("right-pad", "npm", [exempt()], now)).toBe(false);
    expect(isCooldownExemptByDgFile("left-pad", "pypi", [exempt()], now)).toBe(false);
    expect(isCooldownExemptByDgFile("left-pad", "cargo", [exempt()], now)).toBe(false);
    expect(isCooldownExemptByDgFile("left-pad", "npm", [exempt({ expiresAt: "2026-07-01T00:00:00.000Z" })], now)).toBe(true);
    expect(isCooldownExemptByDgFile("left-pad", "npm", [exempt({ expiresAt: "2026-01-01T00:00:00.000Z" })], now)).toBe(false);
    expect(isCooldownExemptByDgFile("My_Package", "pypi", [exempt({ ecosystem: "pypi", name: "my-package" })], now)).toBe(true);
    expect(isCooldownExemptByDgFile("anything", "npm", [], now)).toBe(false);
    expect(isCooldownExemptByDgFile("serde", "cargo", [exempt({ ecosystem: "cargo", name: "serde" })], now)).toBe(true);
    expect(isCooldownExemptByDgFile("serde", "cargo", [exempt({ ecosystem: "npm", name: "serde" })], now)).toBe(false);
  });

  it("formats durations and ages for rendering", () => {
    expect(formatCooldownDuration(1)).toBe("24h");
    expect(formatCooldownDuration(1.5)).toBe("36h");
    expect(formatCooldownDuration(7)).toBe("7d");
    expect(formatPackageAge(3 / 24)).toBe("3h ago");
    expect(formatPackageAge(0.01)).toBe("<1h ago");
    expect(formatPackageAge(44)).toBe("44d ago");
    expect(formatPackageAge(-1)).toBe("in the future");
  });

  it("describes the effective settings for status/doctor", () => {
    expect(describeCooldownSettings(DEFAULT_CONFIG, {})).toBe("24h");
    const withOverride = setConfigValue(DEFAULT_CONFIG, "cooldown.pypi.age", "14d");
    expect(describeCooldownSettings(withOverride, {})).toBe("24h (pypi 14d)");
    const off = setConfigValue(DEFAULT_CONFIG, "cooldown.age", "0");
    expect(describeCooldownSettings(off, {})).toBe("off");
    expect(describeCooldownSettings(DEFAULT_CONFIG, { DG_COOLDOWN_AGE: "3d" })).toBe("3d (DG_COOLDOWN_AGE)");
  });
});

describe("cooldown block enforcement + override flow", () => {
  let home: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "dg-cooldown-enforce-"));
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  const classification = classifyPackageManagerInvocation("npm", ["install", "left-pad"]);
  const cooldownVerdict = {
    verdict: "block" as const,
    packageName: "left-pad@2.0.1",
    cause: "cooldown" as const,
    reason: "published 3h ago — younger than your 24h cooldown",
    cooldown: { requiredDays: 1, ageDays: 0.125, publishedAt: "2026-06-10T00:00:00.000Z", eligibleAt: "2026-06-11T00:00:00.000Z" }
  };

  it("blocks on cause cooldown and carries the structured cooldown fields onto the decision", () => {
    const decision = enforceProtectedInstall({
      classification,
      env: { HOME: home },
      proxyVerdict: cooldownVerdict
    });
    expect(decision.action).toBe("block");
    expect(decision.cause).toBe("cooldown");
    expect(decision.cooldown).toEqual(cooldownVerdict.cooldown);
  });

  it("honors --dg-force-install exactly like any other block (existing override path)", () => {
    const decision = enforceProtectedInstall({
      classification,
      env: { HOME: home },
      proxyVerdict: cooldownVerdict,
      forceOverride: { force: true }
    });
    expect(decision.action).toBe("warn");
    expect(decision.forceOverride).toEqual({ allowed: true, reason: "developer override via --dg-force-install" });
    expect(decision.cooldown).toEqual(cooldownVerdict.cooldown);
  });

  it("a trusted allowlist wins over any block verdict, cooldown included", () => {
    const evaluation = evaluatePackagePolicy({
      verdict: "block",
      packageName: "left-pad",
      policy: resolveEffectivePolicy({ userConfig: DEFAULT_CONFIG }),
      allowlists: [{ packageName: "left-pad", reason: "vetted internally", trustedBy: "user" }]
    });
    expect(evaluation.action).toBe("pass");
    expect(evaluation.source).toBe("allowlist");
  });

  it("refuses the override when policy disables it", () => {
    const decision = enforceProtectedInstall({
      classification,
      env: { HOME: home },
      userConfig: { ...DEFAULT_CONFIG, policy: { ...DEFAULT_CONFIG.policy, allowForceOverride: false } },
      proxyVerdict: cooldownVerdict,
      forceOverride: { force: true }
    });
    expect(decision.action).toBe("block");
    expect(decision.forceOverride).toEqual({ allowed: false, reason: "force override is disabled by policy" });
  });
});
