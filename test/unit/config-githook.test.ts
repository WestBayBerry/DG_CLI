import { describe, expect, it } from "vitest";
import {
  CONFIG_KEYS,
  ConfigError,
  DEFAULT_CONFIG,
  getConfigValue,
  isConfigKey,
  listConfig,
  setConfigValue,
  unsetConfigValue
} from "../../src/config/settings.js";

describe("gitHook config keys", () => {
  it("are registered and default to prompt/allow", () => {
    expect(isConfigKey("gitHook.onWarn")).toBe(true);
    expect(isConfigKey("gitHook.onIncomplete")).toBe(true);
    expect(CONFIG_KEYS).toContain("gitHook.onWarn");
    expect(getConfigValue(DEFAULT_CONFIG, "gitHook.onWarn")).toBe("prompt");
    expect(getConfigValue(DEFAULT_CONFIG, "gitHook.onIncomplete")).toBe("allow");
    expect(listConfig(DEFAULT_CONFIG).some((entry) => entry.key === "gitHook.onWarn")).toBe(true);
  });

  it("round-trips valid values and unsets back to default", () => {
    const updated = setConfigValue(DEFAULT_CONFIG, "gitHook.onWarn", "block");
    expect(getConfigValue(updated, "gitHook.onWarn")).toBe("block");
    expect(getConfigValue(unsetConfigValue(updated, "gitHook.onWarn"), "gitHook.onWarn")).toBe("prompt");
  });

  it("rejects invalid values", () => {
    expect(() => setConfigValue(DEFAULT_CONFIG, "gitHook.onWarn", "sometimes")).toThrow(ConfigError);
    expect(() => setConfigValue(DEFAULT_CONFIG, "gitHook.onIncomplete", "prompt")).toThrow(ConfigError);
  });
});
