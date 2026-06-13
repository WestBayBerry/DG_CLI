import type { CommandSpec } from "./types.js";
import { EXIT_USAGE, type CommandResult } from "./types.js";
import {
  ConfigError,
  getConfigValue,
  isConfigKey,
  listConfig,
  loadUserConfig,
  setConfigValue,
  unsetConfigValue,
  updateUserConfig
} from "../config/settings.js";

export const configCommand: CommandSpec = {
  name: "config",
  summary: "Inspect or edit trusted dg configuration.",
  usage: "dg config <get|set|unset|list> [key] [value] [--json] [--all]",
  args: [
    { name: "<action>", summary: "list | get <key> | set <key> <value> | unset <key>." },
    { name: "[key]", summary: "e.g. policy.mode, gitHook.onWarn, cooldown.age, cooldown.exempt, api.baseUrl." }
  ],
  flags: [
    { flag: "--json", summary: "Machine-readable output for list/get." },
    { flag: "--all", summary: "Include advanced keys in list (per-ecosystem cooldowns, internal flags)." }
  ],
  examples: [
    "dg config list",
    "dg config get policy.mode",
    "dg config set gitHook.onWarn allow",
    "dg config set cooldown.age 7d",
    "dg config set cooldown.exempt '@myorg/*,typescript'",
    "dg config unset api.baseUrl"
  ],
  details: [
    "Reads and writes user-global dg configuration only.",
    "Project-local config and allowlists remain untrusted for install-time firewall enforcement by default.",
    "cooldown.age quarantines registry releases younger than the window on new installs (default 24h; 0 disables; per-ecosystem overrides via cooldown.npm.age / cooldown.pypi.age / cooldown.cargo.age; DG_COOLDOWN_AGE overrides for CI)."
  ],
  handler: (context) => configHandler(context.args)
};

function configHandler(args: readonly string[]): CommandResult {
  const json = args.includes("--json");
  const all = args.includes("--all");
  const filtered = args.filter((arg) => arg !== "--json" && arg !== "--all");
  const [action, key, value, extra] = filtered;
  if (!action || extra) {
    return usageError("expected get, set, unset, or list");
  }
  try {
    const config = loadUserConfig();
    if (action === "list") {
      if (key || value) {
        return usageError("list does not accept a key or value");
      }
      const entries = listConfig(config, all);
      return {
        exitCode: 0,
        stdout: json ? `${JSON.stringify(Object.fromEntries(entries.map((entry) => [entry.key, entry.value])), null, 2)}\n` : renderConfigList(entries, !all),
        stderr: ""
      };
    }
    if (!key || !isConfigKey(key)) {
      return usageError(`unknown config key '${key ?? ""}'`);
    }
    if (action === "get") {
      if (value) {
        return usageError("get accepts only a key");
      }
      const result = getConfigValue(config, key);
      return {
        exitCode: 0,
        stdout: json ? `${JSON.stringify({ key, value: result }, null, 2)}\n` : `${result}\n`,
        stderr: ""
      };
    }
    if (action === "set") {
      if (value === undefined) {
        return usageError("set requires a value");
      }
      const next = updateUserConfig((current) => setConfigValue(current, key, value));
      return {
        exitCode: 0,
        stdout: `${key}=${getConfigValue(next, key)}\n`,
        stderr: ""
      };
    }
    if (action === "unset") {
      if (value) {
        return usageError("unset accepts only a key");
      }
      const next = updateUserConfig((current) => unsetConfigValue(current, key));
      return {
        exitCode: 0,
        stdout: `${key}=${getConfigValue(next, key)}\n`,
        stderr: ""
      };
    }
    return usageError(`unknown action '${action}'`);
  } catch (error) {
    if (error instanceof ConfigError) {
      return {
        exitCode: EXIT_USAGE,
        stdout: "",
        stderr: `dg config: ${error.message}\n`
      };
    }
    throw error;
  }
}

function renderConfigList(entries: readonly { readonly key: string; readonly value: string }[], truncated: boolean): string {
  const lines = entries.map((entry) => `${entry.key}=${entry.value}`);
  if (truncated) {
    lines.push("(advanced keys hidden — dg config list --all)");
  }
  return `${lines.join("\n")}\n`;
}

function usageError(message: string): CommandResult {
  return {
    exitCode: EXIT_USAGE,
    stdout: "",
    stderr: `dg config: ${message}. Run 'dg config --help'.\n`
  };
}
