import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { writeJsonAtomic } from "../util/json-file.js";
import { acquireLockSyncWithRetry, resolveDgPaths, type DgPathEnvironment, type DgPaths } from "../state/index.js";

export type PolicyMode = "off" | "warn" | "block" | "strict";
export type GitHookOnWarn = "prompt" | "allow" | "block";
export type GitHookOnIncomplete = "allow" | "block";
export type CooldownOnUnknown = "allow" | "block";
export type ScriptGateMode = "observe" | "enforce" | "off";

export interface DgUserConfig {
  readonly version: 1;
  readonly api: {
    readonly baseUrl: string;
  };
  readonly org: {
    readonly id: string;
  };
  readonly policy: {
    readonly mode: PolicyMode;
    readonly trustProjectAllowlists: boolean;
    readonly allowForceOverride: boolean;
    readonly scriptHardening: boolean;
  };
  readonly scriptGate: {
    readonly mode: ScriptGateMode;
    readonly observe: boolean;
  };
  readonly gitHook: {
    readonly onWarn: GitHookOnWarn;
    readonly onIncomplete: GitHookOnIncomplete;
  };
  readonly cooldown: {
    readonly age: string;
    readonly npmAge: string;
    readonly pypiAge: string;
    readonly cargoAge: string;
    readonly onUnknown: CooldownOnUnknown;
    readonly exempt: string;
  };
  readonly audit: {
    readonly upload: boolean;
  };
}

export type ConfigKey =
  | "api.baseUrl"
  | "org.id"
  | "policy.mode"
  | "policy.trustProjectAllowlists"
  | "policy.allowForceOverride"
  | "policy.scriptHardening"
  | "scriptGate.mode"
  | "scriptGate.observe"
  | "gitHook.onWarn"
  | "gitHook.onIncomplete"
  | "cooldown.age"
  | "cooldown.npm.age"
  | "cooldown.pypi.age"
  | "cooldown.cargo.age"
  | "cooldown.onUnknown"
  | "cooldown.exempt"
  | "audit.upload";

export const CONFIG_KEYS: readonly ConfigKey[] = Object.freeze([
  "api.baseUrl",
  "org.id",
  "policy.mode",
  "policy.trustProjectAllowlists",
  "policy.allowForceOverride",
  "policy.scriptHardening",
  "scriptGate.mode",
  "scriptGate.observe",
  "gitHook.onWarn",
  "gitHook.onIncomplete",
  "cooldown.age",
  "cooldown.npm.age",
  "cooldown.pypi.age",
  "cooldown.cargo.age",
  "cooldown.onUnknown",
  "cooldown.exempt",
  "audit.upload"
]);

export const DEFAULT_CONFIG = Object.freeze({
  version: 1,
  api: {
    baseUrl: "https://api.westbayberry.com"
  },
  org: {
    id: ""
  },
  policy: {
    mode: "block",
    trustProjectAllowlists: false,
    allowForceOverride: true,
    scriptHardening: false
  },
  scriptGate: {
    mode: "observe",
    observe: false
  },
  gitHook: {
    onWarn: "prompt",
    onIncomplete: "allow"
  },
  cooldown: {
    age: "24h",
    npmAge: "",
    pypiAge: "",
    cargoAge: "",
    onUnknown: "allow",
    exempt: ""
  },
  audit: {
    upload: false
  }
} satisfies DgUserConfig);

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export function userConfigPath(paths: DgPaths): string {
  return join(paths.configDir, "config.json");
}

export function loadUserConfig(env: DgPathEnvironment = process.env): DgUserConfig {
  const paths = resolveDgPaths(env);
  const path = userConfigPath(paths);
  if (!existsSync(path)) {
    return DEFAULT_CONFIG;
  }
  try {
    return normalizeConfig(JSON.parse(readFileSync(path, "utf8")) as unknown);
  } catch (error) {
    if (error instanceof ConfigError) {
      throw new ConfigError(`Invalid dg config at ${path}: ${error.message}`);
    }
    throw new ConfigError(`Malformed dg config at ${path}: ${error instanceof Error ? error.message : "unknown error"}`);
  }
}

export function saveUserConfig(config: DgUserConfig, env: DgPathEnvironment = process.env): void {
  const paths = resolveDgPaths(env);
  writeJsonAtomic(userConfigPath(paths), config);
}

export const USER_CONFIG_LOCK = "user-config";
const USER_CONFIG_LOCK_TIMEOUT_MS = 5_000;
const USER_CONFIG_LOCK_STALE_MS = 60_000;

export function withUserConfigLock<T>(env: DgPathEnvironment, action: () => T): T {
  const lock = acquireLockSyncWithRetry(resolveDgPaths(env), USER_CONFIG_LOCK, {
    staleMs: USER_CONFIG_LOCK_STALE_MS,
    timeoutMs: USER_CONFIG_LOCK_TIMEOUT_MS
  });
  try {
    return action();
  } finally {
    lock.release();
  }
}

export function updateUserConfig(
  apply: (config: DgUserConfig) => DgUserConfig,
  env: DgPathEnvironment = process.env
): DgUserConfig {
  return withUserConfigLock(env, () => {
    const next = apply(loadUserConfig(env));
    saveUserConfig(next, env);
    return next;
  });
}

export function getConfigValue(config: DgUserConfig, key: ConfigKey): string {
  if (key === "api.baseUrl") {
    return config.api.baseUrl;
  }
  if (key === "org.id") {
    return config.org.id;
  }
  if (key === "policy.mode") {
    return config.policy.mode;
  }
  if (key === "policy.trustProjectAllowlists") {
    return String(config.policy.trustProjectAllowlists);
  }
  if (key === "policy.allowForceOverride") {
    return String(config.policy.allowForceOverride);
  }
  if (key === "policy.scriptHardening") {
    return String(config.policy.scriptHardening);
  }
  if (key === "scriptGate.mode") {
    return config.scriptGate.mode;
  }
  if (key === "scriptGate.observe") {
    return String(config.scriptGate.observe);
  }
  if (key === "gitHook.onWarn") {
    return config.gitHook.onWarn;
  }
  if (key === "gitHook.onIncomplete") {
    return config.gitHook.onIncomplete;
  }
  if (key === "cooldown.age") {
    return config.cooldown.age;
  }
  if (key === "cooldown.npm.age") {
    return config.cooldown.npmAge;
  }
  if (key === "cooldown.pypi.age") {
    return config.cooldown.pypiAge;
  }
  if (key === "cooldown.cargo.age") {
    return config.cooldown.cargoAge;
  }
  if (key === "cooldown.onUnknown") {
    return config.cooldown.onUnknown;
  }
  if (key === "cooldown.exempt") {
    return config.cooldown.exempt;
  }
  return String(config.audit.upload);
}

export const ADVANCED_CONFIG_KEYS: ReadonlySet<ConfigKey> = new Set([
  "org.id",
  "policy.scriptHardening",
  "scriptGate.observe",
  "cooldown.npm.age",
  "cooldown.pypi.age",
  "cooldown.cargo.age"
]);

export function listConfig(config: DgUserConfig, includeAdvanced = false): readonly { readonly key: ConfigKey; readonly value: string }[] {
  return CONFIG_KEYS.filter((key) => includeAdvanced || !ADVANCED_CONFIG_KEYS.has(key)).map((key) => ({
    key,
    value: getConfigValue(config, key)
  }));
}

export function setConfigValue(config: DgUserConfig, key: ConfigKey, rawValue: string): DgUserConfig {
  if (key === "api.baseUrl") {
    return {
      ...config,
      api: {
        baseUrl: parseUrl(rawValue)
      }
    };
  }
  if (key === "org.id") {
    return {
      ...config,
      org: {
        id: rawValue.trim()
      }
    };
  }
  if (key === "policy.mode") {
    return {
      ...config,
      policy: {
        ...config.policy,
        mode: parsePolicyMode(rawValue)
      }
    };
  }
  if (key === "policy.trustProjectAllowlists") {
    return withPolicyBoolean(config, "trustProjectAllowlists", rawValue);
  }
  if (key === "policy.allowForceOverride") {
    return withPolicyBoolean(config, "allowForceOverride", rawValue);
  }
  if (key === "policy.scriptHardening") {
    return withPolicyBoolean(config, "scriptHardening", rawValue);
  }
  if (key === "scriptGate.mode") {
    return {
      ...config,
      scriptGate: {
        ...config.scriptGate,
        mode: parseScriptGateMode(rawValue)
      }
    };
  }
  if (key === "scriptGate.observe") {
    return {
      ...config,
      scriptGate: {
        ...config.scriptGate,
        observe: parseBoolean(rawValue, key)
      }
    };
  }
  if (key === "gitHook.onWarn") {
    return {
      ...config,
      gitHook: {
        ...config.gitHook,
        onWarn: parseOnWarn(rawValue)
      }
    };
  }
  if (key === "gitHook.onIncomplete") {
    return {
      ...config,
      gitHook: {
        ...config.gitHook,
        onIncomplete: parseOnIncomplete(rawValue)
      }
    };
  }
  if (key === "cooldown.age") {
    return withCooldown(config, { age: parseCooldownAge(rawValue, key, false) });
  }
  if (key === "cooldown.npm.age") {
    return withCooldown(config, { npmAge: parseCooldownAge(rawValue, key, true) });
  }
  if (key === "cooldown.pypi.age") {
    return withCooldown(config, { pypiAge: parseCooldownAge(rawValue, key, true) });
  }
  if (key === "cooldown.cargo.age") {
    return withCooldown(config, { cargoAge: parseCooldownAge(rawValue, key, true) });
  }
  if (key === "cooldown.onUnknown") {
    return withCooldown(config, { onUnknown: parseCooldownOnUnknown(rawValue) });
  }
  if (key === "cooldown.exempt") {
    return withCooldown(config, { exempt: parseCooldownExempt(rawValue) });
  }
  return {
    ...config,
    audit: {
      upload: parseBoolean(rawValue, key)
    }
  };
}

export function unsetConfigValue(config: DgUserConfig, key: ConfigKey): DgUserConfig {
  return setConfigValue(config, key, getConfigValue(DEFAULT_CONFIG, key));
}

export function isConfigKey(value: string): value is ConfigKey {
  return CONFIG_KEYS.includes(value as ConfigKey);
}

function normalizeConfig(raw: unknown): DgUserConfig {
  if (!isPlainObject(raw)) {
    throw new ConfigError(`config must be a JSON object, got ${describeJsonType(raw)}`);
  }
  if (raw.version !== undefined && raw.version !== 1) {
    throw new ConfigError("unsupported config version");
  }
  const api = fieldObject(raw, "api");
  const org = fieldObject(raw, "org");
  const policy = fieldObject(raw, "policy");
  const scriptGate = fieldObject(raw, "scriptGate");
  const gitHook = fieldObject(raw, "gitHook");
  const cooldown = fieldObject(raw, "cooldown");
  const audit = fieldObject(raw, "audit");
  const scriptHardening = fieldBoolean(policy, "policy.scriptHardening", "scriptHardening") ?? DEFAULT_CONFIG.policy.scriptHardening;
  return {
    version: 1,
    api: {
      baseUrl: parseUrl(fieldString(api, "api.baseUrl", "baseUrl") ?? DEFAULT_CONFIG.api.baseUrl)
    },
    org: {
      id: fieldString(org, "org.id", "id") ?? DEFAULT_CONFIG.org.id
    },
    policy: {
      mode: parsePolicyMode(fieldString(policy, "policy.mode", "mode") ?? DEFAULT_CONFIG.policy.mode),
      trustProjectAllowlists:
        fieldBoolean(policy, "policy.trustProjectAllowlists", "trustProjectAllowlists") ?? DEFAULT_CONFIG.policy.trustProjectAllowlists,
      allowForceOverride:
        fieldBoolean(policy, "policy.allowForceOverride", "allowForceOverride") ?? DEFAULT_CONFIG.policy.allowForceOverride,
      scriptHardening
    },
    scriptGate: {
      mode: parseScriptGateMode(
        fieldString(scriptGate, "scriptGate.mode", "mode") ?? (scriptHardening ? "enforce" : DEFAULT_CONFIG.scriptGate.mode)
      ),
      observe: fieldBoolean(scriptGate, "scriptGate.observe", "observe") ?? DEFAULT_CONFIG.scriptGate.observe
    },
    gitHook: {
      onWarn: parseOnWarn(fieldString(gitHook, "gitHook.onWarn", "onWarn") ?? DEFAULT_CONFIG.gitHook.onWarn),
      onIncomplete: parseOnIncomplete(fieldString(gitHook, "gitHook.onIncomplete", "onIncomplete") ?? DEFAULT_CONFIG.gitHook.onIncomplete)
    },
    cooldown: {
      age: parseCooldownAge(fieldString(cooldown, "cooldown.age", "age") ?? DEFAULT_CONFIG.cooldown.age, "cooldown.age", false),
      npmAge: parseCooldownAge(fieldString(cooldown, "cooldown.npm.age", "npmAge") ?? DEFAULT_CONFIG.cooldown.npmAge, "cooldown.npm.age", true),
      pypiAge: parseCooldownAge(fieldString(cooldown, "cooldown.pypi.age", "pypiAge") ?? DEFAULT_CONFIG.cooldown.pypiAge, "cooldown.pypi.age", true),
      cargoAge: parseCooldownAge(fieldString(cooldown, "cooldown.cargo.age", "cargoAge") ?? DEFAULT_CONFIG.cooldown.cargoAge, "cooldown.cargo.age", true),
      onUnknown: parseCooldownOnUnknown(fieldString(cooldown, "cooldown.onUnknown", "onUnknown") ?? DEFAULT_CONFIG.cooldown.onUnknown),
      exempt: parseCooldownExempt(fieldString(cooldown, "cooldown.exempt", "exempt") ?? DEFAULT_CONFIG.cooldown.exempt)
    },
    audit: {
      upload: fieldBoolean(audit, "audit.upload", "upload") ?? DEFAULT_CONFIG.audit.upload
    }
  };
}

function fieldObject(root: Record<string, unknown>, field: string): Record<string, unknown> {
  const value = root[field];
  if (value === undefined) {
    return {};
  }
  if (!isPlainObject(value)) {
    throw new ConfigError(`${field} must be a JSON object, got ${describeJsonType(value)}`);
  }
  return value;
}

function fieldBoolean(section: Record<string, unknown>, field: string, key: string): boolean | undefined {
  const value = section[key];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value === "boolean") {
    return value;
  }
  throw new ConfigError(`${field} must be a JSON boolean (true or false), got ${describeJsonType(value)}`);
}

function fieldString(section: Record<string, unknown>, field: string, key: string): string | undefined {
  const value = section[key];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value === "string") {
    return value;
  }
  throw new ConfigError(`${field} must be a string, got ${describeJsonType(value)}`);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function describeJsonType(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "an array";
  }
  if (typeof value === "string") {
    return `the string "${value.length > 32 ? `${value.slice(0, 32)}…` : value}"`;
  }
  return `a ${typeof value}`;
}

function withPolicyBoolean(
  config: DgUserConfig,
  key: keyof DgUserConfig["policy"],
  rawValue: string
): DgUserConfig {
  if (key === "mode") {
    return config;
  }
  return {
    ...config,
    policy: {
      ...config.policy,
      [key]: parseBoolean(rawValue, `policy.${key}`)
    }
  };
}

function parsePolicyMode(value: string): PolicyMode {
  if (value === "off" || value === "warn" || value === "block" || value === "strict") {
    return value;
  }
  throw new ConfigError("policy.mode must be one of: off, warn, block, strict");
}

function parseScriptGateMode(value: string): ScriptGateMode {
  if (value === "observe" || value === "enforce" || value === "off") {
    return value;
  }
  throw new ConfigError("scriptGate.mode must be one of: observe, enforce, off");
}

function parseOnWarn(value: string): GitHookOnWarn {
  if (value === "prompt" || value === "allow" || value === "block") {
    return value;
  }
  throw new ConfigError("gitHook.onWarn must be one of: prompt, allow, block");
}

function parseOnIncomplete(value: string): GitHookOnIncomplete {
  if (value === "allow" || value === "block") {
    return value;
  }
  throw new ConfigError("gitHook.onIncomplete must be one of: allow, block");
}

const COOLDOWN_AGE_RE = /^([1-9]\d{0,3})(h|d)$/;
const COOLDOWN_EXEMPT_ENTRY_RE = /^[@A-Za-z0-9][@A-Za-z0-9._/-]*\*?$/;

export function parseCooldownAge(value: string, field: string, allowEmpty: boolean): string {
  const trimmed = value.trim();
  if (trimmed === "" && allowEmpty) {
    return "";
  }
  if (trimmed === "0" || trimmed === "off") {
    return "0";
  }
  if (COOLDOWN_AGE_RE.test(trimmed)) {
    return trimmed;
  }
  throw new ConfigError(
    `${field} must be a duration like 24h or 7d, or 0 to disable${allowEmpty ? ", or empty to inherit cooldown.age" : ""}`
  );
}

function parseCooldownOnUnknown(value: string): CooldownOnUnknown {
  if (value === "allow" || value === "block") {
    return value;
  }
  throw new ConfigError("cooldown.onUnknown must be one of: allow, block");
}

function parseCooldownExempt(value: string): string {
  const entries = value.split(",").map((entry) => entry.trim()).filter(Boolean);
  for (const entry of entries) {
    if (!COOLDOWN_EXEMPT_ENTRY_RE.test(entry)) {
      throw new ConfigError(`cooldown.exempt entry '${entry}' is not a valid package name or pattern (use names or globs like @org/*)`);
    }
  }
  return entries.join(",");
}

function withCooldown(config: DgUserConfig, patch: Partial<DgUserConfig["cooldown"]>): DgUserConfig {
  return {
    ...config,
    cooldown: {
      ...config.cooldown,
      ...patch
    }
  };
}

function parseBoolean(value: string, field: string): boolean {
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  throw new ConfigError(`${field} must be true or false`);
}

function parseUrl(value: string): string {
  const trimmed = value.trim();
  try {
    const url = new URL(trimmed);
    const localhost = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    if (url.protocol !== "https:" && !(url.protocol === "http:" && localhost)) {
      throw new ConfigError("api.baseUrl must use https, or http for localhost");
    }
    return url.toString().replace(/\/$/, "");
  } catch (error) {
    if (error instanceof ConfigError) {
      throw error;
    }
    throw new ConfigError("api.baseUrl must be an absolute URL");
  }
}
