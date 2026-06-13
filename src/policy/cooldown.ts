import { parseCooldownAge, type CooldownOnUnknown, type DgUserConfig } from "../config/settings.js";
import { cooldownExemptionActive, type CooldownExemption } from "../project/dgfile.js";
import { canonicalCooldownName, normalizePypiName } from "./pypi-name.js";

export { normalizePypiName };

export type CooldownEcosystem = "npm" | "pypi" | "cargo";

export interface CooldownRequestParam {
  readonly minAgeDays: number;
  readonly onUnknown: CooldownOnUnknown;
}

export function durationToDays(value: string): number {
  const trimmed = value.trim();
  if (trimmed === "" || trimmed === "0" || trimmed === "off") {
    return 0;
  }
  const match = /^([1-9]\d{0,3})(h|d)$/.exec(trimmed);
  if (!match || !match[1] || !match[2]) {
    return 0;
  }
  const amount = Number.parseInt(match[1], 10);
  return match[2] === "h" ? amount / 24 : amount;
}

export function effectiveCooldownAge(
  config: DgUserConfig,
  env: NodeJS.ProcessEnv,
  ecosystem: CooldownEcosystem
): string {
  const fromEnv = env.DG_COOLDOWN_AGE;
  if (fromEnv !== undefined) {
    try {
      return parseCooldownAge(fromEnv, "DG_COOLDOWN_AGE", false);
    } catch {
      // fall through to config: a malformed env override must not change policy
    }
  }
  const perEcosystem = ecosystem === "npm"
    ? config.cooldown.npmAge
    : ecosystem === "pypi"
      ? config.cooldown.pypiAge
      : config.cooldown.cargoAge;
  return perEcosystem !== "" ? perEcosystem : config.cooldown.age;
}

export function isCooldownExempt(
  packageName: string,
  exempt: string,
  ecosystem?: CooldownEcosystem
): boolean {
  const name = ecosystem ? canonicalCooldownName(ecosystem, packageName) : packageName;
  return exempt
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .some((pattern) => {
      const candidate = ecosystem ? canonicalCooldownName(ecosystem, pattern) : pattern;
      if (candidate.endsWith("*")) {
        return name.startsWith(candidate.slice(0, -1));
      }
      return name === candidate;
    });
}

export function isCooldownExemptByDgFile(
  packageName: string,
  ecosystem: CooldownEcosystem,
  exemptions: readonly CooldownExemption[],
  now: Date = new Date()
): boolean {
  if (ecosystem !== "npm" && ecosystem !== "pypi" && ecosystem !== "cargo") {
    return false;
  }
  const target = canonicalCooldownName(ecosystem, packageName);
  return exemptions.some((e) => {
    if (e.ecosystem !== ecosystem) {
      return false;
    }
    const candidate = canonicalCooldownName(ecosystem, e.name);
    return candidate === target && cooldownExemptionActive(e, now);
  });
}

export function cooldownRequestParam(
  config: DgUserConfig,
  env: NodeJS.ProcessEnv,
  ecosystem: CooldownEcosystem,
  packageName: string
): CooldownRequestParam | undefined {
  const minAgeDays = durationToDays(effectiveCooldownAge(config, env, ecosystem));
  if (minAgeDays <= 0) {
    return undefined;
  }
  if (packageName && isCooldownExempt(packageName, config.cooldown.exempt, ecosystem)) {
    return undefined;
  }
  return { minAgeDays, onUnknown: config.cooldown.onUnknown };
}

export function formatCooldownDuration(days: number): string {
  const hours = days * 24;
  if (hours <= 0) {
    return "0h";
  }
  if (hours < 48) {
    return `${Math.round(hours)}h`;
  }
  return `${Math.floor(days)}d`;
}

export function formatPackageAge(ageDays: number): string {
  if (ageDays < 0) {
    return "in the future";
  }
  const hours = ageDays * 24;
  if (hours < 1) {
    return "<1h ago";
  }
  if (hours < 48) {
    return `${Math.floor(hours)}h ago`;
  }
  return `${Math.floor(ageDays)}d ago`;
}

export function describeCooldownSettings(config: DgUserConfig, env: NodeJS.ProcessEnv): string {
  if (env.DG_COOLDOWN_AGE !== undefined) {
    try {
      const envDays = durationToDays(parseCooldownAge(env.DG_COOLDOWN_AGE, "DG_COOLDOWN_AGE", false));
      return `${envDays > 0 ? formatCooldownDuration(envDays) : "off"} (DG_COOLDOWN_AGE)`;
    } catch {
      // malformed env override is ignored everywhere; describe the config instead
    }
  }
  const baseDays = durationToDays(config.cooldown.age);
  const base = baseDays > 0 ? formatCooldownDuration(baseDays) : "off";
  const overrides = (["npm", "pypi", "cargo"] as const)
    .map((ecosystem) => {
      const value = ecosystem === "npm" ? config.cooldown.npmAge : ecosystem === "pypi" ? config.cooldown.pypiAge : config.cooldown.cargoAge;
      if (value === "") {
        return undefined;
      }
      const days = durationToDays(value);
      return `${ecosystem} ${days > 0 ? formatCooldownDuration(days) : "off"}`;
    })
    .filter((entry): entry is string => entry !== undefined);
  return overrides.length > 0 ? `${base} (${overrides.join(", ")})` : base;
}
