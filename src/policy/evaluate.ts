import { recordAuditEvent } from "../audit/events.js";
import { DEFAULT_CONFIG, type DgUserConfig, type PolicyMode } from "../config/settings.js";
import type { DgPathEnvironment } from "../state/index.js";

export type Verdict = "pass" | "warn" | "block";
export type PolicyAction = "pass" | "warn" | "block";

export interface AllowlistEntry {
  readonly packageName: string;
  readonly reason: string;
  readonly trustedBy: "project" | "user" | "org";
}

export interface EffectivePolicy {
  readonly mode: PolicyMode;
  readonly trustProjectAllowlists: boolean;
  readonly allowForceOverride: boolean;
  readonly scriptHardening: boolean;
  readonly source: "built-in" | "user" | "org";
}

export interface PolicyEvaluation {
  readonly action: PolicyAction;
  readonly source: EffectivePolicy["source"] | "allowlist";
  readonly reason: string;
}

export interface ForceOverrideResult {
  readonly allowed: boolean;
  readonly reason: string;
  readonly auditRecorded: boolean;
}

export function resolveEffectivePolicy(options: {
  readonly userConfig?: DgUserConfig;
  readonly orgPolicy?: Partial<EffectivePolicy>;
}): EffectivePolicy {
  if (options.orgPolicy) {
    return {
      mode: options.orgPolicy.mode ?? "strict",
      trustProjectAllowlists: options.orgPolicy.trustProjectAllowlists ?? false,
      allowForceOverride: options.orgPolicy.allowForceOverride ?? false,
      scriptHardening: options.orgPolicy.scriptHardening ?? true,
      source: "org"
    };
  }
  if (options.userConfig) {
    return {
      ...options.userConfig.policy,
      source: "user"
    };
  }
  return {
    ...DEFAULT_CONFIG.policy,
    source: "built-in"
  };
}

export function evaluatePackagePolicy(options: {
  readonly verdict: Verdict;
  readonly packageName: string;
  readonly policy: EffectivePolicy;
  readonly allowlists?: readonly AllowlistEntry[];
}): PolicyEvaluation {
  const trustedAllowlist = findTrustedAllowlist(options.packageName, options.policy, options.allowlists ?? []);
  if (trustedAllowlist) {
    return {
      action: "pass",
      source: "allowlist",
      reason: `${trustedAllowlist.trustedBy} allowlist: ${trustedAllowlist.reason}`
    };
  }
  if (options.policy.mode === "off") {
    return {
      action: "pass",
      source: options.policy.source,
      reason: "policy mode off"
    };
  }
  if (options.verdict === "pass") {
    return {
      action: "pass",
      source: options.policy.source,
      reason: "verdict pass"
    };
  }
  if (options.policy.mode === "warn") {
    return {
      action: "warn",
      source: options.policy.source,
      reason: `policy warn mode for ${options.verdict} verdict`
    };
  }
  if (options.policy.mode === "strict" && options.verdict === "warn") {
    return {
      action: "block",
      source: options.policy.source,
      reason: "strict mode upgrades warn verdicts to blocks"
    };
  }
  return {
    action: options.verdict,
    source: options.policy.source,
    reason: `${options.policy.mode} mode keeps ${options.verdict} verdict`
  };
}

export function applyForceOverride(
  options: {
    readonly packageName: string;
    readonly currentAction: PolicyAction;
    readonly force: boolean;
    readonly policy: EffectivePolicy;
    readonly now?: Date;
  },
  env: DgPathEnvironment = process.env
): ForceOverrideResult {
  if (!options.force) {
    return {
      allowed: false,
      reason: "force override was not requested",
      auditRecorded: false
    };
  }
  if (options.currentAction !== "block") {
    return {
      allowed: false,
      reason: "force override is only valid for block decisions",
      auditRecorded: false
    };
  }
  if (!options.policy.allowForceOverride) {
    return {
      allowed: false,
      reason: "force override is disabled by policy",
      auditRecorded: false
    };
  }
  const event = {
    type: "install.force_override" as const,
    packageName: options.packageName,
    reason: "developer override via --dg-force-install",
    policyMode: options.policy.mode,
    createdAt: (options.now ?? new Date()).toISOString()
  };
  return {
    allowed: true,
    reason: event.reason,
    auditRecorded: recordAuditEvent(event, env)
  };
}

function findTrustedAllowlist(
  packageName: string,
  policy: EffectivePolicy,
  allowlists: readonly AllowlistEntry[]
): AllowlistEntry | undefined {
  return allowlists.find((entry) => {
    if (entry.packageName !== packageName) {
      return false;
    }
    if (entry.trustedBy === "project") {
      return policy.trustProjectAllowlists;
    }
    return true;
  });
}
