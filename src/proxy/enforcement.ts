import { recordAuditEvent } from "../audit/events.js";
import { DEFAULT_CONFIG, loadUserConfig, type DgUserConfig } from "../config/settings.js";
import type { PackageManagerClassification } from "../launcher/classify.js";
import {
  applyForceOverride,
  evaluatePackagePolicy,
  resolveEffectivePolicy,
  type EffectivePolicy,
  type PolicyAction,
  type Verdict
} from "../policy/evaluate.js";
import type { DgPathEnvironment } from "../state/index.js";

export type EnforcementCause =
  | "pass"
  | "warn"
  | "malware"
  | "policy"
  | "license"
  | "hash-mismatch"
  | "private-upload-disabled"
  | "needs-login"
  | "api-unavailable"
  | "quota-exceeded"
  | "api-timeout"
  | "registry-timeout"
  | "analysis-incomplete"
  | "cooldown"
  | "unsupported-manager"
  | "proxy-setup-failure";

export interface CooldownInfo {
  readonly requiredDays: number;
  readonly ageDays?: number;
  readonly publishedAt?: string;
  readonly eligibleAt?: string;
}

export interface EnforcementDecision {
  readonly action: PolicyAction;
  readonly cause: EnforcementCause;
  readonly packageName: string;
  readonly policyMode: EffectivePolicy["mode"];
  readonly reason: string;
  readonly dashboardUrl?: string;
  readonly unauthenticated?: boolean;
  readonly resetsAt?: string;
  readonly quotaBehavior?: "block" | "pass";
  readonly cooldown?: CooldownInfo;
  readonly forceOverride?: {
    readonly allowed: boolean;
    readonly reason: string;
  };
}

export interface ForceOverrideRequest {
  readonly force: boolean;
}

export interface ProtectedInstallRequest {
  readonly classification: PackageManagerClassification;
  readonly env: DgPathEnvironment;
  readonly userConfig?: DgUserConfig;
  readonly proxyVerdict?: ProxyVerdict;
  readonly forceOverride?: ForceOverrideRequest;
  readonly now?: Date;
}

export interface ProxyVerdict {
  readonly verdict: Verdict;
  readonly packageName?: string;
  readonly cause?: EnforcementCause;
  readonly reason?: string;
  readonly dashboardUrl?: string;
  readonly unauthenticated?: boolean;
  readonly resetsAt?: string;
  readonly quotaBehavior?: "block" | "pass";
  readonly cooldown?: CooldownInfo;
}

export function parseForceOverrideRequest(raw: string | undefined): ForceOverrideRequest | undefined {
  if (!raw) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(raw) as Partial<ForceOverrideRequest>;
    if (parsed.force !== true) {
      return undefined;
    }
    return { force: true };
  } catch {
    return undefined;
  }
}

let sideEffectFailureNoticed = false;

export function noteEnforcementSideEffectFailure(error: unknown): void {
  if (sideEffectFailureNoticed) {
    return;
  }
  sideEffectFailureNoticed = true;
  const message = error instanceof Error ? error.message : String(error);
  try {
    process.stderr.write(`dg: local state read/write failed (${message}); the install decision is still enforced.\n`);
  } catch {
    return;
  }
}

function loadUserConfigOrDefault(env: DgPathEnvironment): DgUserConfig {
  try {
    return loadUserConfig(env);
  } catch (error) {
    noteEnforcementSideEffectFailure(error);
    return DEFAULT_CONFIG;
  }
}

export function enforceProtectedInstall(request: ProtectedInstallRequest): EnforcementDecision {
  const userConfig = request.userConfig ?? loadUserConfigOrDefault(request.env);
  const policy = resolveEffectivePolicy({ userConfig });
  const proxyVerdict = request.proxyVerdict ?? failClosedVerdict(request.classification);
  const packageName = proxyVerdict.packageName ?? derivePackageName(request.classification);
  const evaluation = evaluatePackagePolicy({
    verdict: proxyVerdict.verdict,
    packageName,
    policy
  });
  const baseDecision: EnforcementDecision = withOptionalDecisionFields({
    action: evaluation.action,
    cause: proxyVerdict.cause ?? causeFromVerdict(proxyVerdict.verdict, evaluation.action),
    packageName,
    policyMode: policy.mode,
    reason: proxyVerdict.reason ?? evaluation.reason
  }, proxyVerdict);

  if (baseDecision.cause === "quota-exceeded" && proxyVerdict.quotaBehavior === "pass") {
    return { ...baseDecision, action: "warn", reason: "over monthly quota — installed unverified per your dashboard setting" };
  }

  if (baseDecision.action !== "block") {
    return baseDecision;
  }

  let force: ReturnType<typeof applyForceOverride>;
  try {
    force = applyForceOverride(
      {
        packageName,
        currentAction: "block",
        force: request.forceOverride?.force ?? false,
        policy,
        ...(request.now ? { now: request.now } : {})
      },
      request.env
    );
  } catch (error) {
    noteEnforcementSideEffectFailure(error);
    force = {
      allowed: false,
      reason: "force override is unavailable because dg local state could not be read or written",
      auditRecorded: false
    };
  }

  if (force.allowed) {
    return {
      ...baseDecision,
      action: "warn",
      reason: `force override allowed: ${force.reason}`,
      forceOverride: {
        allowed: true,
        reason: force.reason
      }
    };
  }

  try {
    recordAuditEvent(
      {
        type: "install.blocked",
        packageName,
        reason: baseDecision.reason,
        policyMode: policy.mode,
        createdAt: (request.now ?? new Date()).toISOString()
      },
      request.env
    );
  } catch (error) {
    noteEnforcementSideEffectFailure(error);
  }

  if (!request.forceOverride?.force) {
    return baseDecision;
  }

  return {
    ...baseDecision,
    forceOverride: {
      allowed: false,
      reason: force.reason
    }
  };
}

function failClosedVerdict(classification: PackageManagerClassification): ProxyVerdict {
  return {
    verdict: "block",
    packageName: derivePackageName(classification),
    cause: "proxy-setup-failure",
    reason: "per-invocation proxy enforcement is not available, so protected installs fail closed"
  };
}

const VALUE_CONSUMING_FLAGS: Record<PackageManagerClassification["ecosystem"], ReadonlySet<string>> = {
  javascript: new Set([
    "--registry", "--userconfig", "--globalconfig", "--cache", "--prefix", "--loglevel",
    "--tag", "--workspace", "-w", "--filter", "-C", "--dir", "--cwd", "--modules-folder",
    "--otp", "--script-shell", "--network-concurrency", "--mutex"
  ]),
  python: new Set([
    "--index-url", "-i", "--extra-index-url", "--find-links", "-f", "--trusted-host",
    "--proxy", "--requirement", "-r", "--constraint", "-c", "--target", "-t", "--prefix",
    "--root", "--src", "--platform", "--python", "--python-version", "--implementation",
    "--abi", "--cache-dir", "--timeout", "--retries", "--cert", "--client-cert", "--log",
    "--progress-bar", "--upgrade-strategy", "--no-binary", "--only-binary", "--report",
    "--editable", "-e", "--index", "--default-index"
  ]),
  rust: new Set([
    "--registry", "--index", "--git", "--branch", "--tag", "--rev", "--path", "--vers",
    "--version", "--features", "-F", "--package", "-p", "--manifest-path", "--target-dir",
    "--profile", "--jobs", "-j", "--target", "--config", "-Z"
  ]),
  gated: new Set()
};

export function derivePackageName(classification: PackageManagerClassification): string {
  const valueFlags = VALUE_CONSUMING_FLAGS[classification.ecosystem];
  const args = classification.args;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg) {
      continue;
    }
    if (arg.startsWith("-")) {
      if (valueFlags.has(arg)) {
        index += 1;
      }
      continue;
    }
    if (arg === classification.action) {
      continue;
    }
    return arg;
  }
  return `${classification.manager}:${classification.action || "install"}`;
}

function causeFromVerdict(verdict: Verdict, action: PolicyAction): EnforcementCause {
  if (verdict === "pass" && action === "pass") {
    return "pass";
  }
  if (action === "warn") {
    return "warn";
  }
  return "policy";
}

function withOptionalDecisionFields(decision: EnforcementDecision, verdict: ProxyVerdict): EnforcementDecision {
  return {
    ...decision,
    ...(verdict.dashboardUrl ? { dashboardUrl: verdict.dashboardUrl } : {}),
    ...(verdict.unauthenticated ? { unauthenticated: true } : {}),
    ...(verdict.resetsAt ? { resetsAt: verdict.resetsAt } : {}),
    ...(verdict.quotaBehavior ? { quotaBehavior: verdict.quotaBehavior } : {}),
    ...(verdict.cooldown ? { cooldown: verdict.cooldown } : {})
  };
}
