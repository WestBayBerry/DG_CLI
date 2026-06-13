import { formatCooldownDuration, formatPackageAge } from "../policy/cooldown.js";
import type { CooldownInfo, EnforcementCause, EnforcementDecision } from "../proxy/enforcement.js";

const VERIFIED_BAD: ReadonlySet<EnforcementCause> = new Set([
  "malware",
  "policy",
  "license",
  "hash-mismatch",
  "private-upload-disabled"
]);

const HEADLINES: Record<EnforcementCause, string> = {
  pass: "clean",
  warn: "flagged",
  malware: "confirmed malware",
  policy: "blocked by policy",
  license: "license policy",
  "hash-mismatch": "artifact integrity mismatch",
  "private-upload-disabled": "private artifact not scanned",
  "needs-login": "sign-in required",
  "api-unavailable": "scanner unavailable",
  "quota-exceeded": "monthly scan limit reached",
  "api-timeout": "scanner timed out",
  "registry-timeout": "registry timed out",
  "analysis-incomplete": "analysis incomplete",
  cooldown: "release too new (cooldown)",
  "unsupported-manager": "unsupported package manager",
  "proxy-setup-failure": "protection unavailable"
};

const NEXT_STEP: Partial<Record<EnforcementCause, string>> = {
  malware: "Do not install. Remove the dependency or pin a known-safe version.",
  policy: "Adjust the dependency to satisfy policy, or ask your admin.",
  license: "Replace the dependency or update your license policy.",
  "hash-mismatch": "Clear your package cache and retry. If it persists, do not install.",
  "private-upload-disabled": "Enable private artifact scanning to verify this package.",
  "needs-login": "Run 'dg login' (free) to check packages from the registry before they install.",
  "quota-exceeded": "Upgrade your plan or wait for your monthly limit to reset. See westbayberry.com/pricing.",
  cooldown: "Wait it out (see holds: dg cooldown), pin an older version, or exempt it: dg cooldown exempt <name>"
};

function cooldownDetailLine(cooldown: CooldownInfo): string {
  const window = formatCooldownDuration(cooldown.requiredDays);
  const eligible = formatResetDate(cooldown.eligibleAt);
  const suffix = eligible ? ` (eligible ${eligible})` : "";
  if (cooldown.ageDays === undefined) {
    return `publish time unknown; your cooldown is ${window}${suffix}`;
  }
  return `published ${formatPackageAge(cooldown.ageDays)}; your cooldown is ${window}${suffix}`;
}

export interface BlockedInstallSummary {
  readonly kind: "blocked" | "unverified";
  readonly packageName: string;
  readonly headline: string;
  readonly reason: string;
  readonly nextStep?: string;
  readonly override?: string;
  readonly cause?: EnforcementCause;
  readonly resetsAt?: string;
}

export function describeBlockedInstall(decision: EnforcementDecision): BlockedInstallSummary {
  const verifiedBad = VERIFIED_BAD.has(decision.cause);
  const override = decision.forceOverride && !decision.forceOverride.allowed
    ? "not allowed by your policy"
    : "re-run with --dg-force-install";
  const nextStep = verifiedBad || decision.cause === "needs-login" || decision.cause === "cooldown"
    ? NEXT_STEP[decision.cause]
    : "Re-check later with 'dg verify', or override if you accept the risk.";
  return {
    kind: verifiedBad ? "blocked" : "unverified",
    packageName: decision.packageName,
    headline: HEADLINES[decision.cause],
    reason: decision.reason,
    cause: decision.cause,
    ...(decision.resetsAt ? { resetsAt: decision.resetsAt } : {}),
    ...(nextStep ? { nextStep } : {}),
    ...(verifiedBad ? {} : { override })
  };
}

export function describeFlaggedWarn(decision: EnforcementDecision): { packageName: string; reason: string } {
  if (decision.cause === "quota-exceeded") {
    return { packageName: decision.packageName, reason: "installed unverified (over quota)" };
  }
  if (decision.forceOverride?.allowed) {
    return { packageName: decision.packageName, reason: "installed despite block (--dg-force-install)" };
  }
  return { packageName: decision.packageName, reason: decision.reason };
}

export function renderInstallDecision(decision: EnforcementDecision): string {
  if (decision.action === "pass") {
    return `✓ DG verified ${decision.packageName} — clean\n`;
  }

  if (decision.action === "warn") {
    if (decision.cause === "quota-exceeded") {
      const reset = formatResetDate(decision.resetsAt);
      return `⚠ Over quota — installed ${decision.packageName} unverified${reset ? ` (resets ${reset})` : ""}\n`;
    }
    if (decision.forceOverride?.allowed) {
      return `⚠ DG override — installing ${decision.packageName} despite block (--dg-force-install)\n`;
    }
    return `⚠ DG flagged ${decision.packageName} (warn) — ${decision.reason}\n`;
  }

  if (decision.cause === "quota-exceeded") {
    const reset = formatResetDate(decision.resetsAt);
    const override = decision.forceOverride && !decision.forceOverride.allowed
      ? "Override:  not allowed by your policy"
      : "Override:  --dg-force-install";
    return `Quota hit${reset ? ` — resets ${reset}` : ""}\n${override}\n`;
  }

  const verifiedBad = VERIFIED_BAD.has(decision.cause);
  const headline = HEADLINES[decision.cause];
  const lines: string[] = [
    verifiedBad
      ? `✘ DG blocked install — ${headline}`
      : decision.cause === "cooldown"
        ? `? DG quarantined ${decision.packageName} — ${headline}`
        : `? DG could not verify ${decision.packageName} — ${headline}`,
    `  ${decision.packageName}   ${decision.reason}`
  ];

  if (decision.cause === "cooldown" && decision.cooldown) {
    lines.push(`  ${cooldownDetailLine(decision.cooldown)}`);
  }
  if (decision.dashboardUrl) {
    lines.push(`  Evidence: ${decision.dashboardUrl}`);
  }
  if (decision.unauthenticated && decision.cause !== "needs-login") {
    lines.push("  Auth: local policy only (run 'dg login' for full coverage)");
  }

  lines.push(
    decision.forceOverride && !decision.forceOverride.allowed
      ? "  Override: not allowed by your policy"
      : "  Override: re-run with --dg-force-install"
  );

  const next = verifiedBad || decision.cause === "needs-login" || decision.cause === "cooldown"
    ? NEXT_STEP[decision.cause]
    : "Re-check later with 'dg verify', or override if you accept the risk.";
  if (next) {
    lines.push(`  Next: ${next}`);
  }

  return `${lines.join("\n")}\n`;
}

export function formatResetDate(iso: string | undefined): string | undefined {
  if (!iso) return undefined;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return undefined;
  return `${String(date.getUTCMonth() + 1).padStart(2, "0")}/${String(date.getUTCDate()).padStart(2, "0")}`;
}
