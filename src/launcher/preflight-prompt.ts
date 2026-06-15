import { analyzePackages, type AnalyzeEcosystem, type ScannerAction, type ScannerFinding, type ScannerPackageResult } from "../api/analyze.js";
import { isCiEnv } from "../presentation/mode.js";
import { matchDecision } from "../decisions/apply.js";
import { offerRememberOnIo } from "../decisions/remember-prompt.js";
import { renderInstallDecision } from "../install-ui/block-render.js";
import { defaultPromptIo } from "../install-ui/prompt.js";
import { normalizePypiName } from "../policy/pypi-name.js";
import { resolveAcceptedBy } from "../project/dgfile.js";
import { enforceProtectedInstall, type ForceOverrideRequest } from "../proxy/enforcement.js";
import { classifyPackageManagerInvocation, isSupportedPackageManager, normalizeManagerName, type PackageManager } from "./classify.js";
import {
  actionRank,
  promptPreflightYesNo,
  recordPreflightApprovals,
  renderCoveredWarns,
  renderProvenanceDowngrades,
  resolvePreflightDecisions,
  type FlaggedPackage
} from "./install-preflight.js";
import { redactSecrets } from "./output-redaction.js";
import { startPrepSpinner } from "../install-ui/prep-spinner.js";
import type { CommandResult } from "../commands/types.js";

const ECOSYSTEM_BY_MANAGER: Partial<Record<PackageManager, AnalyzeEcosystem>> = {
  npm: "npm",
  pnpm: "npm",
  yarn: "npm",
  pip: "pypi",
  pipx: "pypi",
  uv: "pypi"
};

type PinnedSpec = {
  readonly name: string;
  readonly version: string;
};

type FlaggedPinnedSpec = {
  readonly action: ScannerAction;
  readonly spec: PinnedSpec;
  readonly reason: string;
  readonly findings: readonly ScannerFinding[];
  readonly dashboardUrl?: string;
};

export type PreflightDecision =
  | { readonly handled: false }
  | { readonly handled: true; readonly result: CommandResult };

const FALL_THROUGH: PreflightDecision = { handled: false };

export async function maybePreflightInstallPrompt(
  args: readonly string[],
  options: {
    readonly env?: NodeJS.ProcessEnv;
    readonly io?: ReturnType<typeof defaultPromptIo>;
    readonly analyze?: typeof analyzePackages;
    readonly decisionsCwd?: string;
  } = {}
): Promise<PreflightDecision> {
  const env = options.env ?? process.env;
  const io = options.io ?? defaultPromptIo();
  if (!io.isTTY || isCiEnv(env)) {
    return FALL_THROUGH;
  }

  const [rawManager, ...rest] = args;
  const manager = normalizeManagerName(rawManager ?? "") as PackageManager;
  if (!rawManager || !isSupportedPackageManager(manager)) {
    return FALL_THROUGH;
  }
  const ecosystem = ECOSYSTEM_BY_MANAGER[manager as PackageManager];
  if (!ecosystem) {
    return FALL_THROUGH;
  }

  const { childArgs, forceOverride } = stripControlArgs(rest);
  const classification = classifyPackageManagerInvocation(manager as PackageManager, childArgs);
  if (classification.kind !== "protected") {
    return FALL_THROUGH;
  }

  const specs = pinnedSpecs(childArgs, ecosystem);
  if (specs.length === 0) {
    return FALL_THROUGH;
  }

  const decisions = options.decisionsCwd ? resolvePreflightDecisions(ecosystem, options.decisionsCwd, env) : null;

  const flagged: FlaggedPinnedSpec[] = [];
  const covered: ScannerPackageResult[] = [];
  const spinner = startPrepSpinner("DG preparing…");
  try {
    const response = await (options.analyze ?? analyzePackages)(
      specs.map((spec) => ({ name: spec.name, version: spec.version })),
      { ecosystem, env }
    );
    spinner.stop();
    renderProvenanceDowngrades(response.packages, io.output);
    for (const spec of specs) {
      const pkg = response.packages.find((entry) => sameSpecName(entry.name, spec.name, ecosystem) && entry.version === spec.version);
      const action = pkg?.action ?? "pass";
      if (action === "pass") {
        continue;
      }
      if (decisions && pkg && action === "warn" && matchDecision(pkg, decisions.ecosystem, decisions.file.decisions).acknowledged) {
        covered.push(pkg);
        continue;
      }
      flagged.push({
        action,
        spec,
        reason: pkg?.reasons[0] ?? pkg?.findings[0]?.title ?? "flagged by the scanner",
        findings: pkg?.findings ?? []
      });
    }
  } catch {
    return FALL_THROUGH;
  } finally {
    spinner.stop();
  }

  if (covered.length > 0) {
    renderCoveredWarns(covered, decisions, io.output);
    recordPreflightApprovals(covered.map((pkg) => ({ name: pkg.name, version: pkg.version, action: "warn" })));
  }

  const worst = flagged.reduce<FlaggedPinnedSpec | undefined>(
    (top, entry) => (!top || actionRank(entry.action) > actionRank(top.action) ? entry : top),
    undefined
  );
  if (!worst) {
    return FALL_THROUGH;
  }

  if (worst.action === "block") {
    const decision = enforceProtectedInstall({
      classification,
      env,
      proxyVerdict: {
        verdict: "block",
        packageName: `${ecosystem}:${worst.spec.name}@${worst.spec.version}`,
        cause: "malware",
        reason: worst.reason,
        ...(worst.dashboardUrl ? { dashboardUrl: worst.dashboardUrl } : {})
      },
      ...(forceOverride ? { forceOverride } : {})
    });
    if (decision.action === "block") {
      return {
        handled: true,
        result: { exitCode: 2, stdout: "", stderr: redactSecrets(renderInstallDecision(decision)) }
      };
    }
    return FALL_THROUGH;
  }

  const label = `${worst.spec.name}@${worst.spec.version}`;
  if (worst.action === "analysis_incomplete") {
    const proceed = await promptPreflightYesNo(
      `? DG could not fully analyze ${label} (analysis incomplete) — ${worst.reason}. Proceed?`,
      io,
      true
    );
    if (proceed) {
      recordPreflightApprovals(flagged.map(asFlaggedPackage));
      return FALL_THROUGH;
    }
    return {
      handled: true,
      result: { exitCode: 4, stdout: "", stderr: "Declined. Nothing was installed.\n" }
    };
  }

  const proceed = await promptPreflightYesNo(`⚠ DG flagged ${label} (warn) — ${worst.reason}. Proceed?`, io, false);
  if (proceed) {
    recordPreflightApprovals(flagged.map(asFlaggedPackage));
    if (decisions) {
      await offerRememberOnIo({
        io,
        file: decisions.file,
        packages: flagged
          .filter((entry) => entry.action === "warn")
          .map((entry) => ({ ecosystem, name: entry.spec.name, version: entry.spec.version, findings: entry.findings })),
        acceptedBy: resolveAcceptedBy(decisions.root, env),
        surface: "install preflight",
        env
      });
    }
    return FALL_THROUGH;
  }
  return {
    handled: true,
    result: { exitCode: 1, stdout: "", stderr: "Declined. Nothing was installed.\n" }
  };
}

function sameSpecName(entryName: string, specName: string, ecosystem: AnalyzeEcosystem): boolean {
  if (ecosystem === "pypi") {
    return normalizePypiName(entryName) === normalizePypiName(specName);
  }
  return entryName === specName;
}

function asFlaggedPackage(entry: FlaggedPinnedSpec): FlaggedPackage {
  return {
    name: entry.spec.name,
    version: entry.spec.version,
    action: entry.action
  };
}

function stripControlArgs(args: readonly string[]): { childArgs: string[]; forceOverride?: ForceOverrideRequest } {
  const childArgs: string[] = [];
  let force = false;
  for (const arg of args) {
    if (arg === "--dg-force-install") {
      force = true;
      continue;
    }
    childArgs.push(arg);
  }
  return force ? { childArgs, forceOverride: { force: true } } : { childArgs };
}

function pinnedSpecs(args: readonly string[], ecosystem: AnalyzeEcosystem): PinnedSpec[] {
  const specs: PinnedSpec[] = [];
  for (const arg of args) {
    if (arg.startsWith("-")) {
      continue;
    }
    const spec = ecosystem === "npm" ? parseNpmSpec(arg) : parsePypiSpec(arg);
    if (spec) {
      specs.push(spec);
    }
  }
  return specs;
}

function parseNpmSpec(token: string): PinnedSpec | undefined {
  const scoped = token.startsWith("@");
  const at = token.indexOf("@", scoped ? 1 : 0);
  if (at <= 0) {
    return undefined;
  }
  const name = token.slice(0, at);
  const version = token.slice(at + 1);
  if (!name || !/^\d/.test(version)) {
    return undefined;
  }
  return { name, version };
}

function parsePypiSpec(token: string): PinnedSpec | undefined {
  const match = /^([A-Za-z0-9._-]+)==([0-9][^\s;]*)$/.exec(token);
  if (!match || !match[1] || !match[2]) {
    return undefined;
  }
  return { name: match[1], version: match[2] };
}
