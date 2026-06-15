import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { analyzePackages, type AnalyzeCooldownParam, type ScannerAction, type ScannerPackageResult } from "../api/analyze.js";
import { DEFAULT_CONFIG, loadUserConfig, trustsProjectOverrides } from "../config/settings.js";
import { honoredOverrides } from "../project/override-trust.js";
import { matchDecision, packageKey } from "../decisions/apply.js";
import { offerRememberOnIo, type RememberPackage } from "../decisions/remember-prompt.js";
import { provenanceDowngradeLine } from "../presentation/provenance.js";
import { defaultPromptIo, type PromptIo } from "../install-ui/prompt.js";
import { cooldownRequestParam, formatCooldownDuration, formatPackageAge, isCooldownExempt, isCooldownExemptByDgFile, type CooldownEcosystem } from "../policy/cooldown.js";
import {
  findProjectRoot,
  loadDgFile,
  resolveAcceptedBy,
  warnUnreadableDgFile,
  type CooldownExemption,
  type DecisionEcosystem,
  type DgFile
} from "../project/dgfile.js";
import { parsePipReportInstallCount, parsePipReportInstallSet, type PipReportPackage } from "./pip-report.js";
import { resolveSpawnInvocation } from "./spawn-invocation.js";
import type { ForceOverrideRequest } from "../proxy/enforcement.js";
import type { PreverifiedEntry } from "../proxy/preverified.js";

export interface InstallPreflight {
  readonly proceed: boolean;
  readonly forceOverride?: ForceOverrideRequest;
  readonly preverified?: readonly PreverifiedEntry[];
}

export interface PreflightCooldownContext {
  readonly param: AnalyzeCooldownParam;
  readonly exempt: string;
  readonly ecosystem: CooldownEcosystem;
}

export function resolvePreflightCooldown(env: NodeJS.ProcessEnv, ecosystem: CooldownEcosystem): PreflightCooldownContext | undefined {
  // A corrupt user config must not silently disable the cooldown gate; fall back
  // to defaults so any env-configured cooldown is still applied.
  let config;
  try {
    config = loadUserConfig(env);
  } catch {
    config = DEFAULT_CONFIG;
  }
  const param = cooldownRequestParam(config, env, ecosystem, "");
  return param ? { param, exempt: config.cooldown.exempt, ecosystem } : undefined;
}

function isQuarantined(
  pkg: ScannerPackageResult,
  context: PreflightCooldownContext | undefined,
  dgExemptions: readonly CooldownExemption[] = []
): boolean {
  if (!context || !pkg.cooldown) {
    return false;
  }
  if (isCooldownExempt(pkg.name, context.exempt, context.ecosystem)
    || isCooldownExemptByDgFile(pkg.name, context.ecosystem, dgExemptions)) {
    return false;
  }
  return pkg.cooldown.status === "quarantine"
    || (pkg.cooldown.status === "unknown" && context.param.onUnknown === "block");
}

export interface PipResolution {
  readonly set: PipReportPackage[] | undefined;
  readonly count: number | undefined;
}

export type FlaggedPackage = Pick<ScannerPackageResult, "name" | "version"> & {
  readonly action: ScannerAction;
};

export type PreflightDecisionContext = {
  readonly root: string;
  readonly file: DgFile;
  readonly ecosystem: DecisionEcosystem;
  readonly env?: NodeJS.ProcessEnv;
};

export function resolvePreflightDecisions(
  ecosystem: DecisionEcosystem,
  cwd: string,
  env: NodeJS.ProcessEnv = process.env
): PreflightDecisionContext | null {
  const root = findProjectRoot(cwd, env);
  if (!root) {
    return null;
  }
  const file = loadDgFile(root);
  warnUnreadableDgFile(file);
  if (!file.readable) {
    return null;
  }
  const honored = honoredOverrides(file, root, env, trustsProjectOverrides(env));
  if (honored.droppedExemptions > 0 || honored.droppedDecisions > 0) {
    process.stderr.write(
      `dg: ignoring ${honored.droppedExemptions} cooldown exemption(s) and ${honored.droppedDecisions} decision(s) in ${file.path} not authored on this machine — re-add with 'dg cooldown add' / 'dg decisions', or 'dg config set policy.trustProjectAllowlists true' to trust this repo\n`,
    );
  }
  const gatedFile: DgFile = { ...file, cooldownExemptions: honored.exemptions, decisions: honored.decisions };
  return { root, file: gatedFile, ecosystem, env };
}

const PROCEED: InstallPreflight = { proceed: true };
const UNRESOLVED: PipResolution = { set: undefined, count: undefined };

const approvedFlagRanks = new Map<string, number>();
const pipResolutions = new Map<string, PipResolution>();

export function resetInstallPreflightSession(): void {
  approvedFlagRanks.clear();
  pipResolutions.clear();
}

export function actionRank(action: ScannerAction): number {
  return { pass: 0, analysis_incomplete: 1, warn: 2, block: 3 }[action];
}

export function recordPreflightApprovals(packages: readonly FlaggedPackage[]): void {
  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version}`;
    const rank = actionRank(pkg.action);
    if ((approvedFlagRanks.get(key) ?? -1) < rank) {
      approvedFlagRanks.set(key, rank);
    }
  }
}

function isPreflightApproved(pkg: FlaggedPackage): boolean {
  return (approvedFlagRanks.get(`${pkg.name}@${pkg.version}`) ?? -1) >= actionRank(pkg.action);
}

export function cachedPipResolution(binary: string, args: readonly string[]): PipResolution | undefined {
  return pipResolutions.get(pipResolutionKey(binary, args));
}

function pipResolutionKey(binary: string, args: readonly string[]): string {
  return JSON.stringify([binary, ...args]);
}

// pip's dry-run resolve downloads sdists/wheels it cannot get PEP 658
// metadata for, so big dependency trees legitimately take minutes on a cold
// pip cache. A short timeout here silently skips the preflight (and with it
// the batched analyze + preverified handoff), pushing every package onto the
// slow per-artifact verdict path.
function pipResolveTimeoutMs(env: NodeJS.ProcessEnv): number {
  const raw = Number(env.DG_PIP_RESOLVE_TIMEOUT_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : 120_000;
}

function resolvePipInstallSet(
  binary: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv
): Promise<PipResolution> {
  if (!binary) return Promise.resolve(UNRESOLVED);
  return new Promise((resolve) => {
    let stdout = "";
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (value: PipResolution): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(value);
    };
    let child: ReturnType<typeof spawn>;
    try {
      const invocation = resolveSpawnInvocation(binary, [...args, "--dry-run", "--report", "-", "--quiet"]);
      child = spawn(invocation.command, [...invocation.args], {
        env,
        stdio: ["ignore", "pipe", "ignore"],
        windowsVerbatimArguments: invocation.windowsVerbatimArguments
      });
    } catch {
      finish(UNRESOLVED);
      return;
    }
    timer = setTimeout(() => {
      try { child.kill(); } catch { /* already exited */ }
      finish(UNRESOLVED);
    }, pipResolveTimeoutMs(env));
    child.stdout?.on("data", (chunk: Buffer) => { stdout += chunk.toString("utf8"); });
    child.on("error", () => finish(UNRESOLVED));
    child.on("close", (code) => finish(
      code === 0
        ? { set: parsePipReportInstallSet(stdout), count: parsePipReportInstallCount(stdout) }
        : UNRESOLVED
    ));
  });
}

function findingSummary(pkg: ScannerPackageResult): string {
  return pkg.reasons[0] ?? pkg.findings[0]?.title ?? pkg.findings[0]?.id ?? "flagged";
}

interface PreflightEntry {
  readonly pkg: ScannerPackageResult;
  readonly action: ScannerAction;
  readonly viaCooldown: boolean;
}

function cooldownSummary(pkg: ScannerPackageResult): string {
  const cooldown = pkg.cooldown;
  if (!cooldown) {
    return "release too new";
  }
  const window = cooldown.requiredDays !== undefined ? formatCooldownDuration(cooldown.requiredDays) : "your cooldown";
  if (cooldown.ageDays === undefined) {
    return `publish time unknown; cooldown ${window}`;
  }
  return `published ${formatPackageAge(cooldown.ageDays)}; cooldown ${window}`;
}

function renderPreflight(flagged: readonly PreflightEntry[], out: NodeJS.WritableStream): void {
  const blocks = flagged.filter((entry) => entry.action === "block").length;
  const noun = flagged.length === 1 ? "package" : "packages";
  const tail = blocks > 0 ? ` (${blocks} blocked)` : "";
  out.write(`\n  DG flagged ${flagged.length} ${noun} before install${tail}:\n`);
  for (const entry of flagged) {
    const tag = entry.viaCooldown ? "cooldown" : entry.action === "block" ? "block" : "warn";
    const summary = entry.viaCooldown ? cooldownSummary(entry.pkg) : findingSummary(entry.pkg);
    out.write(`    ${entry.pkg.name}@${entry.pkg.version}   ${tag}   ${summary}${provenanceSuffix(entry.pkg)}\n`);
  }
  out.write("\n");
}

function provenanceSuffix(pkg: ScannerPackageResult): string {
  const prov = pkg.provenance;
  if (!prov || prov.status === "unknown") {
    return "";
  }
  return `   provenance: ${prov.status}`;
}

export function renderProvenanceDowngrades(
  packages: readonly ScannerPackageResult[],
  out: NodeJS.WritableStream
): void {
  const downgraded = packages.filter((pkg) => pkg.provenance?.downgrade);
  if (downgraded.length === 0) {
    return;
  }
  out.write("\n");
  for (const pkg of downgraded) {
    const line = provenanceDowngradeLine(pkg.version, pkg.provenance!);
    out.write(`  ⚠ ${pkg.name}@${pkg.version}: ${line} (display only, verdict unchanged)\n`);
  }
}

export async function runInstallPreflight(
  manager: string,
  binary: string,
  childArgs: readonly string[],
  env: NodeJS.ProcessEnv,
  cwd: string = process.cwd(),
  beforeInteraction?: () => void
): Promise<InstallPreflight> {
  if (manager !== "pip" || !binary) {
    return PROCEED;
  }
  const key = pipResolutionKey(binary, childArgs);
  let resolution = pipResolutions.get(key);
  if (!resolution) {
    resolution = await resolvePipInstallSet(binary, childArgs, env);
    pipResolutions.set(key, resolution);
  }
  const set = resolution.set;
  if (!set) {
    process.stderr.write("  dg: could not resolve the install set ahead of time — verifying during install instead\n");
    return PROCEED;
  }
  if (set.length === 0) {
    return PROCEED;
  }

  const cooldownContext = resolvePreflightCooldown(env, "pypi");
  let verdicts;
  try {
    verdicts = await analyzePackages(
      set.map((pkg) => ({ name: pkg.name, version: pkg.version })),
      { ecosystem: "pypi", env, ...(cooldownContext ? { cooldown: cooldownContext.param } : {}) }
    );
  } catch {
    process.stderr.write("  dg: pre-install check unavailable — verifying during install instead\n");
    return PROCEED;
  }

  beforeInteraction?.();
  const decision = await decideFromVerdicts(verdicts.packages, defaultPromptIo(), cooldownContext, resolvePreflightDecisions("pypi", cwd, env));
  if (!decision.proceed || decision.forceOverride) {
    return decision;
  }
  const preverified = preverifiedEntries(verdicts.packages, cooldownContext !== undefined);
  return preverified.length > 0 ? { ...decision, preverified } : decision;
}

export function preverifiedEntries(
  packages: readonly ScannerPackageResult[],
  cooldownRequested: boolean
): PreverifiedEntry[] {
  return packages
    .filter((pkg): pkg is ScannerPackageResult & { action: "pass" | "warn" } => pkg.action === "pass" || pkg.action === "warn")
    .map((pkg) => ({
      ecosystem: "pypi" as const,
      name: pkg.name,
      version: pkg.version,
      action: pkg.action,
      ...(pkg.reasons[0] ? { reason: pkg.reasons[0] } : {}),
      ...(typeof pkg.artifactSha256 === "string" && pkg.artifactSha256.length > 0 ? { scannedSha256: pkg.artifactSha256 } : {}),
      cooldownEvaluated: cooldownRequested && pkg.cooldown !== undefined
    }));
}

export async function decideFromVerdicts(
  packages: readonly ScannerPackageResult[],
  io: PromptIo,
  cooldownContext?: PreflightCooldownContext,
  decisions: PreflightDecisionContext | null = null
): Promise<InstallPreflight> {
  if (io.isTTY) {
    renderProvenanceDowngrades(packages, io.output);
  }
  const covered: ScannerPackageResult[] = [];
  const entries: PreflightEntry[] = packages
    .map((pkg) => {
      const viaCooldown = isQuarantined(pkg, cooldownContext, decisions?.file.cooldownExemptions ?? []) && pkg.action !== "block";
      const action: ScannerAction = viaCooldown ? "block" : pkg.action ?? "pass";
      return { pkg, action, viaCooldown };
    })
    .filter((entry) => {
      if ((entry.action !== "warn" && entry.action !== "block")
        || isPreflightApproved({ name: entry.pkg.name, version: entry.pkg.version, action: entry.action })) {
        return false;
      }
      if (decisions && entry.action === "warn" && matchDecision(entry.pkg, decisions.ecosystem, decisions.file.decisions).acknowledged) {
        covered.push(entry.pkg);
        return false;
      }
      return true;
    });
  if (covered.length > 0 && io.isTTY) {
    renderCoveredWarns(covered, decisions, io.output);
    recordPreflightApprovals(covered.map((pkg) => ({ name: pkg.name, version: pkg.version, action: "warn" })));
  }
  if (entries.length === 0 || !io.isTTY) {
    return PROCEED;
  }
  renderPreflight(entries, io.output);
  const hasBlock = entries.some((entry) => entry.action === "block");
  const accepted = await promptPreflightYesNo(
    hasBlock ? "  Override and install anyway?" : "  Proceed?",
    io,
    false
  );
  if (!accepted) {
    return { proceed: false };
  }
  recordPreflightApprovals(
    entries.map((entry) => ({ name: entry.pkg.name, version: entry.pkg.version, action: entry.action }))
  );
  if (!hasBlock && decisions) {
    await offerRememberOnIo({
      io,
      file: decisions.file,
      packages: entries
        .filter((entry) => entry.action === "warn")
        .map((entry): RememberPackage => ({ ecosystem: decisions.ecosystem, name: entry.pkg.name, version: entry.pkg.version, findings: entry.pkg.findings })),
      acceptedBy: resolveAcceptedBy(decisions.root, decisions.env ?? process.env),
      surface: "install preflight",
      env: decisions.env ?? process.env
    });
  }
  return hasBlock ? { proceed: true, forceOverride: { force: true } } : PROCEED;
}

export function renderCoveredWarns(
  covered: readonly ScannerPackageResult[],
  decisions: PreflightDecisionContext | null,
  out: NodeJS.WritableStream
): void {
  for (const pkg of covered) {
    const match = decisions ? matchDecision(pkg, decisions.ecosystem, decisions.file.decisions) : { acknowledged: false as const };
    const who = match.acknowledged ? match.entry.acceptedBy : "dg.json";
    const when = match.acknowledged && match.entry.acceptedAt ? ` on ${match.entry.acceptedAt.slice(0, 10)}` : "";
    out.write(`  ⚠ ${packageKey(pkg.name, pkg.version)} warn previously accepted by ${who}${when} — see 'dg decisions'\n`);
  }
}

export async function promptPreflightYesNo(question: string, io: PromptIo, defaultYes: boolean): Promise<boolean> {
  if (!io.isTTY) {
    return false;
  }
  const rl = createInterface({ input: io.input, output: io.output });
  try {
    const answer = await new Promise<string | undefined>((resolve) => {
      rl.once("SIGINT", () => resolve(undefined));
      rl.question(`${question} ${defaultYes ? "[Y/n]" : "[y/N]"} `, resolve);
    });
    if (answer === undefined) {
      rl.close();
      restoreRawInput(io.input);
      io.output.write("\n");
      process.exit(130);
    }
    const normalized = answer.trim().toLowerCase();
    if (normalized === "") {
      return defaultYes;
    }
    return normalized === "y" || normalized === "yes";
  } finally {
    rl.close();
    restoreRawInput(io.input);
  }
}

function restoreRawInput(input: NodeJS.ReadableStream): void {
  const stream = input as Partial<NodeJS.ReadStream>;
  if (stream.isTTY && typeof stream.setRawMode === "function") {
    stream.setRawMode(false);
  }
}
