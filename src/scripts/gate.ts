import { loadUserConfig, type ScriptGateMode } from "../config/settings.js";
import type { PackageManagerClassification } from "../launcher/classify.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme } from "../presentation/theme.js";
import {
  loadDgFile,
  saveDgFile,
  type DgFile,
  type ObservedScriptEntry,
  type ScriptApprovalEntry,
  type ScriptApprovalProvenance,
  type ScriptDecision
} from "../project/dgfile.js";
import type { DgPathEnvironment } from "../state/index.js";
import { detectPnpmIgnoredBuilds, detectScriptWanters, type ScriptWanter } from "./detect.js";

export interface ScriptGateEvaluation {
  readonly approved: readonly ScriptWanter[];
  readonly denied: readonly ScriptWanter[];
  readonly pending: readonly ScriptWanter[];
  readonly drifted: readonly { readonly wanter: ScriptWanter; readonly priorHash: string }[];
}

export function evaluateScriptGate(
  wanters: readonly ScriptWanter[],
  approvals: Readonly<Record<string, ScriptApprovalEntry>>
): ScriptGateEvaluation {
  const approved: ScriptWanter[] = [];
  const denied: ScriptWanter[] = [];
  const pending: ScriptWanter[] = [];
  const drifted: { readonly wanter: ScriptWanter; readonly priorHash: string }[] = [];
  for (const wanter of wanters) {
    const entry = approvals[wanter.name];
    if (!entry) {
      pending.push(wanter);
      continue;
    }
    if (entry.scriptsHash !== wanter.scriptsHash) {
      drifted.push({ wanter, priorHash: entry.scriptsHash });
      continue;
    }
    if (entry.decision === "allow") {
      approved.push(wanter);
    } else {
      denied.push(wanter);
    }
  }
  return { approved, denied, pending, drifted };
}

export interface ScriptDecisionInput {
  readonly wanter: ScriptWanter;
  readonly decision: ScriptDecision;
  readonly reason?: string;
  readonly provenance?: ScriptApprovalProvenance;
}

export function applyScriptDecisions(
  file: DgFile,
  decisions: readonly ScriptDecisionInput[],
  now: Date
): DgFile {
  if (decisions.length === 0) {
    return file;
  }
  const npm: Record<string, ScriptApprovalEntry> = { ...file.scriptApprovals.npm };
  for (const input of decisions) {
    npm[input.wanter.name] = {
      decision: input.decision,
      scriptsHash: input.wanter.scriptsHash,
      hooks: input.wanter.hooks,
      ...(input.wanter.version ? { approvedVersion: input.wanter.version } : {}),
      ...(input.reason ? { reason: input.reason } : {}),
      approvedAt: now.toISOString(),
      provenance: input.provenance ?? "prompt"
    };
  }
  return {
    ...file,
    scriptApprovals: { ...file.scriptApprovals, npm }
  };
}

export function recordScriptObservations(options: {
  readonly projectDir: string;
  readonly wanters: readonly ScriptWanter[];
  readonly createIfMissing: boolean;
  readonly now: Date;
}): { readonly written: boolean; readonly path: string } {
  const file = loadDgFile(options.projectDir);
  if (!file.readable || (!file.exists && !options.createIfMissing) || options.wanters.length === 0) {
    return { written: false, path: file.path };
  }
  const observed: Record<string, ObservedScriptEntry> = { ...file.scriptApprovals.observed };
  let changed = false;
  for (const wanter of options.wanters) {
    const existing = observed[wanter.name];
    if (
      existing &&
      existing.version === wanter.version &&
      existing.scriptsHash === wanter.scriptsHash &&
      sameHooks(existing.hooks, wanter.hooks)
    ) {
      continue;
    }
    observed[wanter.name] = {
      version: wanter.version,
      hooks: wanter.hooks,
      scriptsHash: wanter.scriptsHash,
      firstSeen: existing ? existing.firstSeen : options.now.toISOString()
    };
    changed = true;
  }
  if (!changed) {
    return { written: false, path: file.path };
  }
  saveDgFile({ ...file, scriptApprovals: { ...file.scriptApprovals, observed } });
  return { written: true, path: file.path };
}

function sameHooks(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((hook, index) => hook === b[index]);
}

export function hasExplicitScriptPreference(args: readonly string[], env: NodeJS.ProcessEnv): boolean {
  if (args.some((arg) => arg === "--ignore-scripts" || arg.startsWith("--ignore-scripts="))) {
    return true;
  }
  return env.npm_config_ignore_scripts !== undefined && env.npm_config_ignore_scripts !== "";
}

export function scriptGateInstallArgs(options: {
  readonly mode: ScriptGateMode;
  readonly manager: string;
  readonly args: readonly string[];
  readonly env: NodeJS.ProcessEnv;
}): readonly string[] {
  if (options.mode !== "enforce") {
    return options.args;
  }
  if (options.manager !== "npm" && options.manager !== "yarn") {
    return options.args;
  }
  if (hasExplicitScriptPreference(options.args, options.env)) {
    return options.args;
  }
  return [...options.args, "--ignore-scripts"];
}

export function scriptGateChildEnv(options: {
  readonly mode: ScriptGateMode;
  readonly manager: string;
  readonly args: readonly string[];
  readonly env: NodeJS.ProcessEnv;
}): Readonly<Record<string, string>> {
  if (options.mode !== "enforce" || (options.manager !== "npm" && options.manager !== "yarn")) {
    return {};
  }
  if (hasExplicitScriptPreference(options.args, options.env)) {
    return {};
  }
  return { npm_config_ignore_scripts: "true" };
}

const REPORTED_NAME_LIMIT = 6;

export function scriptGateReportLine(options: {
  readonly manager: string;
  readonly wanters?: readonly ScriptWanter[];
  readonly pnpmIgnoredBuilds?: readonly string[];
}): string {
  const theme = createTheme(resolvePresentation().color);
  if (options.manager === "pnpm") {
    const ignored = options.pnpmIgnoredBuilds ?? [];
    if (ignored.length === 0) {
      return "";
    }
    return `\n  ${theme.paint(
      "muted",
      `dg scripts: pnpm natively blocked install scripts for ${formatNames(ignored)} — review with 'pnpm approve-builds'`
    )}\n`;
  }
  const wanters = options.wanters ?? [];
  if (wanters.length === 0) {
    return "";
  }
  const names = wanters.map((wanter) => (wanter.version ? `${wanter.name}@${wanter.version}` : wanter.name));
  const noun = wanters.length === 1 ? "package ran" : "packages ran";
  return `\n  ${theme.paint(
    "muted",
    `dg scripts: ${wanters.length} ${noun} install scripts (${formatNames(names)}) — observed, not blocked · silence: dg config set scriptGate.mode off`
  )}\n`;
}

function formatNames(names: readonly string[]): string {
  if (names.length <= REPORTED_NAME_LIMIT) {
    return names.join(", ");
  }
  return `${names.slice(0, REPORTED_NAME_LIMIT).join(", ")}, +${names.length - REPORTED_NAME_LIMIT} more`;
}

const MUTATING_ACTIONS: Readonly<Record<string, ReadonlySet<string>>> = {
  npm: new Set(["install", "i", "ci", "add", "update", "dedupe"]),
  yarn: new Set(["add", "install", "upgrade"]),
  pnpm: new Set(["install", "i", "add", "update"])
};

export function runScriptGateAfterInstall(options: {
  readonly classification: PackageManagerClassification;
  readonly env?: DgPathEnvironment;
  readonly projectDir?: string;
  readonly now?: Date;
}): string {
  try {
    const classification = options.classification;
    if (classification.kind !== "protected" || classification.ecosystem !== "javascript") {
      return "";
    }
    const mutatingActions = MUTATING_ACTIONS[classification.manager];
    if (!mutatingActions || !mutatingActions.has(classification.action)) {
      return "";
    }
    const config = loadUserConfig(options.env ?? process.env);
    if (config.scriptGate.mode === "off") {
      return "";
    }
    const projectDir = options.projectDir ?? process.cwd();
    if (classification.manager === "pnpm") {
      return scriptGateReportLine({ manager: "pnpm", pnpmIgnoredBuilds: detectPnpmIgnoredBuilds(projectDir) });
    }
    const wanters = detectScriptWanters(projectDir);
    recordScriptObservations({
      projectDir,
      wanters,
      createIfMissing: config.scriptGate.observe,
      now: options.now ?? new Date()
    });
    return scriptGateReportLine({ manager: classification.manager, wanters });
  } catch {
    // observing must never fail or block an install that already succeeded
    return "";
  }
}
