import type { ScannerFinding } from "../api/analyze.js";
import { recordAuditEvent, type AuditEvent } from "../audit/events.js";
import { loadUserConfig } from "../config/settings.js";
import { promptText, promptYesNo, type PromptIo } from "../install-ui/prompt.js";
import { dirname } from "node:path";
import {
  appendDecisions,
  mutateDgFile,
  type DecisionEcosystem,
  type DgFile,
  type NewDecision
} from "../project/dgfile.js";
import { promptLine as ttyPromptLine, promptYesNo as ttyPromptYesNo } from "../util/tty-prompt.js";
import { findingFingerprint, packageKey } from "./apply.js";

export type RememberPackage = {
  readonly ecosystem: DecisionEcosystem;
  readonly name: string;
  readonly version: string;
  readonly findings: readonly ScannerFinding[];
};

export type SyncRememberPrompts = {
  readonly yesNo: (question: string, defaultYes: boolean) => boolean | null;
  readonly line: (question: string) => string | null;
  readonly write: (text: string) => void;
};

const defaultSyncPrompts: SyncRememberPrompts = {
  yesNo: (question, defaultYes) => ttyPromptYesNo(question, defaultYes),
  line: (question) => ttyPromptLine(question),
  write: (text) => process.stderr.write(text)
};

export async function offerRememberOnIo(options: {
  readonly io: PromptIo;
  readonly file: DgFile;
  readonly packages: readonly RememberPackage[];
  readonly acceptedBy: string;
  readonly surface: string;
  readonly env?: NodeJS.ProcessEnv;
}): Promise<boolean> {
  const { io, file, packages } = options;
  if (!io.isTTY || !file.readable || packages.length === 0) {
    return false;
  }
  const choice = (await promptText("  Remember this acceptance? [v] this version / [o] just once: ", io)).trim().toLowerCase();
  if (choice !== "v" && choice !== "version") {
    return false;
  }
  if (!file.exists) {
    const create = await promptYesNo(`  Create ${file.path}?`, io, false);
    if (!create) {
      return false;
    }
  }
  const reason = (await promptText("  Reason (Enter to skip): ", io)).trim();
  persistRemembered(file, packages, {
    reason: reason || `accepted at ${options.surface}`,
    acceptedBy: options.acceptedBy,
    env: options.env ?? process.env
  });
  io.output.write(`  ✓ remembered in ${file.path} — review with 'dg decisions'\n`);
  return true;
}

export function offerRememberSync(options: {
  readonly file: DgFile;
  readonly packages: readonly RememberPackage[];
  readonly acceptedBy: string;
  readonly surface: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly prompts?: SyncRememberPrompts;
}): boolean {
  const { file, packages } = options;
  const prompts = options.prompts ?? defaultSyncPrompts;
  if (!file.readable || packages.length === 0) {
    return false;
  }
  const remember = prompts.yesNo("  Remember this acceptance in dg.json for future commits?", false);
  if (remember !== true) {
    return false;
  }
  if (!file.exists) {
    const create = prompts.yesNo(`  Create ${file.path}?`, false);
    if (create !== true) {
      return false;
    }
  }
  const reason = (prompts.line("  Reason (Enter to skip): ") ?? "").trim();
  persistRemembered(file, packages, {
    reason: reason || `accepted at ${options.surface}`,
    acceptedBy: options.acceptedBy,
    env: options.env ?? process.env
  });
  prompts.write(`  ✓ remembered in ${file.path} — review with 'dg decisions'\n`);
  return true;
}

export function persistRemembered(
  file: DgFile,
  packages: readonly RememberPackage[],
  options: { readonly reason: string; readonly acceptedBy: string; readonly env: NodeJS.ProcessEnv }
): void {
  const additions: NewDecision[] = packages.map((pkg) => ({
    ecosystem: pkg.ecosystem,
    name: pkg.name,
    scope: { kind: "exact", version: pkg.version },
    findings: findingFingerprint(pkg.findings),
    reason: options.reason,
    acceptedBy: options.acceptedBy
  }));
  mutateDgFile(dirname(file.path), options.env, (current) => appendDecisions(current, additions));
  recordDecisionEvents("decision.accepted", packages.map((pkg) => `${pkg.ecosystem}:${packageKey(pkg.name, pkg.version)}`), options.reason, options.env);
}

export function recordDecisionEvents(
  type: "decision.accepted" | "decision.revoked",
  packageNames: readonly string[],
  reason: string,
  env: NodeJS.ProcessEnv
): void {
  let policyMode = "unknown";
  try {
    policyMode = loadUserConfig(env).policy.mode;
  } catch {
    // a corrupt user config must not block recording the decision trail
  }
  for (const packageName of packageNames) {
    const event: AuditEvent = {
      type,
      packageName,
      reason,
      policyMode,
      createdAt: new Date().toISOString()
    };
    recordAuditEvent(event, env);
  }
}
