import { createHash, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { userInfo } from "node:os";
import { join } from "node:path";
import { gitTrimmed } from "../util/git.js";
import { writeJsonAtomic } from "../util/json-file.js";
import { canonicalCooldownName } from "../policy/pypi-name.js";
import { acquireLockSyncWithRetry, resolveDgPaths } from "../state/index.js";
import { stampAuthoredEntries } from "./override-trust.js";

const DG_FILE_LOCK_STALE_MS = 10_000;
const DG_FILE_LOCK_TIMEOUT_MS = 5_000;

export function withDgFileLock<T>(root: string, env: NodeJS.ProcessEnv, action: () => T): T {
  const name = `dgfile-${createHash("sha1").update(root).digest("hex").slice(0, 16)}`;
  const lock = acquireLockSyncWithRetry(resolveDgPaths(env), name, {
    staleMs: DG_FILE_LOCK_STALE_MS,
    timeoutMs: DG_FILE_LOCK_TIMEOUT_MS
  });
  try {
    return action();
  } finally {
    lock.release();
  }
}

// Serialized read-modify-write: re-reads dg.json under the lock so a concurrent
// cooldown/decisions writer can never clobber the other's section.
export function mutateDgFile(root: string, env: NodeJS.ProcessEnv, mutate: (file: DgFile) => DgFile): DgFile {
  return withDgFileLock(root, env, () => {
    const file = loadDgFile(root);
    if (!file.readable) {
      throw new Error(`refusing to rewrite ${file.path}: ${file.failure ?? "unreadable"}`);
    }
    const next = stampAuthoredEntries(mutate(file), file, root, env);
    saveDgFile(next);
    return next;
  });
}

function canonicalExemptionName(ecosystem: ExemptionEcosystem, name: string): string {
  return canonicalCooldownName(ecosystem, name);
}

export class CooldownExemptionCapError extends Error {}

export const DG_FILE_NAME = "dg.json";
export const DECISION_ENTRY_CAP = 500;
export const COOLDOWN_EXEMPTION_CAP = 500;
export const DECISION_REASON_MAX = 500;

export type ScriptHook = "preinstall" | "install" | "postinstall" | "gyp";
export type ScriptDecision = "allow" | "deny";
export type ScriptApprovalProvenance = "prompt" | "command" | "imported-pnpm";

export interface ScriptApprovalEntry {
  readonly decision: ScriptDecision;
  readonly scriptsHash: string;
  readonly hooks: readonly ScriptHook[];
  readonly approvedVersion?: string;
  readonly reason?: string;
  readonly approvedAt: string;
  readonly provenance: ScriptApprovalProvenance;
}

export interface ObservedScriptEntry {
  readonly version: string;
  readonly hooks: readonly ScriptHook[];
  readonly scriptsHash: string;
  readonly firstSeen: string;
}

export interface ScriptApprovals {
  readonly npm: Readonly<Record<string, ScriptApprovalEntry>>;
  readonly observed: Readonly<Record<string, ObservedScriptEntry>>;
  readonly unknownKeys: Readonly<Record<string, unknown>>;
}

export type DecisionEcosystem = "npm" | "pypi";
export type ExemptionEcosystem = "npm" | "pypi" | "cargo";

export type DecisionScope =
  | { readonly kind: "exact"; readonly version: string }
  | { readonly kind: "any" };

export type DecisionEntry = {
  readonly id: string;
  readonly ecosystem: DecisionEcosystem;
  readonly name: string;
  readonly scope: DecisionScope;
  readonly findings: Readonly<Record<string, number>>;
  readonly reason: string;
  readonly acceptedBy: string;
  readonly acceptedAt: string;
  readonly expiresAt?: string;
  readonly extra?: Readonly<Record<string, unknown>>;
};

export type NewDecision = Omit<DecisionEntry, "id" | "acceptedAt" | "extra"> & {
  readonly acceptedAt?: string;
};

export type CooldownExemption = {
  readonly ecosystem: ExemptionEcosystem;
  readonly name: string;
  readonly reason: string;
  readonly acceptedBy: string;
  readonly acceptedAt: string;
  readonly expiresAt?: string;
  readonly extra?: Readonly<Record<string, unknown>>;
};

export type NewCooldownExemption = Omit<CooldownExemption, "acceptedAt" | "extra"> & {
  readonly acceptedAt?: string;
};

export type DgFile = {
  readonly path: string;
  readonly exists: boolean;
  readonly readable: boolean;
  readonly failure?: string;
  readonly raw: Readonly<Record<string, unknown>>;
  readonly decisions: readonly DecisionEntry[];
  readonly cooldownExemptions: readonly CooldownExemption[];
  readonly scriptApprovals: ScriptApprovals;
};

const KNOWN_TOP_LEVEL_KEYS = new Set(["version", "scriptApprovals", "decisions", "cooldownExemptions"]);
const KNOWN_SCRIPT_APPROVAL_KEYS = new Set(["npm", "observed"]);
const SCRIPT_HOOKS: readonly ScriptHook[] = ["preinstall", "install", "postinstall", "gyp"];
const UNSAFE_OBJECT_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export function dgFilePath(root: string): string {
  return join(root, DG_FILE_NAME);
}

export function findProjectRoot(cwd: string, env: NodeJS.ProcessEnv = process.env): string | null {
  try {
    return gitTrimmed(["rev-parse", "--show-toplevel"], { cwd, env });
  } catch {
    return null;
  }
}

export function emptyDgFile(path: string): DgFile {
  return { path, exists: false, readable: true, raw: {}, decisions: [], cooldownExemptions: [], scriptApprovals: emptyScriptApprovals() };
}

export function loadDgFile(root: string): DgFile {
  const path = dgFilePath(root);
  if (!existsSync(path)) {
    return emptyDgFile(path);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    return failOpen(path, `malformed JSON (${error instanceof Error ? error.message : "parse error"})`);
  }
  if (!isPlainObject(raw)) {
    return failOpen(path, "top level must be a JSON object");
  }
  if (raw.version !== undefined && raw.version !== 1) {
    return failOpen(path, `unsupported dg.json version ${String(raw.version)}`);
  }
  const listed = raw.decisions;
  if (listed !== undefined && !Array.isArray(listed)) {
    return failOpen(path, "decisions must be an array");
  }
  const entries = Array.isArray(listed) ? listed : [];
  if (entries.length > DECISION_ENTRY_CAP) {
    return failOpen(path, `more than ${DECISION_ENTRY_CAP} decisions`);
  }
  const approvalsRaw = raw.scriptApprovals;
  if (approvalsRaw !== undefined && !isPlainObject(approvalsRaw)) {
    return failOpen(path, "scriptApprovals must be an object");
  }
  const decisions: DecisionEntry[] = [];
  for (const entry of entries) {
    const parsed = parseDecisionEntry(entry);
    if (parsed) {
      decisions.push(parsed);
    }
  }
  const exemptionsRaw = raw.cooldownExemptions;
  if (exemptionsRaw !== undefined && !Array.isArray(exemptionsRaw)) {
    return failOpen(path, "cooldownExemptions must be an array");
  }
  if (Array.isArray(exemptionsRaw) && exemptionsRaw.length > COOLDOWN_EXEMPTION_CAP) {
    return failOpen(path, `more than ${COOLDOWN_EXEMPTION_CAP} cooldownExemptions`);
  }
  const cooldownExemptions: CooldownExemption[] = [];
  for (const entry of Array.isArray(exemptionsRaw) ? exemptionsRaw : []) {
    const parsed = parseCooldownExemption(entry);
    if (parsed) {
      cooldownExemptions.push(parsed);
    }
  }
  const approvals = approvalsRaw ?? {};
  return {
    path,
    exists: true,
    readable: true,
    raw,
    decisions,
    cooldownExemptions,
    scriptApprovals: {
      npm: parseEntryMap(approvals.npm, parseApprovalEntry),
      observed: parseEntryMap(approvals.observed, parseObservedEntry),
      unknownKeys: unknownKeysOf(approvals, KNOWN_SCRIPT_APPROVAL_KEYS)
    }
  };
}

export function warnUnreadableDgFile(file: DgFile, write: (line: string) => void = (line) => process.stderr.write(line)): void {
  if (!file.readable) {
    write(`dg: ignoring decisions in ${file.path} — ${file.failure ?? "unreadable"} (no warnings suppressed)\n`);
  }
}

export function appendDecisions(file: DgFile, additions: readonly NewDecision[], now = new Date()): DgFile {
  const added = additions.map((decision) => ({
    ...decision,
    id: randomUUID(),
    reason: decision.reason.slice(0, DECISION_REASON_MAX),
    acceptedAt: decision.acceptedAt ?? now.toISOString()
  }));
  return { ...file, decisions: [...file.decisions, ...added] };
}

export function removeDecisions(file: DgFile, ids: ReadonlySet<string>): DgFile {
  return { ...file, decisions: file.decisions.filter((entry) => !ids.has(entry.id)) };
}

export function appendCooldownExemptions(
  file: DgFile,
  additions: readonly NewCooldownExemption[],
  now = new Date()
): DgFile {
  const canonicalAll = additions.map((a) => ({ ...a, name: canonicalExemptionName(a.ecosystem, a.name) }));
  const canonical = [...new Map(canonicalAll.map((a) => [`${a.ecosystem}:${a.name}`, a])).values()];
  const priorExtra = new Map(file.cooldownExemptions.map((e) => [`${e.ecosystem}:${e.name}`, e.extra]));
  const keep = file.cooldownExemptions.filter(
    (e) => !canonical.some((a) => a.ecosystem === e.ecosystem && a.name === e.name)
  );
  const added: CooldownExemption[] = canonical.map((a) => {
    const carried = priorExtra.get(`${a.ecosystem}:${a.name}`);
    return {
      ...a,
      reason: a.reason.slice(0, DECISION_REASON_MAX),
      acceptedAt: a.acceptedAt ?? now.toISOString(),
      ...(carried !== undefined ? { extra: carried } : {})
    };
  });
  const next = [...keep, ...added];
  if (next.length > COOLDOWN_EXEMPTION_CAP) {
    const live = next.filter((e) => cooldownExemptionActive(e, now));
    if (live.length > COOLDOWN_EXEMPTION_CAP) {
      throw new CooldownExemptionCapError(
        `cooldown exemptions would exceed the ${COOLDOWN_EXEMPTION_CAP} cap; run 'dg cooldown prune' or remove some with 'dg cooldown rm'`
      );
    }
    return { ...file, cooldownExemptions: live };
  }
  return { ...file, cooldownExemptions: next };
}

export function removeCooldownExemptions(
  file: DgFile,
  predicate: (e: CooldownExemption) => boolean
): DgFile {
  return { ...file, cooldownExemptions: file.cooldownExemptions.filter((e) => !predicate(e)) };
}

// Active when there is no expiry, or the expiry parses to a future instant. A
// present-but-unparseable expiry fails CLOSED (treated as expired) so a typo'd
// date can never become a permanent cooldown bypass.
export function cooldownExemptionActive(e: CooldownExemption, now = new Date()): boolean {
  if (!e.expiresAt) {
    return true;
  }
  const expiry = Date.parse(e.expiresAt);
  return Number.isFinite(expiry) && expiry > now.getTime();
}

function serializeCooldownExemption(e: CooldownExemption): Record<string, unknown> {
  return {
    ...e.extra,
    ecosystem: e.ecosystem,
    name: e.name,
    reason: e.reason,
    acceptedBy: e.acceptedBy,
    acceptedAt: e.acceptedAt,
    ...(e.expiresAt ? { expiresAt: e.expiresAt } : {})
  };
}

const EXEMPTION_FIELDS = new Set(["ecosystem", "name", "reason", "acceptedBy", "acceptedAt", "expiresAt"]);

export function parseCooldownExemption(value: unknown): CooldownExemption | null {
  if (!isPlainObject(value)) {
    return null;
  }
  const ecosystem = value.ecosystem;
  if (ecosystem !== "npm" && ecosystem !== "pypi" && ecosystem !== "cargo") {
    return null;
  }
  const rawName = value.name;
  if (typeof rawName !== "string" || rawName.length === 0 || /[\u0000-\u001f\u007f\s*]/u.test(rawName)) {
    return null;
  }
  const name = canonicalExemptionName(ecosystem, rawName);
  const extra: Record<string, unknown> = {};
  for (const [key, field] of Object.entries(value)) {
    if (!EXEMPTION_FIELDS.has(key) && !UNSAFE_OBJECT_KEYS.has(key)) {
      extra[key] = field;
    }
  }
  const expiresAt = value.expiresAt;
  return {
    ecosystem,
    name,
    reason: typeof value.reason === "string" ? value.reason.slice(0, DECISION_REASON_MAX) : "",
    acceptedBy:
      typeof value.acceptedBy === "string" && value.acceptedBy.length > 0 ? value.acceptedBy : "unknown",
    acceptedAt: typeof value.acceptedAt === "string" ? value.acceptedAt : "",
    ...(typeof expiresAt === "string" ? { expiresAt } : {}),
    ...(Object.keys(extra).length > 0 ? { extra } : {})
  };
}

export function saveDgFile(file: DgFile): void {
  if (!file.readable) {
    throw new Error(`refusing to rewrite ${file.path}: ${file.failure ?? "unreadable"}`);
  }
  const top: Record<string, unknown> = unknownKeysOf(file.raw, KNOWN_TOP_LEVEL_KEYS);
  if (file.decisions.length > 0) {
    top.decisions = file.decisions.map(serializeDecisionEntry);
  }
  if (file.cooldownExemptions.length > 0) {
    top.cooldownExemptions = file.cooldownExemptions.map(serializeCooldownExemption);
  }
  const approvals: Record<string, unknown> = { ...file.scriptApprovals.unknownKeys };
  if (Object.keys(file.scriptApprovals.npm).length > 0) {
    approvals.npm = sortedRecord(file.scriptApprovals.npm);
  }
  if (Object.keys(file.scriptApprovals.observed).length > 0) {
    approvals.observed = sortedRecord(file.scriptApprovals.observed);
  }
  if (Object.keys(approvals).length > 0) {
    top.scriptApprovals = sortedRecord(approvals);
  }
  const ordered: Record<string, unknown> = { version: 1 };
  for (const key of Object.keys(top).sort()) {
    ordered[key] = top[key];
  }
  writeJsonAtomic(file.path, ordered, { fileMode: 0o644, dirMode: 0o755 });
}

export function resolveAcceptedBy(cwd: string, env: NodeJS.ProcessEnv = process.env): string {
  try {
    const email = gitTrimmed(["config", "user.email"], { cwd, env });
    if (email) {
      return email;
    }
  } catch {
    /* fall through */
  }
  try {
    return userInfo().username;
  } catch {
    return "unknown";
  }
}

function serializeDecisionEntry(entry: DecisionEntry): Record<string, unknown> {
  return {
    ...entry.extra,
    id: entry.id,
    ecosystem: entry.ecosystem,
    name: entry.name,
    scope: entry.scope.kind === "exact" ? { kind: "exact", version: entry.scope.version } : { kind: "any" },
    findings: entry.findings,
    reason: entry.reason,
    acceptedBy: entry.acceptedBy,
    acceptedAt: entry.acceptedAt,
    ...(entry.expiresAt ? { expiresAt: entry.expiresAt } : {})
  };
}

const ENTRY_FIELDS = new Set(["id", "ecosystem", "name", "scope", "findings", "reason", "acceptedBy", "acceptedAt", "expiresAt"]);

function parseDecisionEntry(value: unknown): DecisionEntry | null {
  if (!isPlainObject(value)) {
    return null;
  }
  const ecosystem = value.ecosystem;
  if (ecosystem !== "npm" && ecosystem !== "pypi") {
    return null;
  }
  const name = value.name;
  if (typeof name !== "string" || name.length === 0) {
    return null;
  }
  const scope = parseScope(value.scope);
  if (!scope) {
    return null;
  }
  const findings = parseFindings(value.findings);
  if (!findings) {
    return null;
  }
  const expiresAt = value.expiresAt;
  if (expiresAt !== undefined && typeof expiresAt !== "string") {
    return null;
  }
  const extra: Record<string, unknown> = {};
  for (const [key, field] of Object.entries(value)) {
    if (!ENTRY_FIELDS.has(key) && !UNSAFE_OBJECT_KEYS.has(key)) {
      extra[key] = field;
    }
  }
  return {
    id: typeof value.id === "string" && value.id.length > 0 ? value.id : derivedEntryId(value),
    ecosystem,
    name,
    scope,
    findings,
    reason: typeof value.reason === "string" ? value.reason.slice(0, DECISION_REASON_MAX) : "",
    acceptedBy: typeof value.acceptedBy === "string" && value.acceptedBy.length > 0 ? value.acceptedBy : "unknown",
    acceptedAt: typeof value.acceptedAt === "string" ? value.acceptedAt : "",
    ...(typeof expiresAt === "string" ? { expiresAt } : {}),
    ...(Object.keys(extra).length > 0 ? { extra } : {})
  };
}

function parseScope(value: unknown): DecisionScope | null {
  if (!isPlainObject(value)) {
    return null;
  }
  if (value.kind === "any") {
    return { kind: "any" };
  }
  if (value.kind === "exact" && typeof value.version === "string" && value.version.length > 0) {
    return { kind: "exact", version: value.version };
  }
  return null;
}

function parseFindings(value: unknown): Record<string, number> | null {
  if (value === undefined) {
    return {};
  }
  if (!isPlainObject(value)) {
    return null;
  }
  const findings: Record<string, number> = {};
  for (const [category, severity] of Object.entries(value)) {
    if (typeof severity !== "number" || !Number.isInteger(severity) || severity < 1 || severity > 5) {
      return null;
    }
    if (!UNSAFE_OBJECT_KEYS.has(category)) {
      findings[category] = severity;
    }
  }
  return findings;
}

function derivedEntryId(value: Record<string, unknown>): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex").slice(0, 12);
}

function parseEntryMap<T>(raw: unknown, parseEntry: (value: unknown) => T | null): Record<string, T> {
  if (!isPlainObject(raw)) {
    return {};
  }
  const entries: Record<string, T> = {};
  for (const [name, value] of Object.entries(raw)) {
    if (UNSAFE_OBJECT_KEYS.has(name)) {
      continue;
    }
    const parsed = parseEntry(value);
    if (parsed !== null) {
      entries[name] = parsed;
    }
  }
  return entries;
}

function parseApprovalEntry(value: unknown): ScriptApprovalEntry | null {
  if (!isPlainObject(value)) {
    return null;
  }
  const decision = value.decision;
  if (decision !== "allow" && decision !== "deny") {
    return null;
  }
  if (typeof value.scriptsHash !== "string" || typeof value.approvedAt !== "string") {
    return null;
  }
  const provenance = value.provenance;
  if (provenance !== "prompt" && provenance !== "command" && provenance !== "imported-pnpm") {
    return null;
  }
  return {
    decision,
    scriptsHash: value.scriptsHash,
    hooks: parseHooks(value.hooks),
    ...(typeof value.approvedVersion === "string" ? { approvedVersion: value.approvedVersion } : {}),
    ...(typeof value.reason === "string" ? { reason: value.reason } : {}),
    approvedAt: value.approvedAt,
    provenance
  };
}

function parseObservedEntry(value: unknown): ObservedScriptEntry | null {
  if (!isPlainObject(value)) {
    return null;
  }
  if (typeof value.version !== "string" || typeof value.scriptsHash !== "string" || typeof value.firstSeen !== "string") {
    return null;
  }
  return {
    version: value.version,
    hooks: parseHooks(value.hooks),
    scriptsHash: value.scriptsHash,
    firstSeen: value.firstSeen
  };
}

function parseHooks(raw: unknown): readonly ScriptHook[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  return SCRIPT_HOOKS.filter((hook) => raw.includes(hook));
}

function sortedRecord<T>(record: Readonly<Record<string, T>>): Record<string, T> {
  const sorted: Record<string, T> = {};
  for (const key of Object.keys(record).sort()) {
    sorted[key] = record[key] as T;
  }
  return sorted;
}

function unknownKeysOf(raw: Readonly<Record<string, unknown>>, known: ReadonlySet<string>): Record<string, unknown> {
  const unknown: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (!known.has(key) && !UNSAFE_OBJECT_KEYS.has(key)) {
      unknown[key] = value;
    }
  }
  return unknown;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function emptyScriptApprovals(): ScriptApprovals {
  return { npm: {}, observed: {}, unknownKeys: {} };
}

function failOpen(path: string, failure: string): DgFile {
  return { path, exists: true, readable: false, failure, raw: {}, decisions: [], cooldownExemptions: [], scriptApprovals: emptyScriptApprovals() };
}
