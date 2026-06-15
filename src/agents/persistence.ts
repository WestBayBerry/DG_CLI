import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";
import {
  readCleanupRegistry,
  recordCleanupEntry,
  removeCleanupEntry,
  type CleanupRegistryEntry,
} from "../state/index.js";
import type {
  AgentHookApplyResult,
  AgentHookCheck,
  AgentHookContext,
  AgentId,
  HookPersistence,
  ProbeDeps,
  ProbeResult,
} from "./types.js";

export const LEGACY_AGENT_HOOK_SENTINEL = "dg-agent-hook-v1";

export function agentHookSentinel(agent: AgentId): string {
  return `${LEGACY_AGENT_HOOK_SENTINEL}:${agent}`;
}

export class AgentHookError extends Error {}

export type Json = Record<string, unknown>;

export function dirExists(path: string): boolean {
  try {
    return lstatSync(path).isDirectory();
  } catch {
    return false;
  }
}

function assertSafeNode(path: string, role: string): void {
  let stats;
  try {
    stats = lstatSync(path);
  } catch {
    return;
  }
  if (stats.isSymbolicLink()) {
    throw new AgentHookError(`${path} is a symlink; refusing to write through it. Edit the link target directly, then retry.`);
  }
  if (typeof process.getuid === "function" && stats.uid !== process.getuid()) {
    throw new AgentHookError(`${path} (${role}) is owned by another user; refusing to write to it.`);
  }
  if ((stats.mode & 0o002) !== 0) {
    throw new AgentHookError(`${path} (${role}) is world-writable; refusing to write to it. Tighten its permissions, then retry.`);
  }
}

export function assertSafeWriteTarget(path: string): void {
  assertSafeNode(dirname(path), "directory");
  assertSafeNode(path, "file");
}

export function readSettings(path: string): { settings: Json; existed: boolean } {
  if (!existsSync(path)) {
    return { settings: {}, existed: false };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new AgentHookError(`${path} is not valid JSON; refusing to modify it. Fix or remove it, then retry.`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new AgentHookError(`${path} is not a JSON object; refusing to modify it.`);
  }
  return { settings: parsed as Json, existed: true };
}

export function writeSettingsAtomic(path: string, settings: Json): void {
  mkdirSync(dirname(path), { recursive: true });
  assertSafeWriteTarget(path);
  const tmp = `${path}.dg-${randomBytes(6).toString("hex")}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  try {
    renameSync(tmp, path);
  } catch (error) {
    rmSync(tmp, { force: true });
    throw error;
  }
}

async function wasCreatedByDg(ctx: AgentHookContext): Promise<boolean> {
  try {
    const reg = await readCleanupRegistry(ctx.paths);
    return reg.entries.some(
      (e) => e.kind === "agent-hook" && e.path === ctx.settingsPath && e.original === "dg-created",
    );
  } catch {
    return false;
  }
}

async function recordHookEntry(ctx: AgentHookContext, legacySentinels: readonly string[], created: boolean): Promise<void> {
  for (const sentinel of legacySentinels) {
    await removeCleanupEntry(ctx.paths, { kind: "agent-hook", path: ctx.settingsPath, sentinel });
  }
  // Preserve the dg-created provenance on re-apply: `created` is false the second
  // time the hook is installed, but if dg created the file originally, uninstall
  // must still remove it, so keep the marker.
  const dgCreated = created || (await wasCreatedByDg(ctx));
  await recordCleanupEntry(ctx.paths, {
    kind: "agent-hook",
    path: ctx.settingsPath,
    mode: "mode1",
    sentinel: agentHookSentinel(ctx.agent),
    ...(dgCreated ? { original: "dg-created" } : {}),
  });
}

async function removeHookEntries(ctx: AgentHookContext, legacySentinels: readonly string[]): Promise<void> {
  await removeCleanupEntry(ctx.paths, { kind: "agent-hook", path: ctx.settingsPath, sentinel: agentHookSentinel(ctx.agent) });
  for (const sentinel of legacySentinels) {
    await removeCleanupEntry(ctx.paths, { kind: "agent-hook", path: ctx.settingsPath, sentinel });
  }
}

function findHookCommand(node: unknown, signature: string): string | null {
  if (typeof node === "string") {
    return node.includes(signature) ? node : null;
  }
  if (Array.isArray(node)) {
    for (const value of node) {
      const found = findHookCommand(value, signature);
      if (found) {
        return found;
      }
    }
    return null;
  }
  if (node && typeof node === "object") {
    for (const value of Object.values(node)) {
      const found = findHookCommand(value, signature);
      if (found) {
        return found;
      }
    }
    return null;
  }
  return null;
}

function hookResolvesCheck(settings: Json, agent: string): AgentHookCheck | null {
  const command = findHookCommand(settings, `hook-exec ${agent}`);
  if (!command) {
    return null;
  }
  const head = command.split(/\s+hook-exec\s+/)[0] ?? command;
  const broken = head
    .split(/\s+/)
    .filter((token) => token.startsWith("/"))
    .filter((token) => !existsSync(token));
  return {
    name: "hook command resolves",
    ok: broken.length === 0,
    detail:
      broken.length === 0
        ? "dg path in the hook resolves"
        : `hook references a missing path (${broken.join(", ")}); re-run 'dg agents on ${agent}'`,
  };
}

export interface MergedJsonHookConfig {
  readonly checkName: string;
  readonly legacySentinels?: readonly string[];
  readonly insert: (settings: Json, dgCommand: string) => Json;
  readonly remove: (settings: Json) => { settings: Json; changed: boolean; empty: boolean };
  readonly isInstalled: (settings: Json) => boolean;
}

export function mergedJsonHook(config: MergedJsonHookConfig): HookPersistence {
  const legacy = config.legacySentinels ?? [];
  return {
    isInstalledCheckName: config.checkName,
    async apply(ctx: AgentHookContext): Promise<AgentHookApplyResult> {
      const { settings, existed } = readSettings(ctx.settingsPath);
      writeSettingsAtomic(ctx.settingsPath, config.insert(settings, ctx.dgCommand));
      await recordHookEntry(ctx, legacy, !existed);
      return { created: !existed };
    },
    async remove(ctx: AgentHookContext): Promise<{ removed: boolean }> {
      let removed = false;
      if (existsSync(ctx.settingsPath)) {
        let settings: Json | null = null;
        try {
          settings = readSettings(ctx.settingsPath).settings;
        } catch {
          settings = null;
        }
        if (settings) {
          const result = config.remove(settings);
          if (result.changed) {
            removed = true;
            if (result.empty && (await wasCreatedByDg(ctx))) {
              rmSync(ctx.settingsPath, { force: true });
            } else {
              writeSettingsAtomic(ctx.settingsPath, result.settings);
            }
          }
        }
      }
      await removeHookEntries(ctx, legacy);
      return { removed };
    },
    verify(ctx: AgentHookContext): AgentHookCheck[] {
      const checks: AgentHookCheck[] = [];
      const present = existsSync(ctx.settingsPath);
      checks.push({ name: "settings file", ok: present, detail: present ? ctx.settingsPath : `${ctx.settingsPath} (absent)` });
      if (!present) {
        return checks;
      }
      let settings: Json | null = null;
      let installed = false;
      try {
        settings = readSettings(ctx.settingsPath).settings;
        installed = config.isInstalled(settings);
      } catch {
        installed = false;
      }
      checks.push({ name: config.checkName, ok: installed, detail: installed ? "installed" : "not installed" });
      if (installed && settings) {
        const resolves = hookResolvesCheck(settings, ctx.agent);
        if (resolves) {
          checks.push(resolves);
        }
      }
      return checks;
    },
    reverseEntry(entry: CleanupRegistryEntry, removed: string[], missing: string[], warnings: string[]): void {
      if (!existsSync(entry.path)) {
        missing.push(entry.path);
        return;
      }
      let settings: Json;
      try {
        const parsed = JSON.parse(readFileSync(entry.path, "utf8")) as unknown;
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
          warnings.push(`${entry.path}: not a JSON object; left untouched`);
          return;
        }
        settings = parsed as Json;
      } catch {
        warnings.push(`${entry.path}: unreadable JSON; left untouched`);
        return;
      }
      const result = config.remove(settings);
      if (!result.changed) {
        missing.push(entry.path);
        return;
      }
      if (result.empty && entry.original === "dg-created") {
        rmSync(entry.path, { force: true });
      } else {
        try {
          writeSettingsAtomic(entry.path, result.settings);
        } catch (error) {
          warnings.push(`${entry.path}: ${error instanceof Error ? error.message : "could not rewrite settings"}`);
          return;
        }
      }
      removed.push(entry.path);
    },
  };
}

export interface OwnedJsonHookConfig {
  readonly agent: AgentId;
  readonly checkName: string;
  readonly render: (dgCommand: string) => Json;
}

export function ownedJsonHook(config: OwnedJsonHookConfig): HookPersistence {
  const sentinel = agentHookSentinel(config.agent);
  const ownsFile = (path: string): boolean => {
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8")) as { dgSentinel?: unknown };
      return parsed?.dgSentinel === sentinel;
    } catch {
      return false;
    }
  };
  return {
    isInstalledCheckName: config.checkName,
    async apply(ctx: AgentHookContext): Promise<AgentHookApplyResult> {
      const existed = existsSync(ctx.settingsPath);
      if (existed && !ownsFile(ctx.settingsPath)) {
        throw new AgentHookError(
          `${ctx.settingsPath} already exists and was not written by dg; refusing to overwrite it. Merge the output of 'dg agents --print ${ctx.agent}' yourself, or remove the file and retry.`,
        );
      }
      writeSettingsAtomic(ctx.settingsPath, { dgSentinel: sentinel, ...config.render(ctx.dgCommand) });
      await recordHookEntry(ctx, [], !existed);
      return { created: !existed };
    },
    async remove(ctx: AgentHookContext): Promise<{ removed: boolean }> {
      let removed = false;
      if (existsSync(ctx.settingsPath) && ownsFile(ctx.settingsPath)) {
        rmSync(ctx.settingsPath, { force: true });
        removed = true;
      }
      await removeHookEntries(ctx, []);
      return { removed };
    },
    verify(ctx: AgentHookContext): AgentHookCheck[] {
      const checks: AgentHookCheck[] = [];
      const present = existsSync(ctx.settingsPath);
      checks.push({ name: "hook file", ok: present, detail: present ? ctx.settingsPath : `${ctx.settingsPath} (absent)` });
      if (!present) {
        return checks;
      }
      const installed = ownsFile(ctx.settingsPath);
      checks.push({ name: config.checkName, ok: installed, detail: installed ? "installed" : "present but not dg-owned" });
      if (installed) {
        try {
          const settings = JSON.parse(readFileSync(ctx.settingsPath, "utf8")) as Json;
          const resolves = hookResolvesCheck(settings, ctx.agent);
          if (resolves) {
            checks.push(resolves);
          }
        } catch {
          // unreadable file: the installed check already reflects the broken state
        }
      }
      return checks;
    },
    reverseEntry(entry: CleanupRegistryEntry, removed: string[], missing: string[], warnings: string[]): void {
      if (!existsSync(entry.path)) {
        missing.push(entry.path);
        return;
      }
      if (!ownsFile(entry.path)) {
        warnings.push(`${entry.path}: not dg-owned; left untouched`);
        return;
      }
      rmSync(entry.path, { force: true });
      removed.push(entry.path);
    },
  };
}

function defaultExecVersion(binary: string, args: readonly string[]): string | null {
  try {
    const result = spawnSync(binary, [...args], { encoding: "utf8", timeout: 1500 });
    if (result.status !== 0 || typeof result.stdout !== "string") {
      return null;
    }
    return result.stdout.trim() || null;
  } catch {
    return null;
  }
}

function parseSemver(text: string): readonly [number, number, number] | null {
  const match = /(\d+)\.(\d+)(?:\.(\d+))?/.exec(text);
  if (!match) {
    return null;
  }
  return [Number(match[1]), Number(match[2]), Number(match[3] ?? "0")];
}

export function probeMinCliVersion(
  binary: string,
  minVersion: string,
  label: string,
  deps?: ProbeDeps,
): ProbeResult {
  const execVersion = deps?.execVersion ?? defaultExecVersion;
  const output = execVersion(binary, ["--version"]);
  if (!output) {
    return { supported: false, detail: `cannot confirm ${label} >= ${minVersion} (the ${binary} CLI did not report a version)` };
  }
  const found = parseSemver(output);
  const wanted = parseSemver(minVersion);
  if (!found || !wanted) {
    return { supported: false, detail: `cannot confirm ${label} >= ${minVersion} (unrecognized version '${output}')` };
  }
  for (let index = 0; index < 3; index += 1) {
    if ((found[index] ?? 0) > (wanted[index] ?? 0)) {
      break;
    }
    if ((found[index] ?? 0) < (wanted[index] ?? 0)) {
      return { supported: false, detail: `${label} ${found.join(".")} is older than ${minVersion}, which added the hook dg needs` };
    }
  }
  return { supported: true, detail: `${label} ${found.join(".")}` };
}
