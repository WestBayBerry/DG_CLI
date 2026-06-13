import { renameSync } from "node:fs";
import { rename } from "node:fs/promises";
import type { DgPaths } from "./paths.js";
import { JsonStoreError, readJsonFile, writeJsonFileAtomic } from "./store.js";
import { acquireLock, CLEANUP_REGISTRY_LOCK } from "./locks.js";

export type CleanupEntryKind =
  | "shim"
  | "rc"
  | "python-hook"
  | "git-hook"
  | "agent-hook"
  | "service"
  | "trust-store"
  | "state"
  | "cache"
  | "policy";

export type CleanupEntryMode = "mode1" | "mode2";

export interface CleanupRegistry {
  readonly version: 1;
  readonly entries: readonly CleanupRegistryEntry[];
}

export interface CleanupRegistryEntry {
  readonly kind: CleanupEntryKind;
  readonly path: string;
  readonly installedAt: string;
  readonly owner: "dg";
  readonly mode: CleanupEntryMode;
  readonly sentinel?: string;
  readonly original?: string;
}

export interface CleanupRegistryLoad {
  readonly registry: CleanupRegistry;
  readonly corruptPreservedPath?: string;
}

export function emptyCleanupRegistry(): CleanupRegistry {
  return {
    version: 1,
    entries: []
  };
}

export async function loadCleanupRegistry(
  paths: DgPaths,
  options: { readonly stderr?: { write(text: string): unknown } } = {}
): Promise<CleanupRegistryLoad> {
  let parsed: unknown;
  try {
    parsed = await readJsonFile<unknown>(paths.cleanupRegistryPath, emptyCleanupRegistry());
  } catch (error) {
    if (!(error instanceof JsonStoreError)) {
      throw error;
    }
    parsed = undefined;
  }
  if (isCleanupRegistry(parsed)) {
    return {
      registry: parsed
    };
  }
  const preserved = await preserveCorruptRegistry(paths, options);
  return {
    registry: emptyCleanupRegistry(),
    ...(preserved ? { corruptPreservedPath: preserved } : {})
  };
}

export async function readCleanupRegistry(paths: DgPaths): Promise<CleanupRegistry> {
  return (await loadCleanupRegistry(paths)).registry;
}

export async function writeCleanupRegistry(paths: DgPaths, registry: CleanupRegistry): Promise<void> {
  await writeJsonFileAtomic(paths.cleanupRegistryPath, registry);
}

export async function recordCleanupEntry(
  paths: DgPaths,
  entry: Omit<CleanupRegistryEntry, "installedAt" | "owner"> & { readonly installedAt?: string }
): Promise<CleanupRegistry> {
  const lock = await acquireLock(paths, CLEANUP_REGISTRY_LOCK);
  try {
    const { registry } = await loadCleanupRegistry(paths);
    const nextEntry: CleanupRegistryEntry = {
      ...entry,
      installedAt: entry.installedAt ?? new Date().toISOString(),
      owner: "dg"
    };
    const entries = registry.entries.filter((candidate) => !sameRegistryTarget(candidate, nextEntry));
    const next = {
      version: 1 as const,
      entries: [...entries, nextEntry]
    };
    await writeCleanupRegistry(paths, next);
    return next;
  } finally {
    await lock.release();
  }
}

export async function removeCleanupEntry(
  paths: DgPaths,
  target: Pick<CleanupRegistryEntry, "kind" | "path"> & { readonly sentinel?: string }
): Promise<CleanupRegistry> {
  const lock = await acquireLock(paths, CLEANUP_REGISTRY_LOCK);
  try {
    const { registry } = await loadCleanupRegistry(paths);
    const next = {
      version: 1 as const,
      entries: registry.entries.filter((candidate) => !sameRegistryTarget(candidate, target))
    };
    await writeCleanupRegistry(paths, next);
    return next;
  } finally {
    await lock.release();
  }
}

export function ownedCleanupEntries(registry: CleanupRegistry): readonly CleanupRegistryEntry[] {
  return registry.entries.filter((entry) => entry.owner === "dg");
}

async function preserveCorruptRegistry(
  paths: DgPaths,
  options: { readonly stderr?: { write(text: string): unknown } }
): Promise<string | undefined> {
  const preservedPath = `${paths.cleanupRegistryPath}.corrupt-${new Date().toISOString().replace(/[:.]/g, "-")}`;
  try {
    await rename(paths.cleanupRegistryPath, preservedPath);
  } catch (error) {
    if (isEnoent(error)) {
      return undefined;
    }
    throw error;
  }
  const stderr = options.stderr ?? process.stderr;
  stderr.write(
    `dg: cleanup registry at ${paths.cleanupRegistryPath} was unreadable; preserved it at ${preservedPath}. Previously registered entries may need 'dg doctor'.\n`
  );
  return preservedPath;
}

export function preserveCorruptCleanupRegistrySync(
  paths: DgPaths,
  options: { readonly stderr?: { write(text: string): unknown } } = {}
): string | undefined {
  const preservedPath = `${paths.cleanupRegistryPath}.corrupt-${new Date().toISOString().replace(/[:.]/g, "-")}`;
  try {
    renameSync(paths.cleanupRegistryPath, preservedPath);
  } catch {
    return undefined;
  }
  const stderr = options.stderr ?? process.stderr;
  stderr.write(
    `dg: cleanup registry at ${paths.cleanupRegistryPath} was unreadable; preserved it at ${preservedPath}. Previously registered entries may need 'dg doctor'.\n`
  );
  return preservedPath;
}

function isCleanupRegistry(value: unknown): value is CleanupRegistry {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    (value as { version?: unknown }).version === 1 &&
    Array.isArray((value as { entries?: unknown }).entries)
  );
}

function isEnoent(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function sameRegistryTarget(
  left: Pick<CleanupRegistryEntry, "kind" | "path"> & { readonly sentinel?: string },
  right: Pick<CleanupRegistryEntry, "kind" | "path"> & { readonly sentinel?: string }
): boolean {
  return left.kind === right.kind && left.path === right.path && left.sentinel === right.sentinel;
}
