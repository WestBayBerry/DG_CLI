import { mkdirSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { appendFile, mkdir, readdir, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { isProcessAlive } from "./locks.js";
import type { DgPaths } from "./paths.js";
import { readJsonFile, writeJsonFileAtomic } from "./store.js";

export interface SessionHandle {
  readonly id: string;
  readonly dir: string;
  readonly files: SessionFiles;
}

export interface SessionFiles {
  readonly proxy: string;
  readonly ca: string;
  readonly block: string;
  readonly hash: string;
  readonly log: string;
  readonly pid: string;
}

export interface StaleSessionSweepResult {
  readonly removed: readonly string[];
}

export interface StaleSessionReport {
  readonly stale: readonly string[];
}

export async function createSession(paths: DgPaths, id = randomUUID()): Promise<SessionHandle> {
  assertSessionId(id);
  const dir = join(paths.sessionsDir, id);
  await mkdir(paths.sessionsDir, {
    recursive: true,
    mode: 0o700
  });
  await mkdir(dir, {
    recursive: false,
    mode: 0o700
  });

  return {
    id,
    dir,
    files: sessionFiles(dir)
  };
}

export function createSessionSync(paths: DgPaths, id = randomUUID()): SessionHandle {
  assertSessionId(id);
  const dir = join(paths.sessionsDir, id);
  mkdirSync(paths.sessionsDir, {
    recursive: true,
    mode: 0o700
  });
  mkdirSync(dir, {
    recursive: false,
    mode: 0o700
  });

  return {
    id,
    dir,
    files: sessionFiles(dir)
  };
}

export async function writeSessionJson(session: SessionHandle, name: "proxy" | "block" | "hash", value: unknown): Promise<void> {
  await writeJsonFileAtomic(session.files[name], value);
}

export async function readSessionJson<T>(session: SessionHandle, name: "proxy" | "block" | "hash", fallback: T): Promise<T> {
  return readJsonFile<T>(session.files[name], fallback);
}

export async function appendSessionLog(session: SessionHandle, value: unknown): Promise<void> {
  await appendFile(session.files.log, `${JSON.stringify(value)}\n`, {
    encoding: "utf8",
    mode: 0o600
  });
}

export async function cleanupSession(session: SessionHandle): Promise<void> {
  await rm(session.dir, {
    force: true,
    recursive: true
  });
}

export function cleanupSessionSync(session: SessionHandle): void {
  rmSync(session.dir, {
    force: true,
    recursive: true
  });
}

export async function sweepStaleSessions(
  paths: DgPaths,
  options: { readonly olderThanMs: number; readonly now?: Date }
): Promise<StaleSessionSweepResult> {
  const now = options.now?.getTime() ?? Date.now();
  const entries = await readdir(paths.sessionsDir, {
    withFileTypes: true
  }).catch((error: unknown) => {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") {
      return [];
    }
    throw error;
  });
  const removed: string[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory() || !isValidSessionId(entry.name)) {
      continue;
    }
    const dir = join(paths.sessionsDir, entry.name);
    const details = await stat(dir).catch((error: unknown) => {
      if (isEnoent(error)) {
        return null;
      }
      throw error;
    });
    if (!details || now - details.mtimeMs < options.olderThanMs) {
      continue;
    }
    await rm(dir, {
      force: true,
      recursive: true
    });
    removed.push(entry.name);
  }

  return {
    removed
  };
}

export function findStaleSessionsSync(
  paths: DgPaths,
  options: { readonly olderThanMs: number; readonly now?: Date }
): StaleSessionReport {
  const now = options.now?.getTime() ?? Date.now();
  let entries;
  try {
    entries = readdirSync(paths.sessionsDir, {
      withFileTypes: true
    });
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") {
      return {
        stale: []
      };
    }
    throw error;
  }

  const stale: string[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || !isValidSessionId(entry.name)) {
      continue;
    }
    const dir = join(paths.sessionsDir, entry.name);
    let details;
    try {
      details = statSync(dir);
    } catch (error) {
      if (isEnoent(error)) {
        continue;
      }
      throw error;
    }
    if (now - details.mtimeMs >= options.olderThanMs) {
      stale.push(entry.name);
    }
  }

  return {
    stale
  };
}

export const DEAD_SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const DEAD_SESSION_PRUNE_MAX = 16;

export function pruneDeadSessionsSync(
  paths: DgPaths,
  options: { readonly olderThanMs?: number; readonly now?: Date; readonly maxRemovals?: number } = {}
): StaleSessionSweepResult {
  const olderThanMs = options.olderThanMs ?? DEAD_SESSION_TTL_MS;
  const maxRemovals = options.maxRemovals ?? DEAD_SESSION_PRUNE_MAX;
  const now = options.now?.getTime() ?? Date.now();
  let entries;
  try {
    entries = readdirSync(paths.sessionsDir, {
      withFileTypes: true
    });
  } catch {
    return {
      removed: []
    };
  }

  const removed: string[] = [];
  for (const entry of entries) {
    if (removed.length >= maxRemovals) {
      break;
    }
    if (!entry.isDirectory() || !isValidSessionId(entry.name)) {
      continue;
    }
    const dir = join(paths.sessionsDir, entry.name);
    let details;
    try {
      details = statSync(dir);
    } catch {
      continue;
    }
    if (now - details.mtimeMs < olderThanMs || sessionWorkerAlive(dir)) {
      continue;
    }
    try {
      rmSync(dir, {
        force: true,
        recursive: true
      });
      removed.push(entry.name);
    } catch {
      continue;
    }
  }

  return {
    removed
  };
}

function sessionWorkerAlive(dir: string): boolean {
  let raw: string;
  try {
    raw = readFileSync(join(dir, "pid"), "utf8");
  } catch {
    return false;
  }
  const pid = Number.parseInt(raw.trim(), 10);
  return Number.isInteger(pid) && pid > 0 && isProcessAlive(pid);
}

export function sweepStaleSessionsSync(
  paths: DgPaths,
  options: { readonly olderThanMs: number; readonly now?: Date }
): StaleSessionSweepResult {
  const report = findStaleSessionsSync(paths, options);
  for (const id of report.stale) {
    rmSync(join(paths.sessionsDir, id), {
      force: true,
      recursive: true
    });
  }
  return {
    removed: report.stale
  };
}

function sessionFiles(dir: string): SessionFiles {
  return {
    proxy: join(dir, "proxy.json"),
    ca: join(dir, "ca.pem"),
    block: join(dir, "block.json"),
    hash: join(dir, "hash.json"),
    log: join(dir, "log.jsonl"),
    pid: join(dir, "pid")
  };
}

function assertSessionId(id: string): void {
  if (!isValidSessionId(id)) {
    throw new Error(`Invalid dg session id: ${id}`);
  }
}

function isValidSessionId(id: string): boolean {
  return /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(id);
}

function isEnoent(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
