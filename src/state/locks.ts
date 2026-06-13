import { closeSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { mkdir, open, readFile, rename, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import type { FileHandle } from "node:fs/promises";
import type { DgPaths } from "./paths.js";

export const CLEANUP_REGISTRY_LOCK = "cleanup-registry";

let takeoverCounter = 0;

function isErrno(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === code;
}

export class LockBusyError extends Error {
  constructor(readonly path: string) {
    super(`dg lock is already held: ${path}`);
    this.name = "LockBusyError";
  }
}

export interface LockHandle {
  readonly name: string;
  readonly path: string;
  release(): Promise<void>;
}

export interface SyncLockHandle {
  readonly name: string;
  readonly path: string;
  release(): void;
}

export interface LockMetadata {
  readonly pid: number;
  readonly acquiredAt: string;
}

export async function acquireLock(
  paths: DgPaths,
  name: string,
  options: { readonly staleMs?: number; readonly now?: Date } = {}
): Promise<LockHandle> {
  assertLockName(name);
  await mkdir(paths.locksDir, {
    recursive: true,
    mode: 0o700
  });

  const path = join(paths.locksDir, `${name}.lock`);
  await removeStaleLock(path, options);

  let handle: FileHandle;
  try {
    handle = await open(path, "wx", 0o600);
  } catch (error) {
    if (isErrno(error, "EEXIST")) {
      throw new LockBusyError(path);
    }
    throw error;
  }

  const metadata: LockMetadata = {
    pid: process.pid,
    acquiredAt: (options.now ?? new Date()).toISOString()
  };

  try {
    await handle.writeFile(`${JSON.stringify(metadata)}\n`, "utf8");
  } finally {
    await handle.close();
  }

  return {
    name,
    path,
    release: async () => {
      await rm(path, {
        force: true
      });
    }
  };
}

export function acquireLockSync(
  paths: DgPaths,
  name: string,
  options: { readonly staleMs?: number; readonly now?: Date } = {}
): SyncLockHandle {
  assertLockName(name);
  mkdirSync(paths.locksDir, {
    recursive: true,
    mode: 0o700
  });

  const path = join(paths.locksDir, `${name}.lock`);
  removeStaleLockSync(path, options);

  let fd: number;
  try {
    fd = openSync(path, "wx", 0o600);
  } catch (error) {
    if (isErrno(error, "EEXIST")) {
      throw new LockBusyError(path);
    }
    throw error;
  }

  const metadata: LockMetadata = {
    pid: process.pid,
    acquiredAt: (options.now ?? new Date()).toISOString()
  };

  try {
    writeFileSync(fd, `${JSON.stringify(metadata)}\n`, "utf8");
  } finally {
    closeSync(fd);
  }

  return {
    name,
    path,
    release: () => {
      rmSync(path, {
        force: true
      });
    }
  };
}

export async function readLockMetadata(path: string): Promise<LockMetadata> {
  return JSON.parse(await readFile(path, "utf8")) as LockMetadata;
}

const LOCK_RETRY_DELAY_MS = 25;

export function acquireLockSyncWithRetry(
  paths: DgPaths,
  name: string,
  options: { readonly staleMs?: number; readonly timeoutMs?: number; readonly now?: Date } = {}
): SyncLockHandle {
  const deadline = Date.now() + (options.timeoutMs ?? 5_000);
  const acquireOptions = {
    ...(options.staleMs !== undefined ? { staleMs: options.staleMs } : {}),
    ...(options.now !== undefined ? { now: options.now } : {})
  };
  for (;;) {
    try {
      return acquireLockSync(paths, name, acquireOptions);
    } catch (error) {
      if (!(error instanceof LockBusyError) || Date.now() + LOCK_RETRY_DELAY_MS > deadline) {
        throw error;
      }
      sleepSync(LOCK_RETRY_DELAY_MS);
    }
  }
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !isErrno(error, "ESRCH");
  }
}

type LockHolderState = "absent" | "alive" | "dead" | "unknown";

function holderStateFromContent(content: string): LockHolderState {
  let pid: unknown;
  try {
    pid = (JSON.parse(content) as Partial<LockMetadata>).pid;
  } catch {
    return "unknown";
  }
  if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) {
    return "unknown";
  }
  return isProcessAlive(pid) ? "alive" : "dead";
}

async function removeStaleLock(
  path: string,
  options: { readonly staleMs?: number; readonly now?: Date }
): Promise<void> {
  let content: string | null;
  try {
    content = await readFile(path, "utf8");
  } catch (error) {
    if (isErrno(error, "ENOENT")) {
      return;
    }
    content = null;
  }
  const holder = content === null ? "unknown" : holderStateFromContent(content);
  if (holder === "alive") {
    return;
  }
  if (holder === "dead") {
    await takeoverLock(path);
    return;
  }
  if (!options.staleMs) {
    return;
  }
  const details = await stat(path).catch((error: unknown) => {
    if (isErrno(error, "ENOENT")) {
      return null;
    }
    throw error;
  });
  if (!details) {
    return;
  }

  const now = options.now?.getTime() ?? Date.now();
  if (now - details.mtimeMs < options.staleMs) {
    return;
  }
  await takeoverLock(path);
}

function removeStaleLockSync(
  path: string,
  options: { readonly staleMs?: number; readonly now?: Date }
): void {
  let content: string | null;
  try {
    content = readFileSync(path, "utf8");
  } catch (error) {
    if (isErrno(error, "ENOENT")) {
      return;
    }
    content = null;
  }
  const holder = content === null ? "unknown" : holderStateFromContent(content);
  if (holder === "alive") {
    return;
  }
  if (holder === "dead") {
    takeoverLockSync(path);
    return;
  }
  if (!options.staleMs) {
    return;
  }
  let details;
  try {
    details = statSync(path);
  } catch (error) {
    if (isErrno(error, "ENOENT")) {
      return;
    }
    throw error;
  }

  const now = options.now?.getTime() ?? Date.now();
  if (now - details.mtimeMs < options.staleMs) {
    return;
  }
  takeoverLockSync(path);
}

async function takeoverLock(path: string): Promise<void> {
  const takeoverPath = `${path}.stale-${process.pid}-${++takeoverCounter}`;
  try {
    await rename(path, takeoverPath);
  } catch (error) {
    if (isErrno(error, "ENOENT")) {
      return;
    }
    throw error;
  }
  await rm(takeoverPath, {
    force: true
  });
}

function takeoverLockSync(path: string): void {
  const takeoverPath = `${path}.stale-${process.pid}-${++takeoverCounter}`;
  try {
    renameSync(path, takeoverPath);
  } catch (error) {
    if (isErrno(error, "ENOENT")) {
      return;
    }
    throw error;
  }
  rmSync(takeoverPath, {
    force: true
  });
}

function assertLockName(name: string): void {
  if (!/^[a-z][a-z0-9-]{0,63}$/.test(name)) {
    throw new Error(`Invalid dg lock name: ${name}`);
  }
}
