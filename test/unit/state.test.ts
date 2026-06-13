import { access, mkdir, readFile, readdir, stat, utimes, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { mkdtemp } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import {
  CLEANUP_REGISTRY_LOCK,
  LockBusyError,
  acquireLock,
  acquireLockSync,
  acquireLockSyncWithRetry,
  appendSessionLog,
  cleanupSession,
  createSession,
  emptyCleanupRegistry,
  loadCleanupRegistry,
  ownedCleanupEntries,
  pruneDeadSessionsSync,
  readCleanupRegistry,
  readJsonFile,
  readLockMetadata,
  readSessionJson,
  recordCleanupEntry,
  removeCleanupEntry,
  resolveDgPaths,
  sweepStaleSessions,
  writeJsonFileAtomic,
  writeSessionJson
} from "../../src/state/index.js";

describe("state paths", () => {
  it("resolves XDG paths when absolute directories are provided", async () => {
    const root = await tempRoot();
    const paths = resolveDgPaths({
      HOME: join(root, "home"),
      XDG_CONFIG_HOME: join(root, "config"),
      XDG_STATE_HOME: join(root, "state"),
      XDG_CACHE_HOME: join(root, "cache")
    });

    expect(paths).toEqual({
      homeDir: join(root, "home"),
      configDir: join(root, "config", "dg"),
      stateDir: join(root, "state", "dg"),
      cacheDir: join(root, "cache", "dg"),
      sessionsDir: join(root, "state", "dg", "sessions"),
      cleanupRegistryPath: join(root, "state", "dg", "cleanup-registry.json"),
      locksDir: join(root, "state", "dg", "locks")
    });
  });

  it("falls back to ~/.dg when XDG directories are unset or relative", async () => {
    const root = await tempRoot();
    const home = join(root, "home");
    const paths = resolveDgPaths({
      HOME: home,
      XDG_CONFIG_HOME: "relative-config",
      XDG_STATE_HOME: "relative-state",
      XDG_CACHE_HOME: "relative-cache"
    });

    expect(paths.configDir).toBe(join(home, ".dg"));
    expect(paths.stateDir).toBe(join(home, ".dg", "state"));
    expect(paths.cacheDir).toBe(join(home, ".dg", "cache"));
  });
});

describe("atomic JSON store", () => {
  it("writes JSON atomically and reads a fallback for missing files", async () => {
    const root = await tempRoot();
    const path = join(root, "state", "value.json");

    await expect(readJsonFile(path, { missing: true })).resolves.toEqual({ missing: true });
    await writeJsonFileAtomic(path, {
      version: 1,
      enabled: true
    });

    await expect(readJsonFile(path, {})).resolves.toEqual({
      version: 1,
      enabled: true
    });
    await expect(readFile(path, "utf8")).resolves.toBe("{\n  \"version\": 1,\n  \"enabled\": true\n}\n");
    expect((await stat(dirname(path))).mode & 0o777).toBe(0o700);
  });

  it("fails malformed JSON explicitly", async () => {
    const root = await tempRoot();
    const path = join(root, "bad.json");
    await writeFile(path, "{bad json", "utf8");

    await expect(readJsonFile(path, {})).rejects.toThrow("Malformed JSON store");
  });
});

describe("session state", () => {
  it("creates isolated per-session files and cleans only that session", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const first = await createSession(paths, "session-a");
    const second = await createSession(paths, "session-b");

    await writeSessionJson(first, "proxy", {
      port: 43111
    });
    await writeSessionJson(second, "proxy", {
      port: 43112
    });
    await appendSessionLog(first, {
      event: "started"
    });

    await expect(readSessionJson(first, "proxy", {})).resolves.toEqual({
      port: 43111
    });
    await expect(readSessionJson(second, "proxy", {})).resolves.toEqual({
      port: 43112
    });
    await expect(readFile(first.files.log, "utf8")).resolves.toBe("{\"event\":\"started\"}\n");

    await cleanupSession(first);
    await expect(access(first.dir)).rejects.toThrow();
    await expect(access(second.dir)).resolves.toBeUndefined();
  });

  it("sweeps stale session directories without deleting active or invalid entries", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const stale = await createSession(paths, "stale-session");
    const active = await createSession(paths, "active-session");
    const invalid = join(paths.sessionsDir, "..not-a-session");
    const oldDate = new Date("2026-01-01T00:00:00.000Z");
    const now = new Date("2026-06-01T00:00:00.000Z");
    await mkdir(invalid);
    await utimes(stale.dir, oldDate, oldDate);
    await utimes(active.dir, now, now);

    const result = await sweepStaleSessions(paths, {
      olderThanMs: 24 * 60 * 60 * 1000,
      now
    });

    expect(result.removed).toEqual(["stale-session"]);
    await expect(access(stale.dir)).rejects.toThrow();
    await expect(access(active.dir)).resolves.toBeUndefined();
    await expect(access(invalid)).resolves.toBeUndefined();
  });

  it("creates session directories with owner-only permissions", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const session = await createSession(paths, "perm-session");

    await expect(stat(paths.sessionsDir).then((details) => details.mode & 0o777)).resolves.toBe(0o700);
    await expect(stat(session.dir).then((details) => details.mode & 0o777)).resolves.toBe(0o700);
  });

  it("tolerates session directories that vanish during concurrent stale sweeps", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const oldDate = new Date("2026-01-01T00:00:00.000Z");
    const now = new Date("2026-06-01T00:00:00.000Z");
    for (const id of ["stale-a", "stale-b", "stale-c", "stale-d"]) {
      const session = await createSession(paths, id);
      await utimes(session.dir, oldDate, oldDate);
    }

    const options = {
      olderThanMs: 24 * 60 * 60 * 1000,
      now
    };
    const [first, second] = await Promise.all([sweepStaleSessions(paths, options), sweepStaleSessions(paths, options)]);

    const removed = [...new Set([...first.removed, ...second.removed])].sort();
    expect(removed).toEqual(["stale-a", "stale-b", "stale-c", "stale-d"]);
    for (const id of removed) {
      await expect(access(join(paths.sessionsDir, id))).rejects.toThrow();
    }
  });

  it("prunes old session dirs whose worker pid is dead or missing, keeping live and fresh ones", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const oldDate = new Date("2026-01-01T00:00:00.000Z");
    const now = new Date("2026-06-01T00:00:00.000Z");

    const deadOld = await createSession(paths, "dead-old");
    await writeFile(deadOld.files.pid, `${exitedPid()}\n`, "utf8");
    await utimes(deadOld.dir, oldDate, oldDate);

    const liveOld = await createSession(paths, "live-old");
    await writeFile(liveOld.files.pid, `${process.pid}\n`, "utf8");
    await utimes(liveOld.dir, oldDate, oldDate);

    const orphanOld = await createSession(paths, "orphan-old");
    await utimes(orphanOld.dir, oldDate, oldDate);

    const fresh = await createSession(paths, "fresh");
    await utimes(fresh.dir, now, now);

    const result = pruneDeadSessionsSync(paths, {
      now
    });

    expect([...result.removed].sort()).toEqual(["dead-old", "orphan-old"]);
    await expect(access(deadOld.dir)).rejects.toThrow();
    await expect(access(orphanOld.dir)).rejects.toThrow();
    await expect(access(liveOld.dir)).resolves.toBeUndefined();
    await expect(access(fresh.dir)).resolves.toBeUndefined();
  });

  it("bounds the number of removals per prune pass", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const oldDate = new Date("2026-01-01T00:00:00.000Z");
    const now = new Date("2026-06-01T00:00:00.000Z");
    for (const id of ["prune-a", "prune-b", "prune-c"]) {
      const session = await createSession(paths, id);
      await utimes(session.dir, oldDate, oldDate);
    }

    const result = pruneDeadSessionsSync(paths, {
      now,
      maxRemovals: 2
    });

    expect(result.removed).toHaveLength(2);
  });

  it("returns no removals when the sessions dir does not exist", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });

    expect(pruneDeadSessionsSync(paths)).toEqual({
      removed: []
    });
  });
});

describe("cleanup registry", () => {
  it("records dg-owned persistent writes and deduplicates by target", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });

    await expect(readCleanupRegistry(paths)).resolves.toEqual(emptyCleanupRegistry());
    const first = await recordCleanupEntry(paths, {
      kind: "shim",
      path: "/tmp/dg/npm",
      mode: "mode1",
      sentinel: "dg-shim",
      installedAt: "2026-06-01T00:00:00.000Z"
    });
    const second = await recordCleanupEntry(paths, {
      kind: "shim",
      path: "/tmp/dg/npm",
      mode: "mode1",
      sentinel: "dg-shim",
      installedAt: "2026-06-01T00:01:00.000Z"
    });

    expect(first.entries).toHaveLength(1);
    expect(second.entries).toEqual([
      {
        kind: "shim",
        path: "/tmp/dg/npm",
        mode: "mode1",
        sentinel: "dg-shim",
        installedAt: "2026-06-01T00:01:00.000Z",
        owner: "dg"
      }
    ]);
    expect(ownedCleanupEntries(second)).toHaveLength(1);
  });

  it("serializes registry writes under the shared cleanup-registry lock", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    expect(CLEANUP_REGISTRY_LOCK).toBe("cleanup-registry");
    const held = await acquireLock(paths, CLEANUP_REGISTRY_LOCK);

    await expect(
      recordCleanupEntry(paths, {
        kind: "service",
        path: "/tmp/dg/service.json",
        mode: "mode2"
      })
    ).rejects.toBeInstanceOf(LockBusyError);

    await held.release();
    await expect(
      recordCleanupEntry(paths, {
        kind: "service",
        path: "/tmp/dg/service.json",
        mode: "mode2"
      })
    ).resolves.toMatchObject({ entries: [expect.objectContaining({ kind: "service" })] });
  });

  it("removes registry entries without deleting the recorded path", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const ownedPath = join(paths.homeDir, ".dg", "shims", "npm");
    await mkdir(join(paths.homeDir, ".dg", "shims"), {
      recursive: true
    });
    await writeFile(ownedPath, "shim", "utf8");
    await recordCleanupEntry(paths, {
      kind: "shim",
      path: ownedPath,
      mode: "mode1"
    });

    const registry = await removeCleanupEntry(paths, {
      kind: "shim",
      path: ownedPath
    });

    expect(registry.entries).toEqual([]);
    await expect(access(ownedPath)).resolves.toBeUndefined();
  });

  it("preserves a corrupt registry file instead of treating it as empty", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const corruptContent = '{"version":1,"entries":[{"kind":"shim","pat';
    await mkdir(dirname(paths.cleanupRegistryPath), {
      recursive: true
    });
    await writeFile(paths.cleanupRegistryPath, corruptContent, "utf8");
    const warnings: string[] = [];

    const load = await loadCleanupRegistry(paths, {
      stderr: {
        write: (text: string) => warnings.push(text)
      }
    });

    expect(load.registry).toEqual(emptyCleanupRegistry());
    expect(load.corruptPreservedPath).toMatch(/cleanup-registry\.json\.corrupt-/);
    await expect(readFile(String(load.corruptPreservedPath), "utf8")).resolves.toBe(corruptContent);
    await expect(access(paths.cleanupRegistryPath)).rejects.toThrow();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(String(load.corruptPreservedPath));
    expect(warnings[0]).toContain("dg doctor");
  });

  it("treats a wrong-shape registry as corrupt and preserves it", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    await mkdir(dirname(paths.cleanupRegistryPath), {
      recursive: true
    });
    await writeFile(paths.cleanupRegistryPath, "[]\n", "utf8");
    const warnings: string[] = [];

    const load = await loadCleanupRegistry(paths, {
      stderr: {
        write: (text: string) => warnings.push(text)
      }
    });

    expect(load.registry).toEqual(emptyCleanupRegistry());
    await expect(readFile(String(load.corruptPreservedPath), "utf8")).resolves.toBe("[]\n");
  });

  it("merge-appends new entries to a fresh registry after preserving a corrupt one", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const corruptContent = "{truncated";
    await mkdir(dirname(paths.cleanupRegistryPath), {
      recursive: true
    });
    await writeFile(paths.cleanupRegistryPath, corruptContent, "utf8");
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    try {
      const registry = await recordCleanupEntry(paths, {
        kind: "git-hook",
        path: "/tmp/dg/pre-commit",
        mode: "mode1",
        installedAt: "2026-06-01T00:00:00.000Z"
      });

      expect(registry.entries).toEqual([
        {
          kind: "git-hook",
          path: "/tmp/dg/pre-commit",
          mode: "mode1",
          installedAt: "2026-06-01T00:00:00.000Z",
          owner: "dg"
        }
      ]);
      await expect(readCleanupRegistry(paths)).resolves.toEqual(registry);
      const preserved = (await readdir(dirname(paths.cleanupRegistryPath))).filter((entry) =>
        entry.startsWith("cleanup-registry.json.corrupt-")
      );
      expect(preserved).toHaveLength(1);
      await expect(readFile(join(dirname(paths.cleanupRegistryPath), String(preserved[0])), "utf8")).resolves.toBe(corruptContent);
    } finally {
      stderrSpy.mockRestore();
    }
  });
});

describe("state locks", () => {
  it("prevents concurrent lock acquisition and releases the lockfile", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const lock = await acquireLock(paths, "setup", {
      now: new Date("2026-06-01T00:00:00.000Z")
    });

    await expect(acquireLock(paths, "setup")).rejects.toBeInstanceOf(LockBusyError);
    await expect(readLockMetadata(lock.path)).resolves.toEqual({
      pid: process.pid,
      acquiredAt: "2026-06-01T00:00:00.000Z"
    });

    await lock.release();
    await expect(access(lock.path)).rejects.toThrow();
    await expect(acquireLock(paths, "setup")).resolves.toMatchObject({
      name: "setup"
    });
  });

  it("creates the locks directory with owner-only permissions in both lock paths", async () => {
    const asyncPaths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const syncPaths = resolveDgPaths({
      HOME: await tempRoot()
    });

    const asyncLock = await acquireLock(asyncPaths, "setup");
    const syncLock = acquireLockSync(syncPaths, "setup");

    expect((await stat(asyncPaths.locksDir)).mode & 0o777).toBe(0o700);
    expect((await stat(syncPaths.locksDir)).mode & 0o777).toBe(0o700);
    await asyncLock.release();
    syncLock.release();
  });

  it("reaps a lock immediately when the recorded holder pid is dead, even without a stale window", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const wedged = await acquireLock(paths, "cleanup-registry");
    await writeFile(wedged.path, `${JSON.stringify({ pid: exitedPid(), acquiredAt: "2026-01-01T00:00:00.000Z" })}\n`, "utf8");

    const recovered = await acquireLock(paths, "cleanup-registry");

    expect(recovered.path).toBe(wedged.path);
    await recovered.release();
  });

  it("reaps a dead-pid lock synchronously as well", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const wedged = acquireLockSync(paths, "cleanup-registry");
    await writeFile(wedged.path, `${JSON.stringify({ pid: exitedPid(), acquiredAt: "2026-01-01T00:00:00.000Z" })}\n`, "utf8");

    const recovered = acquireLockSync(paths, "cleanup-registry");

    expect(recovered.path).toBe(wedged.path);
    recovered.release();
  });

  it("never steals a lock whose recorded holder is alive, even past the stale window", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const held = await acquireLock(paths, "cleanup-registry", {
      now: new Date("2026-01-01T00:00:00.000Z")
    });
    const oldDate = new Date("2026-01-01T00:00:00.000Z");
    await utimes(held.path, oldDate, oldDate);

    const staleOptions = {
      staleMs: 24 * 60 * 60 * 1000,
      now: new Date("2026-06-01T00:00:00.000Z")
    };

    await expect(acquireLock(paths, "cleanup-registry", staleOptions)).rejects.toBeInstanceOf(LockBusyError);
    expect(() => acquireLockSync(paths, "cleanup-registry", staleOptions)).toThrow(LockBusyError);

    await held.release();
  });

  it("falls back to mtime staleness only when the lock metadata has no usable pid", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    await mkdir(paths.locksDir, {
      recursive: true
    });
    const path = join(paths.locksDir, "cleanup-registry.lock");
    await writeFile(path, "not lock metadata\n", "utf8");
    const oldDate = new Date("2026-01-01T00:00:00.000Z");
    await utimes(path, oldDate, oldDate);

    await expect(acquireLock(paths, "cleanup-registry")).rejects.toBeInstanceOf(LockBusyError);

    const recovered = await acquireLock(paths, "cleanup-registry", {
      staleMs: 24 * 60 * 60 * 1000,
      now: new Date("2026-06-01T00:00:00.000Z")
    });

    expect(recovered.path).toBe(path);
    await recovered.release();
  });

  it("does not treat a takeover-acquired fresh lock as stale for a racing acquirer", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const wedged = await acquireLock(paths, "cleanup-registry");
    await writeFile(wedged.path, `${JSON.stringify({ pid: exitedPid(), acquiredAt: "2026-01-01T00:00:00.000Z" })}\n`, "utf8");

    const recovered = await acquireLock(paths, "cleanup-registry");
    expect(recovered.path).toBe(wedged.path);

    await expect(acquireLock(paths, "cleanup-registry")).rejects.toBeInstanceOf(LockBusyError);
    expect((await readdir(paths.locksDir)).filter((entry) => entry.includes(".stale-"))).toEqual([]);

    await recovered.release();
  });

  it("applies the same dead-pid takeover for the synchronous acquirer racing an async one", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const wedged = acquireLockSync(paths, "cleanup-registry");
    await writeFile(wedged.path, `${JSON.stringify({ pid: exitedPid(), acquiredAt: "2026-01-01T00:00:00.000Z" })}\n`, "utf8");

    const recovered = acquireLockSync(paths, "cleanup-registry");
    expect(recovered.path).toBe(wedged.path);

    expect(() => acquireLockSync(paths, "cleanup-registry")).toThrow(LockBusyError);
    expect((await readdir(paths.locksDir)).filter((entry) => entry.includes(".stale-"))).toEqual([]);

    recovered.release();
  });

  it("retries a busy lock until timeout and acquires once it frees", async () => {
    const paths = resolveDgPaths({
      HOME: await tempRoot()
    });
    const held = await acquireLock(paths, "user-config");

    expect(() => acquireLockSyncWithRetry(paths, "user-config", { timeoutMs: 150 })).toThrow(LockBusyError);

    await held.release();
    const acquired = acquireLockSyncWithRetry(paths, "user-config", { timeoutMs: 150 });
    expect(acquired.name).toBe("user-config");
    acquired.release();
  });
});

function exitedPid(): number {
  const probe = spawnSync(process.execPath, ["-e", ""]);
  if (typeof probe.pid !== "number") {
    throw new Error("failed to spawn pid probe");
  }
  return probe.pid;
}

async function tempRoot(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "dg-state-test-"));
  return path;
}
