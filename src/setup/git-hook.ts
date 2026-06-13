import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { randomBytes } from "node:crypto";
import { acquireLockSync, CLEANUP_REGISTRY_LOCK, resolveDgPaths, type CleanupRegistryEntry, type DgPaths } from "../state/index.js";
import { resolveToolPath } from "../util/external-tool.js";
import { gitTrimmed } from "../util/git.js";
import {
  GUARD_HOOK_SENTINEL,
  SETUP_UNINSTALL_LOCK,
  SETUP_UNINSTALL_LOCK_STALE_MS,
  chainedHookOriginal,
  guardHookScript,
  mergeRegistry,
  readRegistry,
  reverseGitHookEntry,
  writeRegistry
} from "./plan.js";

export { GUARD_HOOK_SENTINEL } from "./plan.js";
export const GUARD_SELFTEST_ENV = "DG_GUARD_COMMIT_SELFTEST";

export interface GitRepoContext {
  readonly cwd: string;
  readonly root: string;
  readonly hooksDir: string;
  readonly hookTarget: string;
  readonly hooksPathConfigured: boolean;
  readonly dgPath: string;
  readonly paths: DgPaths;
  readonly env: NodeJS.ProcessEnv;
}

export interface ResolveOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly cwd?: string;
  readonly dgPath?: string;
}

export type GitHookState = "fresh" | "managed" | "foreign";

export interface GitHookPlan {
  readonly context: GitRepoContext;
  readonly state: GitHookState;
  readonly willChain: boolean;
}

export interface GuardCheck {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

export interface GitHookApplyResult {
  readonly hookTarget: string;
  readonly chainedOriginal: string | null;
  readonly checks: readonly GuardCheck[];
  readonly active: boolean;
}

export interface GitHookRemoveResult {
  readonly removed: readonly string[];
  readonly missing: readonly string[];
  readonly warnings: readonly string[];
  readonly found: number;
}

export type GuardStatusState = "not-a-repo" | "active" | "off" | "dead";

function dgEntrypoint(): string {
  const argv1 = process.argv[1];
  return argv1 ? resolve(argv1) : "dg";
}

function resolveHooksDir(cwd: string, env: NodeJS.ProcessEnv, root: string): { dir: string; configured: boolean } | null {
  const configured = gitTrimmed(["config", "--get", "core.hooksPath"], { cwd, env });
  if (configured) {
    return { dir: isAbsolute(configured) ? configured : resolve(root, configured), configured: true };
  }
  const gitPath = gitTrimmed(["rev-parse", "--git-path", "hooks"], { cwd, env });
  if (!gitPath) {
    return null;
  }
  return { dir: isAbsolute(gitPath) ? gitPath : resolve(root, gitPath), configured: false };
}

export function resolveGitRepo(options: ResolveOptions = {}): GitRepoContext | { error: string } {
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const inside = gitTrimmed(["rev-parse", "--is-inside-work-tree"], { cwd, env });
  if (inside !== "true") {
    return { error: "not a git repository — run dg guard-commit inside a repo" };
  }
  const root = gitTrimmed(["rev-parse", "--show-toplevel"], { cwd, env });
  if (!root) {
    return { error: "could not resolve the repository root" };
  }
  const hooks = resolveHooksDir(cwd, env, root);
  if (!hooks) {
    return { error: "could not resolve the git hooks directory" };
  }
  return {
    cwd,
    root,
    hooksDir: hooks.dir,
    hookTarget: join(hooks.dir, "pre-commit"),
    hooksPathConfigured: hooks.configured,
    dgPath: options.dgPath ?? dgEntrypoint(),
    paths: resolveDgPaths(env),
    env
  };
}

function hookText(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

function secondLine(path: string): string {
  return hookText(path).split("\n", 2)[1] ?? "";
}

function isManaged(path: string): boolean {
  return existsSync(path) && secondLine(path).includes(GUARD_HOOK_SENTINEL);
}

function isExecutable(path: string): boolean {
  try {
    return (statSync(path).mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

export function gitHookState(context: GitRepoContext): GitHookState {
  if (!existsSync(context.hookTarget)) {
    return "fresh";
  }
  return isManaged(context.hookTarget) ? "managed" : "foreign";
}

export function planGitHook(context: GitRepoContext): GitHookPlan {
  const state = gitHookState(context);
  return { context, state, willChain: state === "foreign" };
}

function registryOriginal(context: GitRepoContext): string | null {
  const entry = readRegistry(context.paths).registry.entries.find(
    (candidate) => candidate.kind === "git-hook" && candidate.owner === "dg" && candidate.path === context.hookTarget
  );
  return entry?.original ?? null;
}

function isSymlinkPath(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

function writeHookAtomic(target: string, content: string): void {
  const tmp = join(dirname(target), `.pre-commit.dg-${randomBytes(6).toString("hex")}.tmp`);
  writeFileSync(tmp, content, { encoding: "utf8", mode: 0o755, flag: "wx" });
  try {
    renameSync(tmp, target);
  } catch (error) {
    rmSync(tmp, { force: true });
    throw error;
  }
}

export function applyGitHook(context: GitRepoContext, now: Date = new Date()): GitHookApplyResult {
  if (gitHookState(context) !== "foreign" && isSymlinkPath(context.hookTarget)) {
    return {
      hookTarget: context.hookTarget,
      chainedOriginal: null,
      checks: [
        {
          name: "hook-writable",
          ok: false,
          detail: `${context.hookTarget} is a symlink; dg refuses to replace it — remove the link or point it at a real file, then re-run dg guard-commit`
        }
      ],
      active: false
    };
  }
  const lock = acquireLockSync(context.paths, SETUP_UNINSTALL_LOCK, { staleMs: SETUP_UNINSTALL_LOCK_STALE_MS });
  let chainedOriginal: string | null = null;
  try {
    mkdirSync(context.hooksDir, { recursive: true });
    const state = gitHookState(context);
    if (state === "foreign") {
      const backup = join(context.hooksDir, `pre-commit.dg-chained-${randomBytes(4).toString("hex")}`);
      renameSync(context.hookTarget, backup);
      chainedOriginal = backup;
    } else if (state === "managed") {
      chainedOriginal = chainedHookOriginal(hookText(context.hookTarget)) ?? registryOriginal(context);
    }
    writeHookAtomic(context.hookTarget, guardHookScript(context.dgPath, chainedOriginal));
    chmodSync(context.hookTarget, 0o755);

    const entry: CleanupRegistryEntry = {
      kind: "git-hook",
      path: context.hookTarget,
      mode: "mode1",
      sentinel: GUARD_HOOK_SENTINEL,
      installedAt: now.toISOString(),
      owner: "dg",
      ...(chainedOriginal ? { original: chainedOriginal } : {})
    };
    const registryLock = acquireLockSync(context.paths, CLEANUP_REGISTRY_LOCK, { staleMs: SETUP_UNINSTALL_LOCK_STALE_MS });
    try {
      const registry = mergeRegistry(readRegistry(context.paths).registry, [entry]);
      writeRegistry(context.paths, registry);
    } finally {
      registryLock.release();
    }
  } finally {
    lock.release();
  }

  const checks = verifyGitHook(context);
  return {
    hookTarget: context.hookTarget,
    chainedOriginal,
    checks,
    active: checks.every((check) => check.ok)
  };
}

export function verifyGitHook(context: GitRepoContext): GuardCheck[] {
  const checks: GuardCheck[] = [];

  const live = resolveHooksDir(context.cwd, context.env, context.root);
  const liveMatches = live !== null && resolve(live.dir) === resolve(context.hooksDir);
  checks.push({
    name: "git-uses-this-dir",
    ok: liveMatches,
    detail: liveMatches
      ? `git runs hooks from ${context.hooksDir}`
      : `git runs hooks from ${live?.dir ?? "an unresolved dir"}, not ${context.hooksDir}`
  });

  const present = existsSync(context.hookTarget);
  checks.push({
    name: "hook-present",
    ok: present,
    detail: present ? `hook written at ${context.hookTarget}` : `no hook at ${context.hookTarget}`
  });

  const sentinel = isManaged(context.hookTarget);
  checks.push({
    name: "dg-owned",
    ok: sentinel,
    detail: sentinel ? "dg sentinel present" : "hook is not dg-owned"
  });

  const exec = isExecutable(context.hookTarget);
  checks.push({
    name: "executable",
    ok: exec,
    detail: exec ? "hook is executable" : "hook is not executable"
  });

  const dgOk = context.dgPath === "dg" || isExecutable(context.dgPath) || existsSync(context.dgPath);
  checks.push({
    name: "dg-runnable",
    ok: dgOk,
    detail: dgOk ? `dg resolves to ${context.dgPath}` : `dg path ${context.dgPath} is not runnable`
  });

  const fires = runSelfTest(context);
  checks.push({
    name: "fires-on-block",
    ok: fires.ok,
    detail: fires.detail
  });

  return checks;
}

function runSelfTest(context: GitRepoContext): { ok: boolean; detail: string } {
  if (!existsSync(context.hookTarget) || !isManaged(context.hookTarget)) {
    return { ok: false, detail: "no dg hook to exercise" };
  }
  const sh = resolveToolPath("sh", context.env);
  if (!sh) {
    return { ok: false, detail: "sh not found on PATH; hook not exercised" };
  }
  const result = spawnSync(sh, [context.hookTarget], {
    cwd: context.root,
    env: { ...context.env, [GUARD_SELFTEST_ENV]: "1" },
    encoding: "utf8",
    stdio: "ignore"
  });
  if (result.status === 2) {
    return { ok: true, detail: "synthetic block aborts the commit (exit 2)" };
  }
  return {
    ok: false,
    detail: `self-test expected exit 2, got ${result.status === null ? "no exit" : result.status}`
  };
}

function unregisteredHookEntry(context: GitRepoContext): CleanupRegistryEntry {
  const original = chainedHookOriginal(hookText(context.hookTarget));
  return {
    kind: "git-hook",
    path: context.hookTarget,
    mode: "mode1",
    sentinel: GUARD_HOOK_SENTINEL,
    installedAt: "",
    owner: "dg",
    ...(original ? { original } : {})
  };
}

function isUnderRoot(path: string, root: string): boolean {
  const a = resolve(path);
  const b = resolve(root);
  return a === b || a.startsWith(b + sep);
}

export function gitHookStatusState(options: ResolveOptions = {}): GuardStatusState {
  const context = resolveGitRepo(options);
  if ("error" in context) {
    return "not-a-repo";
  }
  if (isManaged(context.hookTarget) && isExecutable(context.hookTarget)) {
    return "active";
  }
  const registry = readRegistry(context.paths).registry;
  const installedHere = registry.entries.some(
    (entry) => entry.kind === "git-hook" && entry.owner === "dg" && isUnderRoot(entry.path, context.root)
  );
  return installedHere ? "dead" : "off";
}

export function commitGuardOffer(options: ResolveOptions = {}): GitRepoContext | null {
  const resolved = resolveGitRepo(options);
  if ("error" in resolved) {
    return null;
  }
  return gitHookStatusState(options) === "off" ? resolved : null;
}

export function removeGitHookForRepo(context: GitRepoContext): GitHookRemoveResult {
  const lock = acquireLockSync(context.paths, SETUP_UNINSTALL_LOCK, { staleMs: SETUP_UNINSTALL_LOCK_STALE_MS });
  const removed: string[] = [];
  const missing: string[] = [];
  const warnings: string[] = [];
  try {
    const registryLock = acquireLockSync(context.paths, CLEANUP_REGISTRY_LOCK, { staleMs: SETUP_UNINSTALL_LOCK_STALE_MS });
    try {
      const registry = readRegistry(context.paths).registry;
      const mine = registry.entries.filter(
        (entry) => entry.kind === "git-hook" && entry.owner === "dg" && isUnderRoot(entry.path, context.root)
      );
      const targets = mine.length > 0
        ? mine
        : isManaged(context.hookTarget)
          ? [unregisteredHookEntry(context)]
          : [];
      for (const entry of targets) {
        reverseGitHookEntry(entry, removed, missing, warnings);
      }
      if (mine.length > 0) {
        writeRegistry(context.paths, {
          version: 1,
          entries: registry.entries.filter((entry) => !mine.includes(entry))
        });
      }
      return { removed, missing, warnings, found: targets.length };
    } finally {
      registryLock.release();
    }
  } finally {
    lock.release();
  }
}
