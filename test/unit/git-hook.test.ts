import { spawnSync } from "node:child_process";
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  applyGitHook,
  gitHookState,
  gitHookStatusState,
  planGitHook,
  removeGitHookForRepo,
  resolveGitRepo,
  verifyGitHook,
  type GitRepoContext
} from "../../src/setup/git-hook.js";
import { chainedHookOriginal, guardHookDgPath, guardHookScript, uninstallSetup } from "../../src/setup/plan.js";

const made: string[] = [];

function baseEnv(home: string): NodeJS.ProcessEnv {
  return {
    ...process.env,
    HOME: home,
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null"
  };
}

function git(repo: string, args: string[], env: NodeJS.ProcessEnv): { code: number | null; stdout: string } {
  const result = spawnSync("git", ["-c", "user.email=t@t.dev", "-c", "user.name=Test", ...args], {
    cwd: repo,
    env,
    encoding: "utf8"
  });
  return { code: result.status, stdout: result.stdout ?? "" };
}

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}

function initRepo(env: NodeJS.ProcessEnv): string {
  const repo = tempDir("dg-hooktest-");
  git(repo, ["init", "-q"], env);
  return repo;
}

function fakeDg(repo: string, mode: "pass" | "block"): string {
  const path = join(repo, mode === "pass" ? "fake-dg-pass" : "fake-dg-block");
  const body =
    mode === "pass"
      ? '#!/bin/sh\nif [ "$DG_GUARD_COMMIT_SELFTEST" = "1" ]; then exit 2; fi\nexit 0\n'
      : "#!/bin/sh\nexit 2\n";
  writeFileSync(path, body, { mode: 0o755 });
  chmodSync(path, 0o755);
  return path;
}

function ctxOrThrow(value: GitRepoContext | { error: string }): GitRepoContext {
  if ("error" in value) {
    throw new Error(value.error);
  }
  return value;
}

describe("git hook — resolution", () => {
  let home: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    home = tempDir("dg-home-");
    env = baseEnv(home);
  });

  afterEach(() => {
    for (const dir of made.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("resolves the default .git/hooks dir", () => {
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env }));
    expect(ctx.hookTarget.endsWith(join(".git", "hooks", "pre-commit"))).toBe(true);
    expect(ctx.hooksPathConfigured).toBe(false);
  });

  it("honors an absolute core.hooksPath", () => {
    const repo = initRepo(env);
    const custom = join(repo, "custom-hooks");
    mkdirSync(custom, { recursive: true });
    git(repo, ["config", "core.hooksPath", custom], env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env }));
    expect(ctx.hooksDir).toBe(custom);
    expect(ctx.hooksPathConfigured).toBe(true);
  });

  it("resolves a relative core.hooksPath against the repo root (husky-style)", () => {
    const repo = initRepo(env);
    git(repo, ["config", "core.hooksPath", ".husky"], env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env }));
    expect(ctx.hooksDir).toBe(join(ctx.root, ".husky"));
    expect(ctx.hookTarget).toBe(join(ctx.root, ".husky", "pre-commit"));
  });

  it("resolves the hooks dir inside a linked worktree", () => {
    const repo = initRepo(env);
    git(repo, ["commit", "--allow-empty", "-q", "-m", "init"], env);
    const wt = join(tempDir("dg-wt-host-"), "wt");
    git(repo, ["worktree", "add", "-q", wt], env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: wt, env }));
    expect(ctx.hookTarget.endsWith("pre-commit")).toBe(true);
    expect(ctx.hooksDir).toContain("hooks");
  });

  it("reports an error outside a git repository", () => {
    const notRepo = tempDir("dg-norepo-");
    const result = resolveGitRepo({ cwd: notRepo, env });
    expect("error" in result).toBe(true);
  });
});

describe("git hook — install, chain, verify", () => {
  let home: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    home = tempDir("dg-home-");
    env = baseEnv(home);
  });

  afterEach(() => {
    for (const dir of made.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("installs a fresh hook and self-verifies it fires", () => {
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "pass") }));
    expect(gitHookState(ctx)).toBe("fresh");

    const result = applyGitHook(ctx);
    expect(result.active).toBe(true);
    expect(result.chainedOriginal).toBeNull();
    expect(readFileSync(ctx.hookTarget, "utf8").split("\n")[1]).toContain("dg-git-hook-v1");
    expect((statSync(ctx.hookTarget).mode & 0o111) !== 0).toBe(true);
    expect(result.checks.find((c) => c.name === "fires-on-block")?.ok).toBe(true);
  });

  it("is idempotent on a dg-owned hook (no chain)", () => {
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "pass") }));
    applyGitHook(ctx);
    expect(gitHookState(ctx)).toBe("managed");
    const second = applyGitHook(ctx);
    expect(second.chainedOriginal).toBeNull();
    expect(planGitHook(ctx).willChain).toBe(false);
  });

  it("chains a foreign hook: dg passes, the original still runs and its exit code wins", () => {
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "pass") }));
    const marker = join(repo, "original-ran");
    writeFileSync(ctx.hookTarget, `#!/bin/sh\ntouch "${marker}"\nexit 3\n`, { mode: 0o755 });
    chmodSync(ctx.hookTarget, 0o755);

    expect(gitHookState(ctx)).toBe("foreign");
    const result = applyGitHook(ctx);
    expect(result.chainedOriginal).not.toBeNull();
    expect(result.active).toBe(true);

    const run = spawnSync("sh", [ctx.hookTarget], { cwd: repo, env, encoding: "utf8" });
    expect(statSync(marker).isFile()).toBe(true);
    expect(run.status).toBe(3);
  });

  it("chains a foreign hook: dg blocks, the original never runs and the commit aborts", () => {
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "block") }));
    const marker = join(repo, "original-ran");
    writeFileSync(ctx.hookTarget, `#!/bin/sh\ntouch "${marker}"\nexit 0\n`, { mode: 0o755 });
    chmodSync(ctx.hookTarget, 0o755);

    applyGitHook(ctx);
    const run = spawnSync("sh", [ctx.hookTarget], { cwd: repo, env, encoding: "utf8" });
    expect(run.status).toBe(2);
    expect(() => statSync(marker)).toThrow();
  });

  it("re-running install preserves the chained hook, the restore pointer, and the hook bytes", () => {
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "pass") }));
    const marker = join(repo, "foreign-ran");
    const foreignBody = `#!/bin/sh\ntouch "${marker}"\nexit 0\n`;
    writeFileSync(ctx.hookTarget, foreignBody, { mode: 0o751 });
    chmodSync(ctx.hookTarget, 0o751);

    const first = applyGitHook(ctx);
    const backup = first.chainedOriginal ?? "";
    expect(backup).not.toBe("");
    const firstHookBytes = readFileSync(ctx.hookTarget, "utf8");

    const second = applyGitHook(ctx);
    expect(second.chainedOriginal).toBe(backup);
    expect(readFileSync(ctx.hookTarget, "utf8")).toBe(firstHookBytes);
    expect(readFileSync(backup, "utf8")).toBe(foreignBody);

    const run = spawnSync("sh", [ctx.hookTarget], { cwd: repo, env, encoding: "utf8" });
    expect(run.status).toBe(0);
    expect(statSync(marker).isFile()).toBe(true);

    const removal = removeGitHookForRepo(ctx);
    expect(removal.found).toBeGreaterThan(0);
    expect(readFileSync(ctx.hookTarget, "utf8")).toBe(foreignBody);
    expect(statSync(ctx.hookTarget).mode & 0o777).toBe(0o751);
  });

  it("fails open with a one-line notice when the dg binary disappears, still running the chain", () => {
    const repo = initRepo(env);
    const dgPath = fakeDg(repo, "pass");
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath }));
    const marker = join(repo, "original-ran");
    writeFileSync(ctx.hookTarget, `#!/bin/sh\ntouch "${marker}"\nexit 0\n`, { mode: 0o755 });
    chmodSync(ctx.hookTarget, 0o755);
    applyGitHook(ctx);

    rmSync(dgPath);
    const run = spawnSync("sh", [ctx.hookTarget], { cwd: repo, env, encoding: "utf8" });
    expect(run.status).toBe(0);
    expect(run.stderr).toContain("dg: pre-commit scan skipped");
    expect(statSync(marker).isFile()).toBe(true);
  });

  it("upgrades a legacy-format dg hook in place without losing its chain", () => {
    const repo = initRepo(env);
    const dgPath = fakeDg(repo, "pass");
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath }));
    mkdirSync(ctx.hooksDir, { recursive: true });
    const marker = join(repo, "chained-ran");
    const backup = join(ctx.hooksDir, "pre-commit.dg-chained-deadbeef");
    writeFileSync(backup, `#!/bin/sh\ntouch "${marker}"\nexit 0\n`, { mode: 0o755 });
    chmodSync(backup, 0o755);
    const legacy = `#!/bin/sh\n# dg-git-hook-v1\n"${dgPath}" scan --staged --hook || exit $?\n[ -x "${backup}" ] && exec "${backup}" "$@"\nexit 0\n`;
    writeFileSync(ctx.hookTarget, legacy, { mode: 0o755 });
    chmodSync(ctx.hookTarget, 0o755);

    const result = applyGitHook(ctx);
    expect(result.chainedOriginal).toBe(backup);
    const upgraded = readFileSync(ctx.hookTarget, "utf8");
    expect(upgraded).toContain(`if command -v "${dgPath}"`);
    expect(upgraded).toContain(`[ -x "${backup}" ] && exec "${backup}" "$@"`);

    const run = spawnSync("sh", [ctx.hookTarget], { cwd: repo, env, encoding: "utf8" });
    expect(run.status).toBe(0);
    expect(statSync(marker).isFile()).toBe(true);
  });

  it("refuses to replace a symlinked dg-managed pre-commit hook", () => {
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "pass") }));
    mkdirSync(ctx.hooksDir, { recursive: true });
    const linkTarget = join(repo, "dotfiles-pre-commit");
    const linkedBody = "#!/bin/sh\n# dg-git-hook-v1\nexit 0\n";
    writeFileSync(linkTarget, linkedBody, { mode: 0o755 });
    symlinkSync(linkTarget, ctx.hookTarget);

    const result = applyGitHook(ctx);
    expect(result.active).toBe(false);
    expect(result.checks.some((check) => check.detail.includes("symlink"))).toBe(true);
    expect(lstatSync(ctx.hookTarget).isSymbolicLink()).toBe(true);
    expect(readFileSync(linkTarget, "utf8")).toBe(linkedBody);
  });

  it("refuses to replace a dangling pre-commit symlink", () => {
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "pass") }));
    mkdirSync(ctx.hooksDir, { recursive: true });
    symlinkSync(join(repo, "missing-target"), ctx.hookTarget);

    const result = applyGitHook(ctx);
    expect(result.active).toBe(false);
    expect(result.checks.some((check) => check.detail.includes("symlink"))).toBe(true);
    expect(lstatSync(ctx.hookTarget).isSymbolicLink()).toBe(true);
  });

  it("installs and chains under a husky-style core.hooksPath", () => {
    const repo = initRepo(env);
    const husky = join(repo, ".husky");
    mkdirSync(husky, { recursive: true });
    const huskyMarker = join(repo, "husky-ran");
    writeFileSync(join(husky, "pre-commit"), `#!/bin/sh\ntouch "${huskyMarker}"\nexit 0\n`, { mode: 0o755 });
    chmodSync(join(husky, "pre-commit"), 0o755);
    git(repo, ["config", "core.hooksPath", ".husky"], env);

    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "pass") }));
    expect(ctx.hooksDir).toBe(join(ctx.root, ".husky"));
    const result = applyGitHook(ctx);
    expect(result.chainedOriginal).not.toBeNull();
    expect(result.active).toBe(true);

    const run = spawnSync("sh", [ctx.hookTarget], { cwd: repo, env, encoding: "utf8" });
    expect(statSync(huskyMarker).isFile()).toBe(true);
    expect(run.status).toBe(0);
  });
});

describe("git hook — status + removal", () => {
  let home: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    home = tempDir("dg-home-");
    env = baseEnv(home);
  });

  afterEach(() => {
    for (const dir of made.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("status: not-a-repo / off / active / dead", () => {
    const notRepo = tempDir("dg-norepo-");
    expect(gitHookStatusState({ cwd: notRepo, env })).toBe("not-a-repo");

    const repo = initRepo(env);
    expect(gitHookStatusState({ cwd: repo, env })).toBe("off");

    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "pass") }));
    applyGitHook(ctx);
    expect(gitHookStatusState({ cwd: repo, env })).toBe("active");

    // git now looks elsewhere → the recorded hook is silently dead
    const elsewhere = join(repo, "moved-hooks");
    mkdirSync(elsewhere, { recursive: true });
    git(repo, ["config", "core.hooksPath", elsewhere], env);
    expect(gitHookStatusState({ cwd: repo, env })).toBe("dead");
  });

  it("removes the dg hook and restores a chained original byte- and mode-identical", () => {
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "pass") }));
    const originalBody = "#!/bin/sh\necho original\nexit 0\n";
    writeFileSync(ctx.hookTarget, originalBody, { mode: 0o751 });
    chmodSync(ctx.hookTarget, 0o751);

    applyGitHook(ctx);
    expect(readFileSync(ctx.hookTarget, "utf8")).toContain("dg-git-hook-v1");

    const result = removeGitHookForRepo(ctx);
    expect(result.found).toBeGreaterThan(0);
    expect(readFileSync(ctx.hookTarget, "utf8")).toBe(originalBody);
    expect(statSync(ctx.hookTarget).mode & 0o777).toBe(0o751);
    expect(gitHookStatusState({ cwd: repo, env })).toBe("off");
  });

  it("removes a non-chained hook cleanly", () => {
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "pass") }));
    applyGitHook(ctx);
    const result = removeGitHookForRepo(ctx);
    expect(result.found).toBeGreaterThan(0);
    expect(() => statSync(ctx.hookTarget)).toThrow();
  });

  it("refuses to delete a hook the user replaced after install (sentinel guard)", () => {
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "pass") }));
    applyGitHook(ctx);
    const userBody = "#!/bin/sh\n# mine now\nexit 0\n";
    writeFileSync(ctx.hookTarget, userBody, { mode: 0o755 });

    const result = removeGitHookForRepo(ctx);
    expect(readFileSync(ctx.hookTarget, "utf8")).toBe(userBody);
    expect(result.warnings.some((w) => w.includes("without dg sentinel"))).toBe(true);
  });

  it("global dg uninstall reverses the git-hook entry and restores the original", () => {
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo, "pass") }));
    const originalBody = "#!/bin/sh\nexit 0\n";
    writeFileSync(ctx.hookTarget, originalBody, { mode: 0o755 });
    chmodSync(ctx.hookTarget, 0o755);
    applyGitHook(ctx);

    const result = uninstallSetup({ keepConfig: true, all: false, env });
    expect(result.removed.some((p) => p === ctx.hookTarget || p.includes(".dg-chained-"))).toBe(true);
    expect(readFileSync(ctx.hookTarget, "utf8")).toBe(originalBody);
  });
});

describe("guard hook script generation and parsing", () => {
  it("generates a fail-open script guarded by command -v", () => {
    const script = guardHookScript("/usr/local/bin/dg", null);
    expect(script.split("\n")[1]).toContain("dg-git-hook-v1");
    expect(script).toContain('if command -v "/usr/local/bin/dg" >/dev/null 2>&1; then');
    expect(script).toContain('"/usr/local/bin/dg" scan --staged --hook || exit $?');
    expect(script).toContain("dg: pre-commit scan skipped");
    expect(script.endsWith("exit 0\n")).toBe(true);
  });

  it("round-trips the chained original path", () => {
    const chained = "/repo/.git/hooks/pre-commit.dg-chained-ab12cd34";
    expect(chainedHookOriginal(guardHookScript("/usr/local/bin/dg", chained))).toBe(chained);
    expect(chainedHookOriginal(guardHookScript("/usr/local/bin/dg", null))).toBeNull();
  });

  it("extracts the dg path from both the current and the legacy hook format", () => {
    expect(guardHookDgPath(guardHookScript("/opt/dg/bin/dg", null))).toBe("/opt/dg/bin/dg");
    const legacy = '#!/bin/sh\n# dg-git-hook-v1\n"/usr/bin/dg" scan --staged --hook || exit $?\n[ -x "/x/backup" ] && exec "/x/backup" "$@"\nexit 0\n';
    expect(guardHookDgPath(legacy)).toBe("/usr/bin/dg");
    expect(chainedHookOriginal(legacy)).toBe("/x/backup");
  });

  it("escapes shell metacharacters in interpolated paths and round-trips them", () => {
    const dgPath = '/opt/dg dir/"weird"/$HOME/`cmd`/dg.js';
    const chained = '/repo/.git/hooks/pre-commit.dg-chained-$x"y';
    const script = guardHookScript(dgPath, chained);
    expect(script).toContain('if command -v "/opt/dg dir/\\"weird\\"/\\$HOME/\\`cmd\\`/dg.js" >/dev/null 2>&1; then');
    expect(script).not.toContain('"/opt/dg dir/"weird"');
    expect(guardHookDgPath(script)).toBe(dgPath);
    expect(chainedHookOriginal(script)).toBe(chained);
  });
});
