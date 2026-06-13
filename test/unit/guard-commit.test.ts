import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const DG = fileURLToPath(new URL("../../dist/bin/dg.js", import.meta.url));
const made: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}

function hookEnv(home: string): NodeJS.ProcessEnv {
  return { ...process.env, HOME: home, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" };
}

function git(repo: string, args: string[], env: NodeJS.ProcessEnv): void {
  spawnSync("git", ["-c", "user.email=t@t.dev", "-c", "user.name=Test", ...args], { cwd: repo, env, encoding: "utf8" });
}

function dg(repo: string, args: string[], env: NodeJS.ProcessEnv): { code: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [DG, ...args], { cwd: repo, env, encoding: "utf8" });
  return { code: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

describe("dg guard-commit (built binary)", () => {
  let home: string;
  let env: NodeJS.ProcessEnv;
  let repo: string;

  beforeEach(() => {
    home = tempDir("dg-home-");
    env = hookEnv(home);
    repo = tempDir("dg-gc-");
    git(repo, ["init", "-q"], env);
  });

  afterEach(() => {
    for (const dir of made.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("installs, self-verifies active, and reports it via --check", () => {
    const install = dg(repo, ["guard-commit", "--yes"], env);
    expect(install.code).toBe(0);
    const hookPath = join(repo, ".git", "hooks", "pre-commit");
    expect(existsSync(hookPath)).toBe(true);
    expect(readFileSync(hookPath, "utf8").split("\n")[1]).toContain("dg-git-hook-v1");

    const check = dg(repo, ["guard-commit", "--check"], env);
    expect(check.code).toBe(0);
    expect(check.stderr).toContain("active");
  });

  it("accepts the explicit 'install' alias the docs use", () => {
    const install = dg(repo, ["guard-commit", "install", "--yes"], env);
    expect(install.code).toBe(0);
    expect(existsSync(join(repo, ".git", "hooks", "pre-commit"))).toBe(true);
  });

  it("the installed hook aborts a commit under the self-test wiring", () => {
    dg(repo, ["guard-commit", "--yes"], env);
    const run = spawnSync("sh", [join(repo, ".git", "hooks", "pre-commit")], {
      cwd: repo,
      env: { ...env, DG_GUARD_COMMIT_SELFTEST: "1" },
      encoding: "utf8"
    });
    expect(run.status).toBe(2);
  });

  it("off removes the hook", () => {
    dg(repo, ["guard-commit", "--yes"], env);
    const off = dg(repo, ["guard-commit", "off"], env);
    expect(off.code).toBe(0);
    expect(existsSync(join(repo, ".git", "hooks", "pre-commit"))).toBe(false);
  });

  it("errors with usage outside a git repository", () => {
    const result = dg(tempDir("dg-norepo-"), ["guard-commit"], env);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("not a git repository");
  });

  it("rejects an unknown argument", () => {
    const result = dg(repo, ["guard-commit", "--frobnicate"], env);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("unknown argument");
  });

  it("off is a no-op when nothing is installed", () => {
    const result = dg(repo, ["guard-commit", "off"], env);
    expect(result.code).toBe(0);
    expect(result.stderr).toContain("no dg guard-commit hook");
  });

  it("--print previews the write plan without writing", () => {
    const result = dg(repo, ["guard-commit", "--print"], env);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("write plan");
    expect(existsSync(join(repo, ".git", "hooks", "pre-commit"))).toBe(false);
  });

  it("--check reports not-set-up before install", () => {
    const result = dg(repo, ["guard-commit", "--check"], env);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("not set up");
  });

  it("scan --staged --hook runs non-interactively and exits 0 when no lockfiles are staged", () => {
    spawnSync("sh", ["-c", "echo hi > README.md"], { cwd: repo, env, encoding: "utf8" });
    git(repo, ["add", "README.md"], env);
    const result = dg(repo, ["scan", "--staged", "--hook"], env);
    expect(result.code).toBe(0);
  });
});
