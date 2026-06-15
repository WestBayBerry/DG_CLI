import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  decideStagedVerdict,
  materializeStaged,
  runStagedScan,
  scopeStagedPaths,
  stagedLockfilePaths,
  stagedScanReport
} from "../../src/scan/staged.js";
import { renderJsonReport } from "../../src/scan/render.js";
import { DEFAULT_CONFIG, saveUserConfig, setConfigValue } from "../../src/config/settings.js";
import type { ScanFinding, ScanReport, ScanStatus } from "../../src/scan/types.js";
import type { AnalyzeResponse, ScannerAction } from "../../src/api/analyze.js";

const made: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}

function baseEnv(home: string): NodeJS.ProcessEnv {
  return { ...process.env, HOME: home, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" };
}

function git(repo: string, args: string[], env: NodeJS.ProcessEnv): void {
  spawnSync("git", ["-c", "user.email=t@t.dev", "-c", "user.name=Test", ...args], { cwd: repo, env, encoding: "utf8" });
}

function initRepo(env: NodeJS.ProcessEnv): string {
  const repo = tempDir("dg-staged-");
  git(repo, ["init", "-q"], env);
  return repo;
}

function finding(severity: "warn" | "block", location: string, message: string): ScanFinding {
  return { id: "x", severity, title: message, message, project: "", location };
}

function report(action: ScannerAction, findings: ScanFinding[] = [], count = 3): ScanReport {
  const status: ScanStatus = action === "analysis_incomplete" ? "unknown" : action;
  return {
    target: "t",
    status,
    projects: [],
    findings,
    errors: [],
    summary: {
      projectCount: 1,
      dependencyCount: count,
      findingCount: findings.length,
      warnCount: findings.filter((f) => f.severity === "warn").length,
      blockCount: findings.filter((f) => f.severity === "block").length,
      errorCount: 0
    },
    scanner: { action } as unknown as AnalyzeResponse
  };
}

describe("staged scan — verdict to exit", () => {
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

  it("pass → exit 0", () => {
    const result = decideStagedVerdict(report("pass"), env);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain("verified");
  });

  it("block → exit 2 with the override hint", () => {
    const result = decideStagedVerdict(report("block", [finding("block", "evil@1.0.0", "credential exfiltration")]), env);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("blocked this commit");
    expect(result.stderr).toContain("git commit --no-verify");
    expect(result.stderr).toContain("evil@1.0.0");
  });

  it("analysis_incomplete → fail-open (exit 0) by default", () => {
    const result = decideStagedVerdict(report("analysis_incomplete"), env);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain("could not fully analyze");
  });

  it("analysis_incomplete → exit 1 when gitHook.onIncomplete=block", () => {
    saveUserConfig(setConfigValue(DEFAULT_CONFIG, "gitHook.onIncomplete", "block"), env);
    const result = decideStagedVerdict(report("analysis_incomplete"), env);
    expect(result.exitCode).toBe(1);
  });

  it("warn + onWarn=allow → exit 0", () => {
    saveUserConfig(setConfigValue(DEFAULT_CONFIG, "gitHook.onWarn", "allow"), env);
    const result = decideStagedVerdict(report("warn", [finding("warn", "lib@2.0.0", "install lifecycle script")]), env);
    expect(result.exitCode).toBe(0);
  });

  it("warn + onWarn=block → exit 1 with override hint", () => {
    saveUserConfig(setConfigValue(DEFAULT_CONFIG, "gitHook.onWarn", "block"), env);
    const result = decideStagedVerdict(report("warn", [finding("warn", "lib@2.0.0", "install lifecycle script")]), env);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("git commit --no-verify");
  });

  it("warn + onWarn=prompt, no terminal, policy block → exit 1", () => {
    const cfg = setConfigValue(setConfigValue(DEFAULT_CONFIG, "gitHook.onWarn", "prompt"), "policy.mode", "block");
    saveUserConfig(cfg, env);
    const result = decideStagedVerdict(report("warn", [finding("warn", "lib@2.0.0", "x")]), env);
    expect(result.exitCode).toBe(1);
  });

  it("warn + onWarn=prompt, no terminal, policy warn → exit 0", () => {
    const cfg = setConfigValue(setConfigValue(DEFAULT_CONFIG, "gitHook.onWarn", "prompt"), "policy.mode", "warn");
    saveUserConfig(cfg, env);
    const result = decideStagedVerdict(report("warn", [finding("warn", "lib@2.0.0", "x")]), env);
    expect(result.exitCode).toBe(0);
  });

  it("hook=true forces non-interactive: warn + onWarn=prompt, policy block → exit 1 without prompting", () => {
    const cfg = setConfigValue(setConfigValue(DEFAULT_CONFIG, "gitHook.onWarn", "prompt"), "policy.mode", "block");
    saveUserConfig(cfg, env);
    const result = decideStagedVerdict(report("warn", [finding("warn", "lib@2.0.0", "x")]), env, true);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("no terminal");
  });

  it("hook=true forces non-interactive: warn + onWarn=prompt, policy warn → exit 0 without prompting", () => {
    const cfg = setConfigValue(setConfigValue(DEFAULT_CONFIG, "gitHook.onWarn", "prompt"), "policy.mode", "warn");
    saveUserConfig(cfg, env);
    const result = decideStagedVerdict(report("warn", [finding("warn", "lib@2.0.0", "x")]), env, true);
    expect(result.exitCode).toBe(0);
  });

  it("hook=true block still exits 2", () => {
    const result = decideStagedVerdict(report("block", [finding("block", "evil@1.0.0", "exfil")]), env, true);
    expect(result.exitCode).toBe(2);
  });

  it("scanner outage (status error, no scanner action) → visible fail-open (exit 0 + notice)", () => {
    const outage = report("pass");
    delete (outage as { scanner?: unknown }).scanner;
    (outage as { status: ScanStatus }).status = "error";
    const result = decideStagedVerdict(outage, env);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain("scanner unavailable");
    expect(result.stderr).toContain("not verified");
  });

  it("scanner outage (status unknown) → visible fail-open (exit 0 + notice)", () => {
    const outage = report("pass");
    delete (outage as { scanner?: unknown }).scanner;
    (outage as { status: ScanStatus }).status = "unknown";
    const result = decideStagedVerdict(outage, env);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain("scanner unavailable");
  });

  it("explicit block still blocks even when status would be a scanner outage", () => {
    const blocked = report("block", [finding("block", "evil@1.0.0", "exfil")]);
    (blocked as { status: ScanStatus }).status = "error";
    const result = decideStagedVerdict(blocked, env);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("blocked this commit");
  });

  it("scanner outage → exit 1 (blocks) when gitHook.onIncomplete=block (B1-H2)", () => {
    saveUserConfig(setConfigValue(DEFAULT_CONFIG, "gitHook.onIncomplete", "block"), env);
    const outage = report("pass");
    delete (outage as { scanner?: unknown }).scanner;
    (outage as { status: ScanStatus }).status = "error";
    const result = decideStagedVerdict(outage, env);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("onIncomplete=block");
  });
});

describe("staged scan — staging + orchestration", () => {
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

  it("materializes the staged blob, not the dirty working tree", () => {
    const repo = initRepo(env);
    writeFileSync(join(repo, "package-lock.json"), '{"staged":true}\n');
    git(repo, ["add", "package-lock.json"], env);
    writeFileSync(join(repo, "package-lock.json"), '{"working":true}\n');

    expect(stagedLockfilePaths(repo, env)).toEqual(["package-lock.json"]);
    const { dir, count } = materializeStaged(["package-lock.json"], repo, env);
    expect(count).toBe(1);
    expect(readFileSync(join(dir, "package-lock.json"), "utf8")).toBe('{"staged":true}\n');
  });

  it("ignores staged files that are not dependency lockfiles", () => {
    const repo = initRepo(env);
    writeFileSync(join(repo, "README.md"), "hi\n");
    git(repo, ["add", "README.md"], env);
    expect(stagedLockfilePaths(repo, env)).toEqual([]);
  });

  it("runStagedScan exits 0 fast when no lockfiles are staged", () => {
    const repo = initRepo(env);
    writeFileSync(join(repo, "README.md"), "hi\n");
    git(repo, ["add", "README.md"], env);
    expect(runStagedScan({ hook: true, env, cwd: repo }).exitCode).toBe(0);
  });

  it("runStagedScan short-circuits to exit 2 under the self-test env", () => {
    const repo = initRepo(env);
    const result = runStagedScan({ hook: true, env: { ...env, DG_GUARD_COMMIT_SELFTEST: "1" }, cwd: repo });
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("self-test");
  });

  it("runStagedScan ignores the self-test env outside the hook invocation", () => {
    const repo = initRepo(env);
    const result = runStagedScan({ hook: false, env: { ...env, DG_GUARD_COMMIT_SELFTEST: "1" }, cwd: repo });
    expect(result.exitCode).toBe(0);
    expect(result.stderr).not.toContain("self-test");
  });

  it("runStagedScan ignores the self-test env during a real git commit (GIT_INDEX_FILE present)", () => {
    const repo = initRepo(env);
    const result = runStagedScan({
      hook: true,
      env: { ...env, DG_GUARD_COMMIT_SELFTEST: "1", GIT_INDEX_FILE: join(repo, ".git", "index") },
      cwd: repo
    });
    expect(result.exitCode).toBe(0);
    expect(result.stderr).not.toContain("self-test");
  });

  it("runStagedScan reports a usage error outside a git repository with exit 64", () => {
    const notRepo = tempDir("dg-norepo-");
    expect(runStagedScan({ hook: true, env, cwd: notRepo }).exitCode).toBe(64);
  });

  it("runStagedScan scopes to the path argument and exits 0 when nothing staged matches", () => {
    const repo = initRepo(env);
    writeFileSync(join(repo, "package-lock.json"), '{"lockfileVersion":3,"packages":{}}\n');
    git(repo, ["add", "package-lock.json"], env);

    expect(runStagedScan({ hook: true, env, cwd: repo, targetPath: "packages/api" }).exitCode).toBe(0);
  });

  it("runStagedScan rejects a path outside the repository with exit 64", () => {
    const repo = initRepo(env);
    const outside = runStagedScan({ hook: true, env, cwd: repo, targetPath: "../elsewhere" });
    expect(outside.exitCode).toBe(64);
    expect(outside.stderr).toContain("outside this repository");
  });
});

describe("staged scan — path scoping", () => {
  const root = "/repo";

  it("returns everything without a target and scopes prefixes with one", () => {
    const paths = ["package-lock.json", "packages/api/pnpm-lock.yaml", "packages/web/yarn.lock"];
    expect(scopeStagedPaths(paths, root, root, null)).toEqual(paths);
    expect(scopeStagedPaths(paths, root, root, ".")).toEqual(paths);
    expect(scopeStagedPaths(paths, root, root, "packages/api")).toEqual(["packages/api/pnpm-lock.yaml"]);
    expect(scopeStagedPaths(paths, root, root, "packages")).toEqual([
      "packages/api/pnpm-lock.yaml",
      "packages/web/yarn.lock"
    ]);
    expect(scopeStagedPaths(paths, root, root, "package-lock.json")).toEqual(["package-lock.json"]);
    expect(scopeStagedPaths(paths, root, root, "missing")).toEqual([]);
  });

  it("resolves the target from the working directory, not the repo root", () => {
    const paths = ["packages/api/pnpm-lock.yaml", "package-lock.json"];
    expect(scopeStagedPaths(paths, root, "/repo/packages", "api")).toEqual(["packages/api/pnpm-lock.yaml"]);
  });

  it("returns null for targets outside the repository", () => {
    expect(scopeStagedPaths(["package-lock.json"], root, root, "../other")).toBeNull();
    expect(scopeStagedPaths(["package-lock.json"], root, root, "/elsewhere")).toBeNull();
  });

  it("does not match sibling directories sharing a prefix", () => {
    expect(scopeStagedPaths(["packages-old/yarn.lock"], root, root, "packages")).toEqual([]);
  });
});

describe("staged scan — machine report inputs", () => {
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

  it("returns a usage result outside a git repository", () => {
    const notRepo = tempDir("dg-norepo-");
    const staged = stagedScanReport({ env, cwd: notRepo });
    expect("result" in staged).toBe(true);
    if ("result" in staged) {
      expect(staged.result.exitCode).toBe(64);
      expect(staged.result.stderr).toContain("not a git repository");
    }
  });

  it("returns a usage result for a target outside the repository", () => {
    const repo = initRepo(env);
    const staged = stagedScanReport({ env, cwd: repo, targetPath: "../elsewhere" });
    expect("result" in staged).toBe(true);
    if ("result" in staged) {
      expect(staged.result.exitCode).toBe(64);
    }
  });

  it("mirrors the empty-scan JSON shape when nothing is staged", () => {
    const repo = initRepo(env);
    const staged = stagedScanReport({ env, cwd: repo });
    expect("report" in staged).toBe(true);
    if (!("report" in staged)) {
      return;
    }
    expect(staged.outcome).toEqual({ kind: "skipped", reason: "no_lockfiles" });
    const json = JSON.parse(renderJsonReport(staged.report, false)) as {
      status: string;
      scannerUnavailable: boolean;
      summary: { projectCount: number; dependencyCount: number; findingCount: number };
      projects: unknown[];
      findings: unknown[];
      errors: unknown[];
    };
    expect(json.status).toBe("pass");
    expect(json.scannerUnavailable).toBe(false);
    expect(json.summary).toMatchObject({ projectCount: 0, dependencyCount: 0, findingCount: 0 });
    expect(json.projects).toEqual([]);
    expect(json.findings).toEqual([]);
    expect(json.errors).toEqual([]);
  });
});
