import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runDecisionsCommand } from "../../src/commands/decisions.js";
import { dgFilePath, loadDgFile } from "../../src/project/dgfile.js";

const made: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of made.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function baseEnv(home: string): NodeJS.ProcessEnv {
  const env = { ...process.env, HOME: home, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" };
  for (const marker of ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "TRAVIS", "TEAMCITY_VERSION"]) {
    delete env[marker];
  }
  return env;
}

function initRepo(env: NodeJS.ProcessEnv): string {
  const repo = tempDir("dg-decisions-repo-");
  spawnSync("git", ["init", "-q"], { cwd: repo, env, encoding: "utf8" });
  return repo;
}

function entryJson(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "aaaabbbb-cccc-dddd-eeee-ffff00001111",
    ecosystem: "npm",
    name: "left-pad",
    scope: { kind: "exact", version: "1.3.0" },
    findings: { lifecycle: 3 },
    reason: "team accepted",
    acceptedBy: "alice@example.com",
    acceptedAt: "2026-06-01T00:00:00.000Z",
    ...over
  };
}

function run(args: string[], cwd: string, env: NodeJS.ProcessEnv) {
  return runDecisionsCommand({ commandPath: ["decisions"], args }, cwd, env);
}

describe("dg decisions", () => {
  it("reports a usage error outside a git repository", () => {
    const home = tempDir("dg-home-");
    const notRepo = tempDir("dg-norepo-");
    const result = run([], notRepo, baseEnv(home));
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("not inside a git repository");
  });

  it("lists nothing gracefully when dg.json is absent", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run([], repo, env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("No dg.json");
  });

  it("revoke exits 1 with a revoke-specific message when dg.json is absent", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["revoke", "lodash@4.17.21"], repo, env);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("nothing to revoke");
    expect(result.stdout).toBe("");
  });

  it("lists entries with id prefix, package, who, and status", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    writeFileSync(
      dgFilePath(repo),
      JSON.stringify({
        version: 1,
        decisions: [entryJson(), entryJson({ id: "22223333-0000-0000-0000-000000000000", name: "stale-pkg", expiresAt: "2020-01-01T00:00:00.000Z" })]
      })
    );
    const result = run(["list"], repo, env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("aaaabbbb");
    expect(result.stdout).toContain("npm:left-pad@1.3.0");
    expect(result.stdout).toContain("lifecycle:3");
    expect(result.stdout).toContain("alice@example.com");
    expect(result.stdout).toContain("active");
    expect(result.stdout).toContain("expired");
    expect(result.stdout).toContain("blocks are never suppressible");
  });

  it("lists as JSON with --json", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    writeFileSync(dgFilePath(repo), JSON.stringify({ version: 1, decisions: [entryJson()] }));
    const result = run(["--json"], repo, env);
    expect(result.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout) as { schemaVersion: number; path: string; decisions: Array<{ name: string; status: string }> };
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.path.endsWith(join(repo.split("/").slice(-1)[0] ?? "", "dg.json"))).toBe(true);
    expect(parsed.decisions).toHaveLength(1);
    expect(parsed.decisions[0]?.name).toBe("left-pad");
    expect(parsed.decisions[0]?.status).toBe("active");
  });

  it("rejects extra positional arguments after --json", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["--json", "garbage"], repo, env);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("unexpected argument 'garbage'");
  });

  it("revokes by name@version and persists the removal", () => {
    const home = tempDir("dg-home-");
    const env = baseEnv(home);
    const repo = initRepo(env);
    writeFileSync(
      dgFilePath(repo),
      JSON.stringify({ version: 1, scriptApprovals: { keep: true }, decisions: [entryJson(), entryJson({ id: "22223333-0000-0000-0000-000000000000", name: "other" })] })
    );
    const result = run(["revoke", "left-pad@1.3.0"], repo, env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Revoked npm:left-pad@1.3.0");

    const reloaded = loadDgFile(repo);
    expect(reloaded.decisions).toHaveLength(1);
    expect(reloaded.decisions[0]?.name).toBe("other");
    const raw = JSON.parse(readFileSync(dgFilePath(repo), "utf8")) as Record<string, unknown>;
    expect(raw.scriptApprovals).toEqual({ keep: true });

    const auditPath = join(home, ".dg", "state", "audit.jsonl");
    expect(existsSync(auditPath)).toBe(true);
    const events = readFileSync(auditPath, "utf8").trim().split("\n").map((line) => JSON.parse(line) as { type: string; packageName: string });
    expect(events.some((event) => event.type === "decision.revoked" && event.packageName === "npm:left-pad@1.3.0")).toBe(true);
  });

  it("revokes by id prefix", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    writeFileSync(dgFilePath(repo), JSON.stringify({ version: 1, decisions: [entryJson()] }));
    const result = run(["revoke", "aaaabbbb"], repo, env);
    expect(result.exitCode).toBe(0);
    expect(loadDgFile(repo).decisions).toHaveLength(0);
  });

  it("exits 1 when nothing matches the revoke selector", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    writeFileSync(dgFilePath(repo), JSON.stringify({ version: 1, decisions: [entryJson()] }));
    const result = run(["revoke", "nope@0.0.1"], repo, env);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("nothing matches");
  });

  it("surfaces an unreadable dg.json instead of pretending it is empty", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    writeFileSync(dgFilePath(repo), "{broken");
    const result = run([], repo, env);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("malformed JSON");
  });

  it("rejects unknown subcommands", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["prune-everything"], repo, env);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("unknown subcommand");
  });
});
