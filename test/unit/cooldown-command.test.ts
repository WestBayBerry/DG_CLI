import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCooldownCommand } from "../../src/commands/cooldown.js";
import { dgFilePath, loadDgFile } from "../../src/project/dgfile.js";
import { recordHeldPackage } from "../../src/state/cooldown-held.js";

const made: string[] = [];
const NOW = new Date("2026-06-10T00:00:00.000Z");

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
  const repo = tempDir("dg-cooldown-repo-");
  spawnSync("git", ["init", "-q"], { cwd: repo, env, encoding: "utf8" });
  spawnSync("git", ["config", "user.email", "alice@example.com"], { cwd: repo, env, encoding: "utf8" });
  return repo;
}

function run(args: string[], cwd: string, env: NodeJS.ProcessEnv) {
  return runCooldownCommand({ commandPath: ["cooldown"], args }, cwd, env, NOW);
}

describe("dg cooldown", () => {
  it("reports a usage error outside a git repository", () => {
    const result = run([], tempDir("dg-norepo-"), baseEnv(tempDir("dg-home-")));
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("not inside a git repository");
  });

  it("shows the cooldown window and no-exemptions note when dg.json is absent", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const result = run([], initRepo(env), env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("window");
    expect(result.stdout).toContain("dg cooldown 3d");
    expect(result.stdout).toContain("No exemptions yet");
  });

  it("sets the window directly from a positional duration and shows the card", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const set = run(["7d"], repo, env);
    expect(set.exitCode).toBe(0);
    expect(set.stdout).toContain("7d");
    const off = run(["off"], repo, env);
    expect(off.exitCode).toBe(0);
    expect(off.stdout).toContain("off — new releases install immediately");
    const bad = run(["7x"], repo, env);
    expect(bad.exitCode).toBe(2);
  });

  it("prune removes only expired exemptions", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    writeFileSync(dgFilePath(repo), JSON.stringify({
      version: 1,
      cooldownExemptions: [
        { ecosystem: "npm", name: "stale", reason: "", acceptedBy: "t", acceptedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2026-02-01T00:00:00.000Z" },
        { ecosystem: "npm", name: "keep", reason: "", acceptedBy: "t", acceptedAt: "2026-01-01T00:00:00.000Z" }
      ]
    }), "utf8");
    const result = run(["prune"], repo, env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Pruned 1 expired");
    expect(loadDgFile(repo).cooldownExemptions.map((e) => e.name)).toEqual(["keep"]);
  });

  it("prune rejects --json like its sibling subcommands", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["prune", "--json"], repo, env);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("unexpected argument '--json'");
  });

  it("rejects extra positional arguments after --json", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["--json", "garbage"], repo, env);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("unexpected argument 'garbage'");
  });

  it("exempts a package and persists it under cooldownExemptions", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["exempt", "left-pad", "--reason", "vendored"], repo, env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Exempted npm:left-pad from cooldown");

    const file = loadDgFile(repo);
    expect(file.cooldownExemptions).toHaveLength(1);
    const entry = file.cooldownExemptions[0];
    expect(entry?.ecosystem).toBe("npm");
    expect(entry?.name).toBe("left-pad");
    expect(entry?.reason).toBe("vendored");
    expect(entry?.acceptedBy).toBe("alice@example.com");
    expect(entry?.expiresAt).toBeUndefined();
  });

  it("derives ecosystem from a pypi: prefix and canonicalizes the name (PEP 503)", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["exempt", "pypi:Flask_Login"], repo, env);
    expect(result.exitCode).toBe(0);
    const file = loadDgFile(repo);
    expect(file.cooldownExemptions[0]?.ecosystem).toBe("pypi");
    expect(file.cooldownExemptions[0]?.name).toBe("flask-login");
  });

  it("rm removes a pypi exemption stored under any case/separator spelling", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    run(["exempt", "pypi:Flask_Login"], repo, env);
    const removed = run(["rm", "pypi:flask-login"], repo, env);
    expect(removed.exitCode).toBe(0);
    expect(removed.stdout).toContain("cooldown applies again");
    expect(loadDgFile(repo).cooldownExemptions).toHaveLength(0);
  });

  it("re-exempting a pypi name variant updates the single canonical entry (no duplicate row)", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    run(["exempt", "pypi:Foo_Bar", "--reason", "first"], repo, env);
    run(["exempt", "pypi:foo-bar", "--reason", "second"], repo, env);
    const file = loadDgFile(repo);
    expect(file.cooldownExemptions).toHaveLength(1);
    expect(file.cooldownExemptions[0]?.name).toBe("foo-bar");
    expect(file.cooldownExemptions[0]?.reason).toBe("second");
  });

  it("removes a hand-edited non-canonical pypi exemption via the canonical name", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    writeFileSync(
      dgFilePath(repo),
      JSON.stringify({ version: 1, cooldownExemptions: [{ ecosystem: "pypi", name: "Flask.SQLAlchemy", reason: "hand", acceptedBy: "x", acceptedAt: "2026-01-01T00:00:00.000Z" }] })
    );
    const result = run(["rm", "pypi:flask-sqlalchemy"], repo, env);
    expect(result.exitCode).toBe(0);
    expect(loadDgFile(repo).cooldownExemptions).toHaveLength(0);
  });

  it("rejects an invalid package name (spaces, control chars, glob) instead of storing a dead entry", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    for (const bad of ["foo bar", "@scope/*"]) {
      const result = run(["exempt", bad], repo, env);
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain("not a valid package name");
    }
    expect(loadDgFile(repo).cooldownExemptions).toHaveLength(0);
  });

  it("rejects an unsupported ecosystem prefix instead of storing a literal colon-name", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["exempt", "maven:foo"], repo, env);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("unknown ecosystem prefix");
    expect(loadDgFile(repo).cooldownExemptions).toHaveLength(0);
  });

  it("supports cargo exemptions (committable dg.json escape hatch for crates.io cooldown)", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["exempt", "cargo:serde"], repo, env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Exempted cargo:serde");
    expect(loadDgFile(repo).cooldownExemptions[0]).toMatchObject({ ecosystem: "cargo", name: "serde" });
  });

  it("shows hour granularity for a sub-day --expires window", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["exempt", "fresh", "--expires", "1h"], repo, env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toMatch(/until 2026-06-10 01:00Z/);
  });

  it("reports an over-cap --expires as too large, not malformed", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["exempt", "x", "--expires", "10000d"], repo, env);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("too large");
  });

  it("computes an expiry from --expires and reports the date", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["exempt", "requests", "--ecosystem", "pypi", "--expires", "30d"], repo, env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("until 2026-07-10");
    const file = loadDgFile(repo);
    expect(file.cooldownExemptions[0]?.expiresAt).toBe("2026-07-10T00:00:00.000Z");
  });

  it("rejects a non-positive --expires duration", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["exempt", "left-pad", "--expires", "garbage"], repo, env);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("--expires must be a positive duration");
  });

  it("re-exempting the same package replaces the prior entry", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    run(["exempt", "left-pad", "--reason", "first"], repo, env);
    run(["exempt", "left-pad", "--reason", "second"], repo, env);
    const file = loadDgFile(repo);
    expect(file.cooldownExemptions).toHaveLength(1);
    expect(file.cooldownExemptions[0]?.reason).toBe("second");
  });

  it("shows currently held packages with their release times and hides released ones", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const seeded = new Date("2026-06-09T23:00:00.000Z");
    recordHeldPackage({
      ecosystem: "npm", name: "left-pad", version: "2.0.1", requiredDays: 1,
      publishedAt: "2026-06-09T18:00:00.000Z", eligibleAt: "2026-06-10T18:00:00.000Z"
    }, env, seeded);
    recordHeldPackage({
      ecosystem: "pypi", name: "released", version: "1.0.0", requiredDays: 1,
      publishedAt: "2026-06-08T00:00:00.000Z", eligibleAt: "2026-06-09T00:00:00.000Z"
    }, env, seeded);
    const result = run(["list"], repo, env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Currently held:");
    expect(result.stdout).toContain("npm:left-pad@2.0.1");
    expect(result.stdout).toContain("2026-06-10 (in 18h)");
    expect(result.stdout).not.toContain("released");
    expect(result.stdout).toContain("release now: dg cooldown exempt");
  });

  it("shows an empty held state when nothing is waiting", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const result = run(["list"], initRepo(env), env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Currently held: none.");
  });

  it("includes held packages in --json output", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    recordHeldPackage({
      ecosystem: "npm", name: "left-pad", version: "2.0.1", requiredDays: 1,
      eligibleAt: "2026-06-10T18:00:00.000Z"
    }, env, new Date("2026-06-09T23:00:00.000Z"));
    const result = run(["--json"], repo, env);
    expect(result.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout) as { held: Array<{ name: string; eligibleAt: string }> };
    expect(parsed.held).toHaveLength(1);
    expect(parsed.held[0]?.name).toBe("left-pad");
    expect(parsed.held[0]?.eligibleAt).toBe("2026-06-10T18:00:00.000Z");
  });

  it("lists active and expired exemptions in a table", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    writeFileSync(
      dgFilePath(repo),
      JSON.stringify({
        version: 1,
        cooldownExemptions: [
          { ecosystem: "npm", name: "left-pad", reason: "vendored", acceptedBy: "alice@example.com", acceptedAt: "2026-06-01T00:00:00.000Z" },
          { ecosystem: "pypi", name: "old", reason: "", acceptedBy: "bob", acceptedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2026-02-01T00:00:00.000Z" }
        ]
      })
    );
    const result = run(["list"], repo, env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("npm:left-pad");
    expect(result.stdout).toContain("active");
    expect(result.stdout).toContain("pypi:old");
    expect(result.stdout).toContain("expired");
  });

  it("lists as JSON with --json", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    writeFileSync(
      dgFilePath(repo),
      JSON.stringify({ version: 1, cooldownExemptions: [{ ecosystem: "npm", name: "left-pad", reason: "x", acceptedBy: "alice", acceptedAt: "2026-06-01T00:00:00.000Z" }] })
    );
    const result = run(["--json"], repo, env);
    expect(result.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout) as { schemaVersion: number; cooldownExemptions: Array<{ name: string; status: string }> };
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.cooldownExemptions[0]?.name).toBe("left-pad");
    expect(parsed.cooldownExemptions[0]?.status).toBe("active");
  });

  it("removes an exemption and preserves unrelated keys", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    writeFileSync(
      dgFilePath(repo),
      JSON.stringify({
        version: 1,
        scriptApprovals: { keep: true },
        cooldownExemptions: [
          { ecosystem: "npm", name: "left-pad", reason: "x", acceptedBy: "alice", acceptedAt: "2026-06-01T00:00:00.000Z" },
          { ecosystem: "npm", name: "other", reason: "y", acceptedBy: "alice", acceptedAt: "2026-06-01T00:00:00.000Z" }
        ]
      })
    );
    const result = run(["rm", "left-pad"], repo, env);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("cooldown applies again");
    const file = loadDgFile(repo);
    expect(file.cooldownExemptions).toHaveLength(1);
    expect(file.cooldownExemptions[0]?.name).toBe("other");
    const raw = JSON.parse(readFileSync(dgFilePath(repo), "utf8")) as Record<string, unknown>;
    expect(raw.scriptApprovals).toEqual({ keep: true });
  });

  it("exits 1 when removing a package that is not exempt", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const repo = initRepo(env);
    const result = run(["rm", "left-pad"], repo, env);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("is not exempt");
  });

  it("rejects unknown subcommands", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const result = run(["nuke"], initRepo(env), env);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("unknown subcommand");
  });
});
