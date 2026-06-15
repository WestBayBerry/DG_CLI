import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { dgVersion } from "../../src/commands/version.js";
import { applyGitHook, resolveGitRepo, type GitRepoContext } from "../../src/setup/git-hook.js";
import { doctorReport, doctorReportWithRemote, shimSource } from "../../src/setup/plan.js";
import { runAgentsCommand } from "../../src/commands/agents.js";

const made: string[] = [];
let previousLatest: string | undefined;

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}

function baseEnv(home: string): NodeJS.ProcessEnv {
  return {
    HOME: home,
    SHELL: "/bin/bash",
    PATH: "/usr/bin:/bin",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null"
  };
}

function fetchReturning(status: number, urls: string[] = []): typeof fetch {
  return (async (input: string | URL | Request) => {
    urls.push(String(input));
    return new Response("ok", { status });
  }) as typeof fetch;
}

function ctxOrThrow(value: GitRepoContext | { error: string }): GitRepoContext {
  if ("error" in value) {
    throw new Error(value.error);
  }
  return value;
}

function initRepo(env: NodeJS.ProcessEnv): string {
  const repo = tempDir("dg-doctor-repo-");
  spawnSync("git", ["init", "-q"], { cwd: repo, env, encoding: "utf8" });
  return repo;
}

function fakeDg(dir: string): string {
  const path = join(dir, "fake-dg");
  writeFileSync(path, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  chmodSync(path, 0o755);
  return path;
}

function writeExecutable(path: string, body: string): void {
  writeFileSync(path, body, { mode: 0o755 });
  chmodSync(path, 0o755);
}

beforeEach(() => {
  previousLatest = process.env.DG_UPDATE_LATEST_VERSION;
  process.env.DG_UPDATE_LATEST_VERSION = dgVersion();
});

afterEach(() => {
  if (previousLatest === undefined) {
    delete process.env.DG_UPDATE_LATEST_VERSION;
  } else {
    process.env.DG_UPDATE_LATEST_VERSION = previousLatest;
  }
  for (const dir of made.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("doctor api reachability", () => {
  it("reports the configured baseUrl and latency when /health responds", async () => {
    const urls: string[] = [];
    const report = await doctorReportWithRemote({ env: baseEnv(tempDir("dg-doctor-home-")), fetchImpl: fetchReturning(200, urls) });
    const api = report.checks.find((check) => check.name === "api");

    expect(urls).toEqual(["https://api.westbayberry.com/health"]);
    expect(api?.status).toBe("pass");
    expect(api?.message).toMatch(/https:\/\/api\.westbayberry\.com\/health responded 200 in \d+ms/);
    expect(api?.group).toBe("account");
  });

  it("warns with the http status when /health responds non-2xx", async () => {
    const report = await doctorReportWithRemote({ env: baseEnv(tempDir("dg-doctor-home-")), fetchImpl: fetchReturning(503) });
    const api = report.checks.find((check) => check.name === "api");

    expect(api?.status).toBe("warn");
    expect(api?.message).toContain("responded 503");
  });

  it("warns with the underlying network error when the API is unreachable", async () => {
    const fetchDown = (async () => {
      throw new TypeError("fetch failed", { cause: new Error("connect ECONNREFUSED 127.0.0.1:443") });
    }) as typeof fetch;
    const report = await doctorReportWithRemote({ env: baseEnv(tempDir("dg-doctor-home-")), fetchImpl: fetchDown });
    const api = report.checks.find((check) => check.name === "api");

    expect(api?.status).toBe("warn");
    expect(api?.message).toContain("ECONNREFUSED");
    expect(api?.fix).toContain("api.baseUrl");
  });
});

describe("doctor version freshness", () => {
  it("warns when a newer version is published", async () => {
    process.env.DG_UPDATE_LATEST_VERSION = "999.0.0";
    const report = await doctorReportWithRemote({ env: baseEnv(tempDir("dg-doctor-home-")), fetchImpl: fetchReturning(200) });
    const update = report.checks.find((check) => check.name === "update");

    expect(update?.status).toBe("warn");
    expect(update?.message).toContain("999.0.0");
    expect(update?.message).toContain(dgVersion());
    expect(update?.fix).toBe("dg update");
  });

  it("passes when the local version is the latest", async () => {
    const report = await doctorReportWithRemote({ env: baseEnv(tempDir("dg-doctor-home-")), fetchImpl: fetchReturning(200) });
    const update = report.checks.find((check) => check.name === "update");

    expect(update?.status).toBe("pass");
    expect(update?.message).toContain(`dg ${dgVersion()} is the latest`);
  });

  it("keeps the synchronous report free of remote checks", () => {
    const report = doctorReport({ env: baseEnv(tempDir("dg-doctor-home-")) });

    expect(report.checks.some((check) => check.name === "api")).toBe(false);
    expect(report.checks.some((check) => check.name === "update")).toBe(false);
  });
});

describe("doctor commit-guard presence", () => {
  it("reports no installed guard as informational", () => {
    const check = doctorReport({ env: baseEnv(tempDir("dg-doctor-home-")) }).checks.find(
      (candidate) => candidate.name === "commit-guard"
    );

    expect(check?.status).toBe("pass");
    expect(check?.message).toContain("No commit guard installed");
  });

  it("passes with an installed hook and runnable dg, then warns when dg disappears", () => {
    const env = baseEnv(tempDir("dg-doctor-home-"));
    const repo = initRepo(env);
    const dgPath = fakeDg(repo);
    applyGitHook(ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath })));

    const installed = doctorReport({ env }).checks.find((check) => check.name === "commit-guard");
    expect(installed?.status).toBe("pass");
    expect(installed?.message).toContain("1 repo");

    rmSync(dgPath);
    const broken = doctorReport({ env }).checks.find((check) => check.name === "commit-guard");
    expect(broken?.status).toBe("warn");
    expect(broken?.message).toContain("fail open");
  });

  it("warns when the registered hook file is gone", () => {
    const env = baseEnv(tempDir("dg-doctor-home-"));
    const repo = initRepo(env);
    const ctx = ctxOrThrow(resolveGitRepo({ cwd: repo, env, dgPath: fakeDg(repo) }));
    applyGitHook(ctx);
    rmSync(ctx.hookTarget);

    const check = doctorReport({ env }).checks.find((candidate) => candidate.name === "commit-guard");
    expect(check?.status).toBe("warn");
    expect(check?.message).toContain(ctx.hookTarget);
  });
});

describe("doctor non-interactive PATH shadowing", () => {
  it("warns when a version manager bin dir resolves a shimmed command first", () => {
    const home = tempDir("dg-doctor-home-");
    const shimDir = join(home, ".dg", "shims");
    mkdirSync(shimDir, { recursive: true });
    writeExecutable(join(shimDir, "npm"), shimSource("npm"));
    const nvmBin = join(home, ".nvm", "versions", "node", "v22.0.0", "bin");
    mkdirSync(nvmBin, { recursive: true });
    writeExecutable(join(nvmBin, "npm"), "#!/bin/sh\nexit 0\n");
    const env = { ...baseEnv(home), PATH: `${nvmBin}:${shimDir}` };

    const check = doctorReport({ env }).checks.find((candidate) => candidate.name === "path-noninteractive");
    expect(check?.status).toBe("warn");
    expect(check?.message).toContain(`npm from ${nvmBin} (nvm) at PATH position 1`);
    expect(check?.message).toContain("PATH position 2");
    expect(check?.fix).toContain(shimDir);
    expect(check?.fix).toContain(nvmBin);
  });

  it("passes when the dg shims win for every resolvable command", () => {
    const home = tempDir("dg-doctor-home-");
    const shimDir = join(home, ".dg", "shims");
    mkdirSync(shimDir, { recursive: true });
    writeExecutable(join(shimDir, "npm"), shimSource("npm"));
    const nvmBin = join(home, ".nvm", "versions", "node", "v22.0.0", "bin");
    mkdirSync(nvmBin, { recursive: true });
    writeExecutable(join(nvmBin, "npm"), "#!/bin/sh\nexit 0\n");
    const env = { ...baseEnv(home), PATH: `${shimDir}:${nvmBin}` };

    const check = doctorReport({ env }).checks.find((candidate) => candidate.name === "path-noninteractive");
    expect(check?.status).toBe("pass");
    expect(check?.message).toContain(shimDir);
  });

  it("warns when the shim dir is missing from PATH entirely", () => {
    const home = tempDir("dg-doctor-home-");
    const nvmBin = join(home, ".nvm", "versions", "node", "v22.0.0", "bin");
    mkdirSync(nvmBin, { recursive: true });
    writeExecutable(join(nvmBin, "npm"), "#!/bin/sh\nexit 0\n");
    const env = { ...baseEnv(home), PATH: nvmBin };

    const check = doctorReport({ env }).checks.find((candidate) => candidate.name === "path-noninteractive");
    expect(check?.status).toBe("warn");
    expect(check?.message).toContain("is not on PATH");
  });
});

describe("doctor script-gate state", () => {
  function writeDoctorConfig(home: string, config: Record<string, unknown>): void {
    mkdirSync(join(home, ".dg"), { recursive: true });
    writeFileSync(join(home, ".dg", "config.json"), JSON.stringify(config), "utf8");
  }

  it("reports observe mode as the default gate state", () => {
    const check = doctorReport({ env: baseEnv(tempDir("dg-doctor-home-")) }).checks.find(
      (candidate) => candidate.name === "script-gate"
    );

    expect(check?.status).toBe("pass");
    expect(check?.group).toBe("setup");
    expect(check?.message).toContain("observes");
    expect(check?.message).toContain("pnpm");
  });

  it("reports an off gate as off", () => {
    const home = tempDir("dg-doctor-home-");
    writeDoctorConfig(home, { scriptGate: { mode: "off" } });

    const check = doctorReport({ env: baseEnv(home) }).checks.find((candidate) => candidate.name === "script-gate");
    expect(check?.status).toBe("pass");
    expect(check?.message).toContain("Install-script gate is off");
  });

  it("reports enforce as actively gating install scripts", () => {
    const home = tempDir("dg-doctor-home-");
    writeDoctorConfig(home, { scriptGate: { mode: "enforce" } });

    const check = doctorReport({ env: baseEnv(home) }).checks.find((candidate) => candidate.name === "script-gate");
    expect(check?.status).toBe("pass");
    expect(check?.message).toContain("enforces");
    expect(check?.message).toContain("--ignore-scripts");
  });

  it("warns when api.baseUrl has been repointed away from the default verdict source", () => {
    const home = tempDir("dg-doctor-home-");
    writeDoctorConfig(home, { api: { baseUrl: "https://evil.example.com" } });

    const check = doctorReport({ env: baseEnv(home) }).checks.find((candidate) => candidate.name === "config");
    expect(check?.status).toBe("warn");
    expect(check?.message).toContain("non-default API endpoint");
    expect(check?.message).toContain("evil.example.com");
  });

  it("keeps config as pass on the default api.baseUrl", () => {
    const home = tempDir("dg-doctor-home-");
    writeDoctorConfig(home, { scriptGate: { mode: "off" } });

    const check = doctorReport({ env: baseEnv(home) }).checks.find((candidate) => candidate.name === "config");
    expect(check?.status).toBe("pass");
  });
});

describe("doctor agent-gate posture", () => {
  it("is gated/unavailable when no agent carries the dg hook", () => {
    const check = doctorReport({ env: baseEnv(tempDir("dg-doctor-home-")) }).checks.find(
      (candidate) => candidate.name === "agent-gate"
    );
    expect(check?.status).toBe("unavailable");
    expect(check?.group).toBe("gated");
  });

  it("warns loudly when an agent is hooked but the network gate is off", async () => {
    const home = tempDir("dg-doctor-home-");
    mkdirSync(join(home, ".claude"), { recursive: true });
    const env = baseEnv(home);
    await runAgentsCommand(["on", "claude-code"], env, home);

    const check = doctorReport({ env }).checks.find((candidate) => candidate.name === "agent-gate");
    expect(check?.status).toBe("warn");
    expect(check?.message).toContain("Claude Code");
    expect(check?.message).toContain("network gate is OFF");
    expect(check?.fix).toContain("dg service start");
  });
});
