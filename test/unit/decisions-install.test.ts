import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { decideFromVerdicts, resetInstallPreflightSession, type PreflightDecisionContext } from "../../src/launcher/install-preflight.js";
import { maybePreflightInstallPrompt } from "../../src/launcher/preflight-prompt.js";
import { dgFilePath, loadDgFile } from "../../src/project/dgfile.js";
import type { AnalyzeResponse, ScannerPackageResult } from "../../src/api/analyze.js";

const made: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}

beforeEach(() => {
  resetInstallPreflightSession();
});

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
  const repo = tempDir("dg-install-repo-");
  spawnSync("git", ["init", "-q"], { cwd: repo, env, encoding: "utf8" });
  return repo;
}

function acceptedEntry(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "99998888-7777-6666-5555-444433332222",
    ecosystem: "pypi",
    name: "leftish",
    scope: { kind: "exact", version: "1.2.3" },
    findings: { lifecycle: 3 },
    reason: "vetted",
    acceptedBy: "alice@example.com",
    acceptedAt: "2026-06-01T00:00:00.000Z",
    ...over
  };
}

function pkg(over: Partial<ScannerPackageResult> = {}): ScannerPackageResult {
  return {
    name: "leftish",
    version: "1.2.3",
    score: 64,
    action: "warn",
    findings: [{ severity: 3, category: "lifecycle" }],
    reasons: ["install lifecycle script"],
    cached: false,
    ...over
  };
}

function io(): { input: PassThrough; output: PassThrough; isTTY: true } {
  return { input: new PassThrough(), output: new PassThrough(), isTTY: true };
}

function written(output: PassThrough): string {
  const chunk = output.read() as Buffer | null;
  return chunk ? chunk.toString("utf8") : "";
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function feed(input: PassThrough, answers: readonly string[]): Promise<void> {
  for (const answer of answers) {
    await sleep(30);
    input.write(`${answer}\n`);
  }
}

function context(root: string, env: NodeJS.ProcessEnv, ecosystem: "npm" | "pypi" = "pypi"): PreflightDecisionContext {
  return { root, file: loadDgFile(root), ecosystem, env };
}

describe("decideFromVerdicts with decision memory", () => {
  it("a covered warn proceeds without prompting and names the acceptor", async () => {
    const env = baseEnv(tempDir("dg-home-"));
    const root = tempDir("dg-root-");
    writeFileSync(dgFilePath(root), JSON.stringify({ version: 1, decisions: [acceptedEntry()] }));
    const promptIo = io();

    const result = await decideFromVerdicts([pkg()], promptIo, undefined, context(root, env));
    expect(result).toEqual({ proceed: true });
    const rendered = written(promptIo.output);
    expect(rendered).toContain("previously accepted by alice@example.com");
    expect(rendered).not.toContain("Proceed?");
  });

  it("a new finding category on the accepted version re-prompts", async () => {
    const env = baseEnv(tempDir("dg-home-"));
    const root = tempDir("dg-root-");
    writeFileSync(dgFilePath(root), JSON.stringify({ version: 1, decisions: [acceptedEntry()] }));
    const promptIo = io();
    promptIo.input.write("n\n");

    const result = await decideFromVerdicts(
      [pkg({ findings: [{ severity: 3, category: "lifecycle" }, { severity: 4, category: "network_exfil" }] })],
      promptIo,
      undefined,
      context(root, env)
    );
    expect(result.proceed).toBe(false);
    expect(written(promptIo.output)).toContain("Proceed?");
  });

  it("a block is never covered by an entry", async () => {
    const env = baseEnv(tempDir("dg-home-"));
    const root = tempDir("dg-root-");
    writeFileSync(
      dgFilePath(root),
      JSON.stringify({ version: 1, decisions: [acceptedEntry({ scope: { kind: "any" }, findings: { malware: 5 } })] })
    );
    const promptIo = io();
    promptIo.input.write("n\n");

    const result = await decideFromVerdicts(
      [pkg({ action: "block", findings: [{ severity: 5, category: "malware" }] })],
      promptIo,
      undefined,
      context(root, env)
    );
    expect(result.proceed).toBe(false);
    expect(written(promptIo.output)).toContain("Override and install anyway?");
  });

  it("remember 'this version' creates dg.json after the confirm and records the acceptance", async () => {
    const home = tempDir("dg-home-");
    const env = baseEnv(home);
    const root = tempDir("dg-root-");
    const promptIo = io();

    const pending = decideFromVerdicts([pkg()], promptIo, undefined, context(root, env));
    await feed(promptIo.input, ["y", "v", "y", "ran it in a sandbox"]);
    const result = await pending;

    expect(result).toEqual({ proceed: true });
    const file = loadDgFile(root);
    expect(file.exists).toBe(true);
    expect(file.decisions).toHaveLength(1);
    expect(file.decisions[0]?.ecosystem).toBe("pypi");
    expect(file.decisions[0]?.scope).toEqual({ kind: "exact", version: "1.2.3" });
    expect(file.decisions[0]?.findings).toEqual({ lifecycle: 3 });
    expect(file.decisions[0]?.reason).toBe("ran it in a sandbox");
    expect(written(promptIo.output)).toContain("remembered in");
  });

  it("remember 'just once' writes nothing", async () => {
    const env = baseEnv(tempDir("dg-home-"));
    const root = tempDir("dg-root-");
    const promptIo = io();

    const pending = decideFromVerdicts([pkg()], promptIo, undefined, context(root, env));
    await feed(promptIo.input, ["y", "o"]);
    const result = await pending;

    expect(result).toEqual({ proceed: true });
    expect(loadDgFile(root).exists).toBe(false);
  });
});

describe("pinned-spec preflight with decision memory", () => {
  function analyzeWarn(findings: ScannerPackageResult["findings"]): () => Promise<AnalyzeResponse> {
    return async () => ({
      score: 64,
      action: "warn",
      packages: [pkg({ name: "left-pad", version: "1.3.0", findings })],
      safeVersions: {},
      durationMs: 5
    });
  }

  it("a covered warn skips the prompt and falls through to the real install", async () => {
    const home = tempDir("dg-home-");
    const env = baseEnv(home);
    const repo = initRepo(env);
    writeFileSync(
      dgFilePath(repo),
      JSON.stringify({ version: 1, decisions: [acceptedEntry({ ecosystem: "npm", name: "left-pad", scope: { kind: "exact", version: "1.3.0" } })] })
    );
    const promptIo = io();

    const result = await maybePreflightInstallPrompt(["npm", "install", "left-pad@1.3.0"], {
      env,
      io: promptIo,
      analyze: analyzeWarn([{ severity: 3, category: "lifecycle" }]),
      decisionsCwd: repo
    });
    expect(result.handled).toBe(false);
    const rendered = written(promptIo.output);
    expect(rendered).toContain("previously accepted by alice@example.com");
    expect(rendered).not.toContain("Proceed?");
  });

  it("a severity escalation re-prompts despite the acceptance", async () => {
    const home = tempDir("dg-home-");
    const env = baseEnv(home);
    const repo = initRepo(env);
    writeFileSync(
      dgFilePath(repo),
      JSON.stringify({ version: 1, decisions: [acceptedEntry({ ecosystem: "npm", name: "left-pad", scope: { kind: "exact", version: "1.3.0" } })] })
    );
    const promptIo = io();
    promptIo.input.write("\n");

    const result = await maybePreflightInstallPrompt(["npm", "install", "left-pad@1.3.0"], {
      env,
      io: promptIo,
      analyze: analyzeWarn([{ severity: 4, category: "lifecycle" }]),
      decisionsCwd: repo
    });
    expect(result.handled).toBe(true);
    if (result.handled) {
      expect(result.result.exitCode).toBe(1);
    }
    expect(written(promptIo.output)).toContain("Proceed?");
  });

  it("after a manual proceed the remember choice persists the acceptance", async () => {
    const home = tempDir("dg-home-");
    const env = baseEnv(home);
    const repo = initRepo(env);
    const promptIo = io();

    const pending = maybePreflightInstallPrompt(["npm", "install", "left-pad@1.3.0"], {
      env,
      io: promptIo,
      analyze: analyzeWarn([{ severity: 3, category: "lifecycle" }]),
      decisionsCwd: repo
    });
    await feed(promptIo.input, ["y", "v", "y", "audited the tarball"]);
    const result = await pending;

    expect(result.handled).toBe(false);
    const file = loadDgFile(repo);
    expect(file.decisions).toHaveLength(1);
    expect(file.decisions[0]?.ecosystem).toBe("npm");
    expect(file.decisions[0]?.name).toBe("left-pad");
    expect(file.decisions[0]?.reason).toBe("audited the tarball");
  });

  it("without a git repository the prompt degrades to session-only behavior", async () => {
    const home = tempDir("dg-home-");
    const env = baseEnv(home);
    const notRepo = tempDir("dg-norepo-");
    const promptIo = io();
    promptIo.input.write("y\n");

    const result = await maybePreflightInstallPrompt(["npm", "install", "left-pad@1.3.0"], {
      env,
      io: promptIo,
      analyze: analyzeWarn([{ severity: 3, category: "lifecycle" }]),
      decisionsCwd: notRepo
    });
    expect(result.handled).toBe(false);
    expect(written(promptIo.output)).not.toContain("Remember");
  });
});
