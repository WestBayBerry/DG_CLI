import { PassThrough } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { maybePreflightInstallPrompt } from "../../src/launcher/preflight-prompt.js";
import { decideFromVerdicts, resetInstallPreflightSession } from "../../src/launcher/install-preflight.js";
import type { AnalyzeResponse, ScannerAction } from "../../src/api/analyze.js";

const tempRoots: string[] = [];

async function tempHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-preflight-"));
  tempRoots.push(root);
  return root;
}

function io(answer: string | null) {
  const input = new PassThrough();
  const output = new PassThrough();
  if (answer !== null) {
    queueMicrotask(() => input.write(answer));
  }
  return { input, output, isTTY: answer !== null };
}

function written(output: PassThrough): string {
  const chunk = output.read() as Buffer | null;
  return chunk ? chunk.toString("utf8") : "";
}

function analyzeReturning(action: ScannerAction, name: string, version: string): () => Promise<AnalyzeResponse> {
  return async () => ({
    score: action === "block" ? 95 : action === "warn" ? 64 : 0,
    action,
    packages: [
      {
        name,
        version,
        score: 64,
        action,
        findings: [{ severity: 3, title: "install lifecycle script" }],
        reasons: ["install lifecycle script"],
        cached: false
      }
    ],
    safeVersions: {},
    durationMs: 5
  });
}

describe("maybePreflightInstallPrompt", () => {
  beforeEach(() => {
    resetInstallPreflightSession();
  });

  afterEach(async () => {
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
  });

  it("falls through when not a TTY", async () => {
    const result = await maybePreflightInstallPrompt(["npm", "install", "left-pad@1.3.0"], {
      env: { HOME: await tempHome() },
      io: io(null),
      analyze: analyzeReturning("block", "left-pad", "1.3.0")
    });
    expect(result.handled).toBe(false);
  });

  it("falls through for unpinned installs", async () => {
    const result = await maybePreflightInstallPrompt(["npm", "install", "left-pad"], {
      env: { HOME: await tempHome() },
      io: io("y\n"),
      analyze: analyzeReturning("block", "left-pad", "1.3.0")
    });
    expect(result.handled).toBe(false);
  });

  it("blocks a malware verdict before spawn with exit 2", async () => {
    const result = await maybePreflightInstallPrompt(["npm", "install", "left-pad@1.3.0"], {
      env: { HOME: await tempHome() },
      io: io("\n"),
      analyze: analyzeReturning("block", "left-pad", "1.3.0")
    });
    expect(result.handled).toBe(true);
    if (result.handled) {
      expect(result.result.exitCode).toBe(2);
      expect(result.result.stderr).toContain("DG blocked install");
    }
  });

  it("prompts on warn with decline-by-default and cancels on Enter", async () => {
    const promptIo = io("\n");
    const result = await maybePreflightInstallPrompt(["npm", "install", "left-pad@1.3.0"], {
      env: { HOME: await tempHome() },
      io: promptIo,
      analyze: analyzeReturning("warn", "left-pad", "1.3.0")
    });
    expect(result.handled).toBe(true);
    if (result.handled) {
      expect(result.result.exitCode).toBe(1);
      expect(result.result.stderr).toContain("Nothing was installed");
    }
    const rendered = written(promptIo.output);
    expect(rendered).toContain("(warn)");
    expect(rendered).toContain("[y/N]");
  });

  it("prompts on warn and proceeds on yes", async () => {
    const result = await maybePreflightInstallPrompt(["npm", "install", "left-pad@1.3.0"], {
      env: { HOME: await tempHome() },
      io: io("y\n"),
      analyze: analyzeReturning("warn", "left-pad", "1.3.0")
    });
    expect(result.handled).toBe(false);
  });

  it("labels analysis-incomplete with its own copy and proceeds by default", async () => {
    const promptIo = io("\n");
    const result = await maybePreflightInstallPrompt(["npm", "install", "left-pad@1.3.0"], {
      env: { HOME: await tempHome() },
      io: promptIo,
      analyze: analyzeReturning("analysis_incomplete", "left-pad", "1.3.0")
    });
    expect(result.handled).toBe(false);
    const rendered = written(promptIo.output);
    expect(rendered).toContain("analysis incomplete");
    expect(rendered).toContain("could not fully analyze");
    expect(rendered).toContain("[Y/n]");
    expect(rendered).not.toContain("(warn)");
  });

  it("exits 4 when an analysis-incomplete prompt is declined", async () => {
    const result = await maybePreflightInstallPrompt(["npm", "install", "left-pad@1.3.0"], {
      env: { HOME: await tempHome() },
      io: io("n\n"),
      analyze: analyzeReturning("analysis_incomplete", "left-pad", "1.3.0")
    });
    expect(result.handled).toBe(true);
    if (result.handled) {
      expect(result.result.exitCode).toBe(4);
      expect(result.result.stderr).toContain("Nothing was installed");
    }
  });

  it("does not re-prompt in the pip preflight after the pinned-spec confirm", async () => {
    const result = await maybePreflightInstallPrompt(["pip", "install", "leftish==1.2.3"], {
      env: { HOME: await tempHome() },
      io: io("y\n"),
      analyze: analyzeReturning("warn", "leftish", "1.2.3")
    });
    expect(result.handled).toBe(false);

    const promptIo = io("n");
    const decision = await decideFromVerdicts(
      [
        {
          name: "leftish",
          version: "1.2.3",
          score: 64,
          action: "warn",
          findings: [],
          reasons: ["install lifecycle script"],
          cached: false
        }
      ],
      promptIo
    );
    expect(decision.proceed).toBe(true);
    expect(written(promptIo.output)).toBe("");
  });

  it("matches pypi names PEP 503-insensitively so a normalized scanner echo still prompts", async () => {
    const result = await maybePreflightInstallPrompt(["pip", "install", "Foo_Bar==1.0.0"], {
      env: { HOME: await tempHome() },
      io: io("\n"),
      analyze: analyzeReturning("warn", "foo-bar", "1.0.0")
    });
    expect(result.handled).toBe(true);
    if (result.handled) {
      expect(result.result.exitCode).toBe(1);
      expect(result.result.stderr).toContain("Nothing was installed");
    }
  });

  it("parses pip pinned specs and pass falls through", async () => {
    const result = await maybePreflightInstallPrompt(["pip", "install", "requests==2.0.0"], {
      env: { HOME: await tempHome() },
      io: io("y\n"),
      analyze: analyzeReturning("pass", "requests", "2.0.0")
    });
    expect(result.handled).toBe(false);
  });

  it("prints the provenance downgrade alarm even when the verdict is pass", async () => {
    const promptIo = io("y\n");
    const analyze = async (): Promise<AnalyzeResponse> => ({
      score: 0,
      action: "pass",
      packages: [
        {
          name: "left-pad",
          version: "1.3.0",
          score: 0,
          action: "pass",
          findings: [],
          reasons: [],
          cached: false,
          provenance: { status: "none", downgrade: { fromVersion: "1.2.0" } }
        }
      ],
      safeVersions: {},
      durationMs: 5
    });
    const result = await maybePreflightInstallPrompt(["npm", "install", "left-pad@1.3.0"], {
      env: { HOME: await tempHome() },
      io: promptIo,
      analyze
    });
    expect(result.handled).toBe(false);
    const rendered = written(promptIo.output);
    expect(rendered).toContain("left-pad@1.3.0: provenance downgraded — 1.2.0 was attested, 1.3.0 is not");
    expect(rendered).not.toContain("[y/N]");
  });
});
