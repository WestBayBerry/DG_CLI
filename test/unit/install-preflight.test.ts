import { PassThrough } from "node:stream";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cachedPipResolution,
  decideFromVerdicts,
  promptPreflightYesNo,
  recordPreflightApprovals,
  resetInstallPreflightSession,
  preverifiedEntries,
  runInstallPreflight
} from "../../src/launcher/install-preflight.js";
import type { PreflightCooldownContext } from "../../src/launcher/install-preflight.js";
import type { PromptIo } from "../../src/install-ui/prompt.js";
import type { ScannerCooldown, ScannerPackageResult } from "../../src/api/analyze.js";

const tempRoots: string[] = [];

async function tempHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-install-preflight-"));
  tempRoots.push(root);
  return root;
}

function pkg(name: string, action: ScannerPackageResult["action"], reason: string): ScannerPackageResult {
  return {
    name,
    version: "1.0.0",
    score: action === "block" ? 90 : 65,
    action,
    findings: [],
    reasons: [reason],
    cached: false
  };
}

function io(answer: string | null): PromptIo & { readonly output: PassThrough } {
  const input = new PassThrough();
  if (answer !== null) input.write(answer + "\n");
  return { input, output: new PassThrough(), isTTY: answer !== null };
}

function written(output: PassThrough): string {
  const chunk = output.read() as Buffer | null;
  return chunk ? chunk.toString("utf8") : "";
}

beforeEach(() => {
  resetInstallPreflightSession();
});

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("preverifiedEntries (preflight verdict handoff)", () => {
  const base = { score: 0, findings: [], reasons: [], cached: true } as const;

  it("maps pass/warn verdicts with sha and reason, and drops blocks and incompletes", () => {
    const entries = preverifiedEntries([
      { ...base, name: "requests", version: "2.32.0", action: "pass", artifactSha256: "a".repeat(64), cooldown: { status: "ok" } },
      { ...base, name: "leftpad", version: "1.0.0", action: "warn", reasons: ["sketchy"], cooldown: { status: "ok" } },
      { ...base, name: "evil", version: "0.0.1", action: "block", cooldown: { status: "ok" } },
      { ...base, name: "slow", version: "9.9.9", action: "analysis_incomplete", cooldown: { status: "ok" } }
    ], true);

    expect(entries).toEqual([
      { ecosystem: "pypi", name: "requests", version: "2.32.0", action: "pass", scannedSha256: "a".repeat(64), cooldownEvaluated: true },
      { ecosystem: "pypi", name: "leftpad", version: "1.0.0", action: "warn", reason: "sketchy", cooldownEvaluated: true }
    ]);
  });

  it("marks cooldown unevaluated when the param was not sent or the server returned no cooldown", () => {
    const noParam = preverifiedEntries([{ ...base, name: "a", version: "1", action: "pass", cooldown: { status: "ok" } }], false);
    expect(noParam[0]?.cooldownEvaluated).toBe(false);
    const noEcho = preverifiedEntries([{ ...base, name: "a", version: "1", action: "pass" }], true);
    expect(noEcho[0]?.cooldownEvaluated).toBe(false);
  });
});

describe("decideFromVerdicts (pre-install confirm)", () => {
  it("proceeds without prompting when nothing is flagged", async () => {
    const res = await decideFromVerdicts([pkg("requests", "pass", "clean")], io(""));
    expect(res).toEqual({ proceed: true });
  });

  it("warn: Enter declines (decline-by-default)", async () => {
    const promptIo = io("");
    const res = await decideFromVerdicts([pkg("scipy", "warn", "composite_metadata_scoring")], promptIo);
    expect(res.proceed).toBe(false);
    expect(written(promptIo.output)).toContain("[y/N]");
  });

  it("warn: 'y' proceeds with no force override", async () => {
    const res = await decideFromVerdicts([pkg("scipy", "warn", "x")], io("y"));
    expect(res.proceed).toBe(true);
    expect(res.forceOverride).toBeUndefined();
  });

  it("warn: 'n' aborts the install", async () => {
    const res = await decideFromVerdicts([pkg("scipy", "warn", "x")], io("n"));
    expect(res.proceed).toBe(false);
  });

  it("block: Enter (default no) declines — no override", async () => {
    const promptIo = io("");
    const res = await decideFromVerdicts([pkg("evil", "block", "malware")], promptIo);
    expect(res.proceed).toBe(false);
    expect(written(promptIo.output)).toContain("[y/N]");
  });

  it("block: 'y' proceeds WITH a force override so the proxy lets it through", async () => {
    const res = await decideFromVerdicts([pkg("evil", "block", "malware")], io("y"));
    expect(res.proceed).toBe(true);
    expect(res.forceOverride).toEqual({ force: true });
  });

  it("non-TTY never prompts (proceeds; the proxy still enforces during install)", async () => {
    const res = await decideFromVerdicts([pkg("evil", "block", "malware")], io(null));
    expect(res).toEqual({ proceed: true });
  });
});

describe("provenance downgrade alarm (display only)", () => {
  const downgraded = { status: "none", downgrade: { fromVersion: "1.2.0" } } as const;

  it("prints the alarm for a pass package and proceeds without prompting", async () => {
    const promptIo = io("");
    const res = await decideFromVerdicts(
      [{ ...pkg("left-pad", "pass", "clean"), provenance: downgraded }],
      promptIo
    );
    expect(res).toEqual({ proceed: true });
    const out = written(promptIo.output);
    expect(out).toContain("left-pad@1.0.0: provenance downgraded — 1.2.0 was attested, 1.0.0 is not");
    expect(out).toContain("verdict unchanged");
    expect(out).not.toContain("[y/N]");
  });

  it("prints the alarm alongside the warn prompt for a flagged downgraded package", async () => {
    const promptIo = io("n");
    const res = await decideFromVerdicts(
      [{ ...pkg("scipy", "warn", "composite_metadata_scoring"), provenance: downgraded }],
      promptIo
    );
    expect(res.proceed).toBe(false);
    const out = written(promptIo.output);
    expect(out).toContain("provenance downgraded — 1.2.0 was attested, 1.0.0 is not");
    expect(out).toContain("provenance: none");
  });

  it("suffixes attested provenance on flagged rows without any alarm", async () => {
    const promptIo = io("y");
    await decideFromVerdicts(
      [{ ...pkg("scipy", "warn", "x"), provenance: { status: "attested" as const } }],
      promptIo
    );
    const out = written(promptIo.output);
    expect(out).toContain("provenance: attested");
    expect(out).not.toContain("provenance downgraded");
  });

  it("stays silent for unknown or absent provenance", async () => {
    const promptIo = io("y");
    await decideFromVerdicts(
      [
        { ...pkg("scipy", "warn", "x"), provenance: { status: "unknown" as const } },
        pkg("requests", "pass", "clean")
      ],
      promptIo
    );
    const out = written(promptIo.output);
    expect(out).not.toContain("provenance:");
    expect(out).not.toContain("provenance downgraded");
  });

  it("writes nothing on a non-TTY stream", async () => {
    const promptIo = io(null);
    const res = await decideFromVerdicts(
      [{ ...pkg("left-pad", "pass", "clean"), provenance: downgraded }],
      promptIo
    );
    expect(res).toEqual({ proceed: true });
    expect(written(promptIo.output)).toBe("");
  });
});

describe("preflight approval dedupe (one decision per transaction)", () => {
  it("skips the prompt for a warn already approved this invocation", async () => {
    recordPreflightApprovals([{ name: "scipy", version: "1.0.0", action: "warn" }]);
    const promptIo = io("n");
    const res = await decideFromVerdicts([pkg("scipy", "warn", "x")], promptIo);
    expect(res.proceed).toBe(true);
    expect(written(promptIo.output)).toBe("");
  });

  it("an accepted warn records the approval for later preflights", async () => {
    const first = await decideFromVerdicts([pkg("left-pad", "warn", "x")], io("y"));
    expect(first.proceed).toBe(true);
    const second = await decideFromVerdicts([pkg("left-pad", "warn", "x")], io("n"));
    expect(second.proceed).toBe(true);
  });

  it("a warn approval does not cover a block on the same package", async () => {
    recordPreflightApprovals([{ name: "evil", version: "1.0.0", action: "warn" }]);
    const promptIo = io("n");
    const res = await decideFromVerdicts([pkg("evil", "block", "malware")], promptIo);
    expect(res.proceed).toBe(false);
    expect(written(promptIo.output)).toContain("Override and install anyway?");
  });

  it("still prompts for newly flagged packages not covered by the approval", async () => {
    recordPreflightApprovals([{ name: "scipy", version: "1.0.0", action: "warn" }]);
    const promptIo = io("n");
    const res = await decideFromVerdicts([pkg("scipy", "warn", "x"), pkg("numpyy", "warn", "typosquat")], promptIo);
    expect(res.proceed).toBe(false);
    const rendered = written(promptIo.output);
    expect(rendered).toContain("numpyy@1.0.0");
    expect(rendered).not.toContain("scipy@1.0.0");
  });
});

describe("cooldown quarantine in the preflight", () => {
  const context: PreflightCooldownContext = {
    param: { minAgeDays: 1, onUnknown: "allow" },
    exempt: "",
    ecosystem: "pypi"
  };

  function quarantinedPkg(name: string, cooldown: ScannerCooldown): ScannerPackageResult {
    return { ...pkg(name, "pass", "clean"), cooldown };
  }

  const freshCooldown: ScannerCooldown = { status: "quarantine", requiredDays: 1, ageDays: 0.125, eligibleAt: "2026-06-11T00:00:00.000Z" };

  it("renders a quarantined pass-action package with the cooldown tag and age summary", async () => {
    const promptIo = io("");
    const res = await decideFromVerdicts([quarantinedPkg("fresh-wheel", freshCooldown)], promptIo, context);
    expect(res.proceed).toBe(false);
    const rendered = written(promptIo.output);
    expect(rendered).toContain("fresh-wheel@1.0.0   cooldown   published 3h ago; cooldown 24h");
    expect(rendered).toContain("(1 blocked)");
    expect(rendered).toContain("Override and install anyway?");
  });

  it("'y' proceeds WITH a force override so the proxy cooldown block is overridden too", async () => {
    const res = await decideFromVerdicts([quarantinedPkg("fresh-wheel", freshCooldown)], io("y"), context);
    expect(res).toEqual({ proceed: true, forceOverride: { force: true } });
  });

  it("ignores ok and unknown annotations under the default fail-open policy", async () => {
    const promptIo = io("");
    const res = await decideFromVerdicts([
      quarantinedPkg("old-lib", { status: "ok", requiredDays: 1, ageDays: 400 }),
      quarantinedPkg("mirror-only", { status: "unknown", requiredDays: 1 })
    ], promptIo, context);
    expect(res).toEqual({ proceed: true });
    expect(written(promptIo.output)).toBe("");
  });

  it("flags unknown publish times when the user configured onUnknown=block", async () => {
    const blockContext: PreflightCooldownContext = { param: { minAgeDays: 1, onUnknown: "block" }, exempt: "", ecosystem: "pypi" };
    const promptIo = io("");
    const res = await decideFromVerdicts([quarantinedPkg("mirror-only", { status: "unknown", requiredDays: 1 })], promptIo, blockContext);
    expect(res.proceed).toBe(false);
    expect(written(promptIo.output)).toContain("publish time unknown; cooldown 24h");
  });

  it("honors cooldown.exempt with pypi name normalization", async () => {
    const exemptContext: PreflightCooldownContext = { param: { minAgeDays: 1, onUnknown: "allow" }, exempt: "Fresh_Wheel", ecosystem: "pypi" };
    const res = await decideFromVerdicts([quarantinedPkg("fresh-wheel", freshCooldown)], io(""), exemptContext);
    expect(res).toEqual({ proceed: true });
  });

  it("does not double-flag a server block that is also quarantined", async () => {
    const promptIo = io("");
    const blocked = { ...pkg("evil", "block", "malware"), cooldown: freshCooldown };
    const res = await decideFromVerdicts([blocked], promptIo, context);
    expect(res.proceed).toBe(false);
    const rendered = written(promptIo.output);
    expect(rendered).toContain("evil@1.0.0   block   malware");
    expect(rendered).not.toContain("evil@1.0.0   cooldown");
  });
});

describe("pip resolution cache", () => {
  it("resolves pip once per invocation and exposes the cached set and count", async () => {
    const home = await tempHome();
    const binDir = join(home, "bin");
    await mkdir(binDir, { recursive: true });
    const counterPath = join(home, "count");
    const report = JSON.stringify({ install: [{ metadata: { name: "requests", version: "2.31.0" } }, {}] });
    const pipPath = join(binDir, "fake-pip");
    await writeFile(pipPath, `#!/bin/sh\necho run >> "${counterPath}"\nprintf '%s' '${report}'\n`, "utf8");
    await chmod(pipPath, 0o755);
    await mkdir(join(home, ".dg"), { recursive: true });
    await writeFile(join(home, ".dg", "config.json"), JSON.stringify({ api: { baseUrl: "http://127.0.0.1:9" } }), "utf8");
    const env = { HOME: home, PATH: binDir };
    const args = ["install", "requests==2.31.0"];

    expect(cachedPipResolution(pipPath, args)).toBeUndefined();
    const first = await runInstallPreflight("pip", pipPath, args, env);
    const second = await runInstallPreflight("pip", pipPath, args, env);

    expect(first).toEqual({ proceed: true });
    expect(second).toEqual({ proceed: true });
    expect((await readFile(counterPath, "utf8")).trim().split("\n")).toHaveLength(1);
    const cached = cachedPipResolution(pipPath, args);
    expect(cached?.set).toEqual([{ name: "requests", version: "2.31.0" }]);
    expect(cached?.count).toBe(2);
  });

  it("caches a failed resolution so enforcement does not re-run pip", async () => {
    const home = await tempHome();
    const binDir = join(home, "bin");
    await mkdir(binDir, { recursive: true });
    const counterPath = join(home, "count");
    const pipPath = join(binDir, "fake-pip");
    await writeFile(pipPath, `#!/bin/sh\necho run >> "${counterPath}"\nexit 1\n`, "utf8");
    await chmod(pipPath, 0o755);
    const env = { HOME: home, PATH: binDir };
    const args = ["install", "requests==2.31.0"];

    const first = await runInstallPreflight("pip", pipPath, args, env);
    const second = await runInstallPreflight("pip", pipPath, args, env);

    expect(first).toEqual({ proceed: true });
    expect(second).toEqual({ proceed: true });
    expect((await readFile(counterPath, "utf8")).trim().split("\n")).toHaveLength(1);
    expect(cachedPipResolution(pipPath, args)).toEqual({ set: undefined, count: undefined });
  });
});

describe("promptPreflightYesNo interrupt handling", () => {
  it("restores raw input mode and exits 130 on ctrl-C during the prompt", async () => {
    const input = new PassThrough() as PassThrough & { isTTY: boolean; setRawMode: (value: boolean) => unknown };
    const rawCalls: boolean[] = [];
    input.isTTY = true;
    input.setRawMode = (value: boolean) => {
      rawCalls.push(value);
      return input;
    };
    const output = new PassThrough() as PassThrough & { isTTY: boolean };
    output.isTTY = true;
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`exit ${code}`);
    }) as never);
    try {
      const pending = promptPreflightYesNo("Proceed?", { input, output, isTTY: true }, false);
      await new Promise((resolve) => setTimeout(resolve, 30));
      input.write("\x03");
      await expect(pending).rejects.toThrow("exit 130");
      expect(rawCalls).toContain(true);
      expect(rawCalls[rawCalls.length - 1]).toBe(false);
    } finally {
      exitSpy.mockRestore();
    }
  });
});
