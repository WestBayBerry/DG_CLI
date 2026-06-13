import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { decideStagedVerdict, stagedRememberOffer } from "../../src/scan/staged.js";
import { annotateReportWithDecisions } from "../../src/scan/scanner-report.js";
import { DEFAULT_CONFIG, saveUserConfig, setConfigValue } from "../../src/config/settings.js";
import { dgFilePath, loadDgFile } from "../../src/project/dgfile.js";
import type { SyncRememberPrompts } from "../../src/decisions/remember-prompt.js";
import type { ScanReport } from "../../src/scan/types.js";
import type { AnalyzeResponse, ScannerAction, ScannerPackageResult } from "../../src/api/analyze.js";

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

function scannerPkg(over: Partial<ScannerPackageResult> = {}): ScannerPackageResult {
  return {
    name: "left-pad",
    version: "1.3.0",
    score: 64,
    action: "warn",
    findings: [{ severity: 3, category: "lifecycle" }],
    reasons: ["install lifecycle script"],
    cached: false,
    ...over
  };
}

function scannerReport(action: ScannerAction, packages: ScannerPackageResult[]): ScanReport {
  const findings = packages
    .filter((pkg) => (pkg.action ?? "pass") !== "pass")
    .map((pkg) => ({
      id: pkg.findings[0]?.category ?? "scanner-finding",
      severity: pkg.action === "block" ? ("block" as const) : ("warn" as const),
      title: pkg.reasons[0] ?? "",
      message: pkg.reasons[0] ?? "",
      project: "",
      location: `${pkg.name}@${pkg.version}`
    }));
  return {
    target: "t",
    status: action === "analysis_incomplete" ? "unknown" : action,
    projects: [],
    findings,
    errors: [],
    summary: {
      projectCount: 1,
      dependencyCount: packages.length,
      findingCount: findings.length,
      warnCount: findings.filter((f) => f.severity === "warn").length,
      blockCount: findings.filter((f) => f.severity === "block").length,
      errorCount: 0
    },
    scanner: { score: 64, action, packages, safeVersions: {}, durationMs: 5 } as AnalyzeResponse
  };
}

function writeDecisions(root: string, entries: Array<Record<string, unknown>>): void {
  writeFileSync(dgFilePath(root), JSON.stringify({ version: 1, decisions: entries }));
}

function acceptedEntry(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "11112222-3333-4444-5555-666677778888",
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

function annotated(report: ScanReport, root: string): ScanReport {
  const ecosystems = new Map<string, "npm" | "pypi">();
  for (const pkg of report.scanner?.packages ?? []) {
    ecosystems.set(`${pkg.name}@${pkg.version}`, "npm");
  }
  return annotateReportWithDecisions(report, loadDgFile(root), ecosystems);
}

describe("staged scan consults decision memory", () => {
  it("a fully acknowledged warn commits clean with the visibility note", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const root = tempDir("dg-root-");
    writeDecisions(root, [acceptedEntry()]);
    const report = annotated(scannerReport("warn", [scannerPkg()]), root);

    const result = decideStagedVerdict(report, env, true);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain("previously accepted");
    expect(result.stderr).toContain("dg.json");
  });

  it("strict policy ignores decision memory for the exit code", () => {
    const home = tempDir("dg-home-");
    const env = baseEnv(home);
    saveUserConfig(setConfigValue(DEFAULT_CONFIG, "policy.mode", "strict"), env);
    const root = tempDir("dg-root-");
    writeDecisions(root, [acceptedEntry()]);
    const report = annotated(scannerReport("warn", [scannerPkg()]), root);

    const result = decideStagedVerdict(report, env, true);
    expect(result.exitCode).toBe(1);
  });

  it("a block is never suppressed by decision entries", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const root = tempDir("dg-root-");
    writeDecisions(root, [acceptedEntry({ scope: { kind: "any" }, findings: { malware: 5, lifecycle: 5 } })]);
    const report = annotated(scannerReport("block", [scannerPkg({ action: "block", findings: [{ severity: 5, category: "malware" }] })]), root);

    const result = decideStagedVerdict(report, env, true);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("blocked this commit");
  });

  it("partially acknowledged warns still prompt, naming only the live one", () => {
    const home = tempDir("dg-home-");
    const env = baseEnv(home);
    saveUserConfig(setConfigValue(DEFAULT_CONFIG, "policy.mode", "block"), env);
    const root = tempDir("dg-root-");
    writeDecisions(root, [acceptedEntry()]);
    const report = annotated(
      scannerReport("warn", [scannerPkg(), scannerPkg({ name: "shady-lib", findings: [{ severity: 4, category: "network_exfil" }], reasons: ["network exfil"] })]),
      root
    );

    const result = decideStagedVerdict(report, env, true);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("shady-lib@1.3.0");
    expect(result.stderr).not.toContain("left-pad@1.3.0");
    expect(result.stderr).toContain("DG flagged 1 staged package");
  });

  it("an escalated finding set re-surfaces despite an older acceptance", () => {
    const home = tempDir("dg-home-");
    const env = baseEnv(home);
    saveUserConfig(setConfigValue(DEFAULT_CONFIG, "policy.mode", "block"), env);
    const root = tempDir("dg-root-");
    writeDecisions(root, [acceptedEntry()]);
    const report = annotated(
      scannerReport("warn", [scannerPkg({ findings: [{ severity: 3, category: "lifecycle" }, { severity: 4, category: "network_exfil" }] })]),
      root
    );

    const result = decideStagedVerdict(report, env, true);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("left-pad@1.3.0");
  });
});

describe("staged remember offer", () => {
  function prompts(answers: { yesNo: boolean[]; line?: string }): { prompts: SyncRememberPrompts; transcript: string[] } {
    const transcript: string[] = [];
    let yesNoIndex = 0;
    return {
      transcript,
      prompts: {
        yesNo: (question) => {
          transcript.push(question);
          return answers.yesNo[yesNoIndex++] ?? false;
        },
        line: (question) => {
          transcript.push(question);
          return answers.line ?? "";
        },
        write: (text) => {
          transcript.push(text);
        }
      }
    };
  }

  it("writes exact-version entries for the unacknowledged warns on accept", () => {
    const home = tempDir("dg-home-");
    const env = baseEnv(home);
    const root = tempDir("dg-root-");
    const report = annotated(scannerReport("warn", [scannerPkg()]), root);
    const file = loadDgFile(root);
    const io = prompts({ yesNo: [true, true], line: "vetted by the team" });

    const offer = stagedRememberOffer(report, { root, file, prompts: io.prompts }, env);
    expect(offer).toBeDefined();
    offer?.();

    const saved = loadDgFile(root);
    expect(saved.decisions).toHaveLength(1);
    expect(saved.decisions[0]?.name).toBe("left-pad");
    expect(saved.decisions[0]?.scope).toEqual({ kind: "exact", version: "1.3.0" });
    expect(saved.decisions[0]?.findings).toEqual({ lifecycle: 3 });
    expect(saved.decisions[0]?.reason).toBe("vetted by the team");
    expect(io.transcript.some((line) => line.includes("Create"))).toBe(true);

    const audit = readFileSync(join(home, ".dg", "state", "audit.jsonl"), "utf8");
    expect(audit).toContain("decision.accepted");
    expect(audit).toContain("npm:left-pad@1.3.0");
  });

  it("declining the create-file confirm writes nothing", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const root = tempDir("dg-root-");
    const report = annotated(scannerReport("warn", [scannerPkg()]), root);
    const io = prompts({ yesNo: [true, false] });

    stagedRememberOffer(report, { root, file: loadDgFile(root), prompts: io.prompts }, env)?.();
    expect(loadDgFile(root).exists).toBe(false);
  });

  it("offers nothing when every warn is already acknowledged", () => {
    const env = baseEnv(tempDir("dg-home-"));
    const root = tempDir("dg-root-");
    writeDecisions(root, [acceptedEntry()]);
    const report = annotated(scannerReport("warn", [scannerPkg()]), root);

    expect(stagedRememberOffer(report, { root, file: loadDgFile(root) }, env)).toBeUndefined();
  });
});
