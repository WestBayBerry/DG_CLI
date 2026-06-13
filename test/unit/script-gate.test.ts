import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { classifyPackageManagerInvocation } from "../../src/launcher/classify.js";
import { DG_FILE_NAME, emptyDgFile, loadDgFile } from "../../src/project/dgfile.js";
import type { ScriptWanter } from "../../src/scripts/detect.js";
import {
  applyScriptDecisions,
  evaluateScriptGate,
  hasExplicitScriptPreference,
  recordScriptObservations,
  runScriptGateAfterInstall,
  scriptGateChildEnv,
  scriptGateInstallArgs,
  scriptGateReportLine
} from "../../src/scripts/gate.js";

const made: string[] = [];
const NOW = new Date("2026-06-10T12:00:00.000Z");

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

function wanter(name: string, overrides: Partial<ScriptWanter> = {}): ScriptWanter {
  return {
    name,
    version: "1.0.0",
    hooks: ["postinstall"],
    scriptsHash: `sha256:hash-of-${name}`,
    ...overrides
  };
}

function writeFileAt(root: string, relative: string, content: string): void {
  const path = join(root, relative);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf8");
}

function fixtureProjectWithEsbuild(): string {
  const project = tempDir("dg-script-gate-project-");
  writeFileAt(
    project,
    "node_modules/esbuild/package.json",
    JSON.stringify({ name: "esbuild", version: "0.25.5", scripts: { postinstall: "node install.js" } })
  );
  writeFileAt(
    project,
    "node_modules/.package-lock.json",
    JSON.stringify({ packages: { "node_modules/esbuild": { version: "0.25.5", hasInstallScript: true } } })
  );
  return project;
}

describe("evaluateScriptGate (enforce-branch diff)", () => {
  it("splits wanters into approved, denied, pending, and drifted", () => {
    const fresh = wanter("pending-pkg");
    const allowed = wanter("allowed-pkg");
    const blocked = wanter("denied-pkg");
    const moved = wanter("drifted-pkg");
    const evaluation = evaluateScriptGate([fresh, allowed, blocked, moved], {
      "allowed-pkg": {
        decision: "allow",
        scriptsHash: allowed.scriptsHash,
        hooks: ["postinstall"],
        approvedAt: NOW.toISOString(),
        provenance: "prompt"
      },
      "denied-pkg": {
        decision: "deny",
        scriptsHash: blocked.scriptsHash,
        hooks: ["postinstall"],
        approvedAt: NOW.toISOString(),
        provenance: "prompt"
      },
      "drifted-pkg": {
        decision: "allow",
        scriptsHash: "sha256:previous",
        hooks: ["postinstall"],
        approvedAt: NOW.toISOString(),
        provenance: "prompt"
      }
    });

    expect(evaluation.pending.map((entry) => entry.name)).toEqual(["pending-pkg"]);
    expect(evaluation.approved.map((entry) => entry.name)).toEqual(["allowed-pkg"]);
    expect(evaluation.denied.map((entry) => entry.name)).toEqual(["denied-pkg"]);
    expect(evaluation.drifted).toEqual([{ wanter: moved, priorHash: "sha256:previous" }]);
  });
});

describe("applyScriptDecisions", () => {
  it("persists allow and deny decisions with hash, hooks, version, and provenance", () => {
    const file = applyScriptDecisions(
      emptyDgFile(""),
      [
        { wanter: wanter("esbuild", { version: "0.25.5" }), decision: "allow", reason: "vetted build script" },
        { wanter: wanter("sketchy"), decision: "deny", provenance: "command" }
      ],
      NOW
    );

    expect(file.scriptApprovals.npm.esbuild).toEqual({
      decision: "allow",
      scriptsHash: "sha256:hash-of-esbuild",
      hooks: ["postinstall"],
      approvedVersion: "0.25.5",
      reason: "vetted build script",
      approvedAt: NOW.toISOString(),
      provenance: "prompt"
    });
    expect(file.scriptApprovals.npm.sketchy?.decision).toBe("deny");
    expect(file.scriptApprovals.npm.sketchy?.provenance).toBe("command");
  });
});

describe("recordScriptObservations", () => {
  it("does not create dg.json unless opted in", () => {
    const project = tempDir("dg-script-gate-obs-");
    const result = recordScriptObservations({
      projectDir: project,
      wanters: [wanter("esbuild")],
      createIfMissing: false,
      now: NOW
    });

    expect(result.written).toBe(false);
    expect(existsSync(join(project, DG_FILE_NAME))).toBe(false);
  });

  it("creates dg.json when createIfMissing is set", () => {
    const project = tempDir("dg-script-gate-obs-");
    const result = recordScriptObservations({
      projectDir: project,
      wanters: [wanter("esbuild", { version: "0.25.5" })],
      createIfMissing: true,
      now: NOW
    });

    expect(result.written).toBe(true);
    const read = loadDgFile(project);
    expect(read.scriptApprovals.observed.esbuild).toEqual({
      version: "0.25.5",
      hooks: ["postinstall"],
      scriptsHash: "sha256:hash-of-esbuild",
      firstSeen: NOW.toISOString()
    });
  });

  it("updates an existing dg.json, preserves firstSeen across version bumps, and skips no-op writes", () => {
    const project = tempDir("dg-script-gate-obs-");
    const keptDecision = {
      id: "11111111-2222-3333-4444-555555555555",
      ecosystem: "npm",
      name: "left-pad",
      scope: { kind: "exact", version: "1.3.0" },
      findings: { lifecycle: 3 },
      reason: "mine",
      acceptedBy: "alice@example.com",
      acceptedAt: "2026-06-01T00:00:00.000Z"
    };
    writeFileSync(
      join(project, DG_FILE_NAME),
      `${JSON.stringify({ version: 1, decisions: [keptDecision] }, null, 2)}\n`,
      "utf8"
    );

    const first = recordScriptObservations({
      projectDir: project,
      wanters: [wanter("esbuild", { version: "0.25.5" })],
      createIfMissing: false,
      now: NOW
    });
    expect(first.written).toBe(true);

    const repeat = recordScriptObservations({
      projectDir: project,
      wanters: [wanter("esbuild", { version: "0.25.5" })],
      createIfMissing: false,
      now: new Date("2026-06-11T00:00:00.000Z")
    });
    expect(repeat.written).toBe(false);

    const bumped = recordScriptObservations({
      projectDir: project,
      wanters: [wanter("esbuild", { version: "0.26.0" })],
      createIfMissing: false,
      now: new Date("2026-06-12T00:00:00.000Z")
    });
    expect(bumped.written).toBe(true);

    const read = loadDgFile(project);
    expect(read.scriptApprovals.observed.esbuild?.version).toBe("0.26.0");
    expect(read.scriptApprovals.observed.esbuild?.firstSeen).toBe(NOW.toISOString());
    expect(read.decisions).toHaveLength(1);
    expect(read.decisions[0]).toMatchObject(keptDecision);
  });

  it("never writes over a malformed dg.json", () => {
    const project = tempDir("dg-script-gate-obs-");
    writeFileSync(join(project, DG_FILE_NAME), "{broken", "utf8");

    const result = recordScriptObservations({
      projectDir: project,
      wanters: [wanter("esbuild")],
      createIfMissing: true,
      now: NOW
    });

    expect(result.written).toBe(false);
    expect(readFileSync(join(project, DG_FILE_NAME), "utf8")).toBe("{broken");
  });
});

describe("script gate install args and child env (enforce plumbing)", () => {
  it("appends --ignore-scripts only in enforce mode for npm and yarn", () => {
    expect(scriptGateInstallArgs({ mode: "enforce", manager: "npm", args: ["install", "esbuild"], env: {} })).toEqual([
      "install",
      "esbuild",
      "--ignore-scripts"
    ]);
    expect(scriptGateInstallArgs({ mode: "enforce", manager: "yarn", args: ["add", "esbuild"], env: {} })).toEqual([
      "add",
      "esbuild",
      "--ignore-scripts"
    ]);
    expect(scriptGateInstallArgs({ mode: "observe", manager: "npm", args: ["install"], env: {} })).toEqual(["install"]);
    expect(scriptGateInstallArgs({ mode: "off", manager: "npm", args: ["install"], env: {} })).toEqual(["install"]);
    expect(scriptGateInstallArgs({ mode: "enforce", manager: "pnpm", args: ["add", "esbuild"], env: {} })).toEqual([
      "add",
      "esbuild"
    ]);
  });

  it("respects an explicit user script preference in argv or environment", () => {
    expect(
      scriptGateInstallArgs({ mode: "enforce", manager: "npm", args: ["install", "--ignore-scripts"], env: {} })
    ).toEqual(["install", "--ignore-scripts"]);
    expect(
      scriptGateInstallArgs({ mode: "enforce", manager: "npm", args: ["install", "--ignore-scripts=false"], env: {} })
    ).toEqual(["install", "--ignore-scripts=false"]);
    expect(
      scriptGateInstallArgs({
        mode: "enforce",
        manager: "npm",
        args: ["install"],
        env: { npm_config_ignore_scripts: "false" }
      })
    ).toEqual(["install"]);
    expect(hasExplicitScriptPreference([], { npm_config_ignore_scripts: "true" })).toBe(true);
    expect(hasExplicitScriptPreference([], {})).toBe(false);
  });

  it("sets the npm_config_ignore_scripts belt only for enforce on npm and yarn", () => {
    expect(scriptGateChildEnv({ mode: "enforce", manager: "npm", args: ["install"], env: {} })).toEqual({
      npm_config_ignore_scripts: "true"
    });
    expect(scriptGateChildEnv({ mode: "enforce", manager: "pnpm", args: ["install"], env: {} })).toEqual({});
    expect(scriptGateChildEnv({ mode: "observe", manager: "npm", args: ["install"], env: {} })).toEqual({});
    expect(
      scriptGateChildEnv({ mode: "enforce", manager: "npm", args: ["install", "--ignore-scripts=false"], env: {} })
    ).toEqual({});
  });
});

describe("scriptGateReportLine", () => {
  it("lists script-running packages with versions and says they were observed", () => {
    const line = scriptGateReportLine({
      manager: "npm",
      wanters: [wanter("esbuild", { version: "0.25.5" }), wanter("better-sqlite3", { version: "11.10.0" })]
    });

    expect(line).toContain("dg scripts: 2 packages ran install scripts");
    expect(line).toContain("esbuild@0.25.5");
    expect(line).toContain("better-sqlite3@11.10.0");
    expect(line).toContain("observed, not blocked");
  });

  it("uses singular wording for one package and stays silent for zero", () => {
    const line = scriptGateReportLine({ manager: "npm", wanters: [wanter("esbuild", { version: "" })] });

    expect(line).toContain("1 package ran install scripts (esbuild)");
    expect(scriptGateReportLine({ manager: "npm", wanters: [] })).toBe("");
  });

  it("caps the listed names and counts the rest", () => {
    const many = ["a", "b", "c", "d", "e", "f", "g", "h"].map((name) => wanter(name, { version: "1.0.0" }));
    const line = scriptGateReportLine({ manager: "npm", wanters: many });

    expect(line).toContain("8 packages ran install scripts");
    expect(line).toContain("+2 more");
    expect(line).not.toContain("g@1.0.0");
  });

  it("notes pnpm's native default-deny instead of wrapping it", () => {
    const line = scriptGateReportLine({ manager: "pnpm", pnpmIgnoredBuilds: ["esbuild"] });

    expect(line).toContain("pnpm natively blocked install scripts for esbuild");
    expect(line).toContain("pnpm approve-builds");
    expect(scriptGateReportLine({ manager: "pnpm", pnpmIgnoredBuilds: [] })).toBe("");
  });
});

describe("runScriptGateAfterInstall", () => {
  function homeWithConfig(config?: Record<string, unknown>): string {
    const home = tempDir("dg-script-gate-home-");
    if (config) {
      mkdirSync(join(home, ".dg"), { recursive: true });
      writeFileSync(join(home, ".dg", "config.json"), JSON.stringify(config), "utf8");
    }
    return home;
  }

  it("reports script wanters after a protected npm install with the default config", () => {
    const project = fixtureProjectWithEsbuild();
    const line = runScriptGateAfterInstall({
      classification: classifyPackageManagerInvocation("npm", ["install", "esbuild"]),
      env: { HOME: homeWithConfig() },
      projectDir: project,
      now: NOW
    });

    expect(line).toContain("dg scripts: 1 package ran install scripts (esbuild@0.25.5)");
    expect(existsSync(join(project, DG_FILE_NAME))).toBe(false);
  });

  it("records observations when the project already has a dg.json", () => {
    const project = fixtureProjectWithEsbuild();
    writeFileSync(join(project, DG_FILE_NAME), '{\n  "version": 1\n}\n', "utf8");

    const line = runScriptGateAfterInstall({
      classification: classifyPackageManagerInvocation("npm", ["install", "esbuild"]),
      env: { HOME: homeWithConfig() },
      projectDir: project,
      now: NOW
    });

    expect(line).toContain("esbuild@0.25.5");
    const read = loadDgFile(project);
    expect(read.scriptApprovals.observed.esbuild?.firstSeen).toBe(NOW.toISOString());
  });

  it("creates dg.json when scriptGate.observe opts in", () => {
    const project = fixtureProjectWithEsbuild();
    const line = runScriptGateAfterInstall({
      classification: classifyPackageManagerInvocation("npm", ["install", "esbuild"]),
      env: { HOME: homeWithConfig({ scriptGate: { observe: true } }) },
      projectDir: project,
      now: NOW
    });

    expect(line).toContain("esbuild@0.25.5");
    expect(loadDgFile(project).scriptApprovals.observed.esbuild?.version).toBe("0.25.5");
  });

  it("stays silent when scriptGate.mode is off", () => {
    const line = runScriptGateAfterInstall({
      classification: classifyPackageManagerInvocation("npm", ["install", "esbuild"]),
      env: { HOME: homeWithConfig({ scriptGate: { mode: "off" } }) },
      projectDir: fixtureProjectWithEsbuild(),
      now: NOW
    });

    expect(line).toBe("");
  });

  it("still observes when scriptGate.mode is enforce in this release", () => {
    const line = runScriptGateAfterInstall({
      classification: classifyPackageManagerInvocation("npm", ["install", "esbuild"]),
      env: { HOME: homeWithConfig({ scriptGate: { mode: "enforce" } }) },
      projectDir: fixtureProjectWithEsbuild(),
      now: NOW
    });

    expect(line).toContain("esbuild@0.25.5");
  });

  it("skips non-mutating protected actions, python installs, and unprotected commands", () => {
    const home = homeWithConfig();
    const project = fixtureProjectWithEsbuild();
    const execLine = runScriptGateAfterInstall({
      classification: classifyPackageManagerInvocation("npm", ["exec", "cowsay"]),
      env: { HOME: home },
      projectDir: project,
      now: NOW
    });
    const pipLine = runScriptGateAfterInstall({
      classification: classifyPackageManagerInvocation("pip", ["install", "requests"]),
      env: { HOME: home },
      projectDir: project,
      now: NOW
    });
    const passthroughLine = runScriptGateAfterInstall({
      classification: classifyPackageManagerInvocation("npm", ["run", "build"]),
      env: { HOME: home },
      projectDir: project,
      now: NOW
    });

    expect(execLine).toBe("");
    expect(pipLine).toBe("");
    expect(passthroughLine).toBe("");
  });

  it("reports pnpm's natively ignored builds without writing dg.json", () => {
    const project = tempDir("dg-script-gate-pnpm-");
    writeFileAt(project, "node_modules/.modules.yaml", "ignoredBuilds:\n  - esbuild\n");

    const line = runScriptGateAfterInstall({
      classification: classifyPackageManagerInvocation("pnpm", ["add", "esbuild"]),
      env: { HOME: homeWithConfig() },
      projectDir: project,
      now: NOW
    });

    expect(line).toContain("pnpm natively blocked install scripts for esbuild");
    expect(existsSync(join(project, DG_FILE_NAME))).toBe(false);
  });

  it("returns an empty line instead of failing when the project dir is unreadable", () => {
    const line = runScriptGateAfterInstall({
      classification: classifyPackageManagerInvocation("npm", ["install", "esbuild"]),
      env: { HOME: homeWithConfig() },
      projectDir: join(tmpdir(), "dg-script-gate-missing", "nope"),
      now: NOW
    });

    expect(line).toBe("");
  });
});
