import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../../src/runtime/cli.js";
import { scanProject } from "../../src/scan/discovery.js";
import { renderJsonReport, renderSarifReport, renderTextReport } from "../../src/scan/render.js";
import { scanExitCode } from "../../src/scan-ui/shims.js";

const tempRoots: string[] = [];

describe("dg scan", () => {
  afterEach(async () => {
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, {
      force: true,
      recursive: true
    })));
  });

  it("discovers package manifests without traversing dependency directories", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "root-project",
      version: "1.0.0",
      license: "MIT",
      dependencies: {
        chalk: "5.4.1"
      }
    });
    await writePackage(join(root, "packages", "api"), "package.json", {
      name: "api",
      version: "2.0.0",
      license: "Apache-2.0",
      devDependencies: {
        vitest: "3.1.4"
      }
    });
    await writePackage(join(root, "node_modules", "ignored"), "package.json", {
      name: "ignored",
      dependencies: {
        ignored: "https://example.test/ignored.tgz"
      }
    });

    const report = scanProject({
      cwd: root
    });

    expect(report.status).toBe("pass");
    expect(report.summary.projectCount).toBe(2);
    expect(report.summary.dependencyCount).toBe(2);
    expect(report.projects.map((project) => project.manifestPath)).toEqual([
      "package.json",
      "packages/api/package.json"
    ]);
  });

  it("reports warn and block states from local manifest evidence", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "risky-project",
      license: "MIT",
      scripts: {
        postinstall: "node install.js"
      },
      dependencies: {
        remote: "https://registry.example.test/remote.tgz",
        local: "file:../local.tgz"
      }
    });

    const report = scanProject({
      cwd: root
    });

    expect(report.status).toBe("block");
    expect(report.summary.warnCount).toBe(2);
    expect(report.summary.blockCount).toBe(1);
    expect(report.findings.map((finding) => finding.id)).toEqual([
      "npm-lifecycle-script",
      "local-artifact-dependency",
      "unverified-network-dependency"
    ]);
  });

  it("prints deterministic text output and wraps long finding lines", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "wrapped-project",
      dependencies: {
        remote: "https://registry.example.test/packages/remote/-/remote-1.0.0.tgz"
      }
    });

    const report = scanProject({
      cwd: root
    });
    const text = renderTextReport(report, 58);

    expect(text).toContain("Dependency Guardian scan");
    expect(text).toContain("Status: block");
    expect(text).toContain("BLOCK unverified-network-dependency");
    expect(text.split("\n").some((line) => line.length > 80)).toBe(false);
  });

  it("groups repeated findings and collapses clean projects in large default scans", async () => {
    const root = await tempRoot();
    for (let index = 0; index < 24; index += 1) {
      await writePackage(join(root, `package-${String(index).padStart(2, "0")}`), "package.json", {
        name: `large-package-${index}`,
        version: "1.0.0",
        license: "MIT",
        ...(index % 4 === 0
          ? {
              scripts: {
                postinstall: "node install.js"
              },
              dependencies: {
                remote: "https://registry.example.test/remote.tgz"
              }
            }
          : {
              dependencies: {
                safe: "1.0.0"
              }
            })
      });
    }

    const result = await runCli(["scan", root]);
    const lines = result.stdout.trim().split("\n");

    expect(result.exitCode).toBe(2);
    expect(result.stdout).toContain("Scanning: checked 24 project manifests.");
    expect(result.stdout).toContain("Finding groups:");
    expect(result.stdout).toContain("BLOCK unverified-network-dependency: 6 findings across 6 projects");
    expect(result.stdout).toContain("WARN npm-lifecycle-script: 6 findings across 6 projects");
    expect(result.stdout).toContain("Clean projects collapsed: 18");
    expect(result.stdout).toContain("For full project detail, run: dg scan");
    expect(lines.filter((line) => /package-\d+/.test(line)).length).toBeLessThan(20);
    expect(lines.length).toBeLessThan(60);
  });

  it("prints JSON and SARIF reports from the command router", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "json-project",
      license: "MIT"
    });

    const json = await runCli(["scan", root, "--json"]);
    const sarif = await runCli(["scan", root, "--sarif"]);

    expect(json.exitCode).toBe(0);
    expect(JSON.parse(json.stdout)).toMatchObject({
      schemaVersion: 1,
      status: "pass",
      summary: {
        projectCount: 1
      }
    });
    expect(sarif.exitCode).toBe(0);
    expect(JSON.parse(sarif.stdout)).toMatchObject({
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Dependency Guardian"
            }
          }
        }
      ]
    });
  });

  it("writes requested exports without mutating project state", async () => {
    const root = await tempRoot();
    const outputPath = join(root, "scan-report.json");
    await writePackage(root, "package.json", {
      name: "export-project",
      license: "MIT"
    });

    const result = await runCli(["scan", root, "--json", "--output", outputPath]);
    const exported = JSON.parse(await readFile(outputPath, "utf8"));

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe(`Wrote json scan report to ${outputPath}\n`);
    expect(exported.status).toBe("pass");
    expect(exported.projects).toHaveLength(1);
  });

  it("handles empty projects and malformed manifests honestly", async () => {
    const emptyRoot = await tempRoot();
    const brokenRoot = await tempRoot();
    await writeFile(join(brokenRoot, "package.json"), "{", "utf8");

    const empty = await runCli(["scan", emptyRoot]);
    const broken = await runCli(["scan", brokenRoot]);

    expect(empty.exitCode).toBe(10);
    expect(empty.stdout).toContain("No supported project manifests found.");
    expect(broken.exitCode).toBe(4);
    expect(broken.stdout).toContain("Status: error");
    expect(broken.stdout).toContain("ERROR package.json:");
  });

  it("exits 10 with a nothing_to_scan JSON status when discovery finds nothing scannable", async () => {
    const emptyRoot = await tempRoot();

    const result = await runCli(["scan", emptyRoot, "--json"]);
    const report = JSON.parse(result.stdout) as { schemaVersion: number; status: string; summary: { projectCount: number } };

    expect(result.exitCode).toBe(10);
    expect(report.schemaVersion).toBe(1);
    expect(report.status).toBe("nothing_to_scan");
    expect(report.summary.projectCount).toBe(0);
  });

  it("exits 4 when the scan target does not exist", async () => {
    const root = await tempRoot();

    const result = await runCli(["scan", join(root, "missing-dir")]);

    expect(result.exitCode).toBe(4);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("dg scan failed:");
  });

  it("creates missing directories for --output", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "write-mkdir-project",
      license: "MIT"
    });

    const result = await runCli(["scan", root, "--json", "--output", join(root, "new-dir", "report.json")]);

    expect(result.stderr).toBe("");
    const written = await readFile(join(root, "new-dir", "report.json"), "utf8");
    expect(JSON.parse(written)).toBeTruthy();
  });

  it("exits 4 when the report cannot be written", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "write-fail-project",
      license: "MIT"
    });
    await writeFile(join(root, "blocker"), "not a directory\n");

    const result = await runCli(["scan", root, "--json", "--output", join(root, "blocker", "report.json")]);

    expect(result.exitCode).toBe(4);
    expect(result.stderr).toContain("could not write");
  });

  it("rejects invalid scan arguments as usage errors with exit 64", async () => {
    const result = await runCli(["scan", "--json", "--sarif"]);

    expect(result.exitCode).toBe(64);
    expect(result.stderr).toContain("choose only one output format");
  });

  it("rejects unknown scan flags with exit 64", async () => {
    const result = await runCli(["scan", "--interactive"]);

    expect(result.exitCode).toBe(64);
    expect(result.stderr).toContain("unknown option '--interactive'");
  });

  it("rejects -o and --output without a path as usage errors with exit 64", async () => {
    const bare = await runCli(["scan", "-o"]);
    const flagAsValue = await runCli(["scan", "-o", "--json"]);
    const longForm = await runCli(["scan", "--output"]);

    expect(bare.exitCode).toBe(64);
    expect(bare.stderr).toContain("-o requires a path");
    expect(flagAsValue.exitCode).toBe(64);
    expect(flagAsValue.stderr).toContain("-o requires a path");
    expect(longForm.exitCode).toBe(64);
    expect(longForm.stderr).toContain("--output requires a path");
  });
});

describe("scanExitCode", () => {
  it("exits 2 for a block action under every policy mode", () => {
    for (const mode of ["off", "warn", "block", "strict"]) {
      expect(scanExitCode("block", mode)).toBe(2);
    }
  });

  it("exits 1 for a warn action unless strict upgrades it to a block", () => {
    expect(scanExitCode("warn", "off")).toBe(1);
    expect(scanExitCode("warn", "warn")).toBe(1);
    expect(scanExitCode("warn", "block")).toBe(1);
    expect(scanExitCode("warn", "strict")).toBe(2);
  });

  it("keeps analysis_incomplete at 4 and pass at 0", () => {
    expect(scanExitCode("analysis_incomplete", "strict")).toBe(4);
    expect(scanExitCode("pass", "block")).toBe(0);
    expect(scanExitCode(undefined, "block")).toBe(0);
  });
});

describe("scan render markers", () => {
  it("names the missing lockfile instead of a generic unavailable notice", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "fallback-project",
      license: "MIT"
    });
    const report = scanProject({ cwd: root });

    const text = renderTextReport(report, 100, undefined, "no_lockfile");
    expect(text).toContain("no lockfile found — server verification skipped (local heuristics only)");
    expect(renderTextReport(report, 100, undefined, undefined)).not.toContain("server verification skipped");
    expect(renderTextReport(report, 100, undefined, "empty_lockfile")).toContain("lockfile contains no scannable packages");

    expect(JSON.parse(renderJsonReport(report, true)).scannerUnavailable).toBe(true);
    expect(JSON.parse(renderJsonReport(report, false)).scannerUnavailable).toBe(false);
  });

  it("links each flagged npm/pypi package to its public page (not cargo, not clean ones)", () => {
    const pkg = (name: string, action: "block" | "warn" | "pass", ecosystem: string) => ({
      name, version: "1.0.0", score: 0, action, findings: [], reasons: [], cached: false, ecosystem
    });
    const report = {
      target: ".",
      status: "block" as const,
      projects: [],
      findings: [],
      errors: [],
      summary: { projectCount: 1, dependencyCount: 4, findingCount: 2, warnCount: 1, blockCount: 1, errorCount: 0 },
      scanner: {
        score: 90,
        action: "block" as const,
        safeVersions: {},
        durationMs: 1,
        packages: [
          pkg("event-stream", "block", "npm"),
          pkg("flask", "warn", "pypi"),
          pkg("serde", "warn", "cargo"),
          pkg("left-pad", "pass", "npm")
        ]
      }
    };
    const text = renderTextReport(report, 100);
    expect(text).toContain("Full report for each flagged package");
    expect(text).toContain("https://westbayberry.com/npm/event-stream");
    expect(text).toContain("https://westbayberry.com/pypi/flask");
    expect(text).not.toContain("/cargo/");
    expect(text).not.toContain("npm/left-pad");
  });

  it("renders the scanner failure loudly with quota numbers and an incomplete status", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "degraded-project",
      license: "MIT"
    });
    const report = {
      ...scanProject({ cwd: root }),
      status: "unknown" as const,
      scannerError: {
        kind: "quota_exceeded" as const,
        message: "Free scan limit reached",
        statusCode: 403,
        scansUsed: 15,
        scansLimit: 15
      }
    };

    const text = renderTextReport(report, 100, undefined, undefined);
    expect(text).toContain("server scan failed: Free scan limit reached");
    expect(text).toContain("scans used: 15 of 15");
    expect(text).toContain("Status: analysis_incomplete");
    expect(text).not.toContain("No supported project manifests found.");

    const json = JSON.parse(renderJsonReport(report, true));
    expect(json.status).toBe("analysis_incomplete");
    expect(json.scannerError).toEqual({
      kind: "quota_exceeded",
      message: "Free scan limit reached",
      statusCode: 403,
      scansUsed: 15,
      scansLimit: 15
    });
  });

  it("hints the plain TTY invocation, not the removed --interactive flag", async () => {
    const root = await tempRoot();
    for (let index = 0; index < 24; index += 1) {
      await writePackage(join(root, `pkg-${String(index).padStart(2, "0")}`), "package.json", {
        name: `m-${index}`,
        version: "1.0.0",
        license: "MIT",
        dependencies: { safe: "1.0.0" }
      });
    }
    const result = await runCli(["scan", root]);

    expect(result.stdout).toContain("For full project detail, run: dg scan");
    expect(result.stdout).not.toContain("--interactive");
  });

  it("strips VT control characters from manifest-controlled strings in the text report", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "\u001b]0;pwned\u0007evil-project",
      license: "MIT",
      dependencies: {
        "\u001b[2Jdep": "file:\u001b[31m../local.tgz"
      }
    });

    const report = scanProject({ cwd: root });
    const text = renderTextReport(report, 100);

    expect(text).not.toContain("\u001b");
    expect(text).not.toContain("\u0007");
    expect(text).toContain("evil-project");
  });

  it("preserves full SARIF artifact uris and only strips a trailing line number", () => {
    const finding = (id: string, location: string) => ({
      id,
      severity: "warn" as const,
      title: id,
      message: id,
      project: "p",
      location
    });
    const report = {
      target: ".",
      status: "warn" as const,
      projects: [],
      findings: [
        finding("a", "left-pad@1.3.0"),
        finding("b", "package.json:scripts.postinstall"),
        finding("c", "src/index.ts:42"),
        finding("d", "C:\\repo\\package.json"),
        finding("e", "C:\\repo\\package.json:12")
      ],
      errors: [],
      summary: { projectCount: 0, dependencyCount: 0, findingCount: 5, warnCount: 5, blockCount: 0, errorCount: 0 }
    };
    const sarif = JSON.parse(renderSarifReport(report));
    const uris = sarif.runs[0].results.map((r: { locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }) =>
      r.locations[0].physicalLocation.artifactLocation.uri
    );

    expect(uris).toEqual([
      "left-pad@1.3.0",
      "package.json:scripts.postinstall",
      "src/index.ts",
      "C:\\repo\\package.json",
      "C:\\repo\\package.json"
    ]);
  });
});

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-scan-test-"));
  tempRoots.push(root);
  return root;
}

async function writePackage(root: string, path: string, contents: Record<string, unknown>): Promise<void> {
  const packagePath = join(root, path);
  await mkdir(join(packagePath, ".."), {
    recursive: true
  });
  await writeFile(packagePath, `${JSON.stringify(contents, null, 2)}\n`, "utf8");
}
