import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../../src/runtime/cli.js";
import { compareVersions } from "../../src/commands/update.js";

const tempRoots: string[] = [];
const originalLatest = process.env.DG_UPDATE_LATEST_VERSION;

describe("legacy-retained command implementations", () => {
  afterEach(async () => {
    if (originalLatest === undefined) {
      delete process.env.DG_UPDATE_LATEST_VERSION;
    } else {
      process.env.DG_UPDATE_LATEST_VERSION = originalLatest;
    }
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, {
      force: true,
      recursive: true
    })));
  });

  it("exports licenses from manifests and lockfiles with policy gates", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "fixture",
      version: "1.0.0",
      license: "MIT"
    });
    await writeFile(join(root, "package-lock.json"), JSON.stringify({
      name: "fixture",
      lockfileVersion: 3,
      packages: {
        "": {
          name: "fixture",
          version: "1.0.0",
          license: "MIT"
        },
        "node_modules/gpl-package": {
          name: "gpl-package",
          version: "2.0.0",
          license: "GPL-3.0",
          resolved: "https://registry.npmjs.org/gpl-package/-/gpl-package-2.0.0.tgz",
          integrity: "sha512-abc="
        }
      }
    }, null, 2), "utf8");

    const result = await runCli(["licenses", root, "--json", "--fail-on", "strong-copyleft"]);
    const report = JSON.parse(result.stdout) as {
      status: string;
      entries: Array<{
        name: string;
        license: string;
        risk: string;
        source: string;
      }>;
      summary: {
        blockedCount: number;
      };
    };

    expect(result.exitCode).toBe(2);
    expect(result.stderr).toBe("");
    expect(report.status).toBe("block");
    expect(report.summary.blockedCount).toBe(1);
    expect(report.entries).toEqual(expect.arrayContaining([
      expect.objectContaining({
        name: "fixture",
        license: "MIT",
        risk: "permissive",
        source: "manifest"
      }),
      expect.objectContaining({
        name: "gpl-package",
        license: "GPL-3.0",
        risk: "strong-copyleft",
        source: "lockfile"
      })
    ]));
  });

  it("writes CSV and Markdown license exports without running project scripts", async () => {
    const root = await tempRoot();
    const csvPath = join(root, "licenses.csv");
    const markdownPath = join(root, "licenses.md");
    await writePackage(root, "package.json", {
      name: "scripted",
      license: "Apache-2.0",
      scripts: {
        postinstall: "node ./write-pwned.js"
      }
    });

    const csv = await runCli(["licenses", root, "--csv", "--output", csvPath]);
    const markdown = await runCli(["licenses", root, "--markdown", "--output", markdownPath]);

    expect(csv.exitCode).toBe(0);
    expect(markdown.exitCode).toBe(0);
    expect(await readFile(csvPath, "utf8")).toContain("ecosystem,name,version,license,risk,source,location");
    expect(await readFile(markdownPath, "utf8")).toContain("| Ecosystem | Package | Version | License | Risk | Source |");
    expect(existsSync(join(root, "pwned"))).toBe(false);
  });

  it("skips unreadable subdirectories with a per-directory notice instead of aborting", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "fixture",
      version: "1.0.0",
      license: "MIT"
    });
    const sealed = join(root, "sealed");
    await mkdir(sealed, { recursive: true });
    await chmod(sealed, 0o000);
    try {
      const result = await runCli(["licenses", root, "--json"]);
      expect(result.exitCode).toBe(0);
      expect(result.stderr).toContain("skipped unreadable directory sealed");
      const report = JSON.parse(result.stdout) as { entries: Array<{ name: string }> };
      expect(report.entries.map((entry) => entry.name)).toContain("fixture");
    } finally {
      await chmod(sealed, 0o755);
    }
  });

  it("treats licenses usage errors as exit 64, distinct from the policy-block exit", async () => {
    const unknown = await runCli(["licenses", "--bogus"]);
    expect(unknown.exitCode).toBe(64);
    expect(unknown.stderr).toContain("unknown option '--bogus'");
    const badRisk = await runCli(["licenses", "--fail-on=not-a-risk"]);
    expect(badRisk.exitCode).toBe(64);
    expect(badRisk.stderr).toContain("unknown license risk");
  });

  it("checks update and upgrade aliases without self-mutating", async () => {
    process.env.DG_UPDATE_LATEST_VERSION = "999.0.0";

    const update = await runCli(["update", "--json"]);
    const upgrade = await runCli(["upgrade"]);
    const report = JSON.parse(update.stdout) as {
      status: string;
      updateCommand: string;
    };

    expect(update.exitCode).toBe(0);
    expect(report.status).toBe("available");
    expect(report.updateCommand).toBe("npm install -g @westbayberry/dg@999.0.0");
    expect(upgrade.exitCode).toBe(0);
    expect(upgrade.stdout).toContain("Run: npm install -g @westbayberry/dg@999.0.0");
    expect(upgrade.stdout).toContain("No package manager was executed");
  });

  it("rejects update --yes instead of mutating the global install", async () => {
    const result = await runCli(["update", "--yes"]);

    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("does not self-mutate");
  });

  it("reports the latest version when injected and prints the install command", async () => {
    process.env.DG_UPDATE_LATEST_VERSION = "999.0.0";

    const result = await runCli(["update"]);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Run: npm install -g @westbayberry/dg@999.0.0");
  });

  it("advertises only the real --json flag in the usage footer", async () => {
    const result = await runCli(["update", "--nope"]);

    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("Usage: dg update [--json]");
    expect(result.stderr).not.toContain("--print");
  });

  it("orders prerelease versions before their release per semver", () => {
    expect(compareVersions("1.2.3-rc1", "1.2.3")).toBeLessThan(0);
    expect(compareVersions("1.2.3", "1.2.3-rc1")).toBeGreaterThan(0);
    expect(compareVersions("1.2.3-rc1", "1.2.3-rc2")).toBeLessThan(0);
    expect(compareVersions("1.2.3-rc.2", "1.2.3-rc.10")).toBeLessThan(0);
    expect(compareVersions("2.0.0-alpha", "2.0.0-beta")).toBeLessThan(0);
    expect(compareVersions("1.2.10", "1.2.3")).toBeGreaterThan(0);
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
    expect(compareVersions("v1.0.0", "1.0.0")).toBe(0);
    expect(compareVersions("1.2.3+build.7", "1.2.3")).toBe(0);
  });

  it("treats a prerelease of the current version as not-newer", async () => {
    process.env.DG_UPDATE_LATEST_VERSION = "0.0.0-rc1";

    const result = await runCli(["update", "--json"]);
    const report = JSON.parse(result.stdout) as { status: string; updateCommand: string | null };

    expect(report.status).toBe("current");
    expect(report.updateCommand).toBeNull();
  });

});

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-legacy-commands-test-"));
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
