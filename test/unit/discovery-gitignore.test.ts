import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverScanProjects } from "../../src/scan/collect.js";
import { gitIgnoredDirectories, scanProject } from "../../src/scan/discovery.js";

const LOCKFILE = JSON.stringify({ name: "fixture", lockfileVersion: 3, packages: {} });
const MANIFEST = JSON.stringify({ name: "fixture", version: "1.0.0" });

function seedProject(dir: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), MANIFEST);
  writeFileSync(join(dir, "package-lock.json"), LOCKFILE);
}

function tempTree(): string {
  const root = mkdtempSync(join(tmpdir(), "dg-gitignore-"));
  seedProject(join(root, "visible"));
  seedProject(join(root, "sandbox", "copy"));
  return root;
}

describe("gitignore-aware discovery", () => {
  it("prunes gitignored directories from lockfile and manifest walks", () => {
    const root = tempTree();
    execFileSync("git", ["-C", root, "init", "-q"]);
    writeFileSync(join(root, ".gitignore"), "sandbox/\n");

    const ignored = gitIgnoredDirectories(root);
    expect(ignored.has(join(root, "sandbox"))).toBe(true);
    expect(ignored.has(join(root, "visible"))).toBe(false);

    const projects = discoverScanProjects(root);
    expect(projects.map((p) => p.relativePath)).toEqual(["visible"]);

    const report = scanProject({ cwd: root });
    expect(report.projects.map((p) => p.manifestPath)).toEqual([join("visible", "package.json")]);
  });

  it("walks everything when the target is not a git work tree", () => {
    const root = tempTree();

    expect(gitIgnoredDirectories(root).size).toBe(0);
    const projects = discoverScanProjects(root);
    expect(projects.map((p) => p.relativePath).sort()).toEqual(["sandbox/copy", "visible"]);
  });
});
