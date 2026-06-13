import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const scriptPath = fileURLToPath(new URL("../../scripts/sync-shrinkwrap.mjs", import.meta.url));
const backupName = ".package.json.prepack-backup";

const fixtureManifest = {
  name: "@westbayberry/dg",
  version: "9.9.9",
  scripts: {
    build: "node build.mjs",
    "check:release-docs": "node scripts/check-release-docs.mjs",
    "check:architecture-cracks": "node scripts/validate-architecture-crack-closure.mjs",
    check: "npm run build && npm run check:release-docs && npm run check:architecture-cracks"
  }
};

const fixtureLock = {
  name: "@westbayberry/dg",
  version: "9.9.9",
  lockfileVersion: 3,
  packages: {}
};

function runScript(mode: string, root: string): { status: number | null; stderr: string } {
  const result = spawnSync(process.execPath, [scriptPath, mode, root], { encoding: "utf8" });
  return { status: result.status, stderr: result.stderr };
}

describe("sync-shrinkwrap", () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dg-shrinkwrap-"));
    await writeFile(join(root, "package.json"), `${JSON.stringify(fixtureManifest, null, 2)}\n`, "utf8");
    await writeFile(join(root, "package-lock.json"), `${JSON.stringify(fixtureLock, null, 2)}\n`, "utf8");
  });

  afterEach(async () => {
    await rm(root, { force: true, recursive: true });
  });

  it("prepack copies the lockfile to npm-shrinkwrap.json", async () => {
    const result = runScript("prepack", root);
    expect(result.status).toBe(0);
    const shrinkwrap = await readFile(join(root, "npm-shrinkwrap.json"), "utf8");
    const lock = await readFile(join(root, "package-lock.json"), "utf8");
    expect(shrinkwrap).toBe(lock);
  });

  it("prepack strips internal script entries and filters the check chain", async () => {
    const result = runScript("prepack", root);
    expect(result.status).toBe(0);
    const manifest = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
    expect(manifest.scripts["check:release-docs"]).toBeUndefined();
    expect(manifest.scripts["check:architecture-cracks"]).toBeUndefined();
    expect(manifest.scripts.check).toBe("npm run build");
    expect(manifest.scripts.build).toBe("node build.mjs");
  });

  it("prepack backs up the original manifest", async () => {
    const original = await readFile(join(root, "package.json"), "utf8");
    const result = runScript("prepack", root);
    expect(result.status).toBe(0);
    const backup = await readFile(join(root, backupName), "utf8");
    expect(backup).toBe(original);
  });

  it("prepack refuses to run over a stale backup", () => {
    expect(runScript("prepack", root).status).toBe(0);
    const second = runScript("prepack", root);
    expect(second.status).not.toBe(0);
    expect(second.stderr).toContain(backupName);
  });

  it("restore puts the original manifest back and removes the shrinkwrap", async () => {
    const original = await readFile(join(root, "package.json"), "utf8");
    expect(runScript("prepack", root).status).toBe(0);
    const result = runScript("restore", root);
    expect(result.status).toBe(0);
    expect(await readFile(join(root, "package.json"), "utf8")).toBe(original);
    expect(existsSync(join(root, "npm-shrinkwrap.json"))).toBe(false);
    expect(existsSync(join(root, backupName))).toBe(false);
  });

  it("restore is a no-op when there is nothing to restore", async () => {
    const original = await readFile(join(root, "package.json"), "utf8");
    const result = runScript("restore", root);
    expect(result.status).toBe(0);
    expect(await readFile(join(root, "package.json"), "utf8")).toBe(original);
  });

  it("rejects an unknown mode", () => {
    const result = runScript("frobnicate", root);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("usage:");
  });
});
