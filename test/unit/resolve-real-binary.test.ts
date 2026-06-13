import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolveRealBinary } from "../../src/launcher/resolve-real-binary.js";

const made: string[] = [];
afterEach(() => {
  for (const d of made.splice(0)) rmSync(d, { recursive: true, force: true });
});

function binDir(names: string[]): string {
  const dir = mkdtempSync(join(tmpdir(), "dg-bin-"));
  made.push(dir);
  for (const name of names) {
    const p = join(dir, name);
    writeFileSync(p, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    chmodSync(p, 0o755);
  }
  return dir;
}

function env(pathDir: string): NodeJS.ProcessEnv {
  const home = mkdtempSync(join(tmpdir(), "dg-home-"));
  made.push(home);
  return { ...process.env, HOME: home, PATH: pathDir };
}

describe("resolveRealBinary fallback to pip3/python3", () => {
  it("finds pip3 when only pip3 is present (no bare pip)", () => {
    const dir = binDir(["pip3"]);
    expect(resolveRealBinary({ name: "pip", env: env(dir) }).path).toBe(join(dir, "pip3"));
  });

  it("finds python3 when only python3 is present", () => {
    const dir = binDir(["python3"]);
    expect(resolveRealBinary({ name: "python", env: env(dir) }).path).toBe(join(dir, "python3"));
  });

  it("prefers the exact name over the fallback when both exist", () => {
    const dir = binDir(["pip", "pip3"]);
    expect(resolveRealBinary({ name: "pip", env: env(dir) }).path).toBe(join(dir, "pip"));
  });

  it("returns null when neither the name nor a fallback exists", () => {
    const dir = binDir(["yarn"]);
    expect(resolveRealBinary({ name: "pip", env: env(dir) }).path).toBeNull();
  });

  it("skips dg shim files even if named correctly", () => {
    const dir = mkdtempSync(join(tmpdir(), "dg-bin-"));
    made.push(dir);
    const shim = join(dir, "pip3");
    writeFileSync(shim, "#!/bin/sh\n# dg-shim-v1\nexit 0\n", { mode: 0o755 });
    chmodSync(shim, 0o755);
    expect(resolveRealBinary({ name: "pip", env: env(dir) }).path).toBeNull();
  });
});
