import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  firstRunMarkerPath,
  lastRunVersionMarkerPath,
  maybeShowFirstRun,
  sweepLegacyHooksOnVersionChange
} from "../../src/runtime/first-run.js";

const tempRoots: string[] = [];

async function tempHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-first-run-"));
  tempRoots.push(root);
  return root;
}

function fakeStderr(isTTY: boolean): { isTTY: boolean; written: string[]; write(text: string): boolean } {
  return {
    isTTY,
    written: [],
    write(text: string) {
      this.written.push(text);
      return true;
    }
  };
}

describe("first-run panel", () => {
  afterEach(async () => {
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
  });

  it("shows once on an interactive TTY and persists the marker", async () => {
    const home = await tempHome();
    const env = { HOME: home };
    const stderr = fakeStderr(true);

    expect(maybeShowFirstRun(["scan"], { env, stderr })).toBe(true);
    expect(stderr.written.join("")).toContain("Dependency Guardian is ready");
    expect(stderr.written.join("")).toContain("dg setup");
    expect(stderr.written.join("")).not.toContain("dg login");
    expect(existsSync(firstRunMarkerPath(env))).toBe(true);

    const second = fakeStderr(true);
    expect(maybeShowFirstRun(["scan"], { env, stderr: second })).toBe(false);
    expect(second.written).toHaveLength(0);
  });

  it("never shows in CI, non-TTY, machine output, or for skip commands", async () => {
    const home = await tempHome();
    const stderr = fakeStderr(true);

    expect(maybeShowFirstRun(["scan"], { env: { HOME: home, CI: "1" }, stderr })).toBe(false);
    expect(maybeShowFirstRun(["scan"], { env: { HOME: home }, stderr: fakeStderr(false) })).toBe(false);
    expect(maybeShowFirstRun(["scan", "--json"], { env: { HOME: home }, stderr })).toBe(false);
    expect(maybeShowFirstRun(["scan", "--sarif"], { env: { HOME: home }, stderr })).toBe(false);
    expect(maybeShowFirstRun(["licenses", "--csv"], { env: { HOME: home }, stderr })).toBe(false);
    expect(maybeShowFirstRun(["licenses", "--markdown"], { env: { HOME: home }, stderr })).toBe(false);
    expect(maybeShowFirstRun(["scan", "--output", "out.json"], { env: { HOME: home }, stderr })).toBe(false);
    expect(maybeShowFirstRun(["scan", "-o", "out.json"], { env: { HOME: home }, stderr })).toBe(false);
    expect(maybeShowFirstRun(["--help"], { env: { HOME: home }, stderr })).toBe(false);
    expect(maybeShowFirstRun(["login"], { env: { HOME: home }, stderr })).toBe(false);
    expect(stderr.written).toHaveLength(0);
    expect(existsSync(firstRunMarkerPath({ HOME: home }))).toBe(false);
  });
});

describe("legacy python hook sweep on version transition", () => {
  afterEach(async () => {
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
  });

  async function writeLegacyHook(home: string): Promise<string> {
    const site = join(home, ".local", "lib", "python3.12", "site-packages");
    await mkdir(site, { recursive: true });
    const pth = join(site, "dg_pip_hook.pth");
    await writeFile(pth, "import dg_pip_hook\n", "utf8");
    return pth;
  }

  it("sweeps once per version and again on the next transition", async () => {
    const home = await tempHome();
    const env = { HOME: home };
    const pth = await writeLegacyHook(home);

    expect(sweepLegacyHooksOnVersionChange(env, "2.0.9")).toBe(true);
    expect(existsSync(pth)).toBe(false);
    expect(existsSync(lastRunVersionMarkerPath(env))).toBe(true);

    await writeFile(pth, "import dg_pip_hook\n", "utf8");
    expect(sweepLegacyHooksOnVersionChange(env, "2.0.9")).toBe(false);
    expect(existsSync(pth)).toBe(true);

    expect(sweepLegacyHooksOnVersionChange(env, "2.1.0")).toBe(true);
    expect(existsSync(pth)).toBe(false);
  });

  it("runs from maybeShowFirstRun even on quiet non-TTY paths", async () => {
    const home = await tempHome();
    const pth = await writeLegacyHook(home);

    maybeShowFirstRun(["--version"], { env: { HOME: home }, stderr: fakeStderr(false) });

    expect(existsSync(pth)).toBe(false);
    expect(existsSync(lastRunVersionMarkerPath({ HOME: home }))).toBe(true);
  });
});
