import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { assertSupportedNode, isSupportedNode, parseNodeVersion, resolveShimFallback } from "../../src/runtime/node-version.js";

describe("node runtime contract", () => {
  it("parses stable and prerelease Node versions", () => {
    expect(parseNodeVersion("v22.14.0")).toEqual({
      major: 22,
      minor: 14,
      patch: 0
    });
    expect(parseNodeVersion("24.0.0-rc.1")).toEqual({
      major: 24,
      minor: 0,
      patch: 0
    });
  });

  it("requires Node >=22.14.0", () => {
    expect(isSupportedNode("22.13.1")).toBe(false);
    expect(isSupportedNode("22.14.0")).toBe(true);
    expect(isSupportedNode("24.3.0")).toBe(true);
  });

  it("throws a hard runtime error for unsupported Node", () => {
    expect(() => assertSupportedNode("22.13.1")).toThrow("dg requires Node.js >=22.14.0");
  });
});

describe("shim fallback on Node-guard failure", () => {
  it("returns null for a direct dg invocation (no shim marker)", async () => {
    const fallback = await resolveShimFallback({ PATH: "/usr/bin:/bin" }, ["node", "/x/dg.js", "npm", "install"]);
    expect(fallback).toBeNull();
  });

  it("resolves the real manager with a protection-inactive warning when shim-invoked", async () => {
    const home = mkdtempSync(join(tmpdir(), "dg-shim-fallback-"));
    const binDir = join(home, "bin");
    mkdirSync(binDir, { recursive: true });
    const npm = join(binDir, "npm");
    writeFileSync(npm, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    chmodSync(npm, 0o755);
    try {
      const fallback = await resolveShimFallback(
        { DG_SHIM_ACTIVE: "npm:1", HOME: home, PATH: binDir },
        ["node", "/x/dg.js", "npm", "install", "left-pad"]
      );
      expect(fallback?.binary).toBe(npm);
      expect(fallback?.args).toEqual(["install", "left-pad"]);
      expect(fallback?.warning).toContain("dg: protection inactive");
      expect(fallback?.warning).toContain("npm");
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  it("returns null when no real manager exists outside the dg shims", async () => {
    const home = mkdtempSync(join(tmpdir(), "dg-shim-fallback-miss-"));
    try {
      const fallback = await resolveShimFallback(
        { DG_SHIM_ACTIVE: "npm:1", HOME: home, PATH: join(home, "empty-bin") },
        ["node", "/x/dg.js", "npm", "install"]
      );
      expect(fallback).toBeNull();
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});
