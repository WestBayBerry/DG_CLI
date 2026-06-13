import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { computeScriptsHash, detectPnpmIgnoredBuilds, detectScriptWanters } from "../../src/scripts/detect.js";

const made: string[] = [];

function tempProject(): string {
  const dir = mkdtempSync(join(tmpdir(), "dg-script-detect-"));
  made.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of made.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function writeFileAt(root: string, relative: string, content: string): void {
  const path = join(root, relative);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf8");
}

function writePackage(root: string, relative: string, manifest: Record<string, unknown>, withBindingGyp = false): void {
  writeFileAt(root, join(relative, "package.json"), JSON.stringify(manifest));
  if (withBindingGyp) {
    writeFileAt(root, join(relative, "binding.gyp"), "{ \"targets\": [] }");
  }
}

describe("detectScriptWanters via the npm hidden lockfile", () => {
  it("detects script wanters, implicit gyp builds, and alias names from a fixture tree", () => {
    const project = tempProject();
    writePackage(project, "node_modules/esbuild", {
      name: "esbuild",
      version: "0.25.5",
      scripts: { postinstall: "node install.js" }
    });
    writePackage(project, "node_modules/left-pad", { name: "left-pad", version: "1.3.0" });
    writePackage(project, "node_modules/@scoped/native", { name: "@scoped/native", version: "2.0.0", scripts: {} }, true);
    writePackage(project, "node_modules/alias-dir", {
      name: "real-native",
      version: "3.1.4",
      scripts: { install: "prebuild-install || node-gyp rebuild" }
    });
    writePackage(project, "node_modules/dup-host/node_modules/esbuild", {
      name: "esbuild",
      version: "0.20.0",
      scripts: { postinstall: "node install.js" }
    });
    writeFileAt(
      project,
      "node_modules/.package-lock.json",
      JSON.stringify({
        name: "fixture",
        lockfileVersion: 3,
        packages: {
          "": { name: "fixture" },
          "node_modules/esbuild": { version: "0.25.5", hasInstallScript: true },
          "node_modules/left-pad": { version: "1.3.0" },
          "node_modules/@scoped/native": { version: "2.0.0", hasInstallScript: true },
          "node_modules/alias-dir": { version: "3.1.4", hasInstallScript: true },
          "node_modules/dup-host/node_modules/esbuild": { version: "0.20.0", hasInstallScript: true }
        }
      })
    );

    const wanters = detectScriptWanters(project);

    expect(wanters.map((wanter) => wanter.name)).toEqual(["@scoped/native", "esbuild", "real-native"]);
    const esbuild = wanters.find((wanter) => wanter.name === "esbuild");
    expect(esbuild?.version).toBe("0.25.5");
    expect(esbuild?.hooks).toEqual(["postinstall"]);
    expect(esbuild?.scriptsHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    const native = wanters.find((wanter) => wanter.name === "@scoped/native");
    expect(native?.hooks).toEqual(["gyp"]);
    const aliased = wanters.find((wanter) => wanter.name === "real-native");
    expect(aliased?.hooks).toEqual(["install"]);
  });

  it("skips lockfile entries whose manifest is missing", () => {
    const project = tempProject();
    writeFileAt(
      project,
      "node_modules/.package-lock.json",
      JSON.stringify({ packages: { "node_modules/ghost": { version: "1.0.0", hasInstallScript: true } } })
    );

    expect(detectScriptWanters(project)).toEqual([]);
  });

  it("ignores lockfile package keys that traverse outside node_modules", () => {
    const base = tempProject();
    const project = join(base, "project");
    writePackage(base, "outside", {
      name: "outside-pkg",
      version: "1.0.0",
      scripts: { postinstall: "node steal.js" }
    });
    writePackage(project, "", {
      name: "project-root",
      version: "1.0.0",
      scripts: { postinstall: "node build.js" }
    });
    writePackage(project, "node_modules/honest", {
      name: "honest",
      version: "1.0.0",
      scripts: { postinstall: "node install.js" }
    });
    writeFileAt(
      project,
      "node_modules/.package-lock.json",
      JSON.stringify({
        packages: {
          "node_modules/../../outside": { version: "1.0.0", hasInstallScript: true },
          "node_modules/..": { version: "1.0.0", hasInstallScript: true },
          "node_modules/.": { version: "1.0.0", hasInstallScript: true },
          "node_modules/honest": { version: "1.0.0", hasInstallScript: true }
        }
      })
    );

    expect(detectScriptWanters(project).map((wanter) => wanter.name)).toEqual(["honest"]);
  });
});

describe("detectScriptWanters via the node_modules walk (yarn classic trees)", () => {
  it("finds lifecycle scripts, scoped packages, and implicit gyp builds without a hidden lockfile", () => {
    const project = tempProject();
    writePackage(project, "node_modules/esbuild", {
      name: "esbuild",
      version: "0.25.5",
      scripts: { postinstall: "node install.js" }
    });
    writePackage(project, "node_modules/@scope/hooked", {
      name: "@scope/hooked",
      version: "1.0.0",
      scripts: { preinstall: "node setup.js", test: "vitest" }
    });
    writePackage(project, "node_modules/plain", { name: "plain", version: "1.0.0", scripts: { test: "noop" } });
    writePackage(project, "node_modules/gyp-only", { name: "gyp-only", version: "0.9.0" }, true);
    writeFileAt(project, "node_modules/.bin/esbuild", "#!/bin/sh\n");

    const wanters = detectScriptWanters(project);

    expect(wanters.map((wanter) => wanter.name)).toEqual(["@scope/hooked", "esbuild", "gyp-only"]);
    expect(wanters.find((wanter) => wanter.name === "gyp-only")?.hooks).toEqual(["gyp"]);
    expect(wanters.find((wanter) => wanter.name === "@scope/hooked")?.hooks).toEqual(["preinstall"]);
  });

  it("returns an empty list when node_modules does not exist", () => {
    expect(detectScriptWanters(tempProject())).toEqual([]);
  });
});

describe("computeScriptsHash", () => {
  it("is stable for identical commands and changes when a command or gyp presence changes", () => {
    const base = computeScriptsHash({ postinstall: "node install.js" }, false);
    expect(base).toBe(computeScriptsHash({ postinstall: "node install.js", test: "irrelevant" }, false));
    expect(base).not.toBe(computeScriptsHash({ postinstall: "node evil.js" }, false));
    expect(base).not.toBe(computeScriptsHash({ postinstall: "node install.js" }, true));
    expect(base).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

describe("detectPnpmIgnoredBuilds", () => {
  it("parses the ignoredBuilds block from .modules.yaml", () => {
    const project = tempProject();
    writeFileAt(
      project,
      "node_modules/.modules.yaml",
      ["hoistPattern:", "  - '*'", "ignoredBuilds:", "  - esbuild", "  - '@scoped/native'", "layoutVersion: 5", ""].join("\n")
    );

    expect(detectPnpmIgnoredBuilds(project)).toEqual(["esbuild", "@scoped/native"]);
  });

  it("handles an empty inline list and a missing file", () => {
    const project = tempProject();
    writeFileAt(project, "node_modules/.modules.yaml", "ignoredBuilds: []\nlayoutVersion: 5\n");

    expect(detectPnpmIgnoredBuilds(project)).toEqual([]);
    expect(detectPnpmIgnoredBuilds(tempProject())).toEqual([]);
  });
});
