import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readNpmManifestSpecs, readPipRequirementSpecs } from "../../src/launcher/manifest-screen.js";

function dir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe("readNpmManifestSpecs", () => {
  it("returns null when no package.json exists", () => {
    expect(readNpmManifestSpecs(dir("dg-npm-none-"))).toBeNull();
  });

  it("collects direct deps from all dependency fields, deduped", () => {
    const d = dir("dg-npm-deps-");
    writeFileSync(
      join(d, "package.json"),
      JSON.stringify({
        dependencies: { a: "^1", b: "^2" },
        devDependencies: { b: "^2", c: "^3" },
        optionalDependencies: { d: "^4" },
      }),
    );
    const result = readNpmManifestSpecs(d);
    expect(result?.truncated).toBe(false);
    expect(result?.specs.map((s) => s.name).sort()).toEqual(["a", "b", "c", "d"]);
  });

  it("pins versions from package-lock.json when present", () => {
    const d = dir("dg-npm-lock-");
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: { lodash: "^4.0.0" } }));
    writeFileSync(
      join(d, "package-lock.json"),
      JSON.stringify({ packages: { "node_modules/lodash": { version: "4.17.21" } } }),
    );
    expect(readNpmManifestSpecs(d)?.specs).toEqual([{ name: "lodash", version: "4.17.21" }]);
  });

  it("leaves the version null when a dep is not in the lockfile", () => {
    const d = dir("dg-npm-nolock-");
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: { lodash: "^4.0.0" } }));
    expect(readNpmManifestSpecs(d)?.specs).toEqual([{ name: "lodash", version: null }]);
  });

  it("marks truncated and caps when there are more than 100 direct deps", () => {
    const d = dir("dg-npm-big-");
    const deps: Record<string, string> = {};
    for (let i = 0; i < 150; i += 1) {
      deps[`pkg-${i}`] = "^1.0.0";
    }
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: deps }));
    const result = readNpmManifestSpecs(d);
    expect(result?.truncated).toBe(true);
    expect(result?.specs.length).toBe(100);
  });

  it("returns null for unparsable package.json", () => {
    const d = dir("dg-npm-bad-");
    writeFileSync(join(d, "package.json"), "{ not json");
    expect(readNpmManifestSpecs(d)).toBeNull();
  });
});

describe("readPipRequirementSpecs", () => {
  it("returns null when no -r flag is present", () => {
    expect(readPipRequirementSpecs(["install", "requests"], dir("dg-pip-none-"))).toBeNull();
  });

  it("returns null (not truncated) when the requirements file is missing", () => {
    expect(readPipRequirementSpecs(["install", "-r", "requirements.txt"], dir("dg-pip-missing-"))).toBeNull();
  });

  it("parses pinned and ranged specs, skipping comments and options", () => {
    const d = dir("dg-pip-parse-");
    writeFileSync(
      join(d, "requirements.txt"),
      ["# a comment", "", "requests==2.31.0", "flask>=2.0", "-e .", "--hash=sha256:abc", "django[argon2]==4.2"].join("\n"),
    );
    const result = readPipRequirementSpecs(["install", "-r", "requirements.txt"], d);
    expect(result?.specs).toEqual([
      { name: "requests", version: "2.31.0" },
      { name: "flask", version: null },
      { name: "django", version: "4.2" },
    ]);
  });

  it("skips git+ and url specs", () => {
    const d = dir("dg-pip-url-");
    writeFileSync(join(d, "requirements.txt"), ["git+https://example.com/x.git", "https://example.com/y.tar.gz", "requests==1.0"].join("\n"));
    expect(readPipRequirementSpecs(["install", "-r", "requirements.txt"], d)?.specs).toEqual([{ name: "requests", version: "1.0" }]);
  });

  it("honors --requirement=<file> form", () => {
    const d = dir("dg-pip-eq-");
    writeFileSync(join(d, "deps.txt"), "requests==2.0.0\n");
    expect(readPipRequirementSpecs(["install", "--requirement=deps.txt"], d)?.specs).toEqual([{ name: "requests", version: "2.0.0" }]);
  });
});
