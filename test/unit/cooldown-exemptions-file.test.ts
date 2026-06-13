import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  COOLDOWN_EXEMPTIONS_ENV,
  loadCooldownExemptionsFile,
  writeCooldownExemptionsFile
} from "../../src/proxy/cooldown-exemptions-file.js";
import type { CooldownExemption } from "../../src/project/dgfile.js";

const made: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "dg-exempt-file-"));
  made.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of made.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function exemption(over: Partial<CooldownExemption> = {}): CooldownExemption {
  return { ecosystem: "npm", name: "left-pad", reason: "", acceptedBy: "t", acceptedAt: "2026-06-01T00:00:00.000Z", ...over };
}

describe("cooldown exemptions file", () => {
  it("round-trips exemptions through the session file", () => {
    const dir = tempDir();
    const env = writeCooldownExemptionsFile(dir, [exemption(), exemption({ ecosystem: "pypi", name: "flask" })]);
    const path = env[COOLDOWN_EXEMPTIONS_ENV];
    expect(path).toBeDefined();
    const loaded = loadCooldownExemptionsFile(path);
    expect(loaded).toHaveLength(2);
    expect(loaded[0]?.name).toBe("left-pad");
    expect(loaded[1]?.ecosystem).toBe("pypi");
  });

  it("passes a path, not the payload — env size stays tiny no matter how many exemptions (no ARG_MAX/E2BIG risk)", () => {
    const dir = tempDir();
    const many = Array.from({ length: 500 }, (_unused, i) => exemption({ name: `${"x".repeat(2000)}-${i}` }));
    const env = writeCooldownExemptionsFile(dir, many);
    const value = env[COOLDOWN_EXEMPTIONS_ENV] ?? "";
    expect(value.length).toBeLessThan(4096);
    expect(loadCooldownExemptionsFile(value)).toHaveLength(500);
  });

  it("returns no env var for an empty exemption set", () => {
    expect(writeCooldownExemptionsFile(tempDir(), [])).toEqual({});
  });

  it("revalidates each entry on load and drops malformed ones (the 0600 file is a trust boundary)", () => {
    const dir = tempDir();
    const path = join(dir, "evil.json");
    writeFileSync(
      path,
      JSON.stringify([
        exemption({ name: "good" }),
        { ecosystem: "npm", name: "" },
        { ecosystem: "bogus", name: "x" },
        { ecosystem: "npm", name: "has space" },
        "not-an-object"
      ]),
      "utf8"
    );
    expect(loadCooldownExemptionsFile(path).map((e) => e.name)).toEqual(["good"]);
  });

  it("fails open: missing path, missing file, and corrupt JSON all yield an empty list", () => {
    const dir = tempDir();
    expect(loadCooldownExemptionsFile(undefined)).toEqual([]);
    expect(loadCooldownExemptionsFile(join(dir, "nope.json"))).toEqual([]);
    const corrupt = join(dir, "corrupt.json");
    writeFileSync(corrupt, "{ not json", "utf8");
    expect(loadCooldownExemptionsFile(corrupt)).toEqual([]);
    const notArray = join(dir, "obj.json");
    writeFileSync(notArray, JSON.stringify({ ecosystem: "npm" }), "utf8");
    expect(loadCooldownExemptionsFile(notArray)).toEqual([]);
  });
});
