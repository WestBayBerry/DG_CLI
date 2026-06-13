import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { isProxyCause } from "../../src/proxy/server.js";

// Producer fixture lives at the monorepo root and does not ship in the
// public snapshot; the contract only runs where the producer exists.
const causesPath = resolve(dirname(fileURLToPath(import.meta.url)), "../../../install-verdict-causes.json");
const causes: string[] = existsSync(causesPath)
  ? (JSON.parse(readFileSync(causesPath, "utf8")) as { causes: string[] }).causes
  : [];

describe.skipIf(causes.length === 0)("install-verdict cause contract (CLI proxy)", () => {
  it("isProxyCause accepts every canonical API cause so none are silently dropped", () => {
    expect(causes.length).toBeGreaterThan(0);
    for (const c of causes) {
      expect(
        isProxyCause(c),
        `isProxyCause must accept API cause "${c}" or proxy/server.ts drops it (block rendered with no reason)`,
      ).toBe(true);
    }
  });
});
