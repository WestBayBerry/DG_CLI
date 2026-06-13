import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  HELD_PACKAGES_CAP,
  heldPackagesPath,
  readHeldPackages,
  recordHeldPackage,
  type NewHeldPackage
} from "../../src/state/cooldown-held.js";

const NOW = new Date("2026-06-12T12:00:00.000Z");

function entry(overrides: Partial<NewHeldPackage> = {}): NewHeldPackage {
  return {
    ecosystem: "npm",
    name: "left-pad",
    version: "2.0.1",
    requiredDays: 7,
    ageDays: 0.2,
    publishedAt: "2026-06-12T07:00:00.000Z",
    eligibleAt: "2026-06-19T07:00:00.000Z",
    manager: "npm",
    ...overrides
  };
}

describe("cooldown held-package store", () => {
  let home: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "dg-held-"));
    env = { HOME: home };
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("records an entry with seen timestamps and tight file permissions", () => {
    recordHeldPackage(entry(), env, NOW);
    const held = readHeldPackages(env, NOW);
    expect(held).toHaveLength(1);
    expect(held[0]).toMatchObject({
      ecosystem: "npm",
      name: "left-pad",
      version: "2.0.1",
      requiredDays: 7,
      eligibleAt: "2026-06-19T07:00:00.000Z",
      firstSeenAt: NOW.toISOString(),
      lastSeenAt: NOW.toISOString()
    });
    expect(statSync(heldPackagesPath(env)).mode & 0o777).toBe(0o600);
  });

  it("dedups on ecosystem:name@version, keeping firstSeenAt and refreshing the rest", () => {
    recordHeldPackage(entry(), env, NOW);
    const later = new Date(NOW.getTime() + 60_000);
    recordHeldPackage(entry({ requiredDays: 3 }), env, later);
    const held = readHeldPackages(env, later);
    expect(held).toHaveLength(1);
    expect(held[0]?.firstSeenAt).toBe(NOW.toISOString());
    expect(held[0]?.lastSeenAt).toBe(later.toISOString());
    expect(held[0]?.requiredDays).toBe(3);

    recordHeldPackage(entry({ version: "2.0.2" }), env, later);
    expect(readHeldPackages(env, later)).toHaveLength(2);
  });

  it("prunes entries whose eligibility has passed", () => {
    recordHeldPackage(entry({ eligibleAt: "2026-06-12T11:00:00.000Z" }), env, NOW);
    expect(readHeldPackages(env, NOW)).toHaveLength(0);
  });

  it("expires unknown-eligibility entries after the 30 day TTL", () => {
    recordHeldPackage(entry({ eligibleAt: undefined, publishedAt: undefined, ageDays: undefined }), env, NOW);
    const within = new Date(NOW.getTime() + 29 * 24 * 60 * 60 * 1000);
    expect(readHeldPackages(env, within)).toHaveLength(1);
    const beyond = new Date(NOW.getTime() + 31 * 24 * 60 * 60 * 1000);
    expect(readHeldPackages(env, beyond)).toHaveLength(0);
  });

  it("caps the store and evicts the oldest entries", () => {
    for (let index = 0; index < HELD_PACKAGES_CAP + 1; index += 1) {
      recordHeldPackage(
        entry({ name: `pkg-${index}` }),
        env,
        new Date(NOW.getTime() + index * 1000)
      );
    }
    const held = readHeldPackages(env, new Date(NOW.getTime() + (HELD_PACKAGES_CAP + 2) * 1000));
    expect(held).toHaveLength(HELD_PACKAGES_CAP);
    expect(held.some((candidate) => candidate.name === "pkg-0")).toBe(false);
    expect(held.some((candidate) => candidate.name === `pkg-${HELD_PACKAGES_CAP}`)).toBe(true);
  });

  it("recovers from a corrupt store file", async () => {
    const path = heldPackagesPath(env);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, "{not json", "utf8");
    expect(readHeldPackages(env, NOW)).toEqual([]);
    recordHeldPackage(entry(), env, NOW);
    expect(readHeldPackages(env, NOW)).toHaveLength(1);
  });
});
