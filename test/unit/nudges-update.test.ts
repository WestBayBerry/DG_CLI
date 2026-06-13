import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const hoisted = vi.hoisted(() => ({
  readLatestVersion: vi.fn<() => string | null>()
}));

vi.mock("../../src/commands/update.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/commands/update.js")>();
  return { ...actual, readLatestVersion: hoisted.readLatestVersion };
});

import { maybeShowNudges, nudgeStatePath, pendingUpdate } from "../../src/runtime/nudges.js";
import { dgVersion } from "../../src/commands/version.js";

const tempRoots: string[] = [];

async function tempHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-nudge-update-"));
  tempRoots.push(root);
  return root;
}

function fakeStderr(): { isTTY: boolean; written: string[]; write(text: string): boolean } {
  return {
    isTTY: true,
    written: [],
    write(text: string) {
      this.written.push(text);
      return true;
    }
  };
}

describe("update-check state", () => {
  beforeEach(() => {
    hoisted.readLatestVersion.mockReset();
  });

  afterEach(async () => {
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
  });

  it("does not burn the 24h slot when the lookup fails", async () => {
    const home = await tempHome();
    const env = { HOME: home };
    const now = new Date("2026-06-09T10:00:00Z");

    hoisted.readLatestVersion.mockReturnValueOnce(null);
    const failed = fakeStderr();
    maybeShowNudges(["doctor"], { env, stderr: failed, now });
    expect(failed.written.join("")).not.toContain("Update available");

    hoisted.readLatestVersion.mockReturnValueOnce("99.0.0");
    const retried = fakeStderr();
    maybeShowNudges(["doctor"], { env, stderr: retried, now: new Date("2026-06-09T10:05:00Z") });
    expect(hoisted.readLatestVersion).toHaveBeenCalledTimes(2);
    expect(retried.written.join("")).toContain(`Update available: ${dgVersion()} → 99.0.0`);

    const state = JSON.parse(await readFile(nudgeStatePath(env), "utf8")) as { updateLatest?: string };
    expect(state.updateLatest).toBe("99.0.0");
  });

  it("throttles the next check only after a successful lookup", async () => {
    const home = await tempHome();
    const env = { HOME: home };

    hoisted.readLatestVersion.mockReturnValue("99.0.0");
    maybeShowNudges(["doctor"], { env, stderr: fakeStderr(), now: new Date("2026-06-09T10:00:00Z") });
    maybeShowNudges(["doctor"], { env, stderr: fakeStderr(), now: new Date("2026-06-09T11:00:00Z") });

    expect(hoisted.readLatestVersion).toHaveBeenCalledTimes(1);
  });

  it("pendingUpdate reads the stored latest without any lookup", async () => {
    const home = await tempHome();
    const env = { HOME: home };

    expect(pendingUpdate(env)).toBeNull();

    hoisted.readLatestVersion.mockReturnValueOnce("99.0.0");
    maybeShowNudges(["doctor"], { env, stderr: fakeStderr(), now: new Date("2026-06-09T10:00:00Z") });

    const lookupsAfterCheck = hoisted.readLatestVersion.mock.calls.length;
    expect(pendingUpdate(env)).toEqual({ current: dgVersion(), latest: "99.0.0" });
    expect(hoisted.readLatestVersion.mock.calls.length).toBe(lookupsAfterCheck);
  });

  it("pendingUpdate is null when the stored latest is current or older", async () => {
    const home = await tempHome();
    const env = { HOME: home };

    hoisted.readLatestVersion.mockReturnValueOnce(dgVersion());
    maybeShowNudges(["doctor"], { env, stderr: fakeStderr(), now: new Date("2026-06-09T10:00:00Z") });

    expect(pendingUpdate(env)).toBeNull();
  });
});
