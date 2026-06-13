import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { maybeShowNudges } from "../../src/runtime/nudges.js";
import { dgVersion } from "../../src/commands/version.js";

const tempRoots: string[] = [];

async function tempHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-nudges-"));
  tempRoots.push(root);
  return root;
}

function fakeStderr(isTTY = true): { isTTY: boolean; written: string[]; write(text: string): boolean } {
  return {
    isTTY,
    written: [],
    write(text: string) {
      this.written.push(text);
      return true;
    }
  };
}

function withLatest<T>(latest: string, run: () => T): T {
  const previous = process.env.DG_UPDATE_LATEST_VERSION;
  process.env.DG_UPDATE_LATEST_VERSION = latest;
  try {
    return run();
  } finally {
    if (previous === undefined) {
      delete process.env.DG_UPDATE_LATEST_VERSION;
    } else {
      process.env.DG_UPDATE_LATEST_VERSION = previous;
    }
  }
}

describe("throttled nudges", () => {
  afterEach(async () => {
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
  });

  it("shows the update and login nudges once, then throttles", async () => {
    const home = await tempHome();
    const env = { HOME: home };
    const first = fakeStderr();
    withLatest("99.0.0", () => maybeShowNudges(["doctor"], { env, stderr: first, now: new Date("2026-06-03T10:00:00Z") }));
    const firstOut = first.written.join("");

    expect(firstOut).toContain(`Update available: ${dgVersion()} → 99.0.0`);
    expect(firstOut).toContain("dg login");

    const second = fakeStderr();
    withLatest("99.0.0", () => maybeShowNudges(["doctor"], { env, stderr: second, now: new Date("2026-06-03T11:00:00Z") }));
    expect(second.written).toHaveLength(0);

    const muchLater = fakeStderr();
    withLatest("99.0.0", () => maybeShowNudges(["doctor"], { env, stderr: muchLater, now: new Date("2026-06-05T10:00:01Z") }));
    expect(muchLater.written.join("")).toContain("Update available");
    expect(muchLater.written.join("")).not.toContain("dg login");
  });

  it("stays silent when current, in CI, non-TTY, machine output, or TUI commands", async () => {
    const home = await tempHome();
    const stderr = fakeStderr();

    withLatest(dgVersion(), () => maybeShowNudges(["doctor"], { env: { HOME: home }, stderr, now: new Date() }));
    expect(stderr.written.join("")).not.toContain("Update available");

    const silent = fakeStderr();
    withLatest("99.0.0", () => {
      maybeShowNudges(["doctor"], { env: { HOME: home, CI: "1" }, stderr: silent });
      maybeShowNudges(["doctor"], { env: { HOME: home }, stderr: fakeStderr(false) });
      maybeShowNudges(["doctor", "--json"], { env: { HOME: home }, stderr: silent });
      maybeShowNudges(["scan"], { env: { HOME: home }, stderr: silent });
      maybeShowNudges(["licenses"], { env: { HOME: home }, stderr: silent });
    });
    expect(silent.written).toHaveLength(0);
  });
});
