import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { auditLogPath, recordAuditEvent, type AuditEvent } from "../../src/audit/events.js";
import { resolveDgPaths } from "../../src/state/index.js";

const made: string[] = [];

afterEach(async () => {
  await Promise.all(made.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function tempHome(): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), "dg-audit-events-"));
  made.push(home);
  return home;
}

function event(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    type: "install.blocked",
    packageName: "left-pad",
    reason: "confirmed malware",
    policyMode: "block",
    createdAt: "2026-06-11T00:00:00.000Z",
    ...over
  };
}

describe("recordAuditEvent", () => {
  it("appends a JSON line to audit.jsonl in a 0700 state dir and reports success", async () => {
    const home = await tempHome();
    const paths = resolveDgPaths({ HOME: home });

    expect(recordAuditEvent(event(), { HOME: home })).toBe(true);
    expect(recordAuditEvent(event({ type: "decision.accepted" }), { HOME: home })).toBe(true);

    const lines = (await readFile(auditLogPath(paths), "utf8")).trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]!)).toMatchObject({ type: "install.blocked", packageName: "left-pad" });
    expect((await stat(paths.stateDir)).mode & 0o777).toBe(0o700);
  });

  it("returns false instead of throwing when the state dir cannot be created", async () => {
    const home = await tempHome();
    const paths = resolveDgPaths({ HOME: home });
    await mkdir(join(paths.stateDir, ".."), { recursive: true });
    await writeFile(paths.stateDir, "not a directory", "utf8");

    expect(recordAuditEvent(event(), { HOME: home })).toBe(false);
  });

  it("never writes a webhook outbox", async () => {
    const home = await tempHome();
    const paths = resolveDgPaths({ HOME: home });

    expect(recordAuditEvent(event(), { HOME: home })).toBe(true);
    expect(await readdir(paths.stateDir)).toEqual(["audit.jsonl"]);
  });
});
