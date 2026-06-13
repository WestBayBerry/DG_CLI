import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  appendCooldownExemptions,
  appendDecisions,
  cooldownExemptionActive,
  COOLDOWN_EXEMPTION_CAP,
  CooldownExemptionCapError,
  DECISION_ENTRY_CAP,
  DG_FILE_NAME,
  dgFilePath,
  emptyDgFile,
  loadDgFile,
  removeCooldownExemptions,
  removeDecisions,
  saveDgFile,
  type NewCooldownExemption,
  type NewDecision
} from "../../src/project/dgfile.js";

const made: string[] = [];

function tempRoot(): string {
  const dir = mkdtempSync(join(tmpdir(), "dg-dgfile-"));
  made.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of made.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function entryJson(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "11111111-2222-3333-4444-555555555555",
    ecosystem: "npm",
    name: "left-pad",
    scope: { kind: "exact", version: "1.3.0" },
    findings: { lifecycle: 3 },
    reason: "team accepted",
    acceptedBy: "alice@example.com",
    acceptedAt: "2026-06-01T00:00:00.000Z",
    ...over
  };
}

function writeDg(root: string, value: unknown): void {
  writeFileSync(dgFilePath(root), typeof value === "string" ? value : JSON.stringify(value), "utf8");
}

const newDecision: NewDecision = {
  ecosystem: "npm",
  name: "left-pad",
  scope: { kind: "exact", version: "1.3.0" },
  findings: { lifecycle: 3 },
  reason: "added in test",
  acceptedBy: "tester"
};

describe("dg.json loader", () => {
  it("resolves dg.json at the project root", () => {
    expect(dgFilePath("/some/project")).toBe(join("/some/project", DG_FILE_NAME));
  });

  it("treats a missing file as an empty readable store", () => {
    const file = loadDgFile(tempRoot());
    expect(file.exists).toBe(false);
    expect(file.readable).toBe(true);
    expect(file.decisions).toEqual([]);
    expect(file.scriptApprovals.npm).toEqual({});
    expect(file.scriptApprovals.observed).toEqual({});
    expect(file.scriptApprovals.unknownKeys).toEqual({});
  });

  it("fails open on malformed JSON without inventing content", () => {
    const root = tempRoot();
    writeDg(root, "{not json");
    const file = loadDgFile(root);
    expect(file.exists).toBe(true);
    expect(file.readable).toBe(false);
    expect(file.failure).toContain("malformed JSON");
    expect(file.decisions).toEqual([]);
    expect(file.scriptApprovals).toEqual(emptyDgFile(file.path).scriptApprovals);
  });

  it("fails open on an unsupported version", () => {
    const root = tempRoot();
    writeDg(root, { version: 2, decisions: [entryJson()] });
    const file = loadDgFile(root);
    expect(file.readable).toBe(false);
    expect(file.decisions).toEqual([]);
  });

  it("fails open when decisions is not an array", () => {
    const root = tempRoot();
    writeDg(root, { version: 1, decisions: { nope: true } });
    expect(loadDgFile(root).readable).toBe(false);
  });

  it("fails open beyond the entry cap", () => {
    const root = tempRoot();
    writeDg(root, { version: 1, decisions: Array.from({ length: DECISION_ENTRY_CAP + 1 }, () => entryJson()) });
    const file = loadDgFile(root);
    expect(file.readable).toBe(false);
    expect(file.failure).toContain(String(DECISION_ENTRY_CAP));
  });

  it("skips invalid entries but keeps valid ones", () => {
    const root = tempRoot();
    writeDg(root, {
      version: 1,
      decisions: [
        entryJson(),
        entryJson({ ecosystem: "cargo" }),
        entryJson({ name: "" }),
        entryJson({ scope: { kind: "range", range: ">=1" } }),
        entryJson({ findings: { lifecycle: 9 } }),
        "garbage"
      ]
    });
    const file = loadDgFile(root);
    expect(file.readable).toBe(true);
    expect(file.decisions).toHaveLength(1);
    expect(file.decisions[0]?.name).toBe("left-pad");
  });

  it("derives a stable id for hand-written entries without one", () => {
    const root = tempRoot();
    const raw = entryJson();
    delete raw.id;
    writeDg(root, { version: 1, decisions: [raw] });
    const first = loadDgFile(root).decisions[0]?.id;
    const second = loadDgFile(root).decisions[0]?.id;
    expect(first).toBeTruthy();
    expect(first).toBe(second);
  });

  it("tolerates unknown top-level keys and missing version", () => {
    const root = tempRoot();
    writeDg(root, { scriptApprovals: { "left-pad@1.3.0": { approved: true } }, decisions: [entryJson()] });
    const file = loadDgFile(root);
    expect(file.readable).toBe(true);
    expect(file.decisions).toHaveLength(1);
    expect(file.scriptApprovals.unknownKeys["left-pad@1.3.0"]).toEqual({ approved: true });
  });

  it("drops __proto__, constructor, and prototype keys from every untrusted dg.json object", () => {
    const root = tempRoot();
    const approval =
      '{"decision":"allow","scriptsHash":"sha256:a","hooks":["install"],"approvedAt":"2026-06-01T00:00:00.000Z","provenance":"prompt"}';
    const decision =
      '{"ecosystem":"npm","name":"left-pad","scope":{"kind":"any"},"findings":{},"reason":"","acceptedBy":"t",' +
      '"acceptedAt":"2026-06-01T00:00:00.000Z","ticket":"JIRA-1","__proto__":{"polluted":true},"prototype":{"polluted":true}}';
    const exemption =
      '{"ecosystem":"npm","name":"left-pad","reason":"","acceptedBy":"t","acceptedAt":"2026-06-01T00:00:00.000Z",' +
      '"__proto__":{"polluted":true},"keep":1}';
    writeDg(
      root,
      '{"version":1,"__proto__":{"polluted":true},"constructor":{"polluted":true},' +
        `"decisions":[${decision}],"cooldownExemptions":[${exemption}],` +
        `"scriptApprovals":{"npm":{"__proto__":${approval},"constructor":${approval},"prototype":${approval},"good":${approval}}}}`
    );

    const file = loadDgFile(root);
    expect(file.readable).toBe(true);
    expect(Object.keys(file.scriptApprovals.npm)).toEqual(["good"]);
    expect(Object.getPrototypeOf(file.scriptApprovals.npm)).toBe(Object.prototype);
    expect(file.decisions[0]?.extra).toEqual({ ticket: "JIRA-1" });
    expect(Object.getPrototypeOf(file.decisions[0]?.extra)).toBe(Object.prototype);
    expect(file.cooldownExemptions[0]?.extra).toEqual({ keep: 1 });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();

    saveDgFile(file);
    const rewritten = readFileSync(dgFilePath(root), "utf8");
    expect(rewritten).not.toContain("__proto__");
    expect(rewritten).not.toContain("polluted");
  });

  it("drops structurally invalid approval entries while keeping valid ones", () => {
    const root = tempRoot();
    writeDg(root, {
      version: 1,
      scriptApprovals: {
        npm: {
          good: {
            decision: "allow",
            scriptsHash: "sha256:a",
            hooks: ["install", "bogus-hook"],
            approvedAt: "2026-06-01T00:00:00.000Z",
            provenance: "prompt"
          },
          bad: { decision: "maybe" }
        },
        observed: {
          seen: { version: "1.0.0", hooks: ["postinstall"], scriptsHash: "sha256:c", firstSeen: "2026-06-01T00:00:00.000Z" },
          broken: "not-an-object"
        }
      }
    });

    const file = loadDgFile(root);
    expect(file.readable).toBe(true);
    expect(Object.keys(file.scriptApprovals.npm)).toEqual(["good"]);
    expect(file.scriptApprovals.npm.good?.hooks).toEqual(["install"]);
    expect(Object.keys(file.scriptApprovals.observed)).toEqual(["seen"]);
  });
});

describe("dg.json writer", () => {
  it("appends, saves, and round-trips while preserving unknown keys", () => {
    const root = tempRoot();
    writeDg(root, { scriptApprovals: { "x@1": { approved: true } }, future: [1, 2] });
    const updated = appendDecisions(loadDgFile(root), [newDecision]);
    saveDgFile(updated);

    const raw = JSON.parse(readFileSync(dgFilePath(root), "utf8")) as Record<string, unknown>;
    expect(raw.version).toBe(1);
    expect(raw.scriptApprovals).toEqual({ "x@1": { approved: true } });
    expect(raw.future).toEqual([1, 2]);

    const reloaded = loadDgFile(root);
    expect(reloaded.decisions).toHaveLength(1);
    expect(reloaded.decisions[0]?.scope).toEqual({ kind: "exact", version: "1.3.0" });
    expect(reloaded.decisions[0]?.findings).toEqual({ lifecycle: 3 });
    expect(reloaded.decisions[0]?.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(reloaded.decisions[0]?.acceptedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("round-trips unknown top-level keys, decisions, and script approvals verbatim", () => {
    const root = tempRoot();
    const original = {
      version: 1,
      allowlist: [{ packageName: "left-pad", reason: "vetted" }],
      decisions: [entryJson()],
      futureTopLevel: { nested: true },
      scriptApprovals: {
        npm: {
          esbuild: {
            decision: "allow",
            scriptsHash: "sha256:abc",
            hooks: ["postinstall"],
            approvedVersion: "0.25.5",
            approvedAt: "2026-06-01T00:00:00.000Z",
            provenance: "prompt"
          }
        },
        futureSection: { keep: "me" }
      }
    };
    writeDg(root, original);

    const read = loadDgFile(root);
    expect(read.readable).toBe(true);
    expect(read.raw.allowlist).toEqual(original.allowlist);
    expect(read.raw.futureTopLevel).toEqual(original.futureTopLevel);
    expect(read.decisions).toHaveLength(1);
    expect(read.scriptApprovals.unknownKeys.futureSection).toEqual({ keep: "me" });
    expect(read.scriptApprovals.npm.esbuild?.decision).toBe("allow");

    saveDgFile(read);
    const reparsed = JSON.parse(readFileSync(read.path, "utf8")) as Record<string, unknown>;
    expect(reparsed.allowlist).toEqual(original.allowlist);
    expect(reparsed.decisions).toEqual(original.decisions);
    expect(reparsed.futureTopLevel).toEqual(original.futureTopLevel);
    expect((reparsed.scriptApprovals as Record<string, unknown>).futureSection).toEqual({ keep: "me" });
    expect((reparsed.scriptApprovals as Record<string, unknown>).npm).toEqual(original.scriptApprovals.npm);
  });

  it("writes canonical sorted two-space JSON with a trailing newline and version first", () => {
    const root = tempRoot();
    const path = dgFilePath(root);
    saveDgFile({
      ...emptyDgFile(path),
      scriptApprovals: {
        npm: {
          zlib: {
            decision: "deny",
            scriptsHash: "sha256:b",
            hooks: ["install"],
            approvedAt: "2026-06-02T00:00:00.000Z",
            provenance: "command"
          },
          esbuild: {
            decision: "allow",
            scriptsHash: "sha256:a",
            hooks: ["postinstall"],
            approvedAt: "2026-06-01T00:00:00.000Z",
            provenance: "prompt"
          }
        },
        observed: {},
        unknownKeys: {}
      }
    });

    const text = readFileSync(path, "utf8");
    expect(text.endsWith("\n")).toBe(true);
    expect(text.startsWith('{\n  "version": 1')).toBe(true);
    expect(text.indexOf('"esbuild"')).toBeLessThan(text.indexOf('"zlib"'));
    const parsed = JSON.parse(text) as { scriptApprovals: { npm: Record<string, unknown> } };
    expect(Object.keys(parsed.scriptApprovals.npm)).toEqual(["esbuild", "zlib"]);
    expect(parsed).not.toHaveProperty("decisions");
  });

  it("creates dg.json with version 1 when none exists", () => {
    const root = tempRoot();
    saveDgFile(appendDecisions(loadDgFile(root), [newDecision]));
    const raw = JSON.parse(readFileSync(dgFilePath(root), "utf8")) as Record<string, unknown>;
    expect(raw.version).toBe(1);
    expect(Array.isArray(raw.decisions)).toBe(true);
  });

  it("removeDecisions drops only the targeted ids", () => {
    const root = tempRoot();
    saveDgFile(appendDecisions(loadDgFile(root), [newDecision, { ...newDecision, name: "other-pkg" }]));
    const file = loadDgFile(root);
    const target = file.decisions.find((entry) => entry.name === "left-pad");
    expect(target).toBeDefined();
    saveDgFile(removeDecisions(file, new Set([target?.id ?? ""])));
    const reloaded = loadDgFile(root);
    expect(reloaded.decisions).toHaveLength(1);
    expect(reloaded.decisions[0]?.name).toBe("other-pkg");
  });

  it("preserves unknown entry fields across a rewrite", () => {
    const root = tempRoot();
    writeDg(root, { version: 1, decisions: [entryJson({ titles: ["install lifecycle script"], artifactSha256: "ab".repeat(32) })] });
    saveDgFile(appendDecisions(loadDgFile(root), [{ ...newDecision, name: "second-pkg" }]));

    const raw = JSON.parse(readFileSync(dgFilePath(root), "utf8")) as { decisions: Array<Record<string, unknown>> };
    expect(raw.decisions).toHaveLength(2);
    expect(raw.decisions[0]?.titles).toEqual(["install lifecycle script"]);
    expect(raw.decisions[0]?.artifactSha256).toBe("ab".repeat(32));
  });

  it("refuses to rewrite an unreadable file", () => {
    const root = tempRoot();
    writeDg(root, "{broken");
    expect(() => saveDgFile(loadDgFile(root))).toThrow(/refusing/);
  });
});

describe("dg.json cooldown exemptions", () => {
  const newExemption: NewCooldownExemption = {
    ecosystem: "npm",
    name: "left-pad",
    reason: "vendored",
    acceptedBy: "tester"
  };

  it("appends, round-trips, and stamps acceptedAt", () => {
    const root = tempRoot();
    const now = new Date("2026-06-10T00:00:00.000Z");
    saveDgFile(appendCooldownExemptions(loadDgFile(root), [newExemption], now));
    const reloaded = loadDgFile(root);
    expect(reloaded.cooldownExemptions).toHaveLength(1);
    expect(reloaded.cooldownExemptions[0]?.name).toBe("left-pad");
    expect(reloaded.cooldownExemptions[0]?.acceptedAt).toBe("2026-06-10T00:00:00.000Z");
  });

  it("de-duplicates by (ecosystem, name) so re-exempting replaces", () => {
    const root = tempRoot();
    let file = appendCooldownExemptions(loadDgFile(root), [{ ...newExemption, reason: "first" }]);
    file = appendCooldownExemptions(file, [{ ...newExemption, reason: "second" }]);
    expect(file.cooldownExemptions).toHaveLength(1);
    expect(file.cooldownExemptions[0]?.reason).toBe("second");
  });

  it("removeCooldownExemptions drops only matching entries and preserves decisions", () => {
    const root = tempRoot();
    let file = appendDecisions(loadDgFile(root), [newDecision]);
    file = appendCooldownExemptions(file, [newExemption, { ...newExemption, name: "other" }]);
    saveDgFile(file);
    const reloaded = loadDgFile(root);
    saveDgFile(removeCooldownExemptions(reloaded, (e) => e.name === "left-pad"));
    const after = loadDgFile(root);
    expect(after.cooldownExemptions).toHaveLength(1);
    expect(after.cooldownExemptions[0]?.name).toBe("other");
    expect(after.decisions).toHaveLength(1);
  });

  it("cooldownExemptionActive respects expiry and fails closed on an unparseable date", () => {
    const now = new Date("2026-06-10T00:00:00.000Z");
    const base = { ecosystem: "npm" as const, name: "x", reason: "", acceptedBy: "t", acceptedAt: "2026-06-01T00:00:00.000Z" };
    expect(cooldownExemptionActive(base, now)).toBe(true);
    expect(cooldownExemptionActive({ ...base, expiresAt: "2026-07-01T00:00:00.000Z" }, now)).toBe(true);
    expect(cooldownExemptionActive({ ...base, expiresAt: "2026-01-01T00:00:00.000Z" }, now)).toBe(false);
    expect(cooldownExemptionActive({ ...base, expiresAt: "not-a-date" }, now)).toBe(false);
  });

  it("drops malformed exemption entries on load", () => {
    const root = tempRoot();
    writeDg(root, {
      version: 1,
      cooldownExemptions: [
        { ecosystem: "npm", name: "ok", reason: "", acceptedBy: "t", acceptedAt: "2026-06-01T00:00:00.000Z" },
        { ecosystem: "cargo", name: "serde", reason: "", acceptedBy: "t", acceptedAt: "2026-06-01T00:00:00.000Z" },
        { ecosystem: "maven", name: "bad-eco" },
        { ecosystem: "npm" },
        "not-an-object"
      ]
    });
    const file = loadDgFile(root);
    expect(file.cooldownExemptions.map((e) => `${e.ecosystem}:${e.name}`)).toEqual(["npm:ok", "cargo:serde"]);
  });

  it("keeps an entry with a non-string expiresAt, treating it as no-expiry (not dropped)", () => {
    const root = tempRoot();
    writeDg(root, {
      version: 1,
      cooldownExemptions: [{ ecosystem: "npm", name: "internal", reason: "", acceptedBy: "t", acceptedAt: "2026-06-01T00:00:00.000Z", expiresAt: 123 }]
    });
    const file = loadDgFile(root);
    expect(file.cooldownExemptions).toHaveLength(1);
    expect(file.cooldownExemptions[0]?.expiresAt).toBeUndefined();
    expect(cooldownExemptionActive(file.cooldownExemptions[0]!, new Date("2026-06-10T00:00:00.000Z"))).toBe(true);
  });

  it("preserves unknown exemption fields across a rewrite", () => {
    const root = tempRoot();
    writeDg(root, {
      version: 1,
      cooldownExemptions: [{ ecosystem: "npm", name: "left-pad", reason: "vendored", acceptedBy: "alice", acceptedAt: "2026-06-01T00:00:00.000Z", approvedTicket: "JIRA-123" }]
    });
    saveDgFile(appendCooldownExemptions(loadDgFile(root), [{ ecosystem: "npm", name: "other", reason: "", acceptedBy: "bob" }]));
    const raw = JSON.parse(readFileSync(dgFilePath(root), "utf8")) as { cooldownExemptions: Array<Record<string, unknown>> };
    const leftPad = raw.cooldownExemptions.find((e) => e.name === "left-pad");
    expect(leftPad?.approvedTicket).toBe("JIRA-123");
  });

  it("carries an unknown field forward when the same package is re-exempted", () => {
    const root = tempRoot();
    writeDg(root, {
      version: 1,
      cooldownExemptions: [{ ecosystem: "npm", name: "left-pad", reason: "old", acceptedBy: "alice", acceptedAt: "2026-06-01T00:00:00.000Z", approvedTicket: "JIRA-123" }]
    });
    saveDgFile(appendCooldownExemptions(loadDgFile(root), [{ ecosystem: "npm", name: "left-pad", reason: "updated", acceptedBy: "bob" }]));
    const raw = JSON.parse(readFileSync(dgFilePath(root), "utf8")) as { cooldownExemptions: Array<Record<string, unknown>> };
    const leftPad = raw.cooldownExemptions.find((e) => e.name === "left-pad");
    expect(leftPad?.reason).toBe("updated");
    expect(leftPad?.approvedTicket).toBe("JIRA-123");
  });

  it("rejects an over-cap append instead of fail-closing the whole file", () => {
    const root = tempRoot();
    writeDg(root, {
      version: 1,
      cooldownExemptions: Array.from({ length: COOLDOWN_EXEMPTION_CAP }, (_unused, i) => ({ ecosystem: "npm", name: `pkg-${i}`, reason: "", acceptedBy: "a", acceptedAt: "2026-06-01T00:00:00.000Z" }))
    });
    expect(() => appendCooldownExemptions(loadDgFile(root), [{ ecosystem: "npm", name: "one-too-many", reason: "", acceptedBy: "a" }]))
      .toThrow(CooldownExemptionCapError);
  });

  it("canonicalizes a hand-edited non-canonical pypi name on load (so rm/dedup/proxy all agree)", () => {
    const root = tempRoot();
    writeDg(root, {
      version: 1,
      cooldownExemptions: [{ ecosystem: "pypi", name: "Flask.SQLAlchemy", reason: "hand", acceptedBy: "x", acceptedAt: "2026-06-01T00:00:00.000Z" }]
    });
    expect(loadDgFile(root).cooldownExemptions[0]?.name).toBe("flask-sqlalchemy");
  });

  it("appendCooldownExemptions dedups within a single additions batch (last canonical wins)", () => {
    const root = tempRoot();
    const updated = appendCooldownExemptions(loadDgFile(root), [
      { ecosystem: "pypi", name: "Foo_Bar", reason: "first", acceptedBy: "x" },
      { ecosystem: "pypi", name: "foo-bar", reason: "second", acceptedBy: "x" }
    ]);
    expect(updated.cooldownExemptions).toHaveLength(1);
    expect(updated.cooldownExemptions[0]).toMatchObject({ name: "foo-bar", reason: "second" });
  });

  it("appendCooldownExemptions dedups a pre-existing non-canonical pypi entry by canonical name", () => {
    const root = tempRoot();
    writeDg(root, {
      version: 1,
      cooldownExemptions: [{ ecosystem: "pypi", name: "Flask.SQLAlchemy", reason: "old", acceptedBy: "x", acceptedAt: "2026-06-01T00:00:00.000Z" }]
    });
    const updated = appendCooldownExemptions(loadDgFile(root), [{ ecosystem: "pypi", name: "flask-sqlalchemy", reason: "new", acceptedBy: "y" }]);
    expect(updated.cooldownExemptions).toHaveLength(1);
    expect(updated.cooldownExemptions[0]?.reason).toBe("new");
  });

  it("drops exemption names with whitespace, control characters, or a glob on load", () => {
    const root = tempRoot();
    writeDg(root, {
      version: 1,
      cooldownExemptions: [
        { ecosystem: "npm", name: "good-pkg", reason: "", acceptedBy: "x", acceptedAt: "2026-06-01T00:00:00.000Z" },
        { ecosystem: "npm", name: "evil\nname", reason: "", acceptedBy: "x", acceptedAt: "2026-06-01T00:00:00.000Z" },
        { ecosystem: "npm", name: "with space", reason: "", acceptedBy: "x", acceptedAt: "2026-06-01T00:00:00.000Z" },
        { ecosystem: "npm", name: "@scope/*", reason: "", acceptedBy: "x", acceptedAt: "2026-06-01T00:00:00.000Z" }
      ]
    });
    const file = loadDgFile(root);
    expect(file.cooldownExemptions.map((e) => e.name)).toEqual(["good-pkg"]);
  });

  it("fails open (treats dg.json as unreadable) when cooldownExemptions exceeds the cap", () => {
    const root = tempRoot();
    const many = Array.from({ length: 501 }, (_unused, i) => ({ ecosystem: "npm", name: `pkg-${i}`, reason: "", acceptedBy: "t", acceptedAt: "2026-06-01T00:00:00.000Z" }));
    writeDg(root, { version: 1, cooldownExemptions: many });
    const file = loadDgFile(root);
    expect(file.readable).toBe(false);
    expect(file.failure).toContain("more than 500 cooldownExemptions");
  });
});
