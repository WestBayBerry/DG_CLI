import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appendCooldownExemptions, dgFilePath, loadDgFile, mutateDgFile } from "../../src/project/dgfile.js";
import { honoredOverrides } from "../../src/project/override-trust.js";

describe("project override provenance gate (H6)", () => {
  let home: string;
  let repo: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-override-home-"));
    repo = mkdtempSync(join(tmpdir(), "dg-override-repo-"));
    env = { HOME: home };
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  });

  function writeHostileExemption(): void {
    writeFileSync(
      dgFilePath(repo),
      JSON.stringify({
        version: 1,
        cooldownExemptions: [{ ecosystem: "npm", name: "evil-pkg", reason: "trust me", acceptedBy: "attacker" }],
      }),
      "utf8",
    );
  }

  it("drops a repo-shipped exemption this machine never authored", () => {
    writeHostileExemption();
    const result = honoredOverrides(loadDgFile(repo), repo, env, false);
    expect(result.exemptions).toHaveLength(0);
    expect(result.droppedExemptions).toBe(1);
  });

  it("honors a repo-shipped exemption when the repo is explicitly trusted", () => {
    writeHostileExemption();
    const result = honoredOverrides(loadDgFile(repo), repo, env, true);
    expect(result.exemptions).toHaveLength(1);
    expect(result.droppedExemptions).toBe(0);
  });

  it("honors a locally-authored exemption (stamped through the write path) without the trust flag", () => {
    mutateDgFile(repo, env, (file) =>
      appendCooldownExemptions(file, [{ ecosystem: "npm", name: "left-pad", reason: "vendored", acceptedBy: "me" }]),
    );
    const result = honoredOverrides(loadDgFile(repo), repo, env, false);
    expect(result.exemptions.map((e) => e.name)).toEqual(["left-pad"]);
    expect(result.droppedExemptions).toBe(0);
  });

  it("does not honor a locally-authored exemption replayed into a different repo root", () => {
    mutateDgFile(repo, env, (file) =>
      appendCooldownExemptions(file, [{ ecosystem: "npm", name: "left-pad", reason: "vendored", acceptedBy: "me" }]),
    );
    const stamped = loadDgFile(repo);
    const otherRepo = mkdtempSync(join(tmpdir(), "dg-override-other-"));
    try {
      // Same stamped file, different root: the HMAC is bound to the authoring
      // repo path, so a copied dg.json doesn't carry its authorization elsewhere.
      const result = honoredOverrides(stamped, otherRepo, env, false);
      expect(result.exemptions).toHaveLength(0);
    } finally {
      rmSync(otherRepo, { recursive: true, force: true });
    }
  });
});
