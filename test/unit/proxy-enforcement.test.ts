import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { classifyPackageManagerInvocation } from "../../src/launcher/classify.js";
import { enforceProtectedInstall } from "../../src/proxy/enforcement.js";

const tempRoots: string[] = [];

async function tempHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-enforce-"));
  tempRoots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("enforceProtectedInstall never throws on corrupt local state", () => {
  it("returns a block decision when config.json is malformed", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".dg"), { recursive: true });
    await writeFile(join(home, ".dg", "config.json"), "{ not json", "utf8");

    const decision = enforceProtectedInstall({
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: home },
      proxyVerdict: {
        verdict: "block",
        packageName: "left-pad",
        cause: "malware",
        reason: "malware found"
      }
    });

    expect(decision.action).toBe("block");
    expect(decision.cause).toBe("malware");
  });

  it("fails closed (block) when no proxy verdict is supplied (B3-L7)", async () => {
    const home = await tempHome();
    const decision = enforceProtectedInstall({
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: home }
      // no proxyVerdict — the per-invocation proxy could not produce one
    });
    expect(decision.action).toBe("block");
    expect(decision.cause).toBe("proxy-setup-failure");
  });

  it("keeps a pass verdict passing when config.json is malformed", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".dg"), { recursive: true });
    await writeFile(join(home, ".dg", "config.json"), "{ not json", "utf8");

    const decision = enforceProtectedInstall({
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: home },
      proxyVerdict: {
        verdict: "pass",
        packageName: "left-pad",
        cause: "pass",
        reason: "ok"
      }
    });

    expect(decision.action).toBe("pass");
  });

  it("still blocks (no crash) when the audit log dir is unwritable during a blocked install", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".dg"), { recursive: true });
    await writeFile(join(home, ".dg", "state"), "a file where the state dir should be", "utf8");

    const decision = enforceProtectedInstall({
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: home },
      proxyVerdict: {
        verdict: "block",
        packageName: "left-pad",
        cause: "malware",
        reason: "malware found"
      }
    });

    expect(decision.action).toBe("block");
  });

  it("refuses the force override fail-closed when auth state is corrupt instead of crashing", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".dg"), { recursive: true });
    await writeFile(join(home, ".dg", "auth.json"), "{ not json", "utf8");

    const decision = enforceProtectedInstall({
      classification: classifyPackageManagerInvocation("npm", ["install", "left-pad"]),
      env: { HOME: home },
      proxyVerdict: {
        verdict: "block",
        packageName: "left-pad",
        cause: "malware",
        reason: "malware found"
      },
      forceOverride: { force: true }
    });

    expect(decision.action === "block" || decision.action === "warn").toBe(true);
    if (decision.action === "block") {
      expect(decision.forceOverride?.allowed).toBe(false);
    }
  });
});
