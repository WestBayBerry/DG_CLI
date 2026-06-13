import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../../src/runtime/cli.js";

const tempRoots: string[] = [];

describe("dg licenses exit codes", () => {
  afterEach(async () => {
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, {
      force: true,
      recursive: true
    })));
  });

  it("exits 2 on a policy block and versions the JSON schema", async () => {
    const root = await tempRoot();
    await writeFile(join(root, "package.json"), JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      license: "GPL-3.0"
    }), "utf8");

    const result = await runCli(["licenses", root, "--json", "--fail-on", "strong-copyleft"]);
    const report = JSON.parse(result.stdout) as { schemaVersion: number; status: string; summary: { blockedCount: number } };

    expect(result.exitCode).toBe(2);
    expect(report.schemaVersion).toBe(1);
    expect(report.status).toBe("block");
    expect(report.summary.blockedCount).toBe(1);
  });

  it("exits 0 on pass", async () => {
    const root = await tempRoot();
    await writeFile(join(root, "package.json"), JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      license: "MIT"
    }), "utf8");

    const result = await runCli(["licenses", root, "--json", "--fail-on", "strong-copyleft"]);

    expect(result.exitCode).toBe(0);
    expect((JSON.parse(result.stdout) as { status: string }).status).toBe("pass");
  });

  it("exits 4 when the target path does not exist", async () => {
    const root = await tempRoot();

    const result = await runCli(["licenses", join(root, "missing-dir"), "--json"]);

    expect(result.exitCode).toBe(4);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("dg licenses failed:");
  });

  it("exits 4 when the report cannot be written", async () => {
    const root = await tempRoot();
    await writeFile(join(root, "package.json"), JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      license: "MIT"
    }), "utf8");
    const blockedDir = join(root, "sealed");
    await mkdir(blockedDir, { mode: 0o555 });

    const result = await runCli(["licenses", root, "--json", "--output", join(blockedDir, "report.json")]);

    expect(result.exitCode).toBe(4);
    expect(result.stderr).toContain("could not write");
  });
});

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-licenses-test-"));
  tempRoots.push(root);
  return root;
}
