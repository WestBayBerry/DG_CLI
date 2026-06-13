import { mkdtemp, rm, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseLockfilePackages, verifyLockfile } from "../../src/verify/preflight.js";

const tempRoots: string[] = [];

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, {
    force: true,
    recursive: true
  })));
});

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-verify-preflight-"));
  tempRoots.push(root);
  return root;
}

async function writeLockfile(root: string, name: string, content: string): Promise<string> {
  const path = join(root, name);
  await writeFile(path, content, "utf8");
  return path;
}

function packageLockWithResolved(resolved: string): string {
  return JSON.stringify({
    name: "fixture",
    lockfileVersion: 3,
    packages: {
      "": {
        name: "fixture",
        dependencies: { foo: "^1.0.0" }
      },
      "node_modules/foo": {
        version: "1.0.0",
        resolved,
        integrity: "sha512-abc="
      }
    }
  });
}

describe("lockfile resolved host validation", () => {
  it("blocks a package-lock entry resolved outside the expected registry hosts", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "package-lock.json", packageLockWithResolved("https://evil.example.com/foo-1.0.0.tgz"));
    const report = verifyLockfile(path);
    const result = parseLockfilePackages(path);

    expect(report.status).toBe("block");
    expect(report.findings).toEqual([expect.objectContaining({
      id: "untrusted-registry-host",
      severity: "block",
      message: expect.stringContaining("evil.example.com")
    })]);
    expect(result.packages).toEqual([]);
    expect(result.skipped).toEqual([expect.objectContaining({ name: "foo", reason: "direct-url" })]);
  });

  it("keeps a registry-resolved package-lock entry passing", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "package-lock.json", packageLockWithResolved("https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"));
    const report = verifyLockfile(path);
    const result = parseLockfilePackages(path);

    expect(report.status).toBe("pass");
    expect(result.packages).toEqual([expect.objectContaining({ name: "foo", version: "1.0.0" })]);
    expect(result.skipped).toEqual([]);
  });

  it("trusts the project-configured registry from .npmrc beside the lockfile", async () => {
    const root = await tempRoot();
    await writeFile(join(root, ".npmrc"), "registry=https://npm.acme-corp.example/\n", "utf8");
    const path = await writeLockfile(root, "package-lock.json", packageLockWithResolved("https://npm.acme-corp.example/foo/-/foo-1.0.0.tgz"));
    const report = verifyLockfile(path);
    const result = parseLockfilePackages(path);

    expect(report.status).toBe("pass");
    expect(result.packages).toEqual([expect.objectContaining({ name: "foo", version: "1.0.0" })]);
  });

  it("trusts scoped registries declared in .npmrc", async () => {
    const root = await tempRoot();
    await writeFile(join(root, ".npmrc"), "@acme:registry=https://npm.pkg.example.com\n", "utf8");
    const path = await writeLockfile(root, "package-lock.json", JSON.stringify({
      name: "fixture",
      lockfileVersion: 3,
      packages: {
        "": { name: "fixture" },
        "node_modules/@acme/tool": {
          version: "2.0.0",
          resolved: "https://npm.pkg.example.com/@acme/tool/-/tool-2.0.0.tgz",
          integrity: "sha512-abc="
        }
      }
    }));
    const result = parseLockfilePackages(path);

    expect(result.packages).toEqual([expect.objectContaining({ name: "@acme/tool", version: "2.0.0" })]);
  });

  it("blocks a legacy lockfileVersion-1 entry resolved off-registry", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "package-lock.json", JSON.stringify({
      name: "fixture",
      lockfileVersion: 1,
      dependencies: {
        foo: {
          version: "1.0.0",
          resolved: "https://evil.example.com/foo-1.0.0.tgz",
          integrity: "sha512-abc="
        }
      }
    }));
    const report = verifyLockfile(path);
    const result = parseLockfilePackages(path);

    expect(report.findings.map((finding) => finding.id)).toContain("untrusted-registry-host");
    expect(result.packages).toEqual([]);
    expect(result.skipped).toEqual([expect.objectContaining({ name: "foo", reason: "direct-url" })]);
  });

  it("blocks a yarn classic entry resolved off-registry", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "yarn.lock", [
      "# yarn lockfile v1",
      "",
      "sneaky@^1.0.0:",
      '  version "1.0.0"',
      '  resolved "https://evil.example.com/sneaky-1.0.0.tgz#deadbeef"',
      "  integrity sha512-AAAA",
      ""
    ].join("\n"));
    const report = verifyLockfile(path);
    const result = parseLockfilePackages(path);

    expect(report.findings.map((finding) => finding.id)).toContain("untrusted-registry-host");
    expect(result.packages).toEqual([]);
  });

  it("keeps yarn classic registry.yarnpkg.com entries passing", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "yarn.lock", [
      "# yarn lockfile v1",
      "",
      "lodash@^4.17.0:",
      '  version "4.17.21"',
      '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#deadbeef"',
      "  integrity sha512-AAAA",
      ""
    ].join("\n"));
    const result = parseLockfilePackages(path);

    expect(result.packages).toEqual([expect.objectContaining({ name: "lodash", version: "4.17.21" })]);
  });

  it("blocks a pnpm packages entry with an off-registry tarball", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "pnpm-lock.yaml", [
      "lockfileVersion: '9.0'",
      "",
      "packages:",
      "",
      "  foo@1.0.0:",
      "    resolution: {integrity: sha512-AAAA, tarball: https://evil.example.com/foo-1.0.0.tgz}",
      "",
      "  is-odd@3.0.1:",
      "    resolution: {integrity: sha512-BBBB}",
      ""
    ].join("\n"));
    const report = verifyLockfile(path);
    const result = parseLockfilePackages(path);

    expect(report.findings.map((finding) => finding.id)).toContain("untrusted-registry-host");
    expect(result.packages).toEqual([expect.objectContaining({ name: "is-odd", version: "3.0.1" })]);
  });
});

describe("requirements.txt PEP 508 direct references", () => {
  it("blocks a name @ https direct reference instead of treating it as a registry pin", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "requirements.txt", [
      "flask==3.0.0",
      "requests @ https://evil.example.com/requests-1.0.0.tar.gz",
      ""
    ].join("\n"));
    const report = verifyLockfile(path);
    const result = parseLockfilePackages(path);

    expect(report.status).toBe("block");
    expect(report.findings.map((finding) => finding.id)).toContain("unverified-lockfile-url");
    expect(result.packages).toEqual([expect.objectContaining({ name: "flask", version: "3.0.0" })]);
    expect(result.skipped).toEqual([expect.objectContaining({ name: "requests", reason: "direct-url" })]);
  });

  it("classifies name @ git references as git sources", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "requirements.txt", [
      "tool @ git+https://github.com/example/tool.git@deadbeef",
      ""
    ].join("\n"));
    const report = verifyLockfile(path);
    const result = parseLockfilePackages(path);

    expect(report.findings.map((finding) => finding.id)).toContain("unverified-lockfile-url");
    expect(result.packages).toEqual([]);
    expect(result.skipped).toEqual([expect.objectContaining({ name: "tool", reason: "git" })]);
  });

  it("classifies name @ file references as local without a block", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "requirements.txt", [
      "local-pkg @ file:./local-pkg",
      ""
    ].join("\n"));
    const report = verifyLockfile(path);
    const result = parseLockfilePackages(path);

    expect(report.findings).toEqual([]);
    expect(result.packages).toEqual([]);
    expect(result.skipped).toEqual([expect.objectContaining({ name: "local-pkg", reason: "local" })]);
  });

  it("handles extras and environment markers on direct references", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "requirements.txt", [
      'requests[security] @ https://evil.example.com/requests.tar.gz ; python_version < "3.8"',
      ""
    ].join("\n"));
    const result = parseLockfilePackages(path);

    expect(result.packages).toEqual([]);
    expect(result.skipped).toEqual([expect.objectContaining({ name: "requests", reason: "direct-url" })]);
  });
});

describe("lockfile read size cap", () => {
  it("surfaces an over-cap lockfile as a parse error instead of reading it", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "package-lock.json", "{}");
    await truncate(path, 64 * 1024 * 1024 + 1);
    const report = verifyLockfile(path);
    const result = parseLockfilePackages(path);

    expect(result.packages).toEqual([]);
    expect(result.parseError?.reason).toContain("parse limit");
    expect(report.status).toBe("error");
    expect(report.errors.join("\n")).toContain("parse limit");
  });
});
