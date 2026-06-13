import { gzipSync } from "node:zlib";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../../src/runtime/cli.js";
import { renderVerifySarif } from "../../src/verify/render.js";
import type { VerifyReport } from "../../src/verify/types.js";

const tempRoots: string[] = [];

describe("dg verify local artifacts", () => {
  afterEach(async () => {
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, {
      force: true,
      recursive: true
    })));
  });

  it("verifies package directories and workspaces without executing package scripts", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "workspace-root",
      scripts: {
        postinstall: "node ./write-pwned.js"
      },
      workspaces: [
        "packages/*"
      ]
    });
    await writePackage(join(root, "packages", "api"), "package.json", {
      name: "api",
      version: "1.0.0"
    });

    const result = await runCli(["verify", root, "--json"]);
    const report = JSON.parse(result.stdout) as {
      inputKind: string;
      status: string;
      sha256: string | null;
      workspaceScan: {
        summary: {
          projectCount: number;
        };
      };
      findings: Array<{
        id: string;
      }>;
    };

    expect(result.exitCode).toBe(1);
    expect(report.inputKind).toBe("workspace");
    expect(report.status).toBe("warn");
    expect(report.sha256).toBeNull();
    expect(report.workspaceScan.summary.projectCount).toBe(2);
    expect(report.findings.map((finding) => finding.id)).toContain("npm-lifecycle-script");
    expect(existsSync(join(root, "pwned"))).toBe(false);
  });

  it("verifies a package.json path through the safe local manifest scan", async () => {
    const root = await tempRoot();
    await writePackage(root, "package.json", {
      name: "manifest-target",
      version: "1.0.0",
      scripts: {
        postinstall: "node ./write-pwned.js"
      }
    });

    const result = await runCli(["verify", join(root, "package.json"), "--json"]);
    const report = JSON.parse(result.stdout) as {
      inputKind: string;
      status: string;
      workspaceScan: {
        summary: {
          projectCount: number;
        };
      };
      findings: Array<{
        id: string;
      }>;
    };

    expect(result.exitCode).toBe(1);
    expect(report.inputKind).toBe("package-directory");
    expect(report.status).toBe("warn");
    expect(report.workspaceScan.summary.projectCount).toBe(1);
    expect(report.findings.map((finding) => finding.id)).toContain("npm-lifecycle-script");
    expect(existsSync(join(root, "pwned"))).toBe(false);
  });

  it("verifies tgz artifacts with sha256 and package manifest findings", async () => {
    const root = await tempRoot();
    const artifactPath = join(root, "package.tgz");
    const tarball = gzipSync(createTarArchive([
      {
        name: "package/package.json",
        body: JSON.stringify({
          name: "archived-package",
          scripts: {
            prepare: "node build.js"
          }
        })
      }
    ]));
    await writeFile(artifactPath, tarball);

    const result = await runCli(["verify", artifactPath, "--json"]);
    const report = JSON.parse(result.stdout) as {
      archive: {
        entryCount: number;
        packageManifestCount: number;
      };
      inputKind: string;
      sha256: string;
      status: string;
      findings: Array<{
        id: string;
      }>;
    };

    expect(result.exitCode).toBe(1);
    expect(report.inputKind).toBe("tarball");
    expect(report.status).toBe("warn");
    expect(report.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(report.archive.entryCount).toBe(1);
    expect(report.archive.packageManifestCount).toBe(1);
    expect(report.findings.map((finding) => finding.id)).toEqual(["npm-lifecycle-script"]);
  });

  it("blocks unsafe zip and wheel archive paths before extraction", async () => {
    const root = await tempRoot();
    const zipPath = join(root, "unsafe.zip");
    const wheelPath = join(root, "unsafe.whl");
    const unsafe = createZipArchive([
      {
        name: "../escape.txt",
        body: "owned"
      }
    ]);
    await writeFile(zipPath, unsafe);
    await writeFile(wheelPath, unsafe);

    const zip = await runCli(["verify", zipPath]);
    const wheel = await runCli(["verify", wheelPath, "--sarif"]);
    const sarif = JSON.parse(wheel.stdout) as {
      runs: Array<{
        results: Array<{
          ruleId: string;
        }>;
      }>;
    };

    expect(zip.exitCode).toBe(2);
    expect(zip.stdout).toContain("BLOCK");
    expect(zip.stdout).toContain("archive-path-traversal");
    expect(wheel.exitCode).toBe(2);
    expect(sarif.runs[0]?.results[0]?.ruleId).toBe("archive-path-traversal");
  });

  it("keeps full SARIF artifact locations and only strips a trailing line suffix", () => {
    const report = sarifReport([
      { id: "npm-lifecycle-script", severity: "warn", title: "lifecycle script", message: "postinstall", location: "package/package.json:scripts.postinstall" },
      { id: "manifest-issue", severity: "warn", title: "manifest", message: "bad field", location: "manifest:$.dependencies.left-pad" },
      { id: "lockfile-url-fallback", severity: "block", title: "url fallback", message: "url", location: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" },
      { id: "lockfile-line", severity: "block", title: "line", message: "line", location: "requirements.txt:42" }
    ]);
    const sarif = JSON.parse(renderVerifySarif(report)) as {
      runs: Array<{ results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }> }>;
    };
    const uris = sarif.runs[0]!.results.map((result) => result.locations[0]!.physicalLocation.artifactLocation.uri);
    expect(uris).toEqual([
      "package/package.json:scripts.postinstall",
      "manifest:$.dependencies.left-pad",
      "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "requirements.txt"
    ]);
  });

  it("writes requested verify exports", async () => {
    const root = await tempRoot();
    const artifactPath = join(root, "package.zip");
    const outputPath = join(root, "verify-report.json");
    await writeFile(artifactPath, createZipArchive([
      {
        name: "package/package.json",
        body: JSON.stringify({
          name: "zip-package"
        })
      }
    ]));

    const result = await runCli(["verify", artifactPath, "--json", "--output", outputPath]);
    const exported = JSON.parse(await readFile(outputPath, "utf8")) as {
      inputKind: string;
      status: string;
    };

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe(`Wrote json verify report to ${outputPath}\n`);
    expect(exported.inputKind).toBe("zip");
    expect(exported.status).toBe("pass");
  });

  it("exits 4 when the verify export cannot be written", async () => {
    const root = await tempRoot();
    const artifactPath = join(root, "package.zip");
    await writeFile(artifactPath, createZipArchive([
      {
        name: "package/package.json",
        body: JSON.stringify({
          name: "zip-package"
        })
      }
    ]));

    const result = await runCli(["verify", artifactPath, "--json", "--output", join(root, "no-such-dir", "report.json")]);

    expect(result.exitCode).toBe(4);
    expect(result.stderr).toContain("could not write");
  });

  it("verifies remote url and git specs as advisory preflight blocks", async () => {
    const url = await runCli(["verify", "https://registry.example.test/remote-1.0.0.tgz", "--json"]);
    const git = await runCli(["verify", "github:example/pkg", "--json"]);
    const urlReport = JSON.parse(url.stdout) as {
      inputKind: string;
      status: string;
      preflight: {
        advisory: boolean;
        identitySource: string;
      };
      packages: Array<{
        ecosystem: string;
        name: string;
        resolvedUrl: string;
        sourceKind: string;
      }>;
      findings: Array<{
        id: string;
        severity: string;
      }>;
    };
    const gitReport = JSON.parse(git.stdout) as {
      status: string;
      findings: Array<{
        id: string;
      }>;
    };

    expect(url.exitCode).toBe(2);
    expect(urlReport.inputKind).toBe("package-spec");
    expect(urlReport.status).toBe("block");
    expect(urlReport.preflight).toMatchObject({
      advisory: true,
      identitySource: "package-spec"
    });
    expect(urlReport.packages[0]).toMatchObject({
      ecosystem: "unknown",
      name: "https://registry.example.test/remote-1.0.0.tgz",
      resolvedUrl: "https://registry.example.test/remote-1.0.0.tgz",
      sourceKind: "package-spec"
    });
    expect(urlReport.findings).toEqual([expect.objectContaining({
      id: "unverified-network-spec",
      severity: "block"
    })]);
    expect(git.exitCode).toBe(2);
    expect(gitReport.status).toBe("block");
    expect(gitReport.findings.map((finding) => finding.id)).toContain("unverified-network-spec");
  });

  it("blocks bare registry-style specs as unsupported in the advisory path", async () => {
    const bare = await runCli(["verify", "lodash@4.17.21", "--json"]);
    const report = JSON.parse(bare.stdout) as {
      status: string;
      findings: Array<{
        id: string;
      }>;
    };

    expect(bare.exitCode).toBe(2);
    expect(report.status).toBe("block");
    expect(report.findings.map((finding) => finding.id)).toContain("unsupported-package-spec");
  });

  it("maps package-lock identity and flags missing integrity before URL fallback", async () => {
    const root = await tempRoot();
    const lockfile = join(root, "package-lock.json");
    await writeFile(lockfile, JSON.stringify({
      name: "fixture",
      lockfileVersion: 3,
      packages: {
        "": {
          name: "fixture"
        },
        "node_modules/left-pad": {
          version: "1.3.0",
          resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
          integrity: "sha512-abc=",
          license: "GPL-3.0"
        },
        "node_modules/no-integrity": {
          version: "2.0.0",
          resolved: "https://registry.npmjs.org/no-integrity/-/no-integrity-2.0.0.tgz"
        }
      }
    }, null, 2), "utf8");

    const result = await runCli(["verify", lockfile, "--json"]);
    const report = JSON.parse(result.stdout) as {
      inputKind: string;
      status: string;
      preflight: {
        advisory: boolean;
        packageCount: number;
        identitySource: string;
      };
      packages: Array<{
        name: string;
        sourceKind: string;
        resolvedUrl: string;
        integrity: string | null;
        license: string | null;
      }>;
      findings: Array<{
        id: string;
        severity: string;
      }>;
    };

    expect(report.inputKind).toBe("lockfile");
    expect(report.preflight).toMatchObject({
      advisory: true,
      packageCount: 2,
      identitySource: "lockfile"
    });
    expect(report.packages[0]).toMatchObject({
      name: "left-pad",
      sourceKind: "lockfile",
      resolvedUrl: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      integrity: "sha512-abc=",
      license: "GPL-3.0"
    });
    expect(report.findings.map((finding) => finding.id)).toContain("missing-artifact-integrity");
  });

  it("takes pnpm identity from the packages section and strips peer-dependency suffixes", async () => {
    const root = await tempRoot();
    const lockfile = join(root, "pnpm-lock.yaml");
    await writeFile(lockfile, [
      "lockfileVersion: '9.0'",
      "",
      "importers:",
      "  .:",
      "    dependencies:",
      "      '@eslint-community/eslint-utils':",
      "        specifier: ^4.9.1",
      "        version: 4.9.1(eslint@9.39.4)",
      "",
      "packages:",
      "",
      "  '@eslint-community/eslint-utils@4.9.1':",
      "    resolution: {integrity: sha512-deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef==}",
      "    peerDependencies:",
      "      eslint: ^6.0.0 || ^7.0.0 || >=8.0.0",
      "",
      "  eslint@9.39.4:",
      "    resolution: {integrity: sha512-cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d==}",
      "",
      "snapshots:",
      "",
      "  '@eslint-community/eslint-utils@4.9.1(eslint@9.39.4)':",
      "    dependencies:",
      "      eslint: 9.39.4",
      "",
      "  eslint@9.39.4: {}",
      ""
    ].join("\n"), "utf8");

    const result = await runCli(["verify", lockfile, "--json"]);
    const report = JSON.parse(result.stdout) as {
      preflight: { packageCount: number };
      packages: Array<{ name: string; version: string | null; integrity: string | null }>;
    };

    expect(report.packages.map((pkg) => `${pkg.name}@${pkg.version}`).sort()).toEqual([
      "@eslint-community/eslint-utils@4.9.1",
      "eslint@9.39.4"
    ]);
    expect(report.preflight.packageCount).toBe(2);
    expect(report.packages.every((pkg) => !(pkg.version ?? "").includes("("))).toBe(true);
    expect(report.packages.find((pkg) => pkg.name === "@eslint-community/eslint-utils")?.integrity)
      .toBe("sha512-deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef==");
  });

  it("parses Yarn Berry colon-form version and checksum integrity without false missing-integrity", async () => {
    const root = await tempRoot();
    const lockfile = join(root, "yarn.lock");
    await writeFile(lockfile, [
      '# This file is generated by running "yarn install" inside your project.',
      "",
      "__metadata:",
      "  version: 8",
      "",
      '"lodash@npm:^4.17.0":',
      "  version: 4.17.21",
      '  resolution: "lodash@npm:4.17.21"',
      "  checksum: 10c0/d8cbea072bb08655bb4c989da418994b073a608dffa608b09ac04b43a791b12aeae7cd7ad919aa4c925f33b48490b5cf38b75d31bb5916ec2d4b2c2a2e74e5d3",
      "  languageName: node",
      "  linkType: hard",
      ""
    ].join("\n"), "utf8");

    const report = JSON.parse((await runCli(["verify", lockfile, "--json"])).stdout) as {
      packages: Array<{ name: string; version: string | null }>;
      findings: Array<{ id: string }>;
    };
    expect(report.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual(["lodash@4.17.21"]);
    expect(report.findings.map((finding) => finding.id)).not.toContain("missing-artifact-integrity");
  });

  it("resolves yarn npm-alias and patch descriptors to the registry target, skipping comments", async () => {
    const root = await tempRoot();
    const lockfile = join(root, "yarn.lock");
    await writeFile(lockfile, [
      "# yarn lockfile v1",
      "",
      '"my-alias@npm:real-package@^2.0.0":',
      '  version "2.3.1"',
      '  resolved "https://registry.yarnpkg.com/real-package/-/real-package-2.3.1.tgz#deadbeef"',
      "  integrity sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
      ""
    ].join("\n"), "utf8");

    const report = JSON.parse((await runCli(["verify", lockfile, "--json"])).stdout) as {
      packages: Array<{ name: string; version: string | null }>;
    };
    expect(report.packages).toEqual([expect.objectContaining({ name: "real-package", version: "2.3.1" })]);
  });

  it("enumerates lockfileVersion-1 nested transitive deps and resolves npm aliases", async () => {
    const root = await tempRoot();
    const lockfile = join(root, "package-lock.json");
    await writeFile(lockfile, JSON.stringify({
      name: "app",
      lockfileVersion: 1,
      dependencies: {
        express: {
          version: "4.18.2",
          resolved: "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
          integrity: "sha512-FFFF",
          dependencies: {
            "react-dom": { version: "npm:@scope/evil-fork@9.9.9", resolved: "https://registry.npmjs.org/@scope/evil-fork/-/evil-fork-9.9.9.tgz", integrity: "sha512-EEEE" }
          }
        }
      }
    }), "utf8");

    const report = JSON.parse((await runCli(["verify", lockfile, "--json"])).stdout) as {
      packages: Array<{ name: string; version: string | null }>;
    };
    const ids = report.packages.map((pkg) => `${pkg.name}@${pkg.version}`).sort();
    expect(ids).toEqual(["@scope/evil-fork@9.9.9", "express@4.18.2"]);
  });

  it("skips workspace link entries in a package-lock packages map", async () => {
    const root = await tempRoot();
    const lockfile = join(root, "package-lock.json");
    await writeFile(lockfile, JSON.stringify({
      name: "root",
      lockfileVersion: 3,
      packages: {
        "": { name: "root", version: "1.0.0", workspaces: ["packages/*"] },
        "node_modules/my-workspace": { resolved: "packages/my-workspace", link: true },
        "node_modules/left-pad": { version: "1.3.0", resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", integrity: "sha512-LP" }
      }
    }), "utf8");

    const report = JSON.parse((await runCli(["verify", lockfile, "--json"])).stdout) as {
      packages: Array<{ name: string }>;
    };
    expect(report.packages.map((pkg) => pkg.name)).toEqual(["left-pad"]);
  });

  it("parses pnpm file: and v5 slash keys without leaking integrity onto neighbours", async () => {
    const root = await tempRoot();
    const v9 = join(root, "pnpm-lock.yaml");
    await writeFile(v9, [
      "lockfileVersion: '9.0'",
      "",
      "packages:",
      "",
      "  is-odd@3.0.1:",
      "    resolution: {integrity: sha512-ISODD3001ISODD3001ISODD3001ISODD3001ISODD3001ISODD3001ISODD30==}",
      "",
      "  local-tarball@file:local-tarball.tgz:",
      "    resolution: {integrity: sha512-LEAKLEAKLEAKLEAKLEAKLEAKLEAKLEAKLEAKLEAKLEAKLEAKLEAKLEAKLEA==, tarball: file:local-tarball.tgz}",
      ""
    ].join("\n"), "utf8");

    const report = JSON.parse((await runCli(["verify", v9, "--json"])).stdout) as {
      packages: Array<{ name: string; version: string | null; integrity: string | null }>;
    };
    expect(report.packages).toEqual([
      expect.objectContaining({ name: "is-odd", version: "3.0.1", integrity: "sha512-ISODD3001ISODD3001ISODD3001ISODD3001ISODD3001ISODD3001ISODD30==" })
    ]);
  });

  it("retains pinned versions and per-requirement hashes in requirements.txt, skipping directives", async () => {
    const root = await tempRoot();
    const reqs = join(root, "requirements.txt");
    await writeFile(reqs, [
      "flask[async] == 3.0.0",
      "requests==2.31.0 \\",
      "    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f",
      "-r other-requirements.txt",
      "-c constraints.txt",
      "./local-package",
      ""
    ].join("\n"), "utf8");

    const report = JSON.parse((await runCli(["verify", reqs, "--json"])).stdout) as {
      packages: Array<{ name: string; version: string | null; integrity: string | null }>;
    };
    const byName = Object.fromEntries(report.packages.map((pkg) => [pkg.name, pkg]));
    expect(Object.keys(byName).sort()).toEqual(["flask", "requests"]);
    expect(byName.flask?.version).toBe("3.0.0");
    expect(byName.requests).toMatchObject({ version: "2.31.0", integrity: "sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f" });
  });

  it("reads poetry.lock inline file hashes as integrity", async () => {
    const root = await tempRoot();
    const lockfile = join(root, "poetry.lock");
    await writeFile(lockfile, [
      "[[package]]",
      'name = "requests"',
      'version = "2.31.0"',
      "files = [",
      '    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f"},',
      "]",
      ""
    ].join("\n"), "utf8");

    const report = JSON.parse((await runCli(["verify", lockfile, "--json"])).stdout) as {
      packages: Array<{ name: string; integrity: string | null }>;
      findings: Array<{ id: string }>;
    };
    expect(report.packages[0]?.integrity).toBe("sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f");
    expect(report.findings.map((finding) => finding.id)).not.toContain("missing-artifact-integrity");
  });

  it("handles hostile lockfile and spec inputs without executing project files", async () => {
    const root = await tempRoot();
    const lockfile = join(root, "requirements.txt");
    await writeFile(join(root, ".dg-allowlist.json"), "{\"packages\":[\"evil\"]}\n", "utf8");
    await writeFile(lockfile, [
      "requests==2.31.0 --hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "https://evil.example.test/pkg.whl"
    ].join("\n"), "utf8");

    const lock = await runCli(["verify", lockfile, "--json"]);
    const hostileSpec = await runCli(["verify", "bad\nname", "--json"]);
    const usage = await runCli(["verify", "--json", "--sarif", lockfile]);
    const lockReport = JSON.parse(lock.stdout) as {
      status: string;
      findings: Array<{
        id: string;
      }>;
    };
    const hostileReport = JSON.parse(hostileSpec.stdout) as {
      findings: Array<{
        id: string;
      }>;
    };

    expect(lock.exitCode).toBe(2);
    expect(lockReport.status).toBe("block");
    expect(lockReport.findings.map((finding) => finding.id)).toContain("lockfile-url-fallback");
    expect(hostileSpec.exitCode).toBe(2);
    expect(hostileReport.findings.map((finding) => finding.id)).toContain("unsupported-package-spec");
    expect(usage.exitCode).toBe(64);
    expect(usage.stderr).toContain("choose only one output format");
  });
});

function sarifReport(findings: VerifyReport["findings"]): VerifyReport {
  return {
    target: "fixture",
    inputKind: "tarball",
    status: "warn",
    sha256: null,
    sizeBytes: null,
    archive: null,
    workspaceScan: null,
    preflight: null,
    packages: [],
    findings,
    errors: [],
    summary: { findingCount: findings.length, warnCount: 0, blockCount: 0, errorCount: 0 }
  };
}

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-verify-test-"));
  tempRoots.push(root);
  return root;
}

async function writePackage(root: string, path: string, contents: Record<string, unknown>): Promise<void> {
  const packagePath = join(root, path);
  await mkdir(join(packagePath, ".."), {
    recursive: true
  });
  await writeFile(packagePath, `${JSON.stringify(contents, null, 2)}\n`, "utf8");
}

function createTarArchive(entries: Array<{ name: string; body: string }>): Buffer {
  const blocks: Buffer[] = [];
  for (const entry of entries) {
    const body = Buffer.from(entry.body);
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, "utf8");
    header.write("0000644\0", 100, 8, "ascii");
    header.write("0000000\0", 108, 8, "ascii");
    header.write("0000000\0", 116, 8, "ascii");
    header.write(`${body.length.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
    header.write("00000000000\0", 136, 12, "ascii");
    header[156] = "0".charCodeAt(0);
    header.write("ustar\0", 257, 6, "ascii");
    header.fill(0x20, 148, 156);
    const checksum = header.reduce((total, byte) => total + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
    blocks.push(header, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

function createZipArchive(entries: Array<{ name: string; body: string }>): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const body = Buffer.from(entry.body);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt32LE(body.length, 18);
    header.writeUInt32LE(body.length, 22);
    header.writeUInt16LE(name.length, 26);
    parts.push(header, name, body);
    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50, 0);
    record.writeUInt16LE(20, 4);
    record.writeUInt16LE(20, 6);
    record.writeUInt32LE(body.length, 20);
    record.writeUInt32LE(body.length, 24);
    record.writeUInt16LE(name.length, 28);
    record.writeUInt32LE(offset, 42);
    central.push(record, name);
    offset += 30 + name.length + body.length;
  }
  const centralSize = central.reduce((total, part) => total + part.length, 0);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, ...central, eocd]);
}
