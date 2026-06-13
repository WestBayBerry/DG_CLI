import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { collectScanPackages, discoverScanProjects } from "../../src/scan/collect.js";
import { parseLockfilePackages, verifyLockfile } from "../../src/verify/preflight.js";

const tempRoots: string[] = [];

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-lockfile-parse-"));
  tempRoots.push(root);
  return root;
}

async function writeLockfile(root: string, name: string, content: string): Promise<string> {
  const path = join(root, name);
  await writeFile(path, content, "utf8");
  return path;
}

function identityList(packages: ReadonlyArray<{ ecosystem: string; name: string; version: string | null }>): string[] {
  return packages.map((pkg) => `${pkg.ecosystem}:${pkg.name}@${pkg.version}`).sort();
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, {
    force: true,
    recursive: true
  })));
});

describe("pnpm lockfile versions", () => {
  const cases = [
    {
      version: "5.4",
      content: [
        "lockfileVersion: 5.4",
        "",
        "specifiers:",
        "  lodash: ^4.17.21",
        "",
        "packages:",
        "",
        "  /@babel/code-frame/7.18.6:",
        "    resolution: {integrity: sha512-AAAA}",
        "    dev: false",
        "",
        "  /lodash/4.17.21:",
        "    resolution: {integrity: sha512-BBBB}",
        "    dev: false",
        "",
        "  /jest-cli/27.0.0_canvas@2.8.0:",
        "    resolution: {integrity: sha512-CCCC}",
        "    dev: true",
        ""
      ].join("\n"),
      expected: [
        "npm:@babel/code-frame@7.18.6",
        "npm:jest-cli@27.0.0",
        "npm:lodash@4.17.21"
      ]
    },
    {
      version: "6.0",
      content: [
        "lockfileVersion: '6.0'",
        "",
        "dependencies:",
        "  '@types/node':",
        "    specifier: ^20.1.0",
        "    version: 20.1.0",
        "",
        "packages:",
        "",
        "  /@types/node@20.1.0:",
        "    resolution: {integrity: sha512-DDDD}",
        "",
        "  /lodash@4.17.21:",
        "    resolution: {integrity: sha512-EEEE}",
        "",
        "  /@typescript-eslint/utils@5.62.0(eslint@8.44.0)(typescript@5.1.6):",
        "    resolution: {integrity: sha512-FFFF}",
        ""
      ].join("\n"),
      expected: [
        "npm:@types/node@20.1.0",
        "npm:@typescript-eslint/utils@5.62.0",
        "npm:lodash@4.17.21"
      ]
    },
    {
      version: "9.0",
      content: [
        "lockfileVersion: '9.0'",
        "",
        "importers:",
        "  .:",
        "    dependencies:",
        "      lodash:",
        "        specifier: ^4.17.21",
        "        version: 4.17.21",
        "",
        "packages:",
        "",
        "  '@eslint-community/eslint-utils@4.9.1':",
        "    resolution: {integrity: sha512-GGGG}",
        "",
        "  lodash@4.17.21:",
        "    resolution: {integrity: sha512-HHHH}",
        ""
      ].join("\n"),
      expected: [
        "npm:@eslint-community/eslint-utils@4.9.1",
        "npm:lodash@4.17.21"
      ]
    }
  ];

  for (const lockfileCase of cases) {
    it(`parses pnpm lockfileVersion ${lockfileCase.version} package keys`, async () => {
      const root = await tempRoot();
      const path = await writeLockfile(root, "pnpm-lock.yaml", lockfileCase.content);
      const result = parseLockfilePackages(path);

      expect(identityList(result.packages)).toEqual(lockfileCase.expected);
      expect(result.parseError).toBeNull();
      expect(result.packages.every((pkg) => /^\d/u.test(pkg.version ?? ""))).toBe(true);
      expect(result.packages.every((pkg) => !(pkg.version ?? "").includes("("))).toBe(true);
    });
  }

  it("classifies pnpm non-registry keys as skipped", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "pnpm-lock.yaml", [
      "lockfileVersion: '9.0'",
      "",
      "packages:",
      "",
      "  is-odd@3.0.1:",
      "    resolution: {integrity: sha512-XXXX}",
      "",
      "  local-tarball@file:local-tarball.tgz:",
      "    resolution: {integrity: sha512-YYYY, tarball: file:local-tarball.tgz}",
      "",
      "  my-git-dep@git+https://github.com/example/my-git-dep#abc123:",
      "    resolution: {commit: abc123}",
      ""
    ].join("\n"));
    const result = parseLockfilePackages(path);

    expect(identityList(result.packages)).toEqual(["npm:is-odd@3.0.1"]);
    expect(result.skipped).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "local-tarball", reason: "local" }),
      expect.objectContaining({ name: "my-git-dep", reason: "git" })
    ]));
    expect(result.skipped).toHaveLength(2);
  });
});

describe("npm-shrinkwrap.json", () => {
  const lock = JSON.stringify({
    name: "fixture",
    lockfileVersion: 3,
    packages: {
      "": { name: "fixture", version: "1.0.0" },
      "node_modules/left-pad": {
        version: "1.3.0",
        resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        integrity: "sha512-AAAA"
      },
      "node_modules/is-odd": {
        version: "3.0.1",
        resolved: "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz",
        integrity: "sha512-BBBB"
      }
    }
  });

  it("parses npm-shrinkwrap.json identically to package-lock.json", async () => {
    const root = await tempRoot();
    const lockPath = await writeLockfile(root, "package-lock.json", lock);
    const shrinkwrapRoot = await tempRoot();
    const shrinkwrapPath = await writeLockfile(shrinkwrapRoot, "npm-shrinkwrap.json", lock);

    expect(identityList(parseLockfilePackages(shrinkwrapPath).packages))
      .toEqual(identityList(parseLockfilePackages(lockPath).packages));
    expect(identityList(parseLockfilePackages(shrinkwrapPath).packages))
      .toEqual(["npm:is-odd@3.0.1", "npm:left-pad@1.3.0"]);
  });

  it("discovers and collects shrinkwrap-only projects", async () => {
    const root = await tempRoot();
    await writeLockfile(root, "npm-shrinkwrap.json", lock);
    const projects = discoverScanProjects(root);
    const collected = collectScanPackages(projects);

    expect(projects).toEqual([expect.objectContaining({
      ecosystem: "npm",
      depFile: "npm-shrinkwrap.json",
      packageCount: 2
    })]);
    expect(collected.byEcosystem.get("npm")).toEqual([
      { name: "left-pad", version: "1.3.0" },
      { name: "is-odd", version: "3.0.1" }
    ]);
  });
});

describe("requirements.txt includes", () => {
  it("resolves -r and -c includes relative to the including file and merges pins", async () => {
    const root = await tempRoot();
    await mkdir(join(root, "dev"), { recursive: true });
    const path = await writeLockfile(root, "requirements.txt", [
      "flask==3.0.0",
      "-r dev/extra.txt",
      "-c constraints.txt",
      ""
    ].join("\n"));
    await writeLockfile(join(root, "dev"), "extra.txt", [
      "requests==2.31.0",
      "flask==3.0.0",
      ""
    ].join("\n"));
    await writeLockfile(root, "constraints.txt", [
      "urllib3==2.2.1",
      ""
    ].join("\n"));
    const result = parseLockfilePackages(path);

    expect(identityList(result.packages)).toEqual([
      "pypi:flask@3.0.0",
      "pypi:requests@2.31.0",
      "pypi:urllib3@2.2.1"
    ]);
    expect(result.parseError).toBeNull();
  });

  it("guards against include cycles", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "requirements.txt", [
      "pkg-a==1.0.0",
      "-r second.txt",
      ""
    ].join("\n"));
    await writeLockfile(root, "second.txt", [
      "pkg-b==2.0.0",
      "-r requirements.txt",
      ""
    ].join("\n"));
    const result = parseLockfilePackages(path);

    expect(identityList(result.packages)).toEqual([
      "pypi:pkg-a@1.0.0",
      "pypi:pkg-b@2.0.0"
    ]);
    expect(result.parseError).toBeNull();
  });

  it("never follows includes outside the scanned directory tree", async () => {
    const outer = await tempRoot();
    const root = join(outer, "project");
    await mkdir(root, { recursive: true });
    await writeLockfile(outer, "outside.txt", "evil-package==6.6.6\n");
    const path = await writeLockfile(root, "requirements.txt", [
      "flask==3.0.0",
      "-r ../outside.txt",
      ""
    ].join("\n"));
    const result = parseLockfilePackages(path);

    expect(identityList(result.packages)).toEqual(["pypi:flask@3.0.0"]);
    expect(result.parseError).toEqual({
      file: "../outside.txt",
      reason: "requirements include escapes the project directory"
    });
  });

  it("reports unreadable includes as parse errors without dropping parsed pins", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "requirements.txt", [
      "flask==3.0.0",
      "-r missing.txt",
      ""
    ].join("\n"));
    const result = parseLockfilePackages(path);

    expect(identityList(result.packages)).toEqual(["pypi:flask@3.0.0"]);
    expect(result.parseError?.file).toBe("missing.txt");
  });

  it("parses PEP 440 arbitrary equality without corrupting the version", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "requirements.txt", [
      "packaging === 23.2",
      "legacy-build===1!1.0+local",
      "flask==3.0.0",
      ""
    ].join("\n"));
    const result = parseLockfilePackages(path);

    expect(identityList(result.packages)).toEqual([
      "pypi:flask@3.0.0",
      "pypi:legacy-build@1!1.0+local",
      "pypi:packaging@23.2"
    ]);
    expect(result.packages.every((pkg) => !(pkg.version ?? "").startsWith("="))).toBe(true);
  });
});

describe("uv.lock", () => {
  const uvLock = [
    "version = 1",
    'requires-python = ">=3.12"',
    "",
    "[[package]]",
    'name = "my-app"',
    'version = "0.1.0"',
    'source = { editable = "." }',
    "dependencies = [",
    '    { name = "idna" },',
    "]",
    "",
    "[package.metadata]",
    'requires-dist = [{ name = "idna", specifier = ">=3" }]',
    "",
    "[[package]]",
    'name = "idna"',
    'version = "3.6"',
    'source = { registry = "https://pypi.org/simple" }',
    'sdist = { url = "https://files.pythonhosted.org/packages/idna-3.6.tar.gz", hash = "sha256:9ecdbbd083b06798ae1e86adcbfe8ab1479cf864e4ee30fe4e46a003d12491ca", size = 175426 }',
    "wheels = [",
    '    { url = "https://files.pythonhosted.org/packages/idna-3.6-py3-none-any.whl", hash = "sha256:c05567e9c24a6b9faaa835c4821bad0590fbb9d5779e7caa6e1cc4978e7eb24f", size = 61567 },',
    "]",
    "",
    "[[package]]",
    'name = "internal-tool"',
    'version = "0.0.1"',
    'source = { git = "https://github.com/example/internal-tool?rev=abc123#abc123" }',
    "",
    "[[package]]",
    'name = "local-lib"',
    'version = "0.2.0"',
    'source = { path = "../local-lib" }',
    ""
  ].join("\n");

  it("parses registry packages and classifies non-registry sources", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "uv.lock", uvLock);
    const result = parseLockfilePackages(path);

    expect(identityList(result.packages)).toEqual(["pypi:idna@3.6"]);
    expect(result.packages[0]?.integrity).toBe("sha256:9ecdbbd083b06798ae1e86adcbfe8ab1479cf864e4ee30fe4e46a003d12491ca");
    expect(result.skipped).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "my-app", reason: "workspace" }),
      expect.objectContaining({ name: "internal-tool", reason: "git" }),
      expect.objectContaining({ name: "local-lib", reason: "local" })
    ]));
    expect(result.skipped).toHaveLength(3);
  });

  it("discovers uv.lock projects for the pypi ecosystem", async () => {
    const root = await tempRoot();
    await writeLockfile(root, "uv.lock", uvLock);
    const projects = discoverScanProjects(root);

    expect(projects).toEqual([expect.objectContaining({
      ecosystem: "pypi",
      depFile: "uv.lock",
      packageCount: 1
    })]);
  });

  it("does not crash on a pathologically deep legacy (lockfileVersion 1) tree", async () => {
    const root = await tempRoot();
    let nested: Record<string, unknown> = {};
    for (let i = 0; i < 5000; i += 1) {
      nested = { [`p${i}`]: { version: "1.0.0", resolved: "https://registry.npmjs.org/x/-/x-1.0.0.tgz", dependencies: nested } };
    }
    await writeLockfile(root, "package-lock.json", JSON.stringify({ name: "x", version: "1.0.0", lockfileVersion: 1, dependencies: nested }));
    const result = parseLockfilePackages(join(root, "package-lock.json"));
    expect(result.packages.length).toBeGreaterThan(0);
  });

  it("skips Pipfile.lock git/file/editable sources instead of emitting registry purls", async () => {
    const root = await tempRoot();
    await writeLockfile(root, "Pipfile.lock", JSON.stringify({
      default: {
        requests: { version: "==2.31.0", hashes: ["sha256:" + "a".repeat(64)] },
        "evil-pkg": { git: "https://github.com/attacker/evil-pkg.git", ref: "deadbeef", version: "==1.0.0" },
        filedep: { file: "https://example.com/filedep-2.0.tar.gz", version: "==2.0.0" },
        editablepkg: { editable: true, path: ".", version: "==3.0.0" }
      }
    }));
    const result = parseLockfilePackages(join(root, "Pipfile.lock"));
    expect(identityList(result.packages)).toEqual(["pypi:requests@2.31.0"]);
    expect(result.skipped).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "evil-pkg", reason: "git" }),
      expect.objectContaining({ name: "filedep", reason: "direct-url" }),
      expect.objectContaining({ name: "editablepkg", reason: "local" })
    ]));
  });

  it("skips a yarn-berry git/url source declared only in the resolution field", async () => {
    const root = await tempRoot();
    await writeLockfile(root, "yarn.lock", [
      "__metadata:",
      "  version: 8",
      "",
      '"sneaky@npm:^1.0.0":',
      "  version: 1.0.0",
      '  resolution: "sneaky@https://evil.example.com/sneaky.git#commit=abc"',
      "  languageName: node",
      "  linkType: hard",
      ""
    ].join("\n"));
    const result = parseLockfilePackages(join(root, "yarn.lock"));
    expect(identityList(result.packages)).toEqual([]);
    expect(result.skipped).toEqual(expect.arrayContaining([expect.objectContaining({ name: "sneaky", reason: "git" })]));
  });

  it("classifies poetry git/path sources as skipped, not registry pypi packages", async () => {
    const root = await tempRoot();
    const poetryLock = [
      "[[package]]",
      'name = "requests"',
      'version = "2.31.0"',
      "",
      "[[package]]",
      'name = "internal-tool"',
      'version = "0.1.0"',
      "",
      "[package.source]",
      'type = "git"',
      'url = "https://github.com/acme/internal-tool.git"',
      'reference = "main"',
      "",
      "[[package]]",
      'name = "local-lib"',
      'version = "0.2.0"',
      "",
      "[package.source]",
      'type = "directory"',
      'url = "../local-lib"',
      ""
    ].join("\n");
    const path = await writeLockfile(root, "poetry.lock", poetryLock);
    const result = parseLockfilePackages(path);

    expect(identityList(result.packages)).toEqual(["pypi:requests@2.31.0"]);
    expect(result.skipped).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "internal-tool", reason: "git" }),
      expect.objectContaining({ name: "local-lib", reason: "local" })
    ]));
    expect(result.skipped).toHaveLength(2);
  });

  it("keeps a legacy-source (custom registry) poetry package and does not bleed a later type= into the source check", async () => {
    const root = await tempRoot();
    const poetryLock = [
      "[[package]]",
      'name = "gamma"',
      'version = "3.0.0"',
      "",
      "[package.source]",
      'url = "https://pypi.internal.acme.com/simple"',
      'reference = "acme-private"',
      "",
      "[package.extras]",
      'type = "git"',
      "",
      "[[package]]",
      'name = "delta"',
      'version = "4.0.0"',
      "",
      "[package.source]",
      'type = "legacy"',
      'url = "https://pypi.internal.acme.com/simple"',
      ""
    ].join("\n");
    const path = await writeLockfile(root, "poetry.lock", poetryLock);
    const result = parseLockfilePackages(path);

    expect(identityList(result.packages).sort()).toEqual(["pypi:delta@4.0.0", "pypi:gamma@3.0.0"]);
    expect(result.skipped).toHaveLength(0);
  });

  it("keeps pypi-internal lockfile precedence", async () => {
    const root = await tempRoot();
    await writeLockfile(root, "uv.lock", uvLock);
    await writeLockfile(root, "requirements.txt", "flask==3.0.0\n");
    await writeLockfile(root, "poetry.lock", [
      "[[package]]",
      'name = "requests"',
      'version = "2.31.0"',
      ""
    ].join("\n"));
    const projects = discoverScanProjects(root);

    expect(projects.map((project) => project.depFile)).toEqual(["poetry.lock"]);
  });
});

describe("polyglot directories", () => {
  it("discovers one lockfile per ecosystem and scans both", async () => {
    const root = await tempRoot();
    await writeLockfile(root, "package-lock.json", JSON.stringify({
      name: "fixture",
      lockfileVersion: 3,
      packages: {
        "": { name: "fixture", version: "1.0.0" },
        "node_modules/left-pad": {
          version: "1.3.0",
          resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
          integrity: "sha512-AAAA"
        }
      }
    }));
    await writeLockfile(root, "yarn.lock", [
      "# yarn lockfile v1",
      "",
      "shadowed@^1.0.0:",
      '  version "1.0.0"',
      ""
    ].join("\n"));
    await writeLockfile(root, "requirements.txt", "flask==3.0.0\n");
    const projects = discoverScanProjects(root);
    const collected = collectScanPackages(projects);

    expect(projects.map((project) => [project.depFile, project.ecosystem])).toEqual([
      ["package-lock.json", "npm"],
      ["requirements.txt", "pypi"]
    ]);
    expect(collected.byEcosystem.get("npm")).toEqual([{ name: "left-pad", version: "1.3.0" }]);
    expect(collected.byEcosystem.get("pypi")).toEqual([{ name: "flask", version: "3.0.0" }]);
  });
});

describe("non-registry lockfile identities", () => {
  it("classifies workspace, local, git, and direct-url package-lock entries as skipped", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "package-lock.json", JSON.stringify({
      name: "root",
      lockfileVersion: 3,
      packages: {
        "": {
          name: "root",
          workspaces: ["packages/*"],
          dependencies: {
            "tarball-dep": "https://example.com/tarball-dep-1.0.0.tgz",
            "git-dep": "git+ssh://git@github.com/example/git-dep.git"
          }
        },
        "packages/internal-a": { version: "1.0.0" },
        "node_modules/internal-a": { resolved: "packages/internal-a", link: true },
        "node_modules/file-dep": { version: "1.0.0", resolved: "file:../file-dep" },
        "node_modules/git-dep": { version: "1.0.0", resolved: "git+ssh://git@github.com/example/git-dep.git#abc" },
        "node_modules/tarball-dep": { version: "1.0.0", resolved: "https://example.com/tarball-dep-1.0.0.tgz", integrity: "sha512-AAAA" },
        "node_modules/left-pad": { version: "1.3.0", resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", integrity: "sha512-BBBB" }
      }
    }));
    const result = parseLockfilePackages(path);
    const report = verifyLockfile(path);

    expect(identityList(result.packages)).toEqual(["npm:left-pad@1.3.0"]);
    expect([...result.skipped].sort((left, right) => left.name.localeCompare(right.name))).toEqual([
      { name: "file-dep", reason: "local", location: "node_modules/file-dep" },
      { name: "git-dep", reason: "git", location: "node_modules/git-dep" },
      { name: "internal-a", reason: "workspace", location: "packages/internal-a" },
      { name: "tarball-dep", reason: "direct-url", location: "node_modules/tarball-dep" }
    ]);
    expect(report.findings.map((finding) => finding.id)).toContain("unverified-lockfile-url");
  });

  it("classifies yarn berry workspace, portal, and link entries as skipped", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "yarn.lock", [
      "__metadata:",
      "  version: 8",
      "",
      '"app@workspace:.":',
      "  version: 0.0.0-use.local",
      '  resolution: "app@workspace:."',
      "  languageName: unknown",
      "  linkType: soft",
      "",
      '"pkg-a@workspace:packages/pkg-a":',
      "  version: 0.0.0-use.local",
      '  resolution: "pkg-a@workspace:packages/pkg-a"',
      "  languageName: unknown",
      "  linkType: soft",
      "",
      '"portal-dep@portal:../portal-dep::locator=app%40workspace%3A.":',
      "  version: 0.0.0-use.local",
      '  resolution: "portal-dep@portal:../portal-dep::locator=app%40workspace%3A."',
      "  languageName: node",
      "  linkType: soft",
      "",
      '"link-dep@link:../link-dep::locator=app%40workspace%3A.":',
      "  version: 0.0.0-use.local",
      '  resolution: "link-dep@link:../link-dep::locator=app%40workspace%3A."',
      "  languageName: node",
      "  linkType: soft",
      "",
      '"lodash@npm:^4.17.0":',
      "  version: 4.17.21",
      '  resolution: "lodash@npm:4.17.21"',
      "  checksum: 10c0/d8cbea072bb08655bb4c989da418994b073a608dffa608b09ac04b43a791b12aeae7cd7ad919aa4c925f33b48490b5cf38b75d31bb5916ec2d4b2c2a2e74e5d3",
      "  languageName: node",
      "  linkType: hard",
      ""
    ].join("\n"));
    const result = parseLockfilePackages(path);

    expect(identityList(result.packages)).toEqual(["npm:lodash@4.17.21"]);
    expect([...result.skipped].sort((left, right) => left.name.localeCompare(right.name))).toEqual([
      expect.objectContaining({ name: "app", reason: "workspace" }),
      expect.objectContaining({ name: "link-dep", reason: "local" }),
      expect.objectContaining({ name: "pkg-a", reason: "workspace" }),
      expect.objectContaining({ name: "portal-dep", reason: "local" })
    ]);
  });

  it("surfaces skipped packages and lockfile locations through collectScanPackages", async () => {
    const root = await tempRoot();
    await writeLockfile(root, "package-lock.json", JSON.stringify({
      name: "root",
      lockfileVersion: 3,
      packages: {
        "": { name: "root", workspaces: ["packages/*"] },
        "packages/internal-a": { version: "1.0.0" },
        "node_modules/left-pad": { version: "1.3.0", resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", integrity: "sha512-BBBB" }
      }
    }));
    const collected = collectScanPackages(discoverScanProjects(root));

    expect(collected.byEcosystem.get("npm")).toEqual([{ name: "left-pad", version: "1.3.0" }]);
    expect(collected.skippedPackages).toEqual([{
      name: "internal-a",
      reason: "workspace",
      location: "package-lock.json: packages/internal-a"
    }]);
    expect(collected.skipped).toBe(1);
    expect(collected.parseErrors).toEqual([]);
  });
});

describe("verify preflight lockfile warn behavior", () => {
  it("does not warn on package-lock workspace members or sha1 integrity entries", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "package-lock.json", JSON.stringify({
      name: "root",
      lockfileVersion: 3,
      packages: {
        "": { name: "root", version: "1.0.0", workspaces: ["packages/*"] },
        "packages/lib-a": { version: "1.0.0" },
        "node_modules/lib-a": { resolved: "packages/lib-a", link: true },
        "node_modules/legacy-dep": {
          version: "0.9.0",
          resolved: "https://registry.npmjs.org/legacy-dep/-/legacy-dep-0.9.0.tgz",
          integrity: "sha1-5BO2242tMMmFGu3CVCrGFm5HFB0="
        },
        "node_modules/modern-dep": {
          version: "2.0.0",
          resolved: "https://registry.npmjs.org/modern-dep/-/modern-dep-2.0.0.tgz",
          integrity: "sha512-CCCC"
        }
      }
    }));
    const report = verifyLockfile(path);

    expect(report.status).toBe("pass");
    expect(report.findings).toEqual([]);
    expect(report.packages.map((pkg) => pkg.name).sort()).toEqual(["legacy-dep", "modern-dep"]);
  });
});

describe("lockfile parse errors", () => {
  it("returns a structured parse error for a corrupt lockfile", async () => {
    const root = await tempRoot();
    const path = await writeLockfile(root, "package-lock.json", '{ "name": "broken"');
    const result = parseLockfilePackages(path);
    const collected = collectScanPackages(discoverScanProjects(root));

    expect(result.packages).toEqual([]);
    expect(result.parseError?.file).toBe("package-lock.json");
    expect(result.parseError?.reason.length).toBeGreaterThan(0);
    expect(collected.byEcosystem.size).toBe(0);
    expect(collected.parseErrors).toEqual([{
      file: "package-lock.json",
      reason: result.parseError?.reason
    }]);
    expect(collected.skipped).toBe(1);
  });
});

describe("registry-resolved entries are scanned regardless of file:/git: spec collisions", () => {
  it("v3: a registry package is still scanned when a sibling declares the same name as file:", async () => {
    const root = await tempRoot();
    const lock = {
      name: "app",
      lockfileVersion: 3,
      packages: {
        "": { name: "app", dependencies: { "evil-pkg": "file:./shim", "good-pkg": "^2.0.0" } },
        "node_modules/evil-pkg": {
          version: "1.2.3",
          resolved: "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.2.3.tgz",
          integrity: "sha512-AAAA"
        },
        "node_modules/good-pkg": {
          version: "2.0.0",
          resolved: "https://registry.npmjs.org/good-pkg/-/good-pkg-2.0.0.tgz",
          integrity: "sha512-BBBB"
        }
      }
    };
    const path = await writeLockfile(root, "package-lock.json", JSON.stringify(lock));
    const ids = identityList(parseLockfilePackages(path).packages);
    expect(ids).toContain("npm:evil-pkg@1.2.3");
    expect(ids).toContain("npm:good-pkg@2.0.0");
  });

  it("v3: still skips a genuinely-local entry whose own resolved is file:", async () => {
    const root = await tempRoot();
    const lock = {
      name: "app",
      lockfileVersion: 3,
      packages: {
        "": { name: "app", dependencies: { "local-dep": "file:../local-dep" } },
        "node_modules/local-dep": { version: "1.0.0", resolved: "file:../local-dep" }
      }
    };
    const path = await writeLockfile(root, "package-lock.json", JSON.stringify(lock));
    const ids = identityList(parseLockfilePackages(path).packages);
    expect(ids.some((s) => s.includes("local-dep"))).toBe(false);
  });

  it("v1: a registry-resolved entry whose version reads file: is still scanned", async () => {
    const root = await tempRoot();
    const lock = {
      name: "app",
      lockfileVersion: 1,
      dependencies: {
        "evil-pkg": {
          version: "file:./shim",
          resolved: "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.2.3.tgz",
          integrity: "sha512-AAAA"
        }
      }
    };
    const path = await writeLockfile(root, "package-lock.json", JSON.stringify(lock));
    const ids = identityList(parseLockfilePackages(path).packages);
    expect(ids.some((s) => s.startsWith("npm:evil-pkg@"))).toBe(true);
  });
});
