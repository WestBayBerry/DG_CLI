import { brotliCompressSync, deflateSync, gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  artifactDisplayName,
  extractRegistryMetadataIdentities,
  isRegistryIndexRequest,
  resolveArtifactIdentity
} from "../../src/proxy/metadata-map.js";
import type { PackageManagerClassification } from "../../src/launcher/classify.js";

const npmClassification: PackageManagerClassification = {
  kind: "protected",
  manager: "npm",
  ecosystem: "javascript",
  realBinaryName: "npm",
  action: "install",
  reason: "npm install/fetch command",
  args: ["install", "left-pad"]
};

const pipClassification: PackageManagerClassification = {
  kind: "protected",
  manager: "pip",
  ecosystem: "python",
  realBinaryName: "pip",
  action: "install",
  reason: "pip install/fetch command",
  args: ["install", "requests"]
};

describe("artifact identity metadata map", () => {
  it("extracts npm tarball identity from registry metadata", () => {
    const metadataUrl = new URL("https://registry.npmjs.org/left-pad");
    const identities = extractRegistryMetadataIdentities(metadataUrl, {
      headers: {
        "content-type": "application/json"
      },
      body: Buffer.from(JSON.stringify({
        name: "left-pad",
        versions: {
          "1.3.0": {
            dist: {
              tarball: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            }
          }
        }
      }))
    });

    expect(identities).toEqual([{
      ecosystem: "npm",
      name: "left-pad",
      version: "1.3.0",
      registryHost: "registry.npmjs.org",
      tarballUrl: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      sourceKind: "registry-metadata"
    }]);
  });

  it("decodes a gzip-encoded npm packument before extracting identities", () => {
    const metadataUrl = new URL("https://registry.npmjs.org/chalk");
    const packument = JSON.stringify({
      name: "chalk",
      versions: {
        "5.6.2": { dist: { tarball: "https://registry.npmjs.org/chalk/-/chalk-5.6.2.tgz" } }
      }
    });
    const identities = extractRegistryMetadataIdentities(metadataUrl, {
      headers: {
        "content-type": "application/vnd.npm.install-v1+json",
        "content-encoding": "gzip"
      },
      body: gzipSync(Buffer.from(packument))
    });

    expect(identities).toEqual([{
      ecosystem: "npm",
      name: "chalk",
      version: "5.6.2",
      registryHost: "registry.npmjs.org",
      tarballUrl: "https://registry.npmjs.org/chalk/-/chalk-5.6.2.tgz",
      sourceKind: "registry-metadata"
    }]);
  });

  it("decodes brotli and deflate metadata bodies and leaves undecodable bodies alone", () => {
    const metadataUrl = new URL("https://registry.npmjs.org/chalk");
    const packument = Buffer.from(JSON.stringify({
      name: "chalk",
      versions: { "5.6.2": { dist: { tarball: "https://registry.npmjs.org/chalk/-/chalk-5.6.2.tgz" } } }
    }));
    for (const [encoding, body] of [
      ["br", brotliCompressSync(packument)],
      ["deflate", deflateSync(packument)]
    ] as const) {
      const identities = extractRegistryMetadataIdentities(metadataUrl, {
        headers: { "content-type": "application/json", "content-encoding": encoding },
        body
      });
      expect(identities).toHaveLength(1);
      expect(identities[0]?.version).toBe("5.6.2");
    }

    const garbled = extractRegistryMetadataIdentities(metadataUrl, {
      headers: { "content-type": "application/json", "content-encoding": "gzip" },
      body: Buffer.from("not gzip at all")
    });
    expect(garbled).toEqual([]);
  });

  it("decodes a gzip-encoded PyPI simple JSON index", () => {
    const metadataUrl = new URL("https://pypi.org/simple/requests/");
    const index = JSON.stringify({
      files: [{ url: "https://files.pythonhosted.org/packages/aa/requests-2.32.0-py3-none-any.whl", filename: "requests-2.32.0-py3-none-any.whl" }]
    });
    const identities = extractRegistryMetadataIdentities(metadataUrl, {
      headers: { "content-type": "application/vnd.pypi.simple.v1+json", "content-encoding": "gzip" },
      body: gzipSync(Buffer.from(index))
    });
    expect(identities).toHaveLength(1);
    expect(identities[0]?.name).toBe("requests");
    expect(identities[0]?.version).toBe("2.32.0");
  });

  it("uses registry metadata before URL fallback", () => {
    const artifactUrl = new URL("https://mirror.example.test/cache/random-name.tgz");
    const resolution = resolveArtifactIdentity(artifactUrl, [{
      ecosystem: "npm",
      name: "@scope/pkg",
      version: "2.0.0",
      registryHost: "registry.npmjs.org",
      tarballUrl: artifactUrl.toString(),
      sourceKind: "registry-metadata"
    }], npmClassification);

    expect(resolution.kind).toBe("resolved");
    if (resolution.kind === "resolved") {
      expect(artifactDisplayName(resolution.identity)).toBe("npm:@scope/pkg@2.0.0");
      expect(resolution.identity.sourceKind).toBe("registry-metadata");
    }
  });

  it("uses argv-pinned npm versions for public registry URL fallback", () => {
    const resolution = resolveArtifactIdentity(
      new URL("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"),
      [],
      {
        ...npmClassification,
        args: ["install", "left-pad@1.3.0"]
      }
    );

    expect(resolution.kind).toBe("resolved");
    if (resolution.kind === "resolved") {
      expect(artifactDisplayName(resolution.identity)).toBe("npm:left-pad@1.3.0");
      expect(resolution.identity.sourceKind).toBe("url-fallback");
    }
  });

  it("parses scoped npm public registry tarball fallback identity", () => {
    const resolution = resolveArtifactIdentity(
      new URL("https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz"),
      [],
      {
        ...npmClassification,
        args: ["install", "@scope/pkg@2.0.0"]
      }
    );

    expect(resolution.kind).toBe("resolved");
    if (resolution.kind === "resolved") {
      expect(artifactDisplayName(resolution.identity)).toBe("npm:@scope/pkg@2.0.0");
      expect(resolution.identity.sourceKind).toBe("url-fallback");
    }
  });

  it("fails ambiguous metadata instead of guessing from the URL", () => {
    const artifactUrl = new URL("https://registry.example.test/shared/pkg.tgz");
    const resolution = resolveArtifactIdentity(artifactUrl, [{
      ecosystem: "npm",
      name: "first",
      version: "1.0.0",
      registryHost: "registry.example.test",
      tarballUrl: artifactUrl.toString(),
      sourceKind: "registry-metadata"
    }, {
      ecosystem: "npm",
      name: "second",
      version: "1.0.0",
      registryHost: "registry.example.test",
      tarballUrl: artifactUrl.toString(),
      sourceKind: "registry-metadata"
    }], npmClassification);

    expect(resolution).toMatchObject({
      kind: "ambiguous",
      packageName: "npm:first@1.0.0"
    });
  });
});

describe("pypi simple-index identity (pip/uv/pipx)", () => {
  it("extracts pypi identities from a PEP 503 HTML simple index", () => {
    const metadataUrl = new URL("https://pypi.org/simple/requests/");
    const html = `<!DOCTYPE html><html><body>
      <a href="https://files.pythonhosted.org/packages/ab/cd/h/requests-2.31.0-py3-none-any.whl#sha256=dead">requests-2.31.0-py3-none-any.whl</a>
      <a href="https://files.pythonhosted.org/packages/ef/gh/i/requests-2.31.0.tar.gz">requests-2.31.0.tar.gz</a>
    </body></html>`;
    const identities = extractRegistryMetadataIdentities(metadataUrl, {
      headers: { "content-type": "text/html; charset=utf-8" },
      body: Buffer.from(html)
    });
    expect(identities.length).toBe(2);
    expect(identities).toEqual(expect.arrayContaining([
      expect.objectContaining({ ecosystem: "pypi", name: "requests", version: "2.31.0", sourceKind: "registry-metadata" })
    ]));
    expect(identities[0]?.tarballUrl).toContain("files.pythonhosted.org");
  });

  it("extracts pypi identities from a PEP 691 JSON simple index", () => {
    const metadataUrl = new URL("https://pypi.org/simple/requests/");
    const body = JSON.stringify({
      files: [{ filename: "requests-2.31.0-py3-none-any.whl", url: "https://files.pythonhosted.org/packages/ab/requests-2.31.0-py3-none-any.whl" }]
    });
    const identities = extractRegistryMetadataIdentities(metadataUrl, {
      headers: { "content-type": "application/vnd.pypi.simple.v1+json" },
      body: Buffer.from(body)
    });
    expect(identities).toEqual([
      expect.objectContaining({ ecosystem: "pypi", name: "requests", version: "2.31.0", sourceKind: "registry-metadata" })
    ]);
  });

  it("resolves PEP 691 identity from the filename field when the url tail is an opaque hash", () => {
    const metadataUrl = new URL("https://pypi.org/simple/requests/");
    const opaqueUrl = "https://files.pythonhosted.org/packages/ab/cd/opaque-blob";
    const body = JSON.stringify({
      files: [{ filename: "requests-2.31.0-py3-none-any.whl", url: opaqueUrl }]
    });
    const identities = extractRegistryMetadataIdentities(metadataUrl, {
      headers: { "content-type": "application/vnd.pypi.simple.v1+json" },
      body: Buffer.from(body)
    });
    expect(identities).toEqual([
      expect.objectContaining({
        ecosystem: "pypi",
        name: "requests",
        version: "2.31.0",
        registryHost: "files.pythonhosted.org",
        tarballUrl: opaqueUrl,
        sourceKind: "registry-metadata"
      })
    ]);
  });

  it("normalizes pypi names (typing_extensions -> typing-extensions)", () => {
    const metadataUrl = new URL("https://pypi.org/simple/typing-extensions/");
    const html = `<a href="https://files.pythonhosted.org/p/typing_extensions-4.5.0-py3-none-any.whl">typing_extensions-4.5.0-py3-none-any.whl</a>`;
    const identities = extractRegistryMetadataIdentities(metadataUrl, { headers: { "content-type": "text/html" }, body: Buffer.from(html) });
    expect(identities[0]).toMatchObject({ name: "typing-extensions", version: "4.5.0" });
  });

  it("treats the simple index + pypi json as index requests; artifacts are not", () => {
    expect(isRegistryIndexRequest(new URL("https://pypi.org/simple/requests/"))).toBe(true);
    expect(isRegistryIndexRequest(new URL("https://pypi.org/simple/"))).toBe(true);
    expect(isRegistryIndexRequest(new URL("https://pypi.org/pypi/requests/json"))).toBe(true);
    expect(isRegistryIndexRequest(new URL("https://files.pythonhosted.org/packages/ab/cd/h/requests-2.31.0-py3-none-any.whl"))).toBe(false);
  });

  it("passes PEP 658 .metadata sidecars through (the wheel itself is verified)", () => {
    expect(isRegistryIndexRequest(new URL("https://files.pythonhosted.org/packages/a0/f4/c6/requests-2.34.2-py3-none-any.whl.metadata"))).toBe(true);
  });

  it("passes npm registry API endpoints (/-/...) through — advisories/audit/search are not packages", () => {
    expect(isRegistryIndexRequest(new URL("https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"))).toBe(true);
    expect(isRegistryIndexRequest(new URL("https://registry.npmjs.org/-/npm/v1/security/audits/quick"))).toBe(true);
    expect(isRegistryIndexRequest(new URL("https://registry.npmjs.org/-/v1/search?text=is-odd"))).toBe(true);
    // a real tarball has /-/ in the MIDDLE, not at the path start — must NOT pass through
    expect(isRegistryIndexRequest(new URL("https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"))).toBe(false);
    expect(isRegistryIndexRequest(new URL("https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz"))).toBe(false);
  });

  it("resolves a files.pythonhosted wheel against the recorded simple-index identity", () => {
    const wheel = new URL("https://files.pythonhosted.org/packages/ab/cd/h/requests-2.31.0-py3-none-any.whl");
    const resolution = resolveArtifactIdentity(wheel, [{
      ecosystem: "pypi", name: "requests", version: "2.31.0", registryHost: "files.pythonhosted.org",
      tarballUrl: wheel.toString(), sourceKind: "registry-metadata"
    }], pipClassification);
    expect(resolution.kind).toBe("resolved");
    if (resolution.kind === "resolved") {
      expect(artifactDisplayName(resolution.identity)).toBe("pypi:requests@2.31.0");
      expect(resolution.identity.sourceKind).toBe("registry-metadata");
    }
  });

  it("parses wheel/sdist filenames in the url-fallback path (not the hash path segment)", () => {
    const wheel = resolveArtifactIdentity(
      new URL("https://files.pythonhosted.org/packages/ab/cd/h/requests-2.31.0-py3-none-any.whl"), [], pipClassification);
    expect(wheel.kind).toBe("resolved");
    if (wheel.kind === "resolved") {
      expect(artifactDisplayName(wheel.identity)).toBe("pypi:requests@2.31.0");
      expect(wheel.identity.sourceKind).toBe("url-fallback");
    }
    const sdist = resolveArtifactIdentity(
      new URL("https://files.pythonhosted.org/packages/ab/typing_extensions-4.5.0.tar.gz"), [], pipClassification);
    if (sdist.kind === "resolved") {
      expect(artifactDisplayName(sdist.identity)).toBe("pypi:typing-extensions@4.5.0");
    }
  });

  it("handles wheels with a build tag", () => {
    const resolution = resolveArtifactIdentity(
      new URL("https://files.pythonhosted.org/packages/x/numpy-1.26.0-1-cp311-cp311-macosx_11_0_arm64.whl"), [], pipClassification);
    if (resolution.kind === "resolved") {
      expect(artifactDisplayName(resolution.identity)).toBe("pypi:numpy@1.26.0");
    }
  });

  const cargoClassification: PackageManagerClassification = {
    kind: "protected",
    manager: "cargo",
    ecosystem: "rust",
    realBinaryName: "cargo",
    action: "add",
    reason: "cargo add/fetch command",
    args: ["add", "serde"]
  };

  it("resolves cargo identity from a crates.io api download URL", () => {
    const resolution = resolveArtifactIdentity(
      new URL("https://crates.io/api/v1/crates/serde/1.0.219/download"), [], cargoClassification);
    expect(resolution.kind).toBe("resolved");
    if (resolution.kind === "resolved") {
      expect(artifactDisplayName(resolution.identity)).toBe("cargo:serde@1.0.219");
      expect(resolution.identity.sourceKind).toBe("url-fallback");
    }
  });

  it("resolves cargo identity from static.crates.io download paths and .crate filenames", () => {
    const staticPath = resolveArtifactIdentity(
      new URL("https://static.crates.io/crates/serde/1.0.219/download"), [], cargoClassification);
    expect(staticPath.kind).toBe("resolved");
    if (staticPath.kind === "resolved") {
      expect(artifactDisplayName(staticPath.identity)).toBe("cargo:serde@1.0.219");
    }
    const crateFile = resolveArtifactIdentity(
      new URL("https://static.crates.io/crates/serde-json-wasm/serde-json-wasm-1.0.3.crate"), [], cargoClassification);
    expect(crateFile.kind).toBe("resolved");
    if (crateFile.kind === "resolved") {
      expect(artifactDisplayName(crateFile.identity)).toBe("cargo:serde-json-wasm@1.0.3");
    }
  });

  it("keeps the unknown-version sentinel for cargo sparse-index metadata fetches", () => {
    const resolution = resolveArtifactIdentity(
      new URL("https://index.crates.io/se/rd/serde"), [], cargoClassification);
    expect(resolution.kind).toBe("resolved");
    if (resolution.kind === "resolved") {
      expect(resolution.identity.version).toBe("unknown");
      expect(resolution.identity.ecosystem).toBe("cargo");
    }
  });
});
