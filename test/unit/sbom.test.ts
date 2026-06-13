import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { renderSbomSummary, runSbomCommand } from "../../src/commands/sbom.js";
import { createTheme } from "../../src/presentation/theme.js";
import {
  buildCycloneDxSbom,
  collectSbomComponents,
  hashesFor,
  purlFor,
  type SbomComponent
} from "../../src/sbom/cyclonedx.js";
import type { LockfileProject } from "../../src/scan/collect.js";

const made: string[] = [];
const NOW = new Date("2026-06-10T00:00:00.000Z");

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "dg-sbom-"));
  made.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of made.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function component(over: Partial<SbomComponent> = {}): SbomComponent {
  return {
    ecosystem: "npm",
    name: "left-pad",
    version: "1.3.0",
    requested: "left-pad",
    sourceKind: "lockfile",
    resolvedUrl: null,
    integrity: null,
    license: null,
    ...over
  };
}

const sri512 = (byte: number): string => `sha512-${Buffer.alloc(64, byte).toString("base64")}`;

function writeNpmLock(dir: string, packages: Record<string, unknown>): void {
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "demo", version: "1.0.0" }, null, 2), "utf8");
  writeFileSync(
    join(dir, "package-lock.json"),
    JSON.stringify({ name: "demo", version: "1.0.0", lockfileVersion: 3, packages }, null, 2),
    "utf8"
  );
}

describe("purlFor", () => {
  it("builds npm, scoped npm, pypi (normalized), and cargo purls", () => {
    expect(purlFor(component())).toBe("pkg:npm/left-pad@1.3.0");
    expect(purlFor(component({ name: "@babel/core", version: "7.0.0" }))).toBe("pkg:npm/%40babel/core@7.0.0");
    expect(purlFor(component({ ecosystem: "pypi", name: "Flask_Cors", version: "4.0.0" }))).toBe("pkg:pypi/flask-cors@4.0.0");
    expect(purlFor(component({ ecosystem: "cargo", name: "serde", version: "1.0.0" }))).toBe("pkg:cargo/serde@1.0.0");
  });

  it("returns null for an unknown ecosystem", () => {
    expect(purlFor(component({ ecosystem: "unknown" }))).toBeNull();
  });
});

describe("hashesFor", () => {
  it("converts an npm sha512 SRI base64 digest to hex", () => {
    const hashes = hashesFor(sri512(0x01));
    expect(hashes).toEqual([{ alg: "SHA-512", content: "01".repeat(64) }]);
  });

  it("reads a pypi alg:hex digest directly", () => {
    const hashes = hashesFor(`sha256:${"ab".repeat(32)}`);
    expect(hashes).toEqual([{ alg: "SHA-256", content: "ab".repeat(32) }]);
  });

  it("drops malformed or wrong-length digests instead of emitting invalid hashes", () => {
    expect(hashesFor(null)).toEqual([]);
    expect(hashesFor("sha512-not_base64_!!")).toEqual([]);
    expect(hashesFor("sha256-AAAA")).toEqual([]);
    expect(hashesFor("sha256:zzzz")).toEqual([]);
  });

  it("reads a yarn-berry cacheKey/hex checksum as a length-mapped hash", () => {
    expect(hashesFor(`10c0/${"d8".repeat(64)}`)).toEqual([{ alg: "SHA-512", content: "d8".repeat(64) }]);
    expect(hashesFor(`8/${"ab".repeat(32)}`)).toEqual([{ alg: "SHA-256", content: "ab".repeat(32) }]);
  });

  it("reads a cargo bare-hex SHA-256 checksum as a hash", () => {
    expect(hashesFor("a".repeat(64))).toEqual([{ alg: "SHA-256", content: "a".repeat(64) }]);
    expect(hashesFor("ff".repeat(20))).toEqual([{ alg: "SHA-1", content: "ff".repeat(20) }]);
    expect(hashesFor("a".repeat(50))).toEqual([]);
  });

  it("strips W3C SRI option suffixes before decoding", () => {
    expect(hashesFor(`${sri512(0x05)}?foo=bar`)).toEqual([{ alg: "SHA-512", content: "05".repeat(64) }]);
  });
});

describe("buildCycloneDxSbom", () => {
  it("emits a valid CycloneDX 1.5 skeleton with sorted components", () => {
    const bom = buildCycloneDxSbom(
      [
        component({ name: "zeta", version: "1.0.0" }),
        component({ name: "alpha", version: "2.0.0", license: "MIT", integrity: sri512(0x02) })
      ],
      { timestamp: NOW.toISOString(), serialNumber: "urn:uuid:fixed", toolVersion: "9.9.9" }
    );
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.specVersion).toBe("1.5");
    expect(bom.serialNumber).toBe("urn:uuid:fixed");
    expect(bom.version).toBe(1);
    expect(bom.metadata.timestamp).toBe("2026-06-10T00:00:00.000Z");
    expect(bom.metadata.tools[0]).toEqual({ vendor: "WestBayBerry", name: "dg", version: "9.9.9" });
    expect(bom.components.map((c) => c.name)).toEqual(["alpha", "zeta"]);
    const alpha = bom.components[0];
    expect(alpha?.purl).toBe("pkg:npm/alpha@2.0.0");
    expect(alpha?.["bom-ref"]).toBe("pkg:npm/alpha@2.0.0");
    expect(alpha?.licenses).toEqual([{ license: { name: "MIT" } }]);
    expect(alpha?.hashes).toEqual([{ alg: "SHA-512", content: "02".repeat(64) }]);
  });

  it("includes a root application component when supplied and uses a fallback bom-ref for unknown ecosystems", () => {
    const bom = buildCycloneDxSbom([component({ ecosystem: "unknown", name: "mystery", version: "0.1.0" })], {
      timestamp: NOW.toISOString(),
      serialNumber: "urn:uuid:fixed",
      toolVersion: "9.9.9",
      rootComponent: { name: "demo", version: "1.0.0" }
    });
    expect(bom.metadata.component).toEqual({ type: "application", "bom-ref": "root", name: "demo", version: "1.0.0" });
    expect(bom.components[0]?.["bom-ref"]).toBe("unknown:mystery@0.1.0");
    expect(bom.components[0]?.purl).toBeUndefined();
  });
});

describe("collectSbomComponents", () => {
  it("reads resolved packages from a lockfile, dedups, and skips versionless entries", () => {
    const dir = tempDir();
    writeNpmLock(dir, {
      "": { name: "demo", version: "1.0.0" },
      "node_modules/left-pad": { version: "1.3.0", integrity: sri512(0x03), license: "WTFPL" },
      "node_modules/@scope/util": { version: "2.0.0" },
      "node_modules/no-version": {}
    });
    const project: LockfileProject = { path: dir, relativePath: ".", ecosystem: "npm", depFile: "package-lock.json", packageCount: 3 };
    const { components } = collectSbomComponents([project]);
    const names = components.map((c) => c.name).sort();
    expect(names).toEqual(["@scope/util", "left-pad"]);
    const leftPad = components.find((c) => c.name === "left-pad");
    expect(leftPad?.integrity).toBe(sri512(0x03));
    expect(leftPad?.license).toBe("WTFPL");
  });
});

describe("dg sbom command", () => {
  it("prints a deterministic CycloneDX document with the resolved components", () => {
    const dir = tempDir();
    writeNpmLock(dir, {
      "": { name: "demo", version: "1.0.0" },
      "node_modules/left-pad": { version: "1.3.0", integrity: sri512(0x04), license: "MIT" }
    });
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW);
    expect(result.exitCode).toBe(0);
    const bom = JSON.parse(result.stdout) as {
      specVersion: string;
      metadata: { timestamp: string; component?: { name: string } };
      components: Array<{ name: string; purl: string; hashes: unknown }>;
    };
    expect(bom.specVersion).toBe("1.5");
    expect(bom.metadata.timestamp).toBe("2026-06-10T00:00:00.000Z");
    expect(bom.metadata.component?.name).toBe("demo");
    expect(bom.components.map((c) => c.name)).toContain("left-pad");
    expect(bom.components[0]?.purl).toBe("pkg:npm/left-pad@1.3.0");
  });

  it("writes to --output and reports the component count", () => {
    const dir = tempDir();
    writeNpmLock(dir, { "": { name: "demo", version: "1.0.0" }, "node_modules/left-pad": { version: "1.3.0" } });
    const out = join(dir, "sbom.cdx.json");
    const result = runSbomCommand({ commandPath: ["sbom"], args: ["--output", out] }, dir, NOW);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("1 components");
    const written = JSON.parse(readFileSync(out, "utf8")) as { bomFormat: string; components: unknown[] };
    expect(written.bomFormat).toBe("CycloneDX");
    expect(written.components).toHaveLength(1);
  });

  it("emits a valid empty SBOM with a stderr note when there are no lockfiles", () => {
    const dir = tempDir();
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW);
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain("no resolvable dependencies");
    const bom = JSON.parse(result.stdout) as { specVersion: string; components: unknown[] };
    expect(bom.specVersion).toBe("1.5");
    expect(bom.components).toEqual([]);
  });

  it("rejects an unknown flag with a usage error", () => {
    const result = runSbomCommand({ commandPath: ["sbom"], args: ["--bogus"] }, tempDir(), NOW);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("unknown flag");
  });

  it("--json prints the raw CycloneDX document, not the summary", () => {
    const dir = tempDir();
    writeNpmLock(dir, { "": { name: "demo", version: "1.0.0" }, "node_modules/left-pad": { version: "1.3.0" } });
    const result = runSbomCommand({ commandPath: ["sbom"], args: ["--json"] }, dir, NOW, {});
    const bom = JSON.parse(result.stdout) as { bomFormat: string; components: unknown[] };
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.components).toHaveLength(1);
  });
});

describe("renderSbomSummary", () => {
  const theme = createTheme(false);
  const comp = (ref: string, over: Record<string, unknown> = {}): Record<string, unknown> => ({ type: "library", "bom-ref": ref, name: ref, version: "1.0.0", ...over });
  const bomWith = (components: Array<Record<string, unknown>>, subject = true): never =>
    ({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      serialNumber: "urn:uuid:x",
      version: 1,
      metadata: { tools: [], ...(subject ? { component: { type: "application", "bom-ref": "root", name: "demo", version: "2.0.0" } } : {}) },
      components
    }) as never;

  it("leads with the component count and the deficit-first license/integrity gaps", () => {
    const out = renderSbomSummary(
      bomWith([
        comp("pkg:npm/a@1.0.0", { licenses: [{ license: { name: "MIT" } }], hashes: [{ alg: "SHA-512", content: "x" }] }),
        comp("pkg:npm/b@1.0.0"),
        comp("pkg:pypi/c@1.0.0", { licenses: [{ license: { name: "Apache-2.0" } }] }),
        comp("pkg:cargo/d@1.0.0", { hashes: [{ alg: "SHA-256", content: "y" }] })
      ]),
      [],
      "demo@2.0.0",
      theme,
      100
    );
    expect(out).toContain("4 components");
    expect(out).toMatch(/2 npm · 1 pypi · 1 cargo/);
    expect(out).toMatch(/License\s+2 unknown\s+2 \/ 4 covered/);
    expect(out).toMatch(/Integrity\s+2 no checksum\s+2 \/ 4 covered/);
    expect(out).toContain("CycloneDX 1.5 · demo@2.0.0 · inventory only");
    expect(out).toContain("dg sbom -o sbom.cdx.json");
    expect(out).toMatch(/dg scan\s+for BLOCK \/ WARN \/ PASS/);
    expect(out).not.toContain("expression");
  });

  it("omits the gap clause when coverage is complete", () => {
    const out = renderSbomSummary(
      bomWith([comp("pkg:npm/a@1.0.0", { licenses: [{ license: { name: "MIT" } }], hashes: [{ alg: "SHA-512", content: "x" }] })]),
      [],
      "demo@2.0.0",
      theme,
      100
    );
    expect(out).not.toContain("unknown");
    expect(out).not.toContain("no hash");
    expect(out).toMatch(/License\s+1 \/ 1 covered/);
    expect(out).toMatch(/Integrity\s+1 \/ 1 covered/);
  });

  it("draws a closed box whose rows are padded to a uniform width", () => {
    const out = renderSbomSummary(bomWith([comp("pkg:npm/a@1.0.0")]), [], "demo@2.0.0", theme, 100);
    const lines = out.split("\n");
    expect(lines[0]).toMatch(/^╭─+╮$/);
    const widths = new Set(lines.filter((l) => l.startsWith("│")).map((l) => l.length));
    expect(widths.size).toBe(1);
    expect(lines.find((l) => /^╰─+╯$/.test(l))).toBeTruthy();
  });

  it("does not restate the product name or command as a vanity header", () => {
    const out = renderSbomSummary(bomWith([comp("pkg:npm/a@1.0.0")]), [], "demo@2.0.0", theme, 100);
    expect(out).not.toContain("Dependency Guardian");
    expect(out).not.toContain("software bill of materials");
  });

  it("orders the ecosystem breakdown by component count, descending", () => {
    const out = renderSbomSummary(
      bomWith([comp("pkg:cargo/a@1.0.0"), comp("pkg:cargo/b@1.0.0"), comp("pkg:cargo/c@1.0.0"), comp("pkg:npm/d@1.0.0")]),
      [],
      "demo@2.0.0",
      theme,
      100
    );
    expect(out).toMatch(/3 cargo · 1 npm/);
  });

  it("surfaces omitted/unpinned deps and shows the provided subject", () => {
    const out = renderSbomSummary(bomWith([comp("pkg:pypi/a@1.0.0")], false), ["pypi:urllib3", "pypi:flask"], "myproj", theme, 100);
    expect(out).toContain("CycloneDX 1.5 · myproj · inventory only");
    expect(out).toMatch(/Omitted\s+2 unpinned, left out of the document/);
  });
});

function writeRequirements(dir: string, lines: string): void {
  writeFileSync(join(dir, "requirements.txt"), lines, "utf8");
}

describe("dg sbom — audit regression fixes", () => {
  it("normalizes PyPI purls to PEP 503 (matching OSV/registry canonical purls)", () => {
    expect(purlFor(component({ ecosystem: "pypi", name: "ruamel.yaml", version: "0.18.6" }))).toBe("pkg:pypi/ruamel-yaml@0.18.6");
    expect(purlFor(component({ ecosystem: "pypi", name: "zope.interface", version: "6.1" }))).toBe("pkg:pypi/zope-interface@6.1");
    expect(purlFor(component({ ecosystem: "pypi", name: "Flask_Cors", version: "4.0.0" }))).toBe("pkg:pypi/flask-cors@4.0.0");
  });

  it("lowercases npm purls per the package-url spec", () => {
    expect(purlFor(component({ name: "React", version: "1.0.0" }))).toBe("pkg:npm/react@1.0.0");
    expect(purlFor(component({ name: "@Babel/Core", version: "7.0.0" }))).toBe("pkg:npm/%40babel/core@7.0.0");
  });

  it("dedups components that normalize to the same bom-ref (no duplicate bom-ref)", () => {
    const bom = buildCycloneDxSbom(
      [
        component({ ecosystem: "pypi", name: "Flask-Cors", version: "3.0.10" }),
        component({ ecosystem: "pypi", name: "flask_cors", version: "3.0.10" })
      ],
      { timestamp: NOW.toISOString(), serialNumber: "urn:uuid:fixed", toolVersion: "9.9.9" }
    );
    const refs = bom.components.map((c) => c["bom-ref"]);
    expect(refs).toEqual(["pkg:pypi/flask-cors@3.0.10"]);
    expect(new Set(refs).size).toBe(refs.length);
  });

  it("dedups PEP 503-equivalent PyPI names that differ only by dot vs dash", () => {
    const dir = tempDir();
    writeRequirements(dir, "ruamel.yaml==0.18.6\nruamel-yaml==0.18.6\nruamel_yaml==0.18.6\n");
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, {});
    const bom = JSON.parse(result.stdout) as { components: Array<{ name: string; "bom-ref": string }> };
    expect(bom.components).toHaveLength(1);
    expect(bom.components[0]?.["bom-ref"]).toBe("pkg:pypi/ruamel-yaml@0.18.6");
  });

  it("does not over-collapse genuinely distinct packages", () => {
    const dir = tempDir();
    writeNpmLock(dir, {
      "": { name: "demo", version: "1.0.0" },
      "node_modules/left-pad": { version: "1.3.0" },
      "node_modules/right-pad": { version: "1.0.0" },
      "node_modules/left-pad/node_modules/left-pad": { version: "1.2.0" }
    });
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, {});
    const bom = JSON.parse(result.stdout) as { components: Array<{ "bom-ref": string }> };
    const refs = bom.components.map((c) => c["bom-ref"]).sort();
    expect(refs).toEqual(["pkg:npm/left-pad@1.2.0", "pkg:npm/left-pad@1.3.0", "pkg:npm/right-pad@1.0.0"]);
  });

  it("orders components by code point, independent of locale", () => {
    const bom = buildCycloneDxSbom(
      [component({ name: "cz" }), component({ name: "ch" }), component({ name: "aa" })],
      { timestamp: NOW.toISOString(), serialNumber: "urn:uuid:fixed", toolVersion: "9.9.9" }
    );
    expect(bom.components.map((c) => c.name)).toEqual(["aa", "ch", "cz"]);
  });

  it("warns on stderr when unpinned requirements are omitted (mixed pinned/unpinned)", () => {
    const dir = tempDir();
    writeRequirements(dir, "requests==2.31.0\nurllib3\ndjango>=4.0\n");
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, {});
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain("omitted");
    expect(result.stderr).toContain("urllib3");
    const bom = JSON.parse(result.stdout) as { components: Array<{ name: string }> };
    expect(bom.components.map((c) => c.name)).toEqual(["requests"]);
  });

  it("--reproducible is byte-identical across runs and drops the timestamp", () => {
    const dir = tempDir();
    writeNpmLock(dir, { "": { name: "demo", version: "1.0.0" }, "node_modules/left-pad": { version: "1.3.0" } });
    const a = runSbomCommand({ commandPath: ["sbom"], args: ["--reproducible"] }, dir, NOW, {});
    const b = runSbomCommand({ commandPath: ["sbom"], args: ["--reproducible"] }, dir, new Date("2030-01-01T00:00:00.000Z"), {});
    expect(a.stdout).toBe(b.stdout);
    const bom = JSON.parse(a.stdout) as { serialNumber: string; metadata: { timestamp?: string } };
    expect(bom.metadata.timestamp).toBeUndefined();
    expect(bom.serialNumber).toMatch(/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it("honors SOURCE_DATE_EPOCH for a reproducible timestamp", () => {
    const dir = tempDir();
    writeNpmLock(dir, { "": { name: "demo", version: "1.0.0" }, "node_modules/left-pad": { version: "1.3.0" } });
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, { SOURCE_DATE_EPOCH: "1700000000" });
    const bom = JSON.parse(result.stdout) as { metadata: { timestamp?: string } };
    expect(bom.metadata.timestamp).toBe("2023-11-14T22:13:20.000Z");
  });

  it("warns when the root package.json is malformed instead of swallowing it", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "package.json"), "{ not json", "utf8");
    writeRequirements(dir, "requests==2.31.0\n");
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, {});
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain("could not be parsed");
    const bom = JSON.parse(result.stdout) as { metadata: { component?: unknown } };
    expect(bom.metadata.component).toBeUndefined();
  });

  it("emits every declared license verbatim as a schema-valid license.name (no SPDX-expression guessing)", () => {
    const dir = tempDir();
    writeNpmLock(dir, {
      "": { name: "demo", version: "1.0.0" },
      "node_modules/dual": { version: "1.0.0", license: "(MIT OR Apache-2.0)" },
      "node_modules/single": { version: "1.0.0", license: "MIT" },
      "node_modules/junk": { version: "1.0.0", license: "(MIT OR Apache-2.0" },
      "node_modules/ops": { version: "1.0.0", license: "OR AND WITH" }
    });
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, {});
    const bom = JSON.parse(result.stdout) as { components: Array<{ name: string; licenses: unknown }> };
    const lic = (name: string): unknown => bom.components.find((c) => c.name === name)?.licenses;
    expect(lic("dual")).toEqual([{ license: { name: "(MIT OR Apache-2.0)" } }]);
    expect(lic("single")).toEqual([{ license: { name: "MIT" } }]);
    expect(lic("junk")).toEqual([{ license: { name: "(MIT OR Apache-2.0" } }]);
    expect(lic("ops")).toEqual([{ license: { name: "OR AND WITH" } }]);
    expect(JSON.stringify(bom)).not.toContain("expression");
  });

  it("--reproducible serial reflects integrity, so a tampered tarball does not collide", () => {
    const serialFor = (byte: number): string => {
      const dir = tempDir();
      writeNpmLock(dir, { "": { name: "demo", version: "1.0.0" }, "node_modules/left-pad": { version: "1.3.0", integrity: sri512(byte) } });
      const result = runSbomCommand({ commandPath: ["sbom"], args: ["--reproducible"] }, dir, NOW, {});
      return (JSON.parse(result.stdout) as { serialNumber: string }).serialNumber;
    };
    expect(serialFor(0x01)).not.toBe(serialFor(0x02));
  });

  const cargoEntry = (name: string, version: string, source: string | null): string =>
    `[[package]]\nname = "${name}"\nversion = "${version}"\n${source ? `source = "${source}"\n` : ""}checksum = "${"9b".repeat(32)}"\n`;
  const CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index";

  it("includes registry Cargo (Rust) dependencies in the SBOM", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "Cargo.lock"), cargoEntry("serde", "1.0.0", CRATES_IO), "utf8");
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, {});
    expect(result.exitCode).toBe(0);
    const bom = JSON.parse(result.stdout) as { components: Array<{ "bom-ref": string }> };
    expect(bom.components.map((c) => c["bom-ref"])).toContain("pkg:cargo/serde@1.0.0");
  });

  it("skips no-source cargo deps (workspace members / path deps) so private crate names don't leak as crates.io purls", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "Cargo.lock"), `version = 3\n\n${cargoEntry("my-private-app", "0.1.0", null)}\n${cargoEntry("serde", "1.0.0", CRATES_IO)}`, "utf8");
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, {});
    const bom = JSON.parse(result.stdout) as { components: Array<{ name: string }> };
    expect(bom.components.map((c) => c.name)).toEqual(["serde"]);
  });

  it("qualifies an alternate-registry cargo purl with repository_url", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "Cargo.lock"), cargoEntry("internal-lib", "2.0.0", "registry+https://internal.corp.example/git/index"), "utf8");
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, {});
    const bom = JSON.parse(result.stdout) as { components: Array<{ purl: string }> };
    expect(bom.components[0]?.purl).toBe("pkg:cargo/internal-lib@2.0.0?repository_url=https%3A%2F%2Finternal.corp.example%2Fgit%2Findex");
  });

  it("does not drop a real cargo crate literally named 'unknown'", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "Cargo.lock"), `${cargoEntry("unknown", "0.1.1", CRATES_IO)}\n${cargoEntry("serde", "1.0.0", CRATES_IO)}`, "utf8");
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, {});
    const bom = JSON.parse(result.stdout) as { components: Array<{ name: string }> };
    expect(bom.components.map((c) => c.name).sort()).toEqual(["serde", "unknown"]);
  });

  it("emits real expressions, prose, and malformed input all as license.name; drops blank", () => {
    const dir = tempDir();
    writeNpmLock(dir, {
      "": { name: "demo", version: "1.0.0" },
      "node_modules/realexpr": { version: "1.0.0", license: "MIT OR Apache-2.0" },
      "node_modules/prose": { version: "1.0.0", license: "Some License OR Another" },
      "node_modules/unbalanced": { version: "1.0.0", license: "MIT) OR (Apache-2.0" },
      "node_modules/blank": { version: "1.0.0", license: "   " }
    });
    const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, {});
    const bom = JSON.parse(result.stdout) as { components: Array<{ name: string; licenses: unknown }> };
    const lic = (name: string): unknown => bom.components.find((c) => c.name === name)?.licenses;
    expect(lic("realexpr")).toEqual([{ license: { name: "MIT OR Apache-2.0" } }]);
    expect(lic("prose")).toEqual([{ license: { name: "Some License OR Another" } }]);
    expect(lic("unbalanced")).toEqual([{ license: { name: "MIT) OR (Apache-2.0" } }]);
    expect(lic("blank")).toBeUndefined();
  });

  it("qualifies cargo sparse-protocol alternate registries with repository_url (and leaves crates.io bare)", () => {
    const alt = tempDir();
    writeFileSync(join(alt, "Cargo.lock"), `[[package]]\nname = "private-crate"\nversion = "1.2.0"\nsource = "sparse+https://internal.corp.example/index/"\nchecksum = "${"ab".repeat(32)}"\n`, "utf8");
    const altResult = runSbomCommand({ commandPath: ["sbom"], args: [] }, alt, NOW, {});
    expect((JSON.parse(altResult.stdout) as { components: Array<{ purl: string }> }).components[0]?.purl)
      .toBe("pkg:cargo/private-crate@1.2.0?repository_url=https%3A%2F%2Finternal.corp.example%2Findex%2F");

    const io = tempDir();
    writeFileSync(join(io, "Cargo.lock"), `[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "sparse+https://index.crates.io/"\nchecksum = "${"cd".repeat(32)}"\n`, "utf8");
    const ioResult = runSbomCommand({ commandPath: ["sbom"], args: [] }, io, NOW, {});
    expect((JSON.parse(ioResult.stdout) as { components: Array<{ purl: string }> }).components[0]?.purl).toBe("pkg:cargo/serde@1.0.0");
  });

  it("omits the timestamp for an out-of-range or millisecond SOURCE_DATE_EPOCH instead of emitting an invalid one or crashing", () => {
    const dir = tempDir();
    writeNpmLock(dir, { "": { name: "demo", version: "1.0.0" }, "node_modules/left-pad": { version: "1.3.0" } });
    for (const epoch of ["1700000000000", "99999999999999999999"]) {
      const result = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, { SOURCE_DATE_EPOCH: epoch });
      expect(result.exitCode).toBe(0);
      const bom = JSON.parse(result.stdout) as { metadata: { timestamp?: string } };
      expect(bom.metadata.timestamp).toBeUndefined();
    }
    const valid = runSbomCommand({ commandPath: ["sbom"], args: [] }, dir, NOW, { SOURCE_DATE_EPOCH: "1700000000" });
    expect((JSON.parse(valid.stdout) as { metadata: { timestamp?: string } }).metadata.timestamp).toBe("2023-11-14T22:13:20.000Z");
  });
});
