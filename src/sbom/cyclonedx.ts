import { join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { parseLockfilePackages } from "../verify/preflight.js";
import { normalizePypiName } from "../policy/cooldown.js";
import type { LockfileProject } from "../scan/collect.js";
import type { VerifyPackageIdentity } from "../verify/types.js";

export type SbomComponent = VerifyPackageIdentity & { version: string };

export type CycloneDxHash = { alg: string; content: string };
export type CycloneDxLicense = { license: { name: string } };

export type CycloneDxComponent = {
  type: "library";
  "bom-ref": string;
  name: string;
  version: string;
  purl?: string;
  licenses?: readonly CycloneDxLicense[];
  hashes?: readonly CycloneDxHash[];
};

export type CycloneDxBom = {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  serialNumber: string;
  version: number;
  metadata: {
    timestamp?: string;
    tools: ReadonlyArray<{ vendor: string; name: string; version: string }>;
    component?: { type: "application"; "bom-ref": string; name: string; version?: string };
  };
  components: readonly CycloneDxComponent[];
};

export type SbomBuildOptions = {
  readonly timestamp?: string;
  readonly serialNumber: string;
  readonly toolVersion: string;
  readonly rootComponent?: { name: string; version?: string };
};

export type SbomCollection = {
  readonly components: readonly SbomComponent[];
  readonly dropped: readonly string[];
};

export function collectSbomComponents(projects: readonly LockfileProject[]): SbomCollection {
  const seen = new Set<string>();
  const droppedSeen = new Set<string>();
  const components: SbomComponent[] = [];
  const dropped: string[] = [];
  for (const project of projects) {
    const parsed = parseLockfilePackages(join(project.path, project.depFile));
    for (const identity of parsed.packages) {
      if (identity.ecosystem === "unknown" || !identity.version) {
        const label = `${identity.ecosystem}:${identity.name}`;
        if (identity.name.length > 0 && !droppedSeen.has(label)) {
          droppedSeen.add(label);
          dropped.push(label);
        }
        continue;
      }
      const component: SbomComponent = { ...identity, version: identity.version };
      const key = canonicalKey(component);
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      components.push(component);
    }
  }
  return { components, dropped };
}

export type RootComponentResult = {
  readonly component?: { name: string; version?: string };
  readonly malformed?: boolean;
};

export function readRootComponent(root: string): RootComponentResult {
  const manifest = join(root, "package.json");
  if (!existsSync(manifest)) {
    return {};
  }
  try {
    const parsed = JSON.parse(readFileSync(manifest, "utf8")) as { name?: unknown; version?: unknown };
    if (typeof parsed.name !== "string" || parsed.name.length === 0) {
      return {};
    }
    return { component: { name: parsed.name, ...(typeof parsed.version === "string" ? { version: parsed.version } : {}) } };
  } catch {
    return { malformed: true };
  }
}

export function buildCycloneDxSbom(components: readonly SbomComponent[], opts: SbomBuildOptions): CycloneDxBom {
  const byRef = new Map<string, CycloneDxComponent>();
  for (const component of components) {
    const mapped = toCycloneDxComponent(component);
    if (!byRef.has(mapped["bom-ref"])) {
      byRef.set(mapped["bom-ref"], mapped);
    }
  }
  const mapped = [...byRef.values()].sort((a, b) => compareCodePoints(a["bom-ref"], b["bom-ref"]));
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: opts.serialNumber,
    version: 1,
    metadata: {
      ...(opts.timestamp ? { timestamp: opts.timestamp } : {}),
      tools: [{ vendor: "WestBayBerry", name: "dg", version: opts.toolVersion }],
      ...(opts.rootComponent
        ? {
            component: {
              type: "application" as const,
              "bom-ref": "root",
              name: opts.rootComponent.name,
              ...(opts.rootComponent.version ? { version: opts.rootComponent.version } : {})
            }
          }
        : {})
    },
    components: mapped
  };
}

function compareCodePoints(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function bomRefOf(component: SbomComponent): string {
  return purlFor(component) ?? `${component.ecosystem}:${component.name}@${component.version}`;
}

function canonicalKey(component: SbomComponent): string {
  const name = canonicalPurlName(component.ecosystem, component.name);
  return `${component.ecosystem}:${name}@${component.version}`;
}

function canonicalPurlName(ecosystem: SbomComponent["ecosystem"], name: string): string {
  if (ecosystem === "pypi") {
    return normalizePypiName(name);
  }
  if (ecosystem === "npm") {
    return name.toLowerCase();
  }
  return name;
}

// The declared license string is emitted verbatim as a CycloneDX `license.name`,
// which is always schema-valid for any free text. We deliberately do NOT classify
// it into the SPDX `expression` form: correctly distinguishing a valid SPDX
// expression from free text requires validating operands against the SPDX license
// registry, and any heuristic shortcut emits schema-invalid expressions for some
// inputs (unbalanced parens, operator-only strings, unregistered ids).
function toCycloneDxComponent(component: SbomComponent): CycloneDxComponent {
  const purl = purlFor(component);
  const hashes = hashesFor(component.integrity);
  const license = component.license?.trim();
  const licenses = license ? [{ license: { name: license } }] : undefined;
  return {
    type: "library",
    "bom-ref": bomRefOf(component),
    name: component.name,
    version: component.version,
    ...(purl ? { purl } : {}),
    ...(licenses ? { licenses } : {}),
    ...(hashes.length > 0 ? { hashes } : {})
  };
}

export function purlFor(component: SbomComponent): string | null {
  const version = encodeURIComponent(component.version);
  if (component.ecosystem === "npm") {
    const lower = component.name.toLowerCase();
    if (lower.startsWith("@") && lower.includes("/")) {
      const slash = lower.indexOf("/");
      const scope = lower.slice(1, slash);
      const bare = lower.slice(slash + 1);
      return `pkg:npm/%40${encodeURIComponent(scope)}/${encodeURIComponent(bare)}@${version}`;
    }
    return `pkg:npm/${encodeURIComponent(lower)}@${version}`;
  }
  if (component.ecosystem === "pypi") {
    return `pkg:pypi/${encodeURIComponent(normalizePypiName(component.name))}@${version}`;
  }
  if (component.ecosystem === "cargo") {
    const base = `pkg:cargo/${encodeURIComponent(component.name.toLowerCase())}@${version}`;
    const repository = cargoAlternateRegistry(component.resolvedUrl);
    return repository ? `${base}?repository_url=${encodeURIComponent(repository)}` : base;
  }
  return null;
}

function cargoAlternateRegistry(source: string | null): string | null {
  if (!source || (!source.startsWith("registry+") && !source.startsWith("sparse+"))) {
    return null;
  }
  const url = source.replace(/^registry\+/u, "").replace(/^sparse\+/u, "");
  if (/(?:^|\/\/)(?:github\.com\/rust-lang\/crates\.io-index|index\.crates\.io)/u.test(url)) {
    return null;
  }
  return url;
}

const SRI_ALG_BYTES: Record<string, { alg: string; bytes: number }> = {
  sha1: { alg: "SHA-1", bytes: 20 },
  sha256: { alg: "SHA-256", bytes: 32 },
  sha384: { alg: "SHA-384", bytes: 48 },
  sha512: { alg: "SHA-512", bytes: 64 }
};

export function hashesFor(integrity: string | null): CycloneDxHash[] {
  if (!integrity) {
    return [];
  }
  const hashes: CycloneDxHash[] = [];
  for (const token of integrity.trim().split(/\s+/)) {
    const sri = /^(sha1|sha256|sha384|sha512)-([^?]+)/u.exec(token);
    if (sri && sri[1] && sri[2]) {
      const spec = SRI_ALG_BYTES[sri[1]];
      const hex = base64ToHex(sri[2]);
      if (spec && hex && hex.length === spec.bytes * 2) {
        hashes.push({ alg: spec.alg, content: hex });
      }
      continue;
    }
    const hex = /^(sha1|sha256|sha384|sha512|md5):([0-9a-fA-F]+)$/u.exec(token);
    if (hex && hex[1] && hex[2]) {
      const spec = SRI_ALG_BYTES[hex[1]];
      if (spec && hex[2].length === spec.bytes * 2) {
        hashes.push({ alg: spec.alg, content: hex[2].toLowerCase() });
      }
      continue;
    }
    const berry = /^[0-9a-z]+\/([0-9a-f]{40,128})$/iu.exec(token);
    if (berry && berry[1]) {
      const content = berry[1].toLowerCase();
      const alg = SHA_HEX_LENGTHS[content.length];
      if (alg) {
        hashes.push({ alg, content });
      }
      continue;
    }
    const bareHex = /^[0-9a-f]{40,128}$/iu.exec(token);
    if (bareHex) {
      const content = token.toLowerCase();
      const alg = SHA_HEX_LENGTHS[content.length];
      if (alg) {
        hashes.push({ alg, content });
      }
    }
  }
  return hashes;
}

const SHA_HEX_LENGTHS: Record<number, string | undefined> = { 40: "SHA-1", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512" };

function base64ToHex(value: string): string | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return null;
  }
  try {
    return Buffer.from(value, "base64").toString("hex");
  } catch {
    return null;
  }
}
