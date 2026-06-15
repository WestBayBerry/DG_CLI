import { createHash } from "node:crypto";
import { brotliDecompressSync, gunzipSync, inflateRawSync, inflateSync } from "node:zlib";
import type { OutgoingHttpHeaders } from "node:http";
import type { PackageManagerClassification } from "../launcher/classify.js";

// decodeURIComponent throws on malformed percent-encoding (e.g. a stray % in a
// registry href); fall back to the raw value so one bad entry cannot throw out of
// the whole metadata-extraction pass and drop every identity.
function safeDecodeUriComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export type ArtifactIdentitySource = "registry-metadata" | "url-fallback";

export interface ArtifactIdentity {
  readonly ecosystem: "npm" | "pypi" | "cargo" | "unknown";
  readonly name: string;
  readonly version: string;
  readonly registryHost: string;
  readonly tarballUrl: string;
  readonly sourceKind: ArtifactIdentitySource;
}

export interface AmbiguousArtifactIdentity {
  readonly kind: "ambiguous";
  readonly packageName: string;
  readonly reason: string;
}

export interface ResolvedArtifactIdentity {
  readonly kind: "resolved";
  readonly identity: ArtifactIdentity;
}

export type ArtifactIdentityResolution = AmbiguousArtifactIdentity | ResolvedArtifactIdentity;

export function extractRegistryMetadataIdentities(
  metadataUrl: URL,
  response: { readonly headers: OutgoingHttpHeaders; readonly body: Buffer }
): ArtifactIdentity[] {
  const decoded = { headers: response.headers, body: decodeContentEncoding(response.headers, response.body) };
  // PyPI Simple index (PEP 503 HTML or PEP 691 JSON) — the pip/uv/pipx flow.
  if (isPypiSimpleIndexUrl(metadataUrl)) {
    return extractPypiSimpleIdentities(metadataUrl, decoded);
  }
  if (!looksLikeJson(decoded.headers["content-type"])) {
    return [];
  }
  const parsed = parseJson(decoded.body);
  if (!isRecord(parsed)) {
    return [];
  }
  return [
    ...extractNpmIdentities(metadataUrl, parsed),
    ...extractPypiIdentities(metadataUrl, parsed)
  ];
}

// A MITM'd registry can return a tiny gzip/brotli body that expands to gigabytes;
// cap the decoded size so a decompression bomb cannot exhaust proxy memory.
const MAX_METADATA_DECODED_BYTES = 32 * 1024 * 1024;

// Content-Encoding lists encodings in the order they were applied; decode in
// reverse. Any unknown token or decode failure returns the body untouched so
// the response falls back to artifact handling instead of crashing the proxy.
function decodeContentEncoding(headers: OutgoingHttpHeaders, body: Buffer): Buffer {
  const raw = headers["content-encoding"];
  const encodings = (Array.isArray(raw) ? raw.join(",") : String(raw ?? ""))
    .split(",")
    .map((token) => token.trim().toLowerCase())
    .filter((token) => token.length > 0 && token !== "identity");
  const cap = { maxOutputLength: MAX_METADATA_DECODED_BYTES };
  let decoded = body;
  for (const encoding of encodings.reverse()) {
    try {
      if (encoding === "gzip" || encoding === "x-gzip") {
        decoded = gunzipSync(decoded, cap);
      } else if (encoding === "br") {
        decoded = brotliDecompressSync(decoded, cap);
      } else if (encoding === "deflate") {
        try {
          decoded = inflateSync(decoded, cap);
        } catch {
          decoded = inflateRawSync(decoded, cap);
        }
      } else {
        return body;
      }
    } catch {
      return body;
    }
  }
  return decoded;
}

// A registry INDEX/metadata request (not an artifact download). These must be
// passed through untouched — never verified as a package — so e.g. pip's
// `pypi.org/simple/<pkg>/` index is not mistaken for a package named "simple".
// PEP 658 `.metadata` sidecars are dist-info metadata pip fetches for dependency
// resolution; the actual wheel/sdist download is what gets verified. npm reserves
// the `/-/` path prefix for registry API endpoints (security/advisories, audits,
// `-/v1/search`) which npm hits during install — those are never package tarballs
// (tarballs live at `/<pkg>/-/<file>.tgz`, where `/-/` is not at the path start).
export function isRegistryIndexRequest(url: URL): boolean {
  return (
    isPypiSimpleIndexUrl(url) ||
    /\/pypi\/[^/]+\/json\/?$/i.test(url.pathname) ||
    // PEP 658 sidecar: only `<wheel|sdist>.metadata`, not any path ending .metadata
    /\.(whl|tar\.gz|tgz|zip)\.metadata$/i.test(url.pathname) ||
    /^\/-\//.test(url.pathname)
  );
}

function isPypiSimpleIndexUrl(url: URL): boolean {
  return /^\/simple(\/|$)/i.test(url.pathname);
}

function extractPypiSimpleIdentities(
  metadataUrl: URL,
  response: { readonly headers: OutgoingHttpHeaders; readonly body: Buffer }
): ArtifactIdentity[] {
  const entries: { readonly href: string; readonly filename?: string }[] = [];
  if (looksLikeJson(response.headers["content-type"])) {
    const parsed = parseJson(response.body);
    const files = isRecord(parsed) && Array.isArray(parsed.files) ? parsed.files : [];
    for (const file of files) {
      if (isRecord(file) && typeof file.url === "string" && file.url.length > 0) {
        entries.push(typeof file.filename === "string" && file.filename.length > 0
          ? { href: file.url, filename: file.filename }
          : { href: file.url });
      }
    }
  } else {
    const html = response.body.toString("utf8");
    const linkRe = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi;
    let match: RegExpExecArray | null;
    while ((match = linkRe.exec(html)) !== null) {
      if (match[1]) {
        entries.push({ href: match[1] });
      }
    }
  }

  const identities: ArtifactIdentity[] = [];
  for (const entry of entries) {
    let absolute: URL;
    try {
      absolute = new URL(entry.href, metadataUrl);
    } catch {
      continue;
    }
    const file = entry.filename ?? safeDecodeUriComponent(absolute.pathname.split("/").filter(Boolean).at(-1) ?? "");
    const parsed = parsePypiArtifactFilename(file);
    if (!parsed) {
      continue;
    }
    identities.push({
      ecosystem: "pypi",
      name: parsed.name,
      version: parsed.version,
      registryHost: absolute.hostname,
      tarballUrl: artifactUrlKey(absolute),
      sourceKind: "registry-metadata"
    });
  }
  return identities;
}

// Parse a PyPI wheel (PEP 427) or sdist filename into {name, version}. Wheel and
// sdist names/versions never contain "-" (it is escaped to "_"), so a wheel is a
// clean dash-split and an sdist is name + a digit-leading version.
function parsePypiArtifactFilename(file: string): { readonly name: string; readonly version: string } | null {
  if (/\.whl$/i.test(file)) {
    const parts = file.replace(/\.whl$/i, "").split("-");
    if (parts.length >= 5 && parts[0] && parts[1]) {
      return { name: normalizePypiName(parts[0]), version: parts[1] };
    }
    return null;
  }
  const sdistExt = /\.(?:tar\.gz|tgz|zip|tar\.bz2|tar\.xz)$/i.exec(file);
  if (sdistExt) {
    const stem = file.slice(0, file.length - sdistExt[0].length);
    const match = /^(.+)-(\d[A-Za-z0-9._!+]*)$/.exec(stem);
    if (match && match[1] && match[2]) {
      return { name: normalizePypiName(match[1]), version: match[2] };
    }
  }
  return null;
}

function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

export function resolveArtifactIdentity(
  artifactUrl: URL,
  identities: readonly ArtifactIdentity[],
  classification: PackageManagerClassification
): ArtifactIdentityResolution {
  const key = artifactUrlKey(artifactUrl);
  const matches = identities.filter((identity) => artifactUrlKey(identity.tarballUrl) === key);
  const unique = dedupeIdentities(matches);
  if (unique.length === 1) {
    const identity = unique[0];
    if (!identity) {
      throw new Error("artifact identity resolution was empty");
    }
    return {
      kind: "resolved",
      identity
    };
  }
  if (unique.length > 1) {
    const first = unique[0];
    if (!first) {
      throw new Error("artifact identity ambiguity was empty");
    }
    return {
      kind: "ambiguous",
      packageName: artifactDisplayName(first),
      reason: `ambiguous artifact identity for ${redactedUrl(artifactUrl)} from registry metadata`
    };
  }
  return {
    kind: "resolved",
    identity: fallbackIdentity(artifactUrl, classification)
  };
}

export function artifactDisplayName(identity: ArtifactIdentity): string {
  return `${identity.ecosystem}:${identity.name}@${identity.version}`;
}

export function artifactUrlHash(url: URL): string {
  return createHash("sha256").update(artifactUrlKey(url)).digest("hex");
}

export function artifactUrlKey(value: URL | string): string {
  const url = typeof value === "string" ? new URL(value) : new URL(value.toString());
  url.username = "";
  url.password = "";
  url.hash = "";
  return url.toString();
}

function extractNpmIdentities(metadataUrl: URL, parsed: Record<string, unknown>): ArtifactIdentity[] {
  const packageName = typeof parsed.name === "string" ? parsed.name : packageNameFromNpmMetadataPath(metadataUrl);
  const versions = isRecord(parsed.versions) ? parsed.versions : {};
  const identities: ArtifactIdentity[] = [];
  for (const [version, rawVersion] of Object.entries(versions)) {
    if (!isRecord(rawVersion) || typeof version !== "string") {
      continue;
    }
    const dist = isRecord(rawVersion.dist) ? rawVersion.dist : {};
    if (typeof dist.tarball !== "string" || dist.tarball.length === 0) {
      continue;
    }
    identities.push({
      ecosystem: "npm",
      name: packageName,
      version,
      registryHost: metadataUrl.hostname,
      tarballUrl: artifactUrlKey(new URL(dist.tarball, metadataUrl)),
      sourceKind: "registry-metadata"
    });
  }
  return identities;
}

function extractPypiIdentities(metadataUrl: URL, parsed: Record<string, unknown>): ArtifactIdentity[] {
  const info = isRecord(parsed.info) ? parsed.info : {};
  const packageName = typeof info.name === "string" && info.name.length > 0
    ? info.name
    : packageNameFromPypiMetadataPath(metadataUrl);
  const releases = isRecord(parsed.releases) ? parsed.releases : {};
  const identities: ArtifactIdentity[] = [];
  for (const [version, rawFiles] of Object.entries(releases)) {
    if (!Array.isArray(rawFiles)) {
      continue;
    }
    for (const rawFile of rawFiles) {
      if (!isRecord(rawFile) || typeof rawFile.url !== "string" || rawFile.url.length === 0) {
        continue;
      }
      identities.push({
        ecosystem: "pypi",
        name: packageName,
        version,
        registryHost: metadataUrl.hostname,
        tarballUrl: artifactUrlKey(new URL(rawFile.url, metadataUrl)),
        sourceKind: "registry-metadata"
      });
    }
  }
  return identities;
}

function fallbackIdentity(artifactUrl: URL, classification: PackageManagerClassification): ArtifactIdentity {
  const ecosystem = ecosystemForManager(classification.manager);
  const parsed = ecosystem === "pypi"
    ? parsePypiArtifactFilename(safeDecodeUriComponent(artifactUrl.pathname.split("/").filter(Boolean).at(-1) ?? "")) ?? parsePackageVersionFromUrl(artifactUrl)
    : ecosystem === "cargo"
      ? parseCargoArtifactUrl(artifactUrl) ?? parsePackageVersionFromUrl(artifactUrl)
      : parsePackageVersionFromUrl(artifactUrl);
  const requested = requestedIdentityFromArgs(classification, parsed.name);
  return {
    ecosystem,
    name: requested?.name ?? parsed.name,
    version: requested?.version ?? parsed.version,
    registryHost: artifactUrl.hostname,
    tarballUrl: artifactUrlKey(artifactUrl),
    sourceKind: "url-fallback"
  };
}

// crates.io serves downloads at /api/v1/crates/{name}/{version}/download,
// static.crates.io at /crates/{name}/{version}/download and as
// {name}-{version}.crate files. Crate versions always start with a digit
// (semver), so the filename split is unambiguous even for names with dashes.
function parseCargoArtifactUrl(artifactUrl: URL): { readonly name: string; readonly version: string } | null {
  const downloadMatch = /^\/(?:api\/v1\/)?crates\/([^/]+)\/([^/]+)\/download\/?$/.exec(artifactUrl.pathname);
  if (downloadMatch && downloadMatch[1] && downloadMatch[2]) {
    return {
      name: safeDecodeUriComponent(downloadMatch[1]),
      version: safeDecodeUriComponent(downloadMatch[2])
    };
  }
  const file = safeDecodeUriComponent(artifactUrl.pathname.split("/").filter(Boolean).at(-1) ?? "");
  if (/\.crate$/i.test(file)) {
    const stem = file.slice(0, -".crate".length);
    const match = /^(.+)-(\d[0-9A-Za-z.+-]*)$/.exec(stem);
    if (match && match[1] && match[2]) {
      return { name: match[1], version: match[2] };
    }
  }
  return null;
}

function parsePackageVersionFromUrl(artifactUrl: URL): { readonly name: string; readonly version: string } {
  const parts = artifactUrl.pathname.split("/").filter(Boolean).map((part) => safeDecodeUriComponent(part));
  const file = parts.at(-1) ?? artifactUrl.hostname;
  const npmPackage = npmPackageFromTarballPath(parts);
  const packageName = npmPackage ?? parts.at(-2) ?? file.replace(/\.(?:tgz|tar\.gz|zip|whl)$/i, "");
  const filePackageName = packageName.split("/").at(-1) ?? packageName;
  const escaped = filePackageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const versionMatch = new RegExp(`${escaped}[-_]v?([^/]+?)\\.(?:tgz|tar\\.gz|zip|whl)$`, "i").exec(file);
  return {
    name: packageName || artifactUrl.hostname,
    version: versionMatch?.[1] ?? "unknown"
  };
}

function npmPackageFromTarballPath(parts: readonly string[]): string | undefined {
  const marker = parts.indexOf("-");
  if (marker <= 0) {
    return undefined;
  }
  const beforeMarker = parts.slice(0, marker);
  const name = beforeMarker.at(-1);
  const scope = beforeMarker.at(-2);
  if (!name) {
    return undefined;
  }
  if (scope?.startsWith("@")) {
    return `${scope}/${name}`;
  }
  return name;
}

function requestedIdentityFromArgs(
  classification: PackageManagerClassification,
  parsedName: string
): { readonly name: string; readonly version: string } | undefined {
  if (classification.ecosystem !== "javascript") {
    return undefined;
  }
  const specs = classification.args
    .filter((arg) => !arg.startsWith("-") && arg !== classification.action)
    .map(parseNpmPackageSpec)
    .filter((spec): spec is { readonly name: string; readonly version: string } => spec !== undefined);
  if (specs.length !== 1) {
    return undefined;
  }
  const [spec] = specs;
  if (!spec || spec.name !== parsedName) {
    return undefined;
  }
  return spec;
}

function parseNpmPackageSpec(spec: string): { readonly name: string; readonly version: string } | undefined {
  if (spec.length === 0 || spec === "." || spec.startsWith("file:") || /^https?:\/\//.test(spec)) {
    return undefined;
  }
  const withoutAlias = spec.includes("@npm:") ? spec.slice(spec.indexOf("@npm:") + 5) : spec;
  const versionSeparator = withoutAlias.lastIndexOf("@");
  if (versionSeparator <= 0) {
    return undefined;
  }
  const name = withoutAlias.slice(0, versionSeparator);
  const version = withoutAlias.slice(versionSeparator + 1);
  if (!name || !version || name === version || /[*xX]|\|\||[<>=~^]/.test(version)) {
    return undefined;
  }
  return { name, version };
}

function packageNameFromNpmMetadataPath(metadataUrl: URL): string {
  const parts = metadataUrl.pathname.split("/").filter(Boolean).map((part) => safeDecodeUriComponent(part));
  if (parts[0]?.startsWith("@") && parts[1]) {
    return `${parts[0]}/${parts[1]}`;
  }
  return parts[0] ?? metadataUrl.hostname;
}

function packageNameFromPypiMetadataPath(metadataUrl: URL): string {
  const parts = metadataUrl.pathname.split("/").filter(Boolean).map((part) => safeDecodeUriComponent(part));
  const projectIndex = parts.findIndex((part) => part.toLowerCase() === "pypi");
  return parts[projectIndex + 1] ?? parts[0] ?? metadataUrl.hostname;
}

function ecosystemForManager(manager: PackageManagerClassification["manager"]): ArtifactIdentity["ecosystem"] {
  if (manager === "npm" || manager === "npx" || manager === "pnpm" || manager === "pnpx" || manager === "yarn") {
    return "npm";
  }
  if (manager === "pip" || manager === "pipx" || manager === "uv" || manager === "uvx") {
    return "pypi";
  }
  if (manager === "cargo") {
    return "cargo";
  }
  return "unknown";
}

function dedupeIdentities(identities: readonly ArtifactIdentity[]): ArtifactIdentity[] {
  const seen = new Set<string>();
  const unique: ArtifactIdentity[] = [];
  for (const identity of identities) {
    const key = `${identity.ecosystem}\0${identity.name}\0${identity.version}\0${identity.registryHost}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(identity);
    }
  }
  return unique;
}

function redactedUrl(url: URL): string {
  const copy = new URL(url.toString());
  if (copy.username || copy.password) {
    copy.username = "<redacted>";
    copy.password = "";
  }
  return copy.toString();
}

function looksLikeJson(value: string | number | readonly string[] | undefined): boolean {
  const header = Array.isArray(value) ? value.join(",") : String(value ?? "");
  return /\bjson\b/i.test(header);
}

function parseJson(body: Buffer): unknown {
  try {
    return JSON.parse(body.toString("utf8"));
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
