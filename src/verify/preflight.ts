import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { loadUserConfig } from "../config/settings.js";
import type { LockfileParseError, LockfileSkippedPackage, LockfileSkipReason } from "../scan/types.js";
import {
  evaluatePackagePolicy,
  resolveEffectivePolicy,
  type AllowlistEntry,
  type PolicyAction,
  type Verdict
} from "../policy/evaluate.js";
import type {
  VerifyFinding,
  VerifyPackageIdentity,
  VerifyPreflightSummary,
  VerifyReport,
  VerifyStatus
} from "./types.js";

type PackageObservation = {
  identity: VerifyPackageIdentity;
  verdict: Verdict;
  finding: Omit<VerifyFinding, "severity"> | null;
};

type VerifyPreflightOptions = {
  allowPackages?: readonly string[];
  denyLicenses?: readonly string[];
  cwd?: string;
};

const LOCKFILE_NAMES = new Set([
  "Cargo.lock",
  "Pipfile.lock",
  "npm-shrinkwrap.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "poetry.lock",
  "requirements.txt",
  "uv.lock",
  "yarn.lock"
]);

const REMOTE_SPEC_PREFIXES = [
  "http://",
  "https://",
  "git+",
  "git://",
  "ssh://",
  "github:"
];

const MAX_LOCKFILE_BYTES = 64 * 1024 * 1024;

const NPM_LOCKFILE_NAMES = new Set([
  "npm-shrinkwrap.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock"
]);

const PYPI_LOCKFILE_NAMES = new Set([
  "Pipfile.lock",
  "poetry.lock",
  "requirements.txt",
  "uv.lock"
]);

const DEFAULT_NPM_REGISTRY_HOSTS = ["registry.npmjs.org", "registry.yarnpkg.com"] as const;
const DEFAULT_PYPI_REGISTRY_HOSTS = ["pypi.org", "files.pythonhosted.org"] as const;

function readLockfileText(path: string): string {
  const sizeBytes = statSync(path).size;
  if (sizeBytes > MAX_LOCKFILE_BYTES) {
    throw new Error(`lockfile is ${sizeBytes} bytes, above the ${MAX_LOCKFILE_BYTES} byte parse limit`);
  }
  return readFileSync(path, "utf8");
}

export function isSupportedLockfilePath(target: string): boolean {
  return LOCKFILE_NAMES.has(basename(target));
}

export function isRemotePackageSpec(spec: string): boolean {
  const lowered = spec.trim().toLowerCase();
  return REMOTE_SPEC_PREFIXES.some((prefix) => lowered.startsWith(prefix)) || lowered.startsWith("file:");
}

export function verifyPackageSpec(spec: string, options: VerifyPreflightOptions = {}): VerifyReport {
  const parsed = parsePackageSpec(spec);
  const observations = parsed
    ? [parsed]
    : [blockedUnknownSpec(spec)];
  return preflightReport({
    target: spec,
    inputKind: "package-spec",
    preflight: {
      advisory: true,
      packageCount: observations.length,
      identitySource: "package-spec",
      message: "Package spec verification is advisory preflight; proxy enforcement remains authoritative for network fetches."
    },
    observations,
    options
  });
}

export function verifyLockfile(targetPath: string, options: VerifyPreflightOptions = {}): VerifyReport {
  const cwd = resolve(options.cwd ?? process.cwd());
  const absoluteTarget = resolve(cwd, targetPath);
  const displayTarget = displayPath(cwd, absoluteTarget);
  if (!existsSync(absoluteTarget)) {
    return preflightReport({
      target: displayTarget,
      inputKind: "lockfile",
      preflight: lockfileSummary(0),
      observations: [],
      options,
      errors: [`lockfile does not exist: ${displayTarget}`]
    });
  }

  let text: string;
  try {
    text = readLockfileText(absoluteTarget);
  } catch (error) {
    return preflightReport({
      target: displayTarget,
      inputKind: "lockfile",
      preflight: lockfileSummary(0),
      observations: [],
      options,
      errors: [`could not read lockfile: ${error instanceof Error ? error.message : "unknown read error"}`]
    });
  }

  const observations = parseLockfile(text, createParseContext(basename(absoluteTarget), absoluteTarget));
  return preflightReport({
    target: displayTarget,
    inputKind: "lockfile",
    preflight: lockfileSummary(observations.length),
    observations,
    options
  });
}

export type LockfileParseResult = {
  packages: readonly VerifyPackageIdentity[];
  skipped: readonly LockfileSkippedPackage[];
  parseError: LockfileParseError | null;
};

export function parseLockfilePackages(targetPath: string): LockfileParseResult {
  const absoluteTarget = resolve(targetPath);
  const fileName = basename(absoluteTarget);
  let text: string;
  try {
    text = readLockfileText(absoluteTarget);
  } catch (error) {
    return {
      packages: [],
      skipped: [],
      parseError: {
        file: fileName,
        reason: error instanceof Error ? error.message : "could not read lockfile"
      }
    };
  }
  const context = createParseContext(fileName, absoluteTarget);
  const observations = parseLockfile(text, context);
  return {
    packages: observations
      .filter((observation) => observation.verdict !== "block" && observation.identity.sourceKind === "lockfile")
      .map((observation) => observation.identity),
    skipped: context.skipped,
    parseError: context.errors[0] ?? null
  };
}

type LockfileParseContext = {
  readonly fileName: string;
  readonly filePath: string | null;
  readonly registryHosts: ReadonlySet<string>;
  readonly skipped: LockfileSkippedPackage[];
  readonly errors: LockfileParseError[];
};

function createParseContext(fileName: string, filePath: string | null): LockfileParseContext {
  return {
    fileName,
    filePath,
    registryHosts: expectedRegistryHosts(fileName, filePath),
    skipped: [],
    errors: []
  };
}

function expectedRegistryHosts(fileName: string, filePath: string | null): ReadonlySet<string> {
  const hosts = new Set<string>();
  if (NPM_LOCKFILE_NAMES.has(fileName)) {
    for (const host of DEFAULT_NPM_REGISTRY_HOSTS) {
      hosts.add(host);
    }
    for (const host of npmrcRegistryHosts(filePath)) {
      hosts.add(host);
    }
  } else if (PYPI_LOCKFILE_NAMES.has(fileName)) {
    for (const host of DEFAULT_PYPI_REGISTRY_HOSTS) {
      hosts.add(host);
    }
  }
  return hosts;
}

function npmrcRegistryHosts(lockfilePath: string | null): string[] {
  if (!lockfilePath) {
    return [];
  }
  let text: string;
  try {
    text = readLockfileText(join(dirname(lockfilePath), ".npmrc"));
  } catch {
    return [];
  }
  const hosts: string[] = [];
  for (const line of text.split(/\r?\n/u)) {
    const value = /^\s*(?:@[^=\s:]+:)?registry\s*=\s*(\S+)/u.exec(line)?.[1];
    if (!value) {
      continue;
    }
    try {
      hosts.push(new URL(value).hostname.toLowerCase());
    } catch {
      continue;
    }
  }
  return hosts;
}

function untrustedResolvedHost(value: string, context: LockfileParseContext): string | null {
  if (context.registryHosts.size === 0 || !/^https?:\/\//iu.test(value)) {
    return null;
  }
  let host: string;
  try {
    host = new URL(value).hostname.toLowerCase();
  } catch {
    return value;
  }
  return context.registryHosts.has(host) ? null : host;
}

function recordSkip(context: LockfileParseContext, name: string, reason: LockfileSkipReason, location: string): void {
  context.skipped.push({ name, reason, location });
}

function recordParseError(context: LockfileParseContext, file: string, error: unknown): void {
  context.errors.push({
    file,
    reason: error instanceof Error ? error.message : String(error)
  });
}

function preflightReport(input: {
  target: string;
  inputKind: "package-spec" | "lockfile";
  preflight: VerifyPreflightSummary;
  observations: readonly PackageObservation[];
  options: VerifyPreflightOptions;
  errors?: readonly string[];
}): VerifyReport {
  const policy = resolveEffectivePolicy({
    userConfig: loadUserConfig()
  });
  const allowlists = (input.options.allowPackages ?? []).map((packageName): AllowlistEntry => ({
    packageName,
    reason: "dg verify command allowlist",
    trustedBy: "user"
  }));
  const deniedLicenses = new Set((input.options.denyLicenses ?? []).map(denyListLicenseKey));
  const findings: VerifyFinding[] = [];

  for (const observation of input.observations) {
    const packageName = packageDisplayName(observation.identity);
    const licenseFinding = deniedLicenseFinding(observation.identity, deniedLicenses);
    const packageVerdict = strongerVerdict(observation.verdict, licenseFinding ? "block" : "pass");
    const evaluation = evaluatePackagePolicy({
      verdict: packageVerdict,
      packageName,
      policy,
      allowlists
    });
    const baseFinding = licenseFinding ?? observation.finding;
    if (baseFinding && evaluation.action !== "pass") {
      findings.push({
        ...baseFinding,
        severity: evaluation.action === "block" ? "block" : "warn",
        message: `${baseFinding.message} (${evaluation.reason})`
      });
    }
  }

  const errors = [...(input.errors ?? [])];
  return {
    target: input.target,
    inputKind: input.inputKind,
    status: statusFor(policyActionFor(findings), errors),
    sha256: null,
    sizeBytes: null,
    archive: null,
    workspaceScan: null,
    preflight: input.preflight,
    packages: input.observations.map((observation) => observation.identity),
    findings,
    errors,
    summary: summarize(findings, errors)
  };
}

function parsePackageSpec(spec: string): PackageObservation | null {
  const trimmed = spec.trim();
  if (trimmed.length === 0 || /[\u0000-\u001f\u007f]/u.test(trimmed)) {
    return null;
  }
  if (!isRemotePackageSpec(trimmed)) {
    return null;
  }
  return packageObservation({
    ecosystem: "unknown",
    name: trimmed,
    version: null,
    requested: spec,
    sourceKind: "package-spec",
    resolvedUrl: trimmed,
    integrity: null,
    license: null
  }, "block", {
    id: "unverified-network-spec",
    title: "Unverified network package spec",
    message: "direct URL, git, and file package specs require artifact verification before install",
    location: spec
  });
}

function parseLockfile(text: string, context: LockfileParseContext): PackageObservation[] {
  const name = context.fileName;
  if (name === "package-lock.json" || name === "npm-shrinkwrap.json") {
    return parsePackageLock(text, context);
  }
  if (name === "yarn.lock") {
    return parseYarnLock(text, context);
  }
  if (name === "pnpm-lock.yaml") {
    return parsePnpmLock(text, context);
  }
  if (name === "requirements.txt") {
    return parseRequirements(text, context);
  }
  if (name === "Cargo.lock") {
    return parseCargoLock(text, context);
  }
  if (name === "poetry.lock") {
    return parsePoetryLock(text, context);
  }
  if (name === "uv.lock") {
    return parseUvLock(text, context);
  }
  if (name === "Pipfile.lock") {
    return parsePipfileLock(text, context);
  }
  return [];
}

function specSourceKind(spec: string): LockfileSkipReason | null {
  const lower = spec.trim().toLowerCase();
  if (lower.startsWith("workspace:")) {
    return "workspace";
  }
  if (lower.startsWith("portal:") || lower.startsWith("link:") || lower.startsWith("file:")) {
    return "local";
  }
  if (lower.startsWith("git+") || lower.startsWith("git://") || lower.startsWith("github:") || lower.startsWith("ssh://")) {
    return "git";
  }
  if (lower.startsWith("http://") || lower.startsWith("https://")) {
    return lower.includes(".git") ? "git" : "direct-url";
  }
  return null;
}

const NPM_LOCK_DEPENDENCY_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;

function npmLockSpecKinds(packages: Record<string, unknown>): Map<string, LockfileSkipReason> {
  const kinds = new Map<string, LockfileSkipReason>();
  for (const rawPackage of Object.values(packages)) {
    if (!isRecord(rawPackage)) {
      continue;
    }
    for (const section of NPM_LOCK_DEPENDENCY_SECTIONS) {
      const dependencies = isRecord(rawPackage[section]) ? rawPackage[section] : {};
      for (const [name, spec] of Object.entries(dependencies)) {
        if (typeof spec !== "string") {
          continue;
        }
        const kind = specSourceKind(spec);
        if (kind) {
          kinds.set(name, kind);
        }
      }
    }
  }
  return kinds;
}

function parsePackageLock(text: string, context: LockfileParseContext): PackageObservation[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    recordParseError(context, context.fileName, error);
    return [malformedLockfileObservation(context.fileName, error)];
  }
  if (!isRecord(parsed)) {
    const error = new Error("root must be an object");
    recordParseError(context, context.fileName, error);
    return [malformedLockfileObservation(context.fileName, error)];
  }
  const observations: PackageObservation[] = [];
  if (isRecord(parsed.packages)) {
    const packagesMap = parsed.packages;
    const specKinds = npmLockSpecKinds(packagesMap);
    for (const [path, rawPackage] of Object.entries(packagesMap)) {
      if (path.length === 0 || !isRecord(rawPackage)) {
        continue;
      }
      const declaredName = typeof rawPackage.name === "string" ? rawPackage.name : packageNameFromNodeModulesPath(path);
      const resolved = stringOrNull(rawPackage.resolved);
      if (rawPackage.link === true) {
        if (!(resolved && isRecord(packagesMap[resolved]))) {
          recordSkip(context, declaredName ?? packageNameFromWorkspacePath(path), "local", path);
        }
        continue;
      }
      if (!path.includes("node_modules")) {
        recordSkip(context, declaredName ?? packageNameFromWorkspacePath(path), "workspace", path);
        continue;
      }
      const alias = npmAliasVersion(stringOrNull(rawPackage.version));
      const name = alias?.name ?? declaredName;
      const version = alias?.version ?? (typeof rawPackage.version === "string" ? rawPackage.version : null);
      if (!name) {
        continue;
      }
      const resolvedIsGit = resolved !== null && isUnsafeResolvedUrl(resolved);
      const resolvedOffRegistry = resolved !== null && untrustedResolvedHost(resolved, context) !== null;
      // A registry `resolved` URL is how npm actually fetched this entry; it must
      // be scanned regardless of how a same-named sibling declares the dependency
      // (a `file:`/`git:` spec elsewhere must not suppress a registry install).
      // The name-keyed cross-package hint only applies when this entry has no
      // registry resolved of its own.
      const resolvedIsRegistry =
        !!resolved && !resolvedIsGit && !resolvedOffRegistry && !resolved.toLowerCase().startsWith("file:");
      const skipReason = resolvedIsGit
        ? "git"
        : resolved?.toLowerCase().startsWith("file:")
          ? "local"
          : resolvedOffRegistry
            ? "direct-url"
            : resolvedIsRegistry
              ? null
              : specKinds.get(name) ?? null;
      if (skipReason) {
        recordSkip(context, name, skipReason, path);
        if (!resolvedIsGit && !resolvedOffRegistry) {
          continue;
        }
      }
      observations.push(lockfileObservation({
        ecosystem: "npm",
        name,
        version,
        requested: path,
        sourceKind: "lockfile",
        resolvedUrl: resolved,
        integrity: stringOrNull(rawPackage.integrity),
        license: stringOrNull(rawPackage.license)
      }, context));
    }
    return observations;
  }
  if (isRecord(parsed.dependencies)) {
    walkLegacyDependencies(parsed.dependencies, observations, new Set(), context);
  }
  return observations;
}

const MAX_LEGACY_DEPENDENCY_DEPTH = 512;

function walkLegacyDependencies(
  dependencies: Record<string, unknown>,
  observations: PackageObservation[],
  seen: Set<string>,
  context: LockfileParseContext,
  depth = 0
): void {
  if (depth > MAX_LEGACY_DEPENDENCY_DEPTH) {
    return;
  }
  for (const [name, rawPackage] of Object.entries(dependencies)) {
    if (!isRecord(rawPackage) || rawPackage.bundled === true) {
      continue;
    }
    const rawVersion = stringOrNull(rawPackage.version);
    const resolved = stringOrNull(rawPackage.resolved);
    const resolvedIsGit = resolved !== null && isUnsafeResolvedUrl(resolved);
    const resolvedOffRegistry = resolved !== null && untrustedResolvedHost(resolved, context) !== null;
    const versionKind = rawVersion && !rawVersion.startsWith("npm:") ? specSourceKind(rawVersion) : null;
    // Prefer the registry `resolved` URL over the version field: an entry npm
    // fetched from the registry must be scanned even if its `version` reads
    // file:/git:/workspace: (a contradiction an attacker can craft to hide it).
    const resolvedIsRegistry =
      resolved !== null && !resolvedIsGit && !resolvedOffRegistry && !resolved.toLowerCase().startsWith("file:");
    const skipReason = resolvedIsGit ? "git" : resolvedOffRegistry ? "direct-url" : resolvedIsRegistry ? null : versionKind;
    const alias = npmAliasVersion(rawVersion);
    const resolvedName = alias?.name ?? name;
    const version = alias?.version ?? rawVersion;
    const key = `${resolvedName}@${version ?? ""}`;
    if (skipReason) {
      recordSkip(context, resolvedName, skipReason, name);
    }
    if (!seen.has(key) && (!skipReason || resolvedIsGit || resolvedOffRegistry)) {
      seen.add(key);
      observations.push(lockfileObservation({
        ecosystem: "npm",
        name: resolvedName,
        version,
        requested: name,
        sourceKind: "lockfile",
        resolvedUrl: resolved,
        integrity: stringOrNull(rawPackage.integrity),
        license: stringOrNull(rawPackage.license)
      }, context));
    }
    if (isRecord(rawPackage.dependencies)) {
      walkLegacyDependencies(rawPackage.dependencies, observations, seen, context, depth + 1);
    }
  }
}

function npmAliasVersion(version: string | null): { name: string; version: string | null } | null {
  if (!version || !version.startsWith("npm:")) {
    return null;
  }
  const spec = version.slice(4);
  const at = spec.startsWith("@") ? spec.indexOf("@", 1) : spec.indexOf("@");
  if (at <= 0) {
    return { name: spec, version: null };
  }
  return { name: spec.slice(0, at), version: spec.slice(at + 1) || null };
}

function parseYarnLock(text: string, context: LockfileParseContext): PackageObservation[] {
  const observations: PackageObservation[] = [];
  const blocks = text.split(/\n(?=(?:"?@?[^"\s].*"?):\n)/u);
  for (const block of blocks) {
    const lines = block.split(/\r?\n/u);
    const header = lines[0]?.trim().replace(/:$/u, "");
    if (!header) {
      continue;
    }
    if (header.startsWith("#") || header === "__metadata") {
      continue;
    }
    const requested = header.split(",")[0]?.trim().replace(/^"|"$/gu, "") ?? header;
    const name = packageNameFromYarnDescriptor(requested);
    const resolved = quotedValue(lines, "resolved");
    const resolution = quotedValue(lines, "resolution");
    const skipReason = specSourceKind(yarnDescriptorSpec(requested))
      ?? (resolution ? specSourceKind(yarnDescriptorSpec(resolution)) : null);
    const resolvedUnsafe = resolved !== null
      && (isUnsafeResolvedUrl(resolved) || untrustedResolvedHost(resolved, context) !== null);
    if (skipReason) {
      recordSkip(context, name ?? requested, skipReason, requested);
      if (!resolvedUnsafe) {
        continue;
      }
    }
    const version = quotedValue(lines, "version");
    if (!name || !version) {
      continue;
    }
    observations.push(lockfileObservation({
      ecosystem: "npm",
      name,
      version,
      requested,
      sourceKind: "lockfile",
      resolvedUrl: resolved,
      integrity: quotedValue(lines, "integrity") ?? quotedValue(lines, "checksum"),
      license: null
    }, context));
  }
  return observations;
}

function parsePnpmLock(text: string, context: LockfileParseContext): PackageObservation[] {
  const observations: PackageObservation[] = [];
  const lines = text.split(/\r?\n/u);
  let inPackages = false;
  let current: VerifyPackageIdentity | null = null;
  const flush = (): void => {
    if (current) {
      observations.push(lockfileObservation(current, context));
      current = null;
    }
  };
  for (const line of lines) {
    const sectionMatch = /^([A-Za-z][\w-]*):\s*$/u.exec(line);
    if (sectionMatch) {
      flush();
      // The `snapshots:` section keys the resolved peer graph, e.g.
      // `eslint-utils@4.9.1(eslint@9.39.4)` — the peer suffix is not a real
      // registry version, so scanning it yields a false "removed from
      // registry" verdict. `packages:` is the canonical inventory (carries
      // integrity); take identity only from there.
      inPackages = sectionMatch[1] === "packages";
      continue;
    }
    if (!inPackages) {
      continue;
    }
    const keyMatch = /^\s{2}(\S.*?):\s*$/u.exec(line);
    if (keyMatch?.[1]) {
      flush();
      const key = stripQuotes(keyMatch[1].trim());
      const skipReason = pnpmKeySkipReason(key);
      if (skipReason) {
        recordSkip(context, pnpmKeyName(key), skipReason, key);
        current = null;
      } else {
        current = parsePnpmPackageKey(key);
      }
      continue;
    }
    if (!current) {
      continue;
    }
    const integrityMatch = /integrity:\s*([^,}\s]+)/u.exec(line);
    const tarballMatch = /tarball:\s*([^,}\s]+)/u.exec(line);
    if (integrityMatch?.[1]) {
      current = {
        ...current,
        integrity: stripQuotes(integrityMatch[1])
      };
    }
    if (tarballMatch?.[1]) {
      current = {
        ...current,
        resolvedUrl: stripQuotes(tarballMatch[1])
      };
    }
  }
  flush();
  return observations;
}

const PNPM_NON_REGISTRY_MARKER = /(?:file|link|workspace|git\+|git:|ssh|https?):/u;

function pnpmKeySkipReason(key: string): LockfileSkipReason | null {
  if (!PNPM_NON_REGISTRY_MARKER.test(key)) {
    return null;
  }
  if (key.includes("workspace:")) {
    return "workspace";
  }
  if (/git\+|git:/u.test(key)) {
    return "git";
  }
  if (/file:|link:/u.test(key)) {
    return "local";
  }
  return "direct-url";
}

function pnpmKeyName(key: string): string {
  const named = /^\/?((?:@[^/\s]+\/)?[^@\s/]+)@/u.exec(key);
  return named?.[1] ?? key;
}

function parsePnpmPackageKey(key: string): VerifyPackageIdentity | null {
  const hadSlash = key.startsWith("/");
  const body = hadSlash ? key.slice(1) : key;
  const parenStart = body.indexOf("(");
  const core = parenStart === -1 ? body : body.slice(0, parenStart);
  let name: string | null = null;
  let version: string | null = null;
  // lockfileVersion 5.x keys are /<name>/<version>[_peer]; 6.0 keys are
  // /<name>@<version>[(peer)]; 9.0 keys drop the leading slash.
  const atForm = /^((?:@[^/\s]+\/)?[^/@\s]+)@([^/\s]+)$/u.exec(core);
  if (atForm?.[1] && atForm[2]) {
    name = atForm[1];
    version = stripPnpmPeerSuffix(atForm[2]);
  } else if (hadSlash) {
    const lastSlash = core.lastIndexOf("/");
    if (lastSlash > 0) {
      name = core.slice(0, lastSlash);
      version = stripPnpmPeerSuffix(core.slice(lastSlash + 1));
    }
  }
  if (!name || !version) {
    return null;
  }
  return {
    ecosystem: "npm",
    name,
    version,
    requested: `${name}@${version}`,
    sourceKind: "lockfile",
    resolvedUrl: null,
    integrity: null,
    license: null
  };
}

function stripPnpmPeerSuffix(version: string): string {
  const peerStart = version.search(/[(_]/u);
  return peerStart === -1 ? version : version.slice(0, peerStart);
}

function parseRequirements(text: string, context: LockfileParseContext): PackageObservation[] {
  const observations: PackageObservation[] = [];
  const baseDir = context.filePath ? dirname(context.filePath) : null;
  const state: RequirementsState = {
    rootDir: baseDir,
    visited: new Set(context.filePath ? [resolve(context.filePath)] : []),
    seen: new Set()
  };
  collectRequirements(text, baseDir, state, context, observations);
  return observations;
}

type RequirementsState = {
  readonly rootDir: string | null;
  readonly visited: Set<string>;
  readonly seen: Set<string>;
};

function collectRequirements(
  text: string,
  baseDir: string | null,
  state: RequirementsState,
  context: LockfileParseContext,
  observations: PackageObservation[]
): void {
  for (const logical of joinRequirementContinuations(text.split(/\r?\n/u))) {
    const line = logical.trim();
    if (line.length === 0 || line.startsWith("#")) {
      continue;
    }
    const include = /^(?:-r|--requirement|-c|--constraint)[=\s]+(\S+)/u.exec(line);
    if (include?.[1]) {
      followRequirementInclude(include[1], baseDir, state, context, observations);
      continue;
    }
    const editable = /^(?:-e|--editable)[=\s]+(.+)$/u.exec(line);
    const target = (editable?.[1] ?? line).trim();
    if (REMOTE_SPEC_PREFIXES.some((prefix) => target.toLowerCase().startsWith(prefix))) {
      recordSkip(context, target, specSourceKind(target) ?? "direct-url", line);
      observations.push(packageObservation({
        ecosystem: "pypi",
        name: target,
        version: null,
        requested: line,
        sourceKind: "lockfile-url-fallback",
        resolvedUrl: target,
        integrity: null,
        license: null
      }, "block", {
        id: "lockfile-url-fallback",
        title: "Lockfile URL fallback identity",
        message: "lockfile entry uses a URL without package identity or hash metadata",
        location: line
      }));
      continue;
    }
    if (editable !== null || /^\.{0,2}\//u.test(target)) {
      recordSkip(context, target, "local", line);
      continue;
    }
    if (line.startsWith("-")) {
      continue;
    }
    const hash = /--hash=([A-Za-z0-9:_-]+)/u.exec(line)?.[1] ?? null;
    const requirement = line.replace(/\s*--hash=[^\s]+/gu, "").trim();
    const directReference = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*@\s*([^;\s]+)/u.exec(requirement);
    if (directReference?.[1] && directReference[2]) {
      const referenceName = directReference[1];
      const referenceUrl = directReference[2];
      const referenceKind = specSourceKind(referenceUrl);
      if (referenceKind === "local" || /^\.{0,2}\//u.test(referenceUrl)) {
        recordSkip(context, referenceName, "local", line);
        continue;
      }
      recordSkip(context, referenceName, referenceKind ?? "direct-url", line);
      observations.push(packageObservation({
        ecosystem: "pypi",
        name: referenceName,
        version: null,
        requested: line,
        sourceKind: "lockfile-url-fallback",
        resolvedUrl: referenceUrl,
        integrity: hash,
        license: null
      }, "block", {
        id: "unverified-lockfile-url",
        title: "Unverified lockfile URL",
        message: "lockfile resolved artifact uses a direct URL or git source that requires proxy hash verification",
        location: line
      }));
      continue;
    }
    const match = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?(?:\s*={2,3}\s*([^;\s]+))?/u.exec(requirement);
    if (!match?.[1]) {
      observations.push(blockedUnknownSpec(line));
      continue;
    }
    const pinKey = `${match[1].toLowerCase()}@${match[2] ?? ""}`;
    if (state.seen.has(pinKey)) {
      continue;
    }
    state.seen.add(pinKey);
    observations.push(lockfileObservation({
      ecosystem: "pypi",
      name: match[1],
      version: match[2] ?? null,
      requested: line,
      sourceKind: "lockfile",
      resolvedUrl: null,
      integrity: hash,
      license: null
    }, context));
  }
}

function followRequirementInclude(
  target: string,
  baseDir: string | null,
  state: RequirementsState,
  context: LockfileParseContext,
  observations: PackageObservation[]
): void {
  if (!baseDir || !state.rootDir) {
    return;
  }
  const includePath = resolve(baseDir, target);
  const containment = relative(state.rootDir, includePath);
  if (containment.startsWith("..") || isAbsolute(containment)) {
    recordParseError(context, target, new Error("requirements include escapes the project directory"));
    return;
  }
  if (state.visited.has(includePath)) {
    return;
  }
  state.visited.add(includePath);
  let text: string;
  try {
    text = readLockfileText(includePath);
  } catch (error) {
    recordParseError(context, target, error);
    return;
  }
  collectRequirements(text, dirname(includePath), state, context, observations);
}

function joinRequirementContinuations(lines: readonly string[]): string[] {
  const joined: string[] = [];
  let buffer = "";
  for (const line of lines) {
    if (line.endsWith("\\")) {
      buffer += `${line.slice(0, -1)} `;
      continue;
    }
    joined.push(buffer + line);
    buffer = "";
  }
  if (buffer.length > 0) {
    joined.push(buffer);
  }
  return joined;
}

function parseCargoLock(text: string, context: LockfileParseContext): PackageObservation[] {
  const observations: PackageObservation[] = [];
  for (const block of lockBlocks(text, "[[package]]")) {
    const name = tomlString(block, "name");
    if (!name) {
      continue;
    }
    const version = tomlString(block, "version");
    const source = tomlString(block, "source");
    if (source === null) {
      recordSkip(context, name, "local", `${name}@${version ?? "unknown"}`);
      continue;
    }
    observations.push(lockfileObservation({
      ecosystem: "cargo",
      name,
      version,
      requested: `${name}@${version ?? "unknown"}`,
      sourceKind: "lockfile",
      resolvedUrl: source,
      integrity: tomlString(block, "checksum"),
      license: null
    }, context));
  }
  return observations;
}

function parsePoetryLock(text: string, context: LockfileParseContext): PackageObservation[] {
  const observations: PackageObservation[] = [];
  for (const block of lockBlocks(text, "[[package]]")) {
    const name = tomlString(block, "name");
    if (!name) {
      continue;
    }
    const version = tomlString(block, "version");
    const skipReason = poetrySourceSkipReason(block);
    if (skipReason) {
      recordSkip(context, name, skipReason, `${name}${version ? `==${version}` : ""}`);
      continue;
    }
    observations.push(lockfileObservation({
      ecosystem: "pypi",
      name,
      version,
      requested: `${name}==${version ?? "unknown"}`,
      sourceKind: "lockfile",
      resolvedUrl: null,
      integrity: /hash\s*=\s*"([^"]+)"/u.exec(block)?.[1] ?? null,
      license: tomlString(block, "license")
    }, context));
  }
  return observations;
}

function poetrySourceSkipReason(block: string): LockfileSkipReason | null {
  const sourceTable = /\[package\.source\]([\s\S]*?)(?=\n\[|$)/u.exec(block)?.[1];
  if (sourceTable === undefined) {
    return null;
  }
  const type = /\btype\s*=\s*"([^"]+)"/u.exec(sourceTable)?.[1];
  if (type === "git") {
    return "git";
  }
  if (type === "url") {
    return "direct-url";
  }
  if (type === "directory" || type === "file") {
    return "local";
  }
  return null;
}

function parseUvLock(text: string, context: LockfileParseContext): PackageObservation[] {
  const observations: PackageObservation[] = [];
  for (const block of lockBlocks(text, "[[package]]")) {
    const name = tomlString(block, "name");
    if (!name) {
      continue;
    }
    const version = tomlString(block, "version");
    const source = /^source\s*=\s*\{([^}]*)\}/mu.exec(block)?.[1] ?? "";
    const skipReason = uvSourceSkipReason(source);
    if (skipReason) {
      recordSkip(context, name, skipReason, `${name}${version ? `==${version}` : ""}`);
      continue;
    }
    observations.push(lockfileObservation({
      ecosystem: "pypi",
      name,
      version,
      requested: `${name}==${version ?? "unknown"}`,
      sourceKind: "lockfile",
      resolvedUrl: null,
      integrity: /hash\s*=\s*"([^"]+)"/u.exec(block)?.[1] ?? null,
      license: null
    }, context));
  }
  return observations;
}

function uvSourceSkipReason(source: string): LockfileSkipReason | null {
  if (source.length === 0 || /\bregistry\s*=/u.test(source)) {
    return null;
  }
  if (/\bgit\s*=/u.test(source)) {
    return "git";
  }
  if (/\burl\s*=/u.test(source)) {
    return "direct-url";
  }
  if (/\b(?:editable|virtual)\s*=/u.test(source)) {
    return "workspace";
  }
  if (/\b(?:path|directory)\s*=/u.test(source)) {
    return "local";
  }
  return null;
}

function parsePipfileLock(text: string, context: LockfileParseContext): PackageObservation[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    recordParseError(context, context.fileName, error);
    return [malformedLockfileObservation(context.fileName, error)];
  }
  if (!isRecord(parsed)) {
    recordParseError(context, context.fileName, new Error("root must be an object"));
    return [];
  }
  return ["default", "develop"].flatMap((section) => {
    const packages = isRecord(parsed[section]) ? parsed[section] : {};
    return Object.entries(packages).flatMap(([name, rawPackage]) => {
      const record = isRecord(rawPackage) ? rawPackage : {};
      const version = stringOrNull(record.version)?.replace(/^==/u, "") ?? null;
      const skipReason = pipfileSourceSkipReason(record);
      if (skipReason) {
        recordSkip(context, name, skipReason, `${name}${version ? `==${version}` : ""}`);
        return [];
      }
      const hashes = Array.isArray(record.hashes) ? record.hashes.filter((hash): hash is string => typeof hash === "string") : [];
      return [lockfileObservation({
        ecosystem: "pypi",
        name,
        version,
        requested: `${name}${version ? `==${version}` : ""}`,
        sourceKind: "lockfile",
        resolvedUrl: null,
        integrity: hashes[0] ?? null,
        license: null
      }, context)];
    });
  });
}

function pipfileSourceSkipReason(record: Record<string, unknown>): LockfileSkipReason | null {
  if (typeof record.git === "string") {
    return "git";
  }
  if (typeof record.file === "string") {
    return "direct-url";
  }
  if (record.editable === true || typeof record.path === "string") {
    return "local";
  }
  return null;
}

function lockfileObservation(identity: VerifyPackageIdentity, context: LockfileParseContext): PackageObservation {
  if (identity.resolvedUrl && isUnsafeResolvedUrl(identity.resolvedUrl)) {
    return packageObservation(identity, "block", {
      id: "unverified-lockfile-url",
      title: "Unverified lockfile URL",
      message: "lockfile resolved artifact uses a direct URL or git source that requires proxy hash verification",
      location: identity.requested
    });
  }
  const untrustedHost = identity.resolvedUrl ? untrustedResolvedHost(identity.resolvedUrl, context) : null;
  if (untrustedHost !== null) {
    return packageObservation(identity, "block", {
      id: "untrusted-registry-host",
      title: "Untrusted lockfile registry host",
      message: `${packageDisplayName(identity)} resolves from '${untrustedHost}', which is not an expected registry host for this lockfile`,
      location: identity.requested
    });
  }
  const integrityFinding = integrityPolicyFinding(identity);
  if (integrityFinding) {
    return packageObservation(identity, "warn", integrityFinding);
  }
  return packageObservation(identity, "pass", null);
}

function integrityPolicyFinding(identity: VerifyPackageIdentity): Omit<VerifyFinding, "severity"> | null {
  if (identity.integrity && isSupportedIntegrity(identity.integrity)) {
    return null;
  }
  return {
    id: "missing-artifact-integrity",
    title: "Missing artifact integrity",
    message: `${packageDisplayName(identity)} has no supported lockfile integrity or checksum metadata`,
    location: identity.requested
  };
}

function deniedLicenseFinding(
  identity: VerifyPackageIdentity,
  deniedLicenses: ReadonlySet<string>
): Omit<VerifyFinding, "severity"> | null {
  if (!identity.license || !deniedLicenses.has(denyListLicenseKey(identity.license))) {
    return null;
  }
  return {
    id: "license-policy-denied",
    title: "Denied package license",
    message: `${packageDisplayName(identity)} declares denied license '${identity.license}'`,
    location: identity.requested
  };
}

function malformedLockfileObservation(lockfile: string, error: unknown): PackageObservation {
  return packageObservation({
    ecosystem: "unknown",
    name: lockfile,
    version: null,
    requested: lockfile,
    sourceKind: "lockfile",
    resolvedUrl: null,
    integrity: null,
    license: null
  }, "block", {
    id: "malformed-lockfile",
    title: "Malformed lockfile",
    message: error instanceof Error ? error.message : "lockfile could not be parsed",
    location: lockfile
  });
}

function blockedUnknownSpec(spec: string): PackageObservation {
  return packageObservation({
    ecosystem: "unknown",
    name: spec,
    version: null,
    requested: spec,
    sourceKind: "package-spec",
    resolvedUrl: null,
    integrity: null,
    license: null
  }, "block", {
    id: "unsupported-package-spec",
    title: "Unsupported package spec",
    message: "package spec could not be parsed without guessing identity",
    location: spec
  });
}

function packageObservation(
  identity: VerifyPackageIdentity,
  verdict: Verdict,
  finding: Omit<VerifyFinding, "severity"> | null
): PackageObservation {
  return {
    identity,
    verdict,
    finding
  };
}

function isSupportedIntegrity(value: string): boolean {
  return /^(?:sha1|sha256|sha384|sha512)-[A-Za-z0-9+/=]+$/u.test(value)
    || /^(?:sha256:)?[a-f0-9]{64}$/iu.test(value)
    || /^[0-9a-f]+\/[0-9a-f]{64,}$/iu.test(value);
}

function isUnsafeResolvedUrl(value: string): boolean {
  const lower = value.toLowerCase();
  return lower.startsWith("git+")
    || lower.startsWith("git://")
    || lower.startsWith("ssh://")
    || lower.startsWith("github:");
}

function strongerVerdict(left: Verdict, right: Verdict): Verdict {
  if (left === "block" || right === "block") {
    return "block";
  }
  if (left === "warn" || right === "warn") {
    return "warn";
  }
  return "pass";
}

function policyActionFor(findings: readonly VerifyFinding[]): PolicyAction {
  if (findings.some((finding) => finding.severity === "block")) {
    return "block";
  }
  if (findings.some((finding) => finding.severity === "warn")) {
    return "warn";
  }
  return "pass";
}

function statusFor(action: PolicyAction, errors: readonly string[]): VerifyStatus {
  if (errors.length > 0) {
    return "error";
  }
  return action;
}

function summarize(findings: readonly VerifyFinding[], errors: readonly string[]) {
  return {
    findingCount: findings.length,
    warnCount: findings.filter((finding) => finding.severity === "warn").length,
    blockCount: findings.filter((finding) => finding.severity === "block").length,
    errorCount: errors.length
  };
}

function lockfileSummary(packageCount: number): VerifyPreflightSummary {
  return {
    advisory: true,
    packageCount,
    identitySource: "lockfile",
    message: "Lockfile verification maps package identity and integrity for preflight only; proxy enforcement remains authoritative for network fetches."
  };
}

function packageDisplayName(identity: VerifyPackageIdentity): string {
  const version = identity.version ? `@${identity.version}` : "";
  return `${identity.ecosystem}:${identity.name}${version}`;
}

function packageNameFromWorkspacePath(path: string): string {
  const parts = path.split("/").filter((part) => part.length > 0);
  const last = parts[parts.length - 1] ?? path;
  const prior = parts[parts.length - 2];
  return prior?.startsWith("@") ? `${prior}/${last}` : last;
}

function packageNameFromNodeModulesPath(path: string): string | null {
  const parts = path.split("/");
  const nodeModulesIndex = parts.lastIndexOf("node_modules");
  if (nodeModulesIndex === -1) {
    return null;
  }
  const first = parts[nodeModulesIndex + 1];
  if (!first) {
    return null;
  }
  if (first.startsWith("@") && parts[nodeModulesIndex + 2]) {
    return `${first}/${parts[nodeModulesIndex + 2]}`;
  }
  return first;
}

function yarnDescriptorSpec(descriptor: string): string {
  const scoped = descriptor.startsWith("@");
  const body = scoped ? descriptor.slice(1) : descriptor;
  const at = body.indexOf("@");
  return at === -1 ? "" : body.slice(at + 1);
}

function packageNameFromYarnDescriptor(descriptor: string): string | null {
  const scoped = descriptor.startsWith("@");
  const body = scoped ? descriptor.slice(1) : descriptor;
  const at = body.indexOf("@");
  const name = at === -1 ? descriptor : scoped ? `@${body.slice(0, at)}` : body.slice(0, at);
  const spec = at === -1 ? "" : body.slice(at + 1);
  // npm: alias descriptors (`alias@npm:real-pkg@range`) resolve to the alias
  // target — that is the registry artifact actually fetched and scanned.
  const alias = /^npm:((?:@[^/\s]+\/)?[^@\s]+)@/u.exec(spec);
  return alias?.[1] ?? (name || null);
}

function quotedValue(lines: readonly string[], key: string): string | null {
  const pattern = new RegExp(`^\\s*${key}:?\\s+"?([^"\\n]+?)"?\\s*$`, "u");
  for (const line of lines) {
    const match = pattern.exec(line);
    if (match?.[1]) {
      return match[1];
    }
  }
  return null;
}

function lockBlocks(text: string, marker: string): string[] {
  return text.split(marker).slice(1).map((block) => `${marker}${block}`);
}

function tomlString(block: string, key: string): string | null {
  const match = new RegExp(`^${key}\\s*=\\s*\"([^\"]*)\"`, "mu").exec(block);
  return match?.[1] ?? null;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function stripQuotes(value: string): string {
  return value.replace(/^["']|["']$/gu, "");
}

function denyListLicenseKey(value: string): string {
  return value.trim().toLowerCase();
}

function displayPath(root: string, path: string): string {
  const relativePath = relative(resolve(root), resolve(path));
  const display = relativePath.length === 0 ? "." : relativePath;
  return display.split(sep).join("/");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
