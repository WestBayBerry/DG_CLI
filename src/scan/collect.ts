import { readdirSync } from "node:fs";
import type { Dirent } from "node:fs";
import { join, relative } from "node:path";
import type { AnalyzeEcosystem, AnalyzePackageInput } from "../api/analyze.js";
import { gitIgnoredDirectories } from "./discovery.js";
import { parseLockfilePackages } from "../verify/preflight.js";
import type { LockfileParseError, LockfileSkippedPackage } from "./types.js";

export type LockfileEcosystem = "npm" | "pypi" | "cargo";

export interface LockfileProject {
  path: string;
  relativePath: string;
  ecosystem: LockfileEcosystem;
  depFile: string;
  packageCount: number;
}

export const LOCKFILE_ECOSYSTEMS: Record<string, LockfileEcosystem> = {
  "package-lock.json": "npm",
  "npm-shrinkwrap.json": "npm",
  "yarn.lock": "npm",
  "pnpm-lock.yaml": "npm",
  "Pipfile.lock": "pypi",
  "poetry.lock": "pypi",
  "uv.lock": "pypi",
  "requirements.txt": "pypi"
};

export const SBOM_LOCKFILE_ECOSYSTEMS: Record<string, LockfileEcosystem> = {
  ...LOCKFILE_ECOSYSTEMS,
  "Cargo.lock": "cargo"
};

export function isLockfileName(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(LOCKFILE_ECOSYSTEMS, name);
}

const IGNORED_DIRECTORIES = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "vendor",
  "__pycache__",
  ".venv",
  "venv",
  "target",
  "coverage"
]);
const MAX_DISCOVERY_DEPTH = 8;

function readDirents(directory: string): Dirent[] {
  try {
    return readdirSync(directory, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  } catch {
    return [];
  }
}

function lockfilesPerEcosystem(
  entries: readonly Dirent[],
  ecosystems: Record<string, LockfileEcosystem>
): ReadonlyArray<readonly [string, LockfileEcosystem]> {
  const matches: Array<readonly [string, LockfileEcosystem]> = [];
  const claimed = new Set<LockfileEcosystem>();
  for (const [lockfile, ecosystem] of Object.entries(ecosystems)) {
    if (claimed.has(ecosystem)) {
      continue;
    }
    if (entries.some((entry) => entry.name === lockfile && entry.isFile())) {
      matches.push([lockfile, ecosystem]);
      claimed.add(ecosystem);
    }
  }
  return matches;
}

function shouldDescend(entry: Dirent, directory: string, gitIgnored: ReadonlySet<string>): boolean {
  return (
    entry.isDirectory() &&
    !IGNORED_DIRECTORIES.has(entry.name) &&
    !entry.name.startsWith(".") &&
    !gitIgnored.has(join(directory, entry.name))
  );
}

export function discoverScanProjects(
  root: string,
  ecosystems: Record<string, LockfileEcosystem> = LOCKFILE_ECOSYSTEMS
): LockfileProject[] {
  const projects: LockfileProject[] = [];
  const gitIgnored = gitIgnoredDirectories(root);
  walk(root, 0);
  return projects;

  function walk(directory: string, depth: number): void {
    if (depth > MAX_DISCOVERY_DEPTH) {
      return;
    }
    const entries = readDirents(directory);
    for (const [depFile, ecosystem] of lockfilesPerEcosystem(entries, ecosystems)) {
      projects.push({
        path: directory,
        relativePath: relative(root, directory) || ".",
        ecosystem,
        depFile,
        packageCount: countLockfilePackages(join(directory, depFile))
      });
    }
    for (const entry of entries) {
      if (shouldDescend(entry, directory, gitIgnored)) {
        walk(join(directory, entry.name), depth + 1);
      }
    }
  }
}

export type DiscoveryProgress = {
  readonly path: string;
  readonly found: number;
};

export async function discoverScanProjectsAsync(
  root: string,
  onProgress?: (progress: DiscoveryProgress) => void
): Promise<LockfileProject[]> {
  const projects: LockfileProject[] = [];
  const gitIgnored = gitIgnoredDirectories(root);
  let lastYield = Date.now();
  await walk(root, 0);
  return projects;

  async function walk(directory: string, depth: number): Promise<void> {
    if (depth > MAX_DISCOVERY_DEPTH) {
      return;
    }
    if (Date.now() - lastYield > 8) {
      await yieldToEventLoop();
      lastYield = Date.now();
    }
    const entries = readDirents(directory);
    for (const [depFile, ecosystem] of lockfilesPerEcosystem(entries, LOCKFILE_ECOSYSTEMS)) {
      const relativePath = relative(root, directory) || ".";
      projects.push({
        path: directory,
        relativePath,
        ecosystem,
        depFile,
        packageCount: countLockfilePackages(join(directory, depFile))
      });
      onProgress?.({ path: relativePath === "." ? depFile : `${relativePath}/${depFile}`, found: projects.length });
    }
    for (const entry of entries) {
      if (shouldDescend(entry, directory, gitIgnored)) {
        await walk(join(directory, entry.name), depth + 1);
      }
    }
  }
}

function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

function countLockfilePackages(lockfilePath: string): number {
  return parseLockfilePackages(lockfilePath).packages.length;
}

export type CollectedScanPackages = {
  byEcosystem: Map<AnalyzeEcosystem, AnalyzePackageInput[]>;
  skipped: number;
  skippedPackages: readonly LockfileSkippedPackage[];
  parseErrors: readonly LockfileParseError[];
};

export function collectScanPackages(projects: readonly LockfileProject[]): CollectedScanPackages {
  const byEcosystem = new Map<AnalyzeEcosystem, AnalyzePackageInput[]>();
  const seen = new Set<string>();
  const skippedPackages: LockfileSkippedPackage[] = [];
  const parseErrors: LockfileParseError[] = [];
  let skipped = 0;
  for (const project of projects) {
    const depFilePath = project.relativePath === "." ? project.depFile : `${project.relativePath}/${project.depFile}`;
    const parsed = parseLockfilePackages(join(project.path, project.depFile));
    for (const skippedPackage of parsed.skipped) {
      skippedPackages.push({ ...skippedPackage, location: `${depFilePath}: ${skippedPackage.location}` });
      skipped += 1;
    }
    if (parsed.parseError) {
      parseErrors.push({
        file: parsed.parseError.file === project.depFile ? depFilePath : parsed.parseError.file,
        reason: parsed.parseError.reason
      });
      skipped += 1;
    }
    for (const identity of parsed.packages) {
      if (identity.ecosystem !== "npm" && identity.ecosystem !== "pypi") {
        skipped += 1;
        continue;
      }
      if (!identity.version) {
        skipped += 1;
        continue;
      }
      const key = `${identity.ecosystem}:${identity.name}@${identity.version}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      const list = byEcosystem.get(identity.ecosystem) ?? [];
      list.push({ name: identity.name, version: identity.version });
      byEcosystem.set(identity.ecosystem, list);
    }
  }
  return { byEcosystem, skipped, skippedPackages, parseErrors };
}
