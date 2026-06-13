import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { resolveToolPath } from "../util/external-tool.js";
import type { ScanError, ScanFinding, ScanProject, ScanReport, ScanStatus } from "./types.js";

const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  "coverage",
  "dist",
  "node_modules",
  "vendor"
]);

const DEPENDENCY_SECTIONS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies"
] as const;

const RISKY_SCRIPT_NAMES = new Set(["preinstall", "install", "postinstall", "prepare"]);

const MAX_DISCOVERY_DEPTH = 8;

type JsonRecord = Record<string, unknown>;

export type ScanOptions = {
  cwd?: string;
  targetPath?: string;
};

export function scanProject(options: ScanOptions = {}): ScanReport {
  const cwd = resolve(options.cwd ?? process.cwd());
  const requestedTarget = options.targetPath ?? ".";
  const absoluteTarget = resolve(cwd, requestedTarget);
  const targetInfo = statSync(absoluteTarget);
  const root = targetInfo.isFile() ? dirname(absoluteTarget) : absoluteTarget;
  const manifestPaths = targetInfo.isFile() && basename(absoluteTarget) === "package.json"
    ? [absoluteTarget]
    : discoverPackageManifests(root);
  const projects: ScanProject[] = [];
  const errors: ScanError[] = [];

  for (const manifestPath of manifestPaths) {
    const result = readPackageProject(root, manifestPath);
    if ("error" in result) {
      errors.push(result.error);
    } else {
      projects.push(result.project);
    }
  }

  const findings = projects.flatMap((project) => [...project.findings]);
  const warnCount = findings.filter((finding) => finding.severity === "warn").length;
  const blockCount = findings.filter((finding) => finding.severity === "block").length;
  const status = resolveStatus({
    blockCount,
    errorCount: errors.length,
    warnCount
  });

  return {
    target: displayPath(cwd, absoluteTarget),
    status,
    projects,
    findings,
    errors,
    summary: {
      projectCount: projects.length,
      dependencyCount: projects.reduce((total, project) => total + project.dependencyCount, 0),
      findingCount: findings.length,
      warnCount,
      blockCount,
      errorCount: errors.length
    }
  };
}

function resolveStatus(counts: { blockCount: number; errorCount: number; warnCount: number }): ScanStatus {
  if (counts.errorCount > 0) {
    return "error";
  }
  if (counts.blockCount > 0) {
    return "block";
  }
  if (counts.warnCount > 0) {
    return "warn";
  }
  return "pass";
}

function discoverPackageManifests(root: string): string[] {
  const manifests: string[] = [];
  walk(root, 0, manifests, gitIgnoredDirectories(root));
  return manifests.sort((left, right) => displayPath(root, left).localeCompare(displayPath(root, right)));
}

export function gitIgnoredDirectories(root: string): ReadonlySet<string> {
  const ignored = new Set<string>();
  if (!insideGitWorkTree(root)) {
    return ignored;
  }
  let level: string[] = [root];
  for (let depth = 0; depth <= MAX_DISCOVERY_DEPTH && level.length > 0; depth++) {
    const candidates: string[] = [];
    for (const directory of level) {
      let entries;
      try {
        entries = readdirSync(directory, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const entry of entries) {
        if (entry.isDirectory() && !IGNORED_DIRECTORIES.has(entry.name)) {
          candidates.push(resolve(directory, entry.name));
        }
      }
    }
    if (candidates.length === 0) {
      break;
    }
    const flagged = checkIgnoreBatch(root, candidates);
    for (const directory of flagged) {
      ignored.add(directory);
    }
    level = candidates.filter((directory) => !flagged.has(directory));
  }
  return ignored;
}

function insideGitWorkTree(root: string): boolean {
  const git = resolveToolPath("git");
  if (!git) {
    return false;
  }
  try {
    const out = execFileSync(git, ["-C", root, "rev-parse", "--is-inside-work-tree"], {
      encoding: "utf8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"]
    });
    return out.trim() === "true";
  } catch {
    return false;
  }
}

function checkIgnoreBatch(root: string, directories: readonly string[]): Set<string> {
  const git = resolveToolPath("git");
  if (!git) {
    return new Set();
  }
  try {
    const out = execFileSync(git, ["-C", root, "check-ignore", "--stdin", "-z"], {
      input: directories.join("\0"),
      encoding: "utf8",
      timeout: 5000,
      maxBuffer: 16 * 1024 * 1024,
      stdio: ["pipe", "pipe", "ignore"]
    });
    return new Set(out.split("\0").filter(Boolean));
  } catch {
    return new Set();
  }
}

function walk(directory: string, depth: number, manifests: string[], gitIgnored: ReadonlySet<string>): void {
  if (depth > MAX_DISCOVERY_DEPTH) {
    return;
  }

  let entries;
  try {
    entries = readdirSync(directory, {
      withFileTypes: true
    }).sort((left, right) => left.name.localeCompare(right.name));
  } catch {
    return;
  }

  for (const entry of entries) {
    const absolutePath = resolve(directory, entry.name);
    if (entry.isDirectory()) {
      if (!IGNORED_DIRECTORIES.has(entry.name) && !gitIgnored.has(absolutePath)) {
        walk(absolutePath, depth + 1, manifests, gitIgnored);
      }
      continue;
    }
    if (entry.isFile() && entry.name === "package.json") {
      manifests.push(absolutePath);
    }
  }
}

function readPackageProject(root: string, manifestPath: string): { project: ScanProject } | { error: ScanError } {
  const manifestDisplayPath = displayPath(root, manifestPath);
  let manifest: unknown;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    return {
      error: {
        location: manifestDisplayPath,
        message: error instanceof Error ? error.message : "package.json could not be parsed"
      }
    };
  }

  if (!isRecord(manifest)) {
    return {
      error: {
        location: manifestDisplayPath,
        message: "package.json must contain an object"
      }
    };
  }

  const name = typeof manifest.name === "string" && manifest.name.length > 0
    ? manifest.name
    : basename(dirname(manifestPath));
  const version = typeof manifest.version === "string" ? manifest.version : null;
  const license = typeof manifest.license === "string" ? manifest.license : null;
  const findings = [
    ...scriptFindings(manifest, manifestDisplayPath, name),
    ...dependencyFindings(manifest, manifestDisplayPath, name)
  ];

  return {
    project: {
      name,
      version,
      license,
      manifestPath: manifestDisplayPath,
      dependencyCount: dependencyCount(manifest),
      findings
    }
  };
}

function scriptFindings(manifest: JsonRecord, manifestPath: string, project: string): ScanFinding[] {
  const scripts = isRecord(manifest.scripts) ? manifest.scripts : {};
  return Object.keys(scripts)
    .filter((scriptName) => RISKY_SCRIPT_NAMES.has(scriptName))
    .sort()
    .map((scriptName) => ({
      id: "npm-lifecycle-script",
      severity: "warn",
      title: "Install lifecycle script present",
      message: `script '${scriptName}' can execute during package manager installs`,
      project,
      location: `${manifestPath}:scripts.${scriptName}`
    }));
}

function dependencyFindings(manifest: JsonRecord, manifestPath: string, project: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  for (const section of DEPENDENCY_SECTIONS) {
    const dependencies = isRecord(manifest[section]) ? manifest[section] : {};
    for (const [dependencyName, specifier] of Object.entries(dependencies).sort(([left], [right]) => left.localeCompare(right))) {
      if (typeof specifier !== "string") {
        continue;
      }
      const severity = dependencySpecifierSeverity(specifier);
      if (!severity) {
        continue;
      }
      findings.push({
        id: severity === "block" ? "unverified-network-dependency" : "local-artifact-dependency",
        severity,
        title: severity === "block" ? "Unverified network dependency" : "Local artifact dependency",
        message: `${dependencyName} uses '${specifier}', which should be verified before install`,
        project,
        location: `${manifestPath}:${section}.${dependencyName}`
      });
    }
  }
  return findings;
}

function dependencySpecifierSeverity(specifier: string): "warn" | "block" | null {
  const normalized = specifier.trim().toLowerCase();
  if (
    normalized.startsWith("http://")
    || normalized.startsWith("https://")
    || normalized.startsWith("git+")
    || normalized.startsWith("git://")
    || normalized.startsWith("ssh://")
    || normalized.startsWith("github:")
  ) {
    return "block";
  }
  if (normalized.startsWith("file:")) {
    return "warn";
  }
  return null;
}

function dependencyCount(manifest: JsonRecord): number {
  return DEPENDENCY_SECTIONS.reduce((total, section) => {
    const dependencies = isRecord(manifest[section]) ? manifest[section] : {};
    return total + Object.keys(dependencies).length;
  }, 0);
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function displayPath(root: string, path: string): string {
  const relativePath = relative(root, path);
  const display = relativePath.length === 0 ? "." : relativePath;
  return display.split(sep).join("/");
}
