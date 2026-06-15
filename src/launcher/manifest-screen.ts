import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";

export interface ManifestSpec {
  readonly name: string;
  readonly version: string | null;
}

export interface ManifestResult {
  readonly specs: ManifestSpec[];
  // The manifest held more direct dependencies than the hook will screen in its
  // time budget. The caller must not claim a clean pass on a partial screen.
  readonly truncated: boolean;
}

// A bare `npm install` resolves the whole dependency tree, but enumerating every
// transitive package in the hook would blow its time budget — that breadth is
// the runtime network gate's job. The static hook screens the DIRECT
// dependencies declared in the manifest, which is where a cloned hostile repo
// plants a malicious package, and caps the count so a giant manifest defers
// instead of silently passing.
const MAX_MANIFEST_SPECS = 100;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;

function readBoundedFile(path: string): string | null {
  try {
    if (statSync(path).size > MAX_MANIFEST_BYTES) {
      return null;
    }
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

// package-lock v2/v3 keys direct deps as "node_modules/<name>"; v1 nests them
// under `dependencies`. Either way, pinning to the lock means the version we
// screen is the version that installs.
function lockfileVersions(cwd: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const file of ["package-lock.json", "npm-shrinkwrap.json"]) {
    const raw = readBoundedFile(join(cwd, file));
    if (!raw) {
      continue;
    }
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      const packages = asRecord(parsed.packages);
      for (const [key, meta] of Object.entries(packages)) {
        if (key.startsWith("node_modules/")) {
          const version = asRecord(meta).version;
          if (typeof version === "string") {
            out.set(key.slice("node_modules/".length), version);
          }
        }
      }
      const deps = asRecord(parsed.dependencies);
      for (const [name, meta] of Object.entries(deps)) {
        const version = asRecord(meta).version;
        if (typeof version === "string" && !out.has(name)) {
          out.set(name, version);
        }
      }
    } catch {
      // Unparsable lockfile: fall back to range resolution, don't crash.
    }
    if (out.size > 0) {
      break;
    }
  }
  return out;
}

export function readNpmManifestSpecs(cwd: string): ManifestResult | null {
  const raw = readBoundedFile(join(cwd, "package.json"));
  if (!raw) {
    return null;
  }
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return null;
  }
  const names: string[] = [];
  const seen = new Set<string>();
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    for (const name of Object.keys(asRecord(parsed[field]))) {
      if (!seen.has(name)) {
        seen.add(name);
        names.push(name);
      }
    }
  }
  if (names.length === 0) {
    return null;
  }
  const truncated = names.length > MAX_MANIFEST_SPECS;
  const locks = lockfileVersions(cwd);
  const specs = names.slice(0, MAX_MANIFEST_SPECS).map((name) => ({ name, version: locks.get(name) ?? null }));
  return { specs, truncated };
}

function parseRequirementLine(line: string): ManifestSpec | null {
  const stripped = line.split(/(?<!\\)#/)[0]?.trim() ?? "";
  if (stripped.length === 0 || stripped.startsWith("-")) {
    return null;
  }
  // Drop environment markers (`; python_version < "3.9"`) and inline options.
  const core = (stripped.split(";")[0] ?? "").trim();
  if (core.length === 0 || core.includes("://") || core.startsWith("git+")) {
    return null;
  }
  const exact = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?==([^,;\s]+)$/.exec(core);
  if (exact && exact[1] && exact[2]) {
    return { name: exact[1], version: exact[2] };
  }
  const ranged = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(?:===|>=|<=|~=|!=|<|>|$)/.exec(core);
  if (ranged && ranged[1]) {
    return { name: ranged[1], version: null };
  }
  return null;
}

export function readPipRequirementSpecs(args: readonly string[], cwd: string): ManifestResult | null {
  const files: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === undefined) {
      continue;
    }
    if (a === "-r" || a === "--requirement") {
      const v = args[i + 1];
      i += 1;
      if (v !== undefined) {
        files.push(v);
      }
    } else if (a.startsWith("--requirement=")) {
      files.push(a.slice("--requirement=".length));
    } else if (a.startsWith("-r=")) {
      files.push(a.slice("-r=".length));
    }
  }
  if (files.length === 0) {
    return null;
  }
  const specs: ManifestSpec[] = [];
  const seen = new Set<string>();
  let truncated = false;
  for (const file of files) {
    const path = isAbsolute(file) ? file : join(cwd, file);
    if (!existsSync(path)) {
      // A missing requirements file means the install will fail anyway — nothing
      // to screen, and no reason to nag the user. Leave it alone.
      continue;
    }
    const raw = readBoundedFile(path);
    if (!raw) {
      // The file exists but we could not read it (oversized / permissions) — that
      // is a real unscreened install, so defer rather than pass it clean.
      truncated = true;
      continue;
    }
    for (const line of raw.split(/\r?\n/)) {
      const spec = parseRequirementLine(line);
      if (!spec || seen.has(spec.name)) {
        continue;
      }
      if (specs.length >= MAX_MANIFEST_SPECS) {
        truncated = true;
        break;
      }
      seen.add(spec.name);
      specs.push(spec);
    }
  }
  if (specs.length === 0) {
    return truncated ? { specs, truncated } : null;
  }
  return { specs, truncated };
}
