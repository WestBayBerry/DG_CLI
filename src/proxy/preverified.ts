import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface PreverifiedEntry {
  readonly ecosystem: "npm" | "pypi";
  readonly name: string;
  readonly version: string;
  readonly action: "pass" | "warn";
  readonly reason?: string;
  readonly scannedSha256?: string;
  readonly cooldownEvaluated: boolean;
}

const PREVERIFIED_FILE = "preverified.json";

export function preverifiedKey(ecosystem: string, name: string, version: string): string {
  const canonicalName = ecosystem === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name;
  return `${ecosystem}:${canonicalName}@${version}`;
}

export function writePreverifiedFile(sessionDir: string, entries: readonly PreverifiedEntry[]): void {
  writeFileSync(join(sessionDir, PREVERIFIED_FILE), `${JSON.stringify(entries)}\n`, {
    encoding: "utf8",
    mode: 0o600
  });
}

let loaded: { readonly dir: string; readonly map: ReadonlyMap<string, PreverifiedEntry> } | null = null;

export function loadPreverifiedMap(sessionDir: string): ReadonlyMap<string, PreverifiedEntry> {
  if (loaded?.dir === sessionDir) {
    return loaded.map;
  }
  const path = join(sessionDir, PREVERIFIED_FILE);
  if (!existsSync(path)) {
    return new Map();
  }
  const map = new Map<string, PreverifiedEntry>();
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (Array.isArray(parsed)) {
      for (const entry of parsed) {
        if (isPreverifiedEntry(entry)) {
          map.set(preverifiedKey(entry.ecosystem, entry.name, entry.version), entry);
        }
      }
    }
  } catch {
    return new Map();
  }
  loaded = { dir: sessionDir, map };
  return map;
}

export function resetPreverifiedCache(): void {
  loaded = null;
}

function isPreverifiedEntry(value: unknown): value is PreverifiedEntry {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const entry = value as Record<string, unknown>;
  return (
    (entry.ecosystem === "npm" || entry.ecosystem === "pypi") &&
    typeof entry.name === "string" && entry.name.length > 0 &&
    typeof entry.version === "string" && entry.version.length > 0 &&
    (entry.action === "pass" || entry.action === "warn") &&
    (entry.reason === undefined || typeof entry.reason === "string") &&
    (entry.scannedSha256 === undefined || typeof entry.scannedSha256 === "string") &&
    typeof entry.cooldownEvaluated === "boolean"
  );
}
