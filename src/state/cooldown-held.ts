import { readFileSync } from "node:fs";
import { join } from "node:path";
import { writeJsonAtomic } from "../util/json-file.js";
import { resolveDgPaths, type DgPathEnvironment } from "./paths.js";

export interface HeldPackageEntry {
  readonly ecosystem: string;
  readonly name: string;
  readonly version: string;
  readonly requiredDays: number;
  readonly ageDays?: number;
  readonly publishedAt?: string;
  readonly eligibleAt?: string;
  readonly manager?: string;
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
}

export type NewHeldPackage = Omit<HeldPackageEntry, "firstSeenAt" | "lastSeenAt">;

export const HELD_PACKAGES_CAP = 500;
export const UNKNOWN_ELIGIBILITY_TTL_MS = 30 * 24 * 60 * 60 * 1000;

interface HeldPackagesDocument {
  readonly schemaVersion: 1;
  readonly entries: readonly HeldPackageEntry[];
}

export function heldPackagesPath(env: DgPathEnvironment = process.env): string {
  return join(resolveDgPaths(env).stateDir, "cooldown-held.json");
}

function heldKey(entry: Pick<HeldPackageEntry, "ecosystem" | "name" | "version">): string {
  return `${entry.ecosystem}:${entry.name}@${entry.version}`;
}

function readDocument(path: string): readonly HeldPackageEntry[] {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  try {
    const parsed = JSON.parse(raw) as Partial<HeldPackagesDocument>;
    if (!parsed || parsed.schemaVersion !== 1 || !Array.isArray(parsed.entries)) {
      return [];
    }
    return parsed.entries.filter(
      (entry): entry is HeldPackageEntry =>
        !!entry
        && typeof entry.ecosystem === "string"
        && typeof entry.name === "string"
        && typeof entry.version === "string"
        && typeof entry.requiredDays === "number"
        && typeof entry.firstSeenAt === "string"
        && typeof entry.lastSeenAt === "string"
    );
  } catch {
    return [];
  }
}

function prune(entries: readonly HeldPackageEntry[], now: Date): HeldPackageEntry[] {
  return entries.filter((entry) => {
    const eligible = entry.eligibleAt ? Date.parse(entry.eligibleAt) : Number.NaN;
    if (Number.isFinite(eligible)) {
      return eligible > now.getTime();
    }
    const lastSeen = Date.parse(entry.lastSeenAt);
    return Number.isFinite(lastSeen) && now.getTime() - lastSeen <= UNKNOWN_ELIGIBILITY_TTL_MS;
  });
}

export function readHeldPackages(env: DgPathEnvironment = process.env, now: Date = new Date()): HeldPackageEntry[] {
  return prune(readDocument(heldPackagesPath(env)), now);
}

export function recordHeldPackage(entry: NewHeldPackage, env: DgPathEnvironment = process.env, now: Date = new Date()): void {
  const path = heldPackagesPath(env);
  const nowIso = now.toISOString();
  const existing = prune(readDocument(path), now);
  const key = heldKey(entry);
  const previous = existing.find((candidate) => heldKey(candidate) === key);
  const updated: HeldPackageEntry = {
    ...entry,
    firstSeenAt: previous?.firstSeenAt ?? nowIso,
    lastSeenAt: nowIso
  };
  const merged = [...existing.filter((candidate) => heldKey(candidate) !== key), updated]
    .sort((left, right) => right.lastSeenAt.localeCompare(left.lastSeenAt))
    .slice(0, HELD_PACKAGES_CAP);
  writeJsonAtomic(path, { schemaVersion: 1, entries: merged } satisfies HeldPackagesDocument);
}
