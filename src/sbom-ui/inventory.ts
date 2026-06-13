import type { ScannerAction } from "../presentation/theme.js";
import type { ScannerPackageResult } from "../api/analyze.js";
import type { SbomComponent } from "../sbom/cyclonedx.js";

export type RowEcosystem = "npm" | "pypi" | "cargo" | "other";

export interface SbomVerdict {
  readonly action: ScannerAction;
  readonly reason: string;
  readonly provenanceFrom?: string;
  readonly cooldownAgeDays?: number;
}

export interface SbomRow {
  readonly key: string;
  readonly name: string;
  readonly version: string;
  readonly ecosystem: RowEcosystem;
  readonly license: string | null;
  readonly hasHash: boolean;
  readonly scannable: boolean;
  readonly verdict?: SbomVerdict;
}

export type SbomFilter = "all" | "risky" | "unlicensed" | "unpinned";

const ROW_ECOSYSTEMS: Record<string, RowEcosystem> = { npm: "npm", pypi: "pypi", cargo: "cargo" };

export function rowKey(ecosystem: RowEcosystem, name: string, version: string): string {
  return `${ecosystem}:${name.toLowerCase()}@${version}`;
}

export function buildSbomRows(components: readonly SbomComponent[]): SbomRow[] {
  return components
    .map((component) => {
      const ecosystem = ROW_ECOSYSTEMS[component.ecosystem] ?? "other";
      return {
        key: rowKey(ecosystem, component.name, component.version),
        name: component.name,
        version: component.version,
        ecosystem,
        license: component.license ?? null,
        hasHash: component.integrity != null && component.integrity.length > 0,
        scannable: ecosystem === "npm" || ecosystem === "pypi"
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

export function verdictFromResult(result: ScannerPackageResult): SbomVerdict | undefined {
  if (!result.action) {
    return undefined;
  }
  const reason = result.provenance?.downgrade
    ? "provenance downgraded"
    : result.cooldown?.status === "quarantine"
      ? "in cooldown"
      : result.reasons[0] ?? (result.action === "block" ? "malware" : result.action === "warn" ? "flagged" : "clean");
  return {
    action: result.action,
    reason,
    ...(result.provenance?.downgrade ? { provenanceFrom: result.provenance.downgrade.fromVersion } : {}),
    ...(result.cooldown?.ageDays !== undefined ? { cooldownAgeDays: result.cooldown.ageDays } : {})
  };
}

export function mergeVerdicts(
  rows: readonly SbomRow[],
  ecosystem: "npm" | "pypi",
  results: readonly ScannerPackageResult[]
): SbomRow[] {
  const byKey = new Map<string, SbomVerdict>();
  for (const result of results) {
    const verdict = verdictFromResult(result);
    if (verdict) {
      byKey.set(rowKey(ecosystem, result.name, result.version), verdict);
    }
  }
  if (byKey.size === 0) {
    return rows as SbomRow[];
  }
  return rows.map((row) => {
    const verdict = byKey.get(row.key);
    return verdict ? { ...row, verdict } : row;
  });
}

const VERDICT_RANK: Record<ScannerAction, number> = { block: 0, warn: 1, analysis_incomplete: 2, pass: 3 };

export function filterRows(rows: readonly SbomRow[], filter: SbomFilter, query: string): SbomRow[] {
  const needle = query.trim().toLowerCase();
  const matched = rows.filter((row) => {
    if (needle && !row.name.toLowerCase().includes(needle)) {
      return false;
    }
    if (filter === "risky") {
      return row.verdict?.action === "block" || row.verdict?.action === "warn";
    }
    if (filter === "unlicensed") {
      return row.license === null;
    }
    return true;
  });
  if (filter === "risky") {
    return matched
      .slice()
      .sort((a, b) => (VERDICT_RANK[a.verdict!.action] - VERDICT_RANK[b.verdict!.action]) || a.name.localeCompare(b.name));
  }
  return matched;
}

export function emptyFilterMessage(
  filter: SbomFilter,
  query: string,
  phase: "inventory" | "scanning" | "done",
  tally: VerdictTally,
  scanError: string | null
): string {
  const trimmed = query.trim();
  if (trimmed) {
    return `no components match "${trimmed}"`;
  }
  if (filter === "risky") {
    if (phase === "scanning") {
      return "scanning… nothing flagged yet";
    }
    if (scanError) {
      return scanError;
    }
    if (tally.scanned === 0) {
      return "no components were verdict-checked";
    }
    return "nothing flagged — no malware, downgrades, or cooldowns";
  }
  if (filter === "unlicensed") {
    return "every component declares a license";
  }
  return "no components";
}

function csvCell(value: string): string {
  return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

export function componentsCsv(rows: readonly SbomRow[]): string {
  const lines = ["name,version,ecosystem,license,verdict"];
  for (const row of rows) {
    lines.push([row.name, row.version, row.ecosystem, row.license ?? "", row.verdict?.action ?? ""].map(csvCell).join(","));
  }
  return `${lines.join("\n")}\n`;
}

export function componentsMarkdown(rows: readonly SbomRow[]): string {
  const cell = (value: string): string => value.replace(/\|/g, "\\|");
  const lines = ["| Name | Version | Ecosystem | License | Verdict |", "|---|---|---|---|---|"];
  for (const row of rows) {
    lines.push(`| ${cell(row.name)} | ${cell(row.version)} | ${row.ecosystem} | ${cell(row.license ?? "—")} | ${row.verdict?.action ?? ""} |`);
  }
  return `${lines.join("\n")}\n`;
}

export interface VerdictTally {
  readonly block: number;
  readonly warn: number;
  readonly pass: number;
  readonly scanned: number;
}

export function tallyVerdicts(rows: readonly SbomRow[]): VerdictTally {
  let block = 0;
  let warn = 0;
  let pass = 0;
  for (const row of rows) {
    if (row.verdict?.action === "block") block += 1;
    else if (row.verdict?.action === "warn") warn += 1;
    else if (row.verdict?.action === "pass") pass += 1;
  }
  return { block, warn, pass, scanned: block + warn + pass };
}
