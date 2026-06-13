import React, { useReducer, useMemo, useRef, useEffect, useState } from "react";
import { Box, Text, useInput } from "ink";
import chalk from "chalk";
import { APIResponse, APIPackageResult } from "../api-aliases.js";
import { ExportDialog, loginRequiredToast, type ExportOption, type ExportOutcome } from "../../export-ui/ExportDialog.js";
import { resolvePresentation } from "../../presentation/mode.js";
import { createTheme } from "../../presentation/theme.js";
import { packagePageUrl } from "../../presentation/package-page.js";
import { CLIConfig } from "../shims.js";
import { accountHeaderLine, isLoggedIn } from "../shims.js";
import { packageKey, type AppliedDecisions, type DecisionAcknowledgement } from "../../decisions/apply.js";
import { ScoreHeader, COMPACT_ROWS, LOGO_MIN_COLS } from "./ScoreHeader.js";
import { renderLogo } from "../logo.js";
import { useExpandAnimation } from "../hooks/useExpandAnimation.js";
import { useTerminalSize } from "../hooks/useTerminalSize.js";
import { clearScreen } from "../alt-screen.js";
import { pad, truncate, groupPackages as sharedGroupPackages, PackageGroup as SharedPackageGroup, formatUsage } from "../format-helpers.js";
import { provenanceLabel, provenanceDowngradeLine } from "../../presentation/provenance.js";

interface InteractiveResultsViewProps {
  result: APIResponse;
  config: CLIConfig;
  durationMs: number;
  onExit: () => void;
  onBack?: (() => void) | undefined;
  discoveredTotal?: number | undefined;
  initialView?: "results" | "licenses" | undefined;
  decisions?: AppliedDecisions | undefined;
}

const ACK_PREVIEW_LIMIT = 3;

type ExportScope = "all" | "summary" | "packages" | "licenses" | "findings" | "current-license";
type ExportFormat = "json" | "csv" | "md" | "txt";

const EXPORT_SCOPE_LABELS: Record<ExportScope, string> = {
  all: "All",
  summary: "Summary",
  packages: "Packages",
  licenses: "Licenses",
  findings: "Findings (warn+block)",
  "current-license": "Current license"
};

const EXPORT_FORMAT_LABELS: Record<ExportFormat, string> = {
  json: "JSON",
  csv: "CSV",
  md: "Markdown",
  txt: "Plain text"
};

type PackageGroup = SharedPackageGroup;

function groupPackages(packages: APIPackageResult[]): PackageGroup[] {
  return sharedGroupPackages(packages, "fingerprint");
}

const SEVERITY_LABELS: Record<number, string> = {
  5: "CRIT",
  4: "HIGH",
  3: "MED",
  2: "LOW",
  1: "INFO",
};

const SEVERITY_COLORS: Record<number, (s: string) => string> = {
  5: (s: string) => chalk.red.bold(s),
  4: (s: string) => chalk.red(s),
  3: (s: string) => chalk.yellow(s),
  2: (s: string) => chalk.cyan(s),
  1: (s: string) => chalk.gray(s),
};


function actionBadge(
  action: string | undefined
): { label: string; color: (s: string) => string } {
  // Scanner is the source of truth — badge from the server's action, not score.
  if (action === "block") return { label: "Block", color: chalk.red };
  if (action === "warn") return { label: "Warn", color: chalk.yellow };
  if (action === "analysis_incomplete") return { label: "Unknown", color: chalk.cyan };
  return { label: "Pass", color: chalk.green };
}

function isYankedIncomplete(pkg: APIPackageResult): boolean {
  if (pkg.action !== "analysis_incomplete") return false;
  const haystack = [...(pkg.reasons ?? []), ...pkg.findings.map((f) => f.title ?? "")]
    .join(" ")
    .toLowerCase();
  return haystack.includes("unpublish") || haystack.includes("yank") || haystack.includes("removed from the registr");
}

export function packageBadge(pkg: APIPackageResult): { label: string; color: (s: string) => string } {
  if (isYankedIncomplete(pkg)) return { label: "Unverified", color: chalk.yellow };
  return actionBadge(pkg.action);
}

export function provenanceMarker(pkg: APIPackageResult): string {
  const prov = pkg.provenance;
  if (!prov) return "  ";
  if (prov.downgrade) return chalk.yellow("◇ ");
  if (prov.status === "attested") return chalk.dim("◆ ");
  return "  ";
}

function packageDowngradeLine(pkg: APIPackageResult): string | null {
  return pkg.provenance ? provenanceDowngradeLine(pkg.version, pkg.provenance) : null;
}

const EVIDENCE_LIMIT = 2;

const BADGE_COL = "Unverified".length + 1;

// Mirrors the list-mode render row-for-row; drift shows up as blank rows or
// overflow on short terminals (counts pinned by resolveResultsLayout tests).
// Header text column: title + score + counts (+usage), full mode adds 2 spacer
// lines and the box is as tall as the logo when shown. Full chrome adds the
// flagged divider + heading and divider + summary + divider + help bar;
// compact drops the logo, spacers, and all three dividers.
export function resolveResultsLayout(input: {
  termRows: number;
  logoRows: number;
  listRows: number;
  ackSectionLines: number;
  hasGroups: boolean;
  hasUsage: boolean;
  extraLines: number;
}): { compact: boolean; availableRows: number } {
  const textRows = input.hasUsage ? 4 : 3;
  const fullHeader = 2 + Math.max(input.logoRows, textRows + 2);
  const compactHeader = 2 + textRows;
  const shared = input.ackSectionLines + input.extraLines;
  const fullChrome = fullHeader + (input.hasGroups ? 2 : 0) + 4 + shared;
  const compactChrome = compactHeader + (input.hasGroups ? 1 : 0) + 2 + shared;
  const compact = input.termRows < COMPACT_ROWS && input.listRows > input.termRows - fullChrome;
  const maxList = input.termRows - (compact ? compactChrome : fullChrome);
  const availableRows = Math.max(5, input.listRows <= maxList ? maxList : maxList - 2);
  return { compact, availableRows };
}

type ExpandLevel = null | "summary";

function firstPackage(group: PackageGroup): APIPackageResult {
  const rep = group.packages[0];
  if (!rep) throw new Error("package group cannot be empty");
  return rep;
}

function statusSummaryLines(rep: APIPackageResult): string[] {
  if ((rep.action ?? "pass") === "pass") return ["No findings"];
  const reasons = rep.reasons.length > 0
    ? [...rep.reasons]
    : rep.findings.map((f) => f.title ?? "").filter((t) => t.length > 0);
  if (reasons.length > 0) return reasons;
  return rep.action === "analysis_incomplete" ? ["Analysis incomplete"] : [];
}

function findingsSummaryHeight(group: PackageGroup): number {
  const rep = firstPackage(group);
  const visibleFindings = rep.findings.filter((f) => f.severity > 1);
  const isFree = visibleFindings.length > 0 && !visibleFindings[0]?.title;
  let h = 0;
  if (rep.license) h += 1;
  if (packageDowngradeLine(rep)) h += 1;
  if (isFree) {
    h += 1;
  } else if (visibleFindings.length > 0) {
    h += visibleFindings.length;
  } else if (rep.score > 0) {
    h += 1;
  } else {
    h += statusSummaryLines(rep).length;
  }
  if (group.packages.length > 3) h += 1;
  return h;
}

function groupRowHeight(group: PackageGroup, level: ExpandLevel): number {
  if (level === null) return 1;
  return 1 + findingsSummaryHeight(group);
}

function nameVer(p: APIPackageResult): string {
  return p.version ? `${p.name}@${p.version}` : p.name;
}

function groupNames(group: PackageGroup): string {
  if (group.packages.length === 1) return nameVer(firstPackage(group));
  if (group.packages.length <= 3)
    return group.packages.map(nameVer).join(", ");
  return `${nameVer(firstPackage(group))} + ${group.packages.length - 1} similar`;
}

function affectsLine(group: PackageGroup): string {
  const labels = group.packages.map(nameVer);
  if (labels.length <= 5) return labels.join(", ");
  return labels.slice(0, 5).join(", ") + ` + ${labels.length - 5} more`;
}

// Chrome lines in detail pane mode:
//  7  ScoreHeader  |  3  detail pane borders+header  |  2  scroll indicators
//  4  Clean/Duration box  |  1  separator  |  1  help bar
const DETAIL_PANE_CHROME = 20;

function buildDetailLines(
  group: PackageGroup,
  safeVersion: string | undefined,
  maxWidth: number,
): React.ReactNode[] {
  const rep = firstPackage(group);
  const badge = packageBadge(rep);
  const analyzedAt = (rep as { analyzedAt?: string }).analyzedAt;
  const visibleFindings = rep.findings
    .filter((f) => f.severity > 1)
    .sort((a, b) => b.severity - a.severity);
  const isFree = visibleFindings.length > 0 && !visibleFindings[0]?.title;
  const lines: React.ReactNode[] = [];

  lines.push(
    <Text key="verdict" wrap="truncate-end">
      {chalk.dim("Verdict")} {badge.color(badge.label)}
      {rep.version ? chalk.dim(`  ·  v${rep.version}`) : ""}
      {analyzedAt ? chalk.dim(`  ·  analyzed ${analyzedAt}`) : ""}
    </Text>
  );
  const page = packagePageUrl(rep.ecosystem ?? "", rep.name);
  if (page) {
    lines.push(<Text key="page" dimColor wrap="truncate-end">{`Full report  ${page}`}</Text>);
  }
  lines.push(<Text key="verdict-gap">{""}</Text>);

  if (group.packages.length > 3) {
    lines.push(
      <Text key="affects" dimColor wrap="truncate-end">
        Affects: {affectsLine(group)}
      </Text>
    );
    lines.push(<Text key="affects-gap">{""}</Text>);
  }

  if (rep.score > 0) {
    lines.push(
      <Text key="score-info" dimColor>
        Score: {rep.score}/100
      </Text>
    );
    lines.push(<Text key="score-gap">{""}</Text>);
  }

  if (rep.provenance) {
    lines.push(
      <Text key="provenance" dimColor>
        Provenance: {provenanceLabel(rep.provenance)}
      </Text>
    );
    const downgrade = packageDowngradeLine(rep);
    if (downgrade) {
      lines.push(
        <Text key="provenance-downgrade" wrap="truncate-end">
          {chalk.yellow(downgrade)}
        </Text>
      );
    }
    lines.push(<Text key="provenance-gap">{""}</Text>);
  }

  if (visibleFindings.length > 0) {
    for (let i = 0; i < visibleFindings.length; i++) {
      const f = visibleFindings[i];
      if (!f) continue;
      const sevLabel = SEVERITY_LABELS[f.severity] ?? "INFO";
      const sevColor = SEVERITY_COLORS[f.severity] ?? SEVERITY_COLORS[1] ?? chalk.dim;
      const connector = i === visibleFindings.length - 1 ? T.last : T.branch;
      lines.push(
        <Text key={`finding-${i}`} wrap="truncate-end">
          {connector} {sevColor(pad(sevLabel, 5))} {chalk.dim(f.category ?? "")}{f.title ? `: ${f.title}` : ""}
        </Text>
      );
      const evidence = f.evidence ?? [];
      for (let e = 0; e < Math.min(evidence.length, EVIDENCE_LIMIT); e++) {
        lines.push(
          <Text key={`evidence-${i}-${e}`} dimColor wrap="truncate-end">
            {"    "}{T.pipe} {evidence[e]}
          </Text>
        );
      }
      if (evidence.length > EVIDENCE_LIMIT) {
        lines.push(
          <Text key={`evidence-more-${i}`} dimColor>
            {"    "}{T.pipe} + {evidence.length - EVIDENCE_LIMIT} more
          </Text>
        );
      }
    }
    if (isFree) {
      lines.push(
        <Text key="upgrade" color="yellow">
          {chalk.yellow("→")} Upgrade to Pro for finding details
        </Text>
      );
    }
    lines.push(<Text key="findings-gap">{""}</Text>);
  } else if (rep.score > 0) {
    lines.push(
      <Text key="upgrade" color="yellow">
        {chalk.yellow("\u2192")} Upgrade to Pro to see risk categories
      </Text>
    );
    lines.push(<Text key="upgrade-gap">{""}</Text>);
  } else {
    const statusLines = statusSummaryLines(rep);
    statusLines.forEach((line, i) => {
      lines.push(
        <Text key={`status-${i}`} wrap="truncate-end">
          {rep.action === "analysis_incomplete"
            ? chalk.yellow(line)
            : (rep.action ?? "pass") === "pass"
              ? chalk.green(`✓ ${line}`)
              : chalk.dim(line)}
        </Text>
      );
    });
    if (statusLines.length > 0) lines.push(<Text key="status-gap">{""}</Text>);
  }

  if (rep.recommendation) {
    lines.push(
      <Text key="recommendation">
        {chalk.dim("Recommendation:")} {chalk.cyan(truncate(rep.recommendation, maxWidth - 18))}
      </Text>
    );
  }

  if (safeVersion) {
    lines.push(
      <Text key="safe">
        {chalk.green(`Safe version: ${rep.name}@${safeVersion}`)}
      </Text>
    );
  }

  return lines;
}

// View state — single reducer to prevent multi-render flicker
interface ViewState {
  cursor: number;
  expandLevel: ExpandLevel;
  expandedKey: string | null;
  viewport: number;
}

type ViewAction =
  | { type: "MOVE"; cursor: number; viewport: number }
  | { type: "EXPAND"; expandedKey: string | null; expandLevel: ExpandLevel; viewport: number };

function viewReducer(_state: ViewState, action: ViewAction): ViewState {
  switch (action.type) {
    case "MOVE":
      return { ..._state, cursor: action.cursor, viewport: action.viewport };
    case "EXPAND":
      return { ..._state, expandedKey: action.expandedKey, expandLevel: action.expandLevel, viewport: action.viewport };
  }
}

export const InteractiveResultsView: React.FC<InteractiveResultsViewProps> = ({
  result,
  config: _config,
  durationMs,
  onExit,
  onBack,
  discoveredTotal,
  initialView,
  decisions,
}) => {

  const usageDisplay = result.usage ? formatUsage(result.usage) : null;
  const scanUsage = usageDisplay
    ? usageDisplay.text
    : result.freeScansRemaining !== undefined
      ? `${result.freeScansRemaining.toLocaleString()} packages left`
      : undefined;
  const usageNearLimit = usageDisplay?.nearLimit ?? false;
  const headerStatus = useMemo(() => accountHeaderLine(result.usage?.tier), [result.usage]);

  // Bucket by the server `action`, never by score: the server can return
  // block/warn at score 0 (policy verdict / yanked / cooldown), and those must
  // surface as flagged, not hide in "clean".
  const flagged = useMemo(
    () => result.packages.filter((p) => (p.action ?? "pass") !== "pass"),
    [result.packages]
  );
  const clean = useMemo(
    () => result.packages.filter((p) => (p.action ?? "pass") === "pass"),
    [result.packages]
  );
  const total = result.packages.length;
  const [searchQuery, setSearchQuery] = useState("");

  const ackByKey = useMemo(() => {
    const map = new Map<string, DecisionAcknowledgement>();
    if (decisions) {
      for (const [key, annotation] of Object.entries(decisions.packages)) {
        if (annotation.acknowledged) map.set(key, annotation.acknowledged);
      }
    }
    return map;
  }, [decisions]);
  const activeFlagged = useMemo(
    () => flagged.filter((p) => !ackByKey.has(packageKey(p.name, p.version))),
    [flagged, ackByKey]
  );
  const acked = useMemo(
    () => flagged.filter((p) => ackByKey.has(packageKey(p.name, p.version))),
    [flagged, ackByKey]
  );
  const ackGroups = useMemo(() => groupPackages(acked), [acked]);

  const allGroups = useMemo(() => groupPackages(activeFlagged), [activeFlagged]);

  const groups = useMemo(() => {
    if (!searchQuery) return allGroups;
    const q = searchQuery.toLowerCase();
    const matched: PackageGroup[] = [];
    for (const g of allGroups) {
      const members = g.packages.filter((p) => p.name.toLowerCase().includes(q));
      if (members.length > 0) matched.push({ packages: members, key: g.key });
    }
    for (const p of acked) {
      if (p.name.toLowerCase().includes(q)) {
        matched.push({ packages: [p], key: `ack|${p.name}@${p.version ?? ""}` });
      }
    }
    for (const p of clean) {
      if (p.name.toLowerCase().includes(q)) {
        matched.push({ packages: [p], key: `pass|${p.name}@${p.version ?? ""}` });
      }
    }
    return matched;
  }, [allGroups, acked, clean, searchQuery]);

  const matchCount = useMemo(
    () => groups.reduce((n, g) => n + g.packages.length, 0),
    [groups]
  );

  const [view, dispatchView] = useReducer(viewReducer, {
    cursor: 0,
    expandLevel: null,
    expandedKey: null,
    viewport: 0,
  });

  const viewRef = useRef(view);
  viewRef.current = view;

  const [detailPane, setDetailPane] = useState<{ groupKey: string; scroll: number } | null>(null);
  const detailPaneRef = useRef(detailPane);
  detailPaneRef.current = detailPane;

  const [showHelp, setShowHelp] = useState(false);
  const showHelpRef = useRef(showHelp);
  showHelpRef.current = showHelp;

  const [showLicenses, setShowLicenses] = useState(initialView === "licenses");
  const showLicensesRef = useRef(showLicenses);
  showLicensesRef.current = showLicenses;

  const [licenseCursor, setLicenseCursor] = useState(0);
  const licenseCursorRef = useRef(licenseCursor);
  licenseCursorRef.current = licenseCursor;

  const [licenseDetailIdx, setLicenseDetailIdx] = useState<number | null>(null);
  const licenseDetailIdxRef = useRef(licenseDetailIdx);
  licenseDetailIdxRef.current = licenseDetailIdx;

  const [licenseDetailScroll, setLicenseDetailScroll] = useState(0);

  const [licenseSearchMode, setLicenseSearchMode] = useState(false);
  const licenseSearchModeRef = useRef(licenseSearchMode);
  licenseSearchModeRef.current = licenseSearchMode;
  const [licenseSearchQuery, setLicenseSearchQuery] = useState("");

  const [exportMsg, setExportMsg] = useState<{ text: string; tone: "ok" | "error" | "nudge" } | null>(null);
  const exportMsgRef = useRef<NodeJS.Timeout | null>(null);
  const showExportMsg = (text: string, tone: "ok" | "error" | "nudge" = "ok") => {
    setExportMsg({ text, tone });
    if (exportMsgRef.current) clearTimeout(exportMsgRef.current);
    exportMsgRef.current = setTimeout(() => setExportMsg(null), 4000);
  };
  const exportMsgText = exportMsg
    ? exportMsg.tone === "nudge"
      ? exportMsg.text
      : (exportMsg.tone === "error" ? chalk.red : chalk.green)(exportMsg.text)
    : null;

  useEffect(() => () => {
    if (exportMsgRef.current) clearTimeout(exportMsgRef.current);
  }, []);

  const [exportMenu, setExportMenu] = useState<null | {
    scope: ExportScope;
    format: ExportFormat;
    activeRow: "scope" | "format";
  }>(null);
  const exportMenuRef = useRef(exportMenu);
  exportMenuRef.current = exportMenu;

  const [exportDialog, setExportDialog] = useState<ExportOption | null>(null);
  const exportDialogRef = useRef(exportDialog);
  exportDialogRef.current = exportDialog;
  const theme = useMemo(() => createTheme(resolvePresentation().color), []);

  const openExportMenu = (defaultScope: ExportScope = "all"): void => {
    if (!isLoggedIn()) {
      // Saved reports are a logged-in feature.
      showExportMsg(loginRequiredToast(), "nudge");
      return;
    }
    setExportMenu({ scope: defaultScope, format: "json", activeRow: "scope" });
  };

  const buildExportPayload = (scope: ExportScope, currentLicenseIdx: number | null): unknown => {
    const blocked = result.packages.filter((p) => p.action === "block");
    const warned = result.packages.filter((p) => p.action === "warn");
    const cleanPkgs = result.packages.filter((p) => (p.action ?? "pass") === "pass");
    const incomplete = result.packages.filter((p) => p.action === "analysis_incomplete");
    const summary = {
      scannedAt: new Date().toISOString(),
      score: result.score,
      action: result.action,
      packagesScanned: result.packages.length,
      blocked: blocked.length,
      warned: warned.length,
      passLowRisk: incomplete.length,
      clean: cleanPkgs.length,
      durationMs,
    };
    if (scope === "summary") return summary;
    if (scope === "packages") {
      return result.packages.map((p) => ({
        name: p.name,
        version: p.version,
        score: p.score,
        license: p.license?.spdx ?? p.license?.raw ?? null,
        riskCategory: p.license?.riskCategory ?? null,
      }));
    }
    if (scope === "licenses") {
      return licenseGroups.map((g) => ({
        spdx: g.spdx,
        riskCategory: g.risk,
        count: g.count,
        packages: g.pkgs.map((p) => ({ name: p.name, version: p.version, score: p.score })),
      }));
    }
    if (scope === "current-license" && currentLicenseIdx !== null) {
      const g = licenseGroups[currentLicenseIdx];
      if (!g) return null;
      return {
        spdx: g.spdx,
        riskCategory: g.risk,
        count: g.count,
        packages: g.pkgs.map((p) => ({ name: p.name, version: p.version, score: p.score })),
      };
    }
    if (scope === "findings") {
      return [...blocked, ...warned].map((p) => ({
        name: p.name,
        version: p.version,
        score: p.score,
        action: p.action,
        findings: p.findings.map((f) => ({
          severity: f.severity,
          category: f.category ?? null,
          title: f.title ?? null,
        })),
        reasons: p.reasons,
      }));
    }
    return {
      ...summary,
      packages: result.packages,
      safeVersions: result.safeVersions,
      licenses: licenseGroups.map((g) => ({
        spdx: g.spdx,
        riskCategory: g.risk,
        count: g.count,
        packages: g.pkgs.map((p) => ({ name: p.name, version: p.version, score: p.score })),
      })),
    };
  };

  const csvCell = (v: unknown): string => {
    const s = v === null || v === undefined ? "" : String(v);
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };

  const formatExport = (payload: unknown, scope: ExportScope, format: ExportFormat): { body: string; ext: string } => {
    if (format === "json") {
      return { body: JSON.stringify(payload, null, 2) + "\n", ext: "json" };
    }
    if (format === "csv") {
      if (scope === "packages") {
        const rows = payload as Array<{ name: string; version: string; score: number; license: string | null; riskCategory: string | null }>;
        const lines = ["name,version,score,license,riskCategory"];
        for (const r of rows) {
          lines.push([r.name, r.version, r.score, r.license, r.riskCategory].map(csvCell).join(","));
        }
        return { body: lines.join("\n") + "\n", ext: "csv" };
      }
      if (scope === "licenses") {
        const rows = payload as Array<{ spdx: string; riskCategory: string; count: number; packages: Array<{ name: string; version: string }> }>;
        const lines = ["spdx,riskCategory,count,package_names"];
        for (const r of rows) {
          const names = r.packages.map((p) => `${p.name}@${p.version}`).join(";");
          lines.push([r.spdx, r.riskCategory, r.count, names].map(csvCell).join(","));
        }
        return { body: lines.join("\n") + "\n", ext: "csv" };
      }
      if (scope === "current-license") {
        const r = payload as { spdx: string; riskCategory: string; count: number; packages: Array<{ name: string; version: string; score: number }> };
        const lines = ["name,version,score,spdx,riskCategory"];
        for (const p of r.packages) {
          lines.push([p.name, p.version, p.score, r.spdx, r.riskCategory].map(csvCell).join(","));
        }
        return { body: lines.join("\n") + "\n", ext: "csv" };
      }
      if (scope === "findings") {
        const rows = payload as Array<{ name: string; version: string; score: number; action: string; findings: Array<{ severity: number; category: string | null; title: string | null }> }>;
        const lines = ["name,version,score,action,top_finding_severity,top_finding_category,top_finding_title"];
        for (const r of rows) {
          const f = r.findings[0] ?? { severity: "", category: "", title: "" };
          lines.push([r.name, r.version, r.score, r.action, f.severity, f.category, f.title].map(csvCell).join(","));
        }
        return { body: lines.join("\n") + "\n", ext: "csv" };
      }
      if (scope === "summary") {
        const s = payload as { score: number; action: string; packagesScanned: number; blocked: number; warned: number; clean: number; durationMs: number };
        const lines = [
          "score,action,packages_scanned,blocked,warned,clean,duration_ms",
          [s.score, s.action, s.packagesScanned, s.blocked, s.warned, s.clean, s.durationMs].map(csvCell).join(","),
        ];
        return { body: lines.join("\n") + "\n", ext: "csv" };
      }
      const a = payload as { score: number; action: string; packagesScanned: number; blocked: number; warned: number; clean: number; durationMs: number; packages: APIPackageResult[] };
      const lines = [
        "scan_score,scan_action,name,version,score,action,license,riskCategory",
      ];
      for (const p of a.packages) {
        lines.push(
          [a.score, a.action, p.name, p.version, p.score, p.action, p.license?.spdx ?? p.license?.raw ?? null, p.license?.riskCategory ?? null].map(csvCell).join(","),
        );
      }
      return { body: lines.join("\n") + "\n", ext: "csv" };
    }
    if (format === "md") {
      const lines: string[] = [`# Dependency Guardian — ${scope}`, ""];
      lines.push(`*Scanned at ${new Date().toISOString()}*`, "");
      const renderSummary = (s: { score: number; action: string; packagesScanned: number; blocked: number; warned: number; clean: number; durationMs: number }) => {
        lines.push(`**Score:** ${s.score} (${s.action})`);
        lines.push(`**Scanned:** ${s.packagesScanned} packages in ${(s.durationMs / 1000).toFixed(1)}s`);
        lines.push(`**Block:** ${s.blocked}  ·  **Warn:** ${s.warned}  ·  **Clean:** ${s.clean}`, "");
      };
      const renderPkgRows = (rows: Array<{ name: string; version: string; score: number; license: string | null }>) => {
        lines.push("## Packages", "", "| Name | Version | Score | License |", "|---|---|---|---|");
        for (const r of rows) lines.push(`| ${r.name} | ${r.version} | ${r.score} | ${r.license ?? "—"} |`);
        lines.push("");
      };
      const renderLicRows = (rows: Array<{ spdx: string; riskCategory: string; count: number }>) => {
        lines.push("## Licenses", "", "| License | Risk | Count |", "|---|---|---|");
        for (const r of rows) lines.push(`| ${r.spdx} | ${r.riskCategory} | ${r.count} |`);
        lines.push("");
      };
      if (scope === "summary") {
        renderSummary(payload as { score: number; action: string; packagesScanned: number; blocked: number; warned: number; clean: number; durationMs: number });
      } else if (scope === "all") {
        const a = payload as { score: number; action: string; packagesScanned: number; blocked: number; warned: number; clean: number; durationMs: number; packages: APIPackageResult[]; licenses: Array<{ spdx: string; riskCategory: string; count: number }> };
        renderSummary(a);
        renderPkgRows(
          a.packages.map((p) => ({
            name: p.name,
            version: p.version,
            score: p.score,
            license: p.license?.spdx ?? p.license?.raw ?? null,
          })),
        );
        renderLicRows(a.licenses);
      } else if (scope === "packages") {
        renderPkgRows(payload as Array<{ name: string; version: string; score: number; license: string | null }>);
      } else if (scope === "licenses") {
        renderLicRows(payload as Array<{ spdx: string; riskCategory: string; count: number }>);
      } else if (scope === "current-license") {
        const r = payload as { spdx: string; riskCategory: string; count: number; packages: Array<{ name: string; version: string; score: number }> };
        lines.push(`## ${r.spdx}  ·  ${r.riskCategory}  ·  ${r.count} packages`, "");
        lines.push("| Name | Version | Score |", "|---|---|---|");
        for (const p of r.packages) lines.push(`| ${p.name} | ${p.version} | ${p.score} |`);
      } else if (scope === "findings") {
        const rows = payload as Array<{ name: string; version: string; score: number; action: string; findings: Array<{ severity: number; title: string | null }> }>;
        if (rows.length === 0) {
          lines.push("> **No warn or block findings.** All scanned packages passed the gate.", "");
        } else {
          for (const r of rows) {
            lines.push(`### ${r.name}@${r.version}  ·  ${r.action.toUpperCase()}  ·  score ${r.score}`);
            for (const f of r.findings) lines.push(`- sev ${f.severity}: ${f.title ?? "(hidden)"}`);
            lines.push("");
          }
        }
      }
      return { body: lines.join("\n"), ext: "md" };
    }
    const txt: string[] = [`Dependency Guardian — ${scope}`, "=".repeat(40), ""];
    const txtSummary = (s: { score: number; action: string; packagesScanned: number; blocked: number; warned: number; clean: number; durationMs: number }) => {
      txt.push(`Score:    ${s.score} (${s.action})`);
      txt.push(`Scanned:  ${s.packagesScanned} packages in ${(s.durationMs / 1000).toFixed(1)}s`);
      txt.push(`Block:    ${s.blocked}`);
      txt.push(`Warn:     ${s.warned}`);
      txt.push(`Clean:    ${s.clean}`, "");
    };
    const txtPackages = (rows: Array<{ name: string; version: string; score: number; license: string | null }>) => {
      txt.push("Packages", "-".repeat(40));
      for (const r of rows) txt.push(`${r.name}@${r.version}  score=${r.score}  ${r.license ?? "no-license"}`);
      txt.push("");
    };
    const txtLicenses = (rows: Array<{ spdx: string; riskCategory: string; count: number }>) => {
      txt.push("Licenses", "-".repeat(40));
      for (const r of rows) txt.push(`${r.spdx.padEnd(36)}  ${r.riskCategory.padEnd(18)}  ${r.count}`);
      txt.push("");
    };
    if (scope === "summary") {
      txtSummary(payload as { score: number; action: string; packagesScanned: number; blocked: number; warned: number; clean: number; durationMs: number });
    } else if (scope === "all") {
      const a = payload as { score: number; action: string; packagesScanned: number; blocked: number; warned: number; clean: number; durationMs: number; packages: APIPackageResult[]; licenses: Array<{ spdx: string; riskCategory: string; count: number }> };
      txtSummary(a);
      txtPackages(
        a.packages.map((p) => ({
          name: p.name,
          version: p.version,
          score: p.score,
          license: p.license?.spdx ?? p.license?.raw ?? null,
        })),
      );
      txtLicenses(a.licenses);
    } else if (scope === "packages") {
      txtPackages(payload as Array<{ name: string; version: string; score: number; license: string | null }>);
    } else if (scope === "licenses") {
      txtLicenses(payload as Array<{ spdx: string; riskCategory: string; count: number }>);
    } else if (scope === "current-license") {
      const r = payload as { spdx: string; riskCategory: string; packages: Array<{ name: string; version: string; score: number }> };
      txt.push(`${r.spdx} (${r.riskCategory})`, "");
      for (const p of r.packages) txt.push(`  ${p.name}@${p.version}  score=${p.score}`);
    } else if (scope === "findings") {
      const rows = payload as Array<{ name: string; version: string; score: number; action: string; findings: Array<{ severity: number; title: string | null }> }>;
      if (rows.length === 0) {
        txt.push("No warn or block findings.", "All scanned packages passed the gate.");
      } else {
        for (const r of rows) {
          txt.push(`${r.action.toUpperCase()}  ${r.name}@${r.version}  score=${r.score}`);
          for (const f of r.findings) txt.push(`  sev ${f.severity}: ${f.title ?? "(hidden)"}`);
          txt.push("");
        }
      }
    }
    return { body: txt.join("\n") + "\n", ext: "txt" };
  };

  const buildExportOption = (scope: ExportScope, format: ExportFormat, currentLicenseIdx: number | null): ExportOption | null => {
    const payload = buildExportPayload(scope, currentLicenseIdx);
    if (payload === null) return null;
    const { body, ext } = formatExport(payload, scope, format);
    const scopeTag = scope === "current-license" && currentLicenseIdx !== null
      ? `${(licenseGroups[currentLicenseIdx]?.spdx ?? "license").replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 32)}`
      : scope;
    return {
      label: `${EXPORT_SCOPE_LABELS[scope]} · ${EXPORT_FORMAT_LABELS[format]}`,
      defaultName: scope === "all" ? `dg-scan.${ext}` : `dg-scan-${scopeTag}.${ext}`,
      render: () => body
    };
  };

  const handleExportDone = (result: ExportOutcome | null): void => {
    setExportDialog(null);
    clearScreen();
    if (result === null) return;
    setExportMenu(null);
    if ("path" in result) showExportMsg(`✓ Exported to ${result.path}`);
    else showExportMsg(`Export failed: ${result.error}`, "error");
  };

  const licenseGroups = useMemo(() => {
    const buckets = new Map<string, {
      spdx: string;
      risk: string;
      count: number;
      pkgs: APIPackageResult[];
    }>();
    for (const pkg of result.packages) {
      const lc = pkg.license;
      const spdx = lc?.spdx ?? lc?.raw ?? "(no license)";
      const risk = lc?.riskCategory ?? "unknown";
      const key = `${risk}::${spdx}`;
      const ex = buckets.get(key);
      if (ex) { ex.count += 1; ex.pkgs.push(pkg); }
      else buckets.set(key, { spdx, risk, count: 1, pkgs: [pkg] });
    }
    for (const b of buckets.values()) {
      b.pkgs.sort((a, b) => a.name.localeCompare(b.name));
    }
    const sinkRanks: Record<string, number> = { "no-license": 2, unknown: 1 };
    return [...buckets.values()].sort((a, b) => {
      const ra = sinkRanks[a.risk] ?? 0;
      const rb = sinkRanks[b.risk] ?? 0;
      if (ra !== rb) return ra - rb;
      return b.count - a.count;
    });
  }, [result.packages]);

  const [searchMode, setSearchMode] = useState(false);
  const searchModeRef = useRef(searchMode);
  searchModeRef.current = searchMode;

  const { rows: termRows, cols: termCols } = useTerminalSize();
  const subviewCompact = termRows < COMPACT_ROWS;
  const ackSectionLines =
    acked.length > 0
      ? 2 + Math.min(ackGroups.length, ACK_PREVIEW_LIMIT) + (ackGroups.length > ACK_PREVIEW_LIMIT ? 1 : 0)
      : 0;

  const innerWidth = Math.max(40, termCols - 6);

  const detailGroup = useMemo(() => {
    if (!detailPane) return null;
    return groups.find((g) => g.key === detailPane.groupKey) ?? null;
  }, [detailPane, groups]);
  const detailLines = useMemo(() => {
    if (!detailGroup) return [];
    return buildDetailLines(detailGroup, result.safeVersions[firstPackage(detailGroup).name], innerWidth);
  }, [detailGroup, result.safeVersions, innerWidth]);
  const detailContentRows = Math.max(3, termRows - DETAIL_PANE_CHROME);

  const getLevel = (idx: number): ExpandLevel => {
    return view.expandedKey !== null && groups[idx]?.key === view.expandedKey ? view.expandLevel : null;
  };

  const expandTargetHeight = useMemo(() => {
    if (view.expandedKey === null || view.expandLevel === null) return 0;
    const group = groups.find((g) => g.key === view.expandedKey);
    if (!group) return 0;
    return findingsSummaryHeight(group);
  }, [view.expandedKey, view.expandLevel, groups]);

  const { visibleLines: animVisibleLines } = useExpandAnimation(
    expandTargetHeight,
    view.expandedKey !== null
  );

  const animatedGroupHeight = (group: PackageGroup, level: ExpandLevel): number => {
    if (level === null) return 1;
    if (group.key === view.expandedKey) return 1 + animVisibleLines;
    return groupRowHeight(group, level);
  };

  const listRows = groups.reduce(
    (sum, group, idx) => sum + animatedGroupHeight(group, getLevel(idx)),
    0
  );
  const { compact, availableRows } = resolveResultsLayout({
    termRows,
    logoRows: termCols >= LOGO_MIN_COLS ? renderLogo(result.action).length : 0,
    listRows,
    ackSectionLines,
    hasGroups: groups.length > 0,
    hasUsage: Boolean(scanUsage),
    extraLines:
      (discoveredTotal !== undefined && discoveredTotal > total ? 1 : 0) +
      (searchQuery && groups.length === 0 ? 1 : 0),
  });

  const visibleEnd = useMemo(() => {
    let consumed = 0;
    let end = view.viewport;
    while (end < groups.length) {
      const level = getLevel(end);
      const endGroup = groups[end];
      if (!endGroup) break;
      const h = animatedGroupHeight(endGroup, level);
      if (consumed + h > availableRows) break;
      consumed += h;
      end++;
    }
    if (end === view.viewport && groups.length > 0) end = view.viewport + 1;
    return end;
  }, [view.viewport, groups, view.expandedKey, view.expandLevel, animVisibleLines, availableRows]);

  const adjustViewport = (
    cursor: number,
    expKey: string | null,
    expLvl: ExpandLevel,
    currentStart: number
  ): number => {
    if (cursor < currentStart) return cursor;

    const getLvl = (i: number): ExpandLevel => (expKey !== null && groups[i]?.key === expKey ? expLvl : null);

    let consumed = 0;
    for (let i = currentStart; i <= cursor && i < groups.length; i++) {
      const g = groups[i];
      if (!g) continue;
      consumed += groupRowHeight(g, getLvl(i));
    }
    if (consumed <= availableRows) return currentStart;

    let newStart = currentStart;
    while (newStart < cursor) {
      newStart++;
      consumed = 0;
      for (let i = newStart; i <= cursor; i++) {
        const g = groups[i];
        if (!g) continue;
        consumed += groupRowHeight(g, getLvl(i));
      }
      if (consumed <= availableRows) break;
    }
    return newStart;
  };

  useEffect(() => {
    if (groups.length === 0) return;
    const { cursor, expandedKey, expandLevel, viewport } = viewRef.current;
    const clamped = Math.min(viewport, Math.max(0, groups.length - 1));
    const newVp = adjustViewport(cursor, expandedKey, expandLevel, clamped);
    dispatchView({ type: "MOVE", cursor, viewport: newVp });
  }, [availableRows]);

  useEffect(() => {
    const dp = detailPaneRef.current;
    if (dp && detailLines.length > 0) {
      const maxScroll = Math.max(0, detailLines.length - detailContentRows);
      if (dp.scroll > maxScroll) {
        setDetailPane({ groupKey: dp.groupKey, scroll: maxScroll });
      }
    }
  }, [detailContentRows, detailLines.length]);

  useEffect(() => {
    if (detailPane !== null && !detailGroup) {
      setDetailPane(null);
    }
  }, [detailPane, detailGroup]);

  useInput((input, key) => {
    if (exportDialogRef.current) return;

    if (exportMenuRef.current) {
      const menu = exportMenuRef.current;
      const SCOPES: ExportScope[] = ["all", "summary", "packages", "licenses", "findings"];
      const FORMATS: ExportFormat[] = ["json", "csv", "md", "txt"];
      const scopes = licenseDetailIdxRef.current !== null
        ? [...SCOPES, "current-license" as ExportScope]
        : SCOPES;
      const move = <T,>(arr: T[], cur: T, dir: 1 | -1): T => {
        const i = arr.indexOf(cur);
        if (i < 0) return arr[0] ?? cur;
        // Clamp at boundaries (no wrap-around) — feels more like a list.
        return arr[Math.max(0, Math.min(arr.length - 1, i + dir))] ?? cur;
      };
      if (key.escape) { setExportMenu(null); return; }
      if (key.return) {
        const m = exportMenuRef.current!;
        const option = buildExportOption(m.scope, m.format, licenseDetailIdxRef.current);
        clearScreen();
        if (!option) {
          setExportMenu(null);
          showExportMsg(`Nothing to export for scope "${m.scope}"`);
          return;
        }
        setExportDialog(option);
        return;
      }
      if (key.tab || key.leftArrow || key.rightArrow) {
        setExportMenu({ ...menu, activeRow: menu.activeRow === "scope" ? "format" : "scope" });
        return;
      }
      if (key.upArrow || input === "k") {
        if (menu.activeRow === "scope") {
          setExportMenu({ ...menu, scope: move(scopes, menu.scope, -1) });
        } else {
          setExportMenu({ ...menu, format: move(FORMATS, menu.format, -1) });
        }
        return;
      }
      if (key.downArrow || input === "j") {
        if (menu.activeRow === "scope") {
          setExportMenu({ ...menu, scope: move(scopes, menu.scope, 1) });
        } else {
          setExportMenu({ ...menu, format: move(FORMATS, menu.format, 1) });
        }
        return;
      }
      if (input === "q") { setExportMenu(null); return; }
      return;
    }

    if (showHelpRef.current) {
      if (input === "?" || key.escape) setShowHelp(false);
      else if (input === "q") onExit();
      return;
    }

    if (showLicensesRef.current) {
      if (licenseDetailIdxRef.current !== null) {
        if (licenseSearchModeRef.current) {
          if (key.escape) {
            setLicenseSearchMode(false);
            setLicenseSearchQuery("");
            setLicenseDetailScroll(0);
          } else if (key.return) {
            setLicenseSearchMode(false);
          } else if (key.backspace || key.delete) {
            setLicenseSearchQuery((q) => q.slice(0, -1));
            setLicenseDetailScroll(0);
          } else if (input && !key.upArrow && !key.downArrow && /^[\x20-\x7e]+$/.test(input)) {
            setLicenseSearchQuery((q) => q + input);
            setLicenseDetailScroll(0);
          }
          return;
        }
        if (input === "q") { onExit(); return; }
        if (input === "/") { setLicenseSearchMode(true); return; }
        if (input === "e") { openExportMenu("current-license"); return; }
        if (key.escape) {
          clearScreen();
          licenseDetailIdxRef.current = null;
          setLicenseDetailIdx(null);
          setLicenseDetailScroll(0);
          if (licenseSearchQuery) setLicenseSearchQuery("");
          return;
        }
        if (key.upArrow || input === "k") {
          setLicenseDetailScroll((s) => Math.max(0, s - 1));
          return;
        }
        if (key.downArrow || input === "j") {
          const grp = licenseGroups[licenseDetailIdxRef.current];
          if (grp) {
            const q = licenseSearchQuery.toLowerCase();
            const filtered = q
              ? grp.pkgs.filter((p) => p.name.toLowerCase().includes(q))
              : grp.pkgs;
            setLicenseDetailScroll((s) =>
              Math.min(Math.max(0, filtered.length - 1), s + 1)
            );
          }
          return;
        }
        return;
      }
      if (input === "q") { onExit(); return; }
      if (input === "e") { openExportMenu("licenses"); return; }
      if (key.escape) {
        if (initialView === "licenses") return;
        setShowLicenses(false);
        return;
      }
      if (key.upArrow || input === "k") {
        setLicenseCursor((c) => Math.max(0, c - 1));
        return;
      }
      if (key.downArrow || input === "j") {
        setLicenseCursor((c) => Math.min(licenseGroups.length - 1, c + 1));
        return;
      }
      if (key.return) {
        setLicenseDetailIdx(licenseCursorRef.current);
        setLicenseDetailScroll(0);
        return;
      }
      return;
    }

    if (searchModeRef.current) {
      if (key.escape) {
        setSearchMode(false);
        setSearchQuery("");
        dispatchView({ type: "MOVE", cursor: 0, viewport: 0 });
      } else if (key.return) {
        setSearchMode(false);
        if (groups.length === 0) {
          setSearchQuery("");
          dispatchView({ type: "MOVE", cursor: 0, viewport: 0 });
        }
      } else if (key.backspace || key.delete) {
        setSearchQuery(prev => prev.slice(0, -1));
        dispatchView({ type: "MOVE", cursor: 0, viewport: 0 });
      } else if (input && !key.upArrow && !key.downArrow && /^[\x20-\x7e]+$/.test(input)) {
        setSearchQuery(prev => prev + input);
        dispatchView({ type: "MOVE", cursor: 0, viewport: 0 });
      }
      return;
    }

    const dp = detailPaneRef.current;
    if (dp !== null) {
      const maxScroll = Math.max(0, detailLines.length - detailContentRows);
      if (key.upArrow || input === "k") {
        setDetailPane({ groupKey: dp.groupKey, scroll: Math.max(0, dp.scroll - 1) });
      } else if (key.downArrow || input === "j") {
        setDetailPane({ groupKey: dp.groupKey, scroll: Math.min(maxScroll, dp.scroll + 1) });
      } else if (input === "g") {
        setDetailPane({ groupKey: dp.groupKey, scroll: 0 });
      } else if (input === "G") {
        setDetailPane({ groupKey: dp.groupKey, scroll: maxScroll });
      } else if (input === "?") {
        setShowHelp(true);
      } else if (key.escape) {
        setDetailPane(null);
      } else if (input === "q") {
        onExit();
      }
      return;
    }

    if (input === "?") { setShowHelp(true); return; }
    if (input === "l") { setShowLicenses(true); setLicenseCursor(0); return; }
    if (input === "e") { openExportMenu("all"); return; }
    if (key.escape) {
      const { expandedKey: openKey, viewport } = viewRef.current;
      if (openKey !== null) {
        dispatchView({ type: "EXPAND", expandedKey: null, expandLevel: null, viewport });
        return;
      }
      if (searchQuery) {
        setSearchQuery("");
        dispatchView({ type: "MOVE", cursor: 0, viewport: 0 });
        return;
      }
      if (onBack) onBack();
      return;
    }
    if (input === "q") { onExit(); return; }

    if (groups.length === 0) {
      if (key.return) onExit();
      else if (input === "/") setSearchMode(true);
      return;
    }

    const { cursor, expandLevel: expLvl, expandedKey: expKey, viewport: vpStart } = viewRef.current;

    if (key.upArrow || input === "k") {
      const next = Math.max(0, cursor - 1);
      const newVp = adjustViewport(next, expKey, expLvl, vpStart < next ? vpStart : next);
      dispatchView({ type: "MOVE", cursor: next, viewport: newVp });
    } else if (key.downArrow || input === "j") {
      const next = Math.min(groups.length - 1, cursor + 1);
      const newVp = adjustViewport(next, expKey, expLvl, vpStart);
      dispatchView({ type: "MOVE", cursor: next, viewport: newVp });
    } else if (input === "g") {
      const newVp = adjustViewport(0, expKey, expLvl, 0);
      dispatchView({ type: "MOVE", cursor: 0, viewport: newVp });
    } else if (input === "G") {
      const last = groups.length - 1;
      const newVp = adjustViewport(last, expKey, expLvl, vpStart);
      dispatchView({ type: "MOVE", cursor: last, viewport: newVp });
    } else if (key.pageDown) {
      const next = Math.min(groups.length - 1, cursor + availableRows);
      const newVp = adjustViewport(next, expKey, expLvl, vpStart);
      dispatchView({ type: "MOVE", cursor: next, viewport: newVp });
    } else if (key.pageUp) {
      const next = Math.max(0, cursor - availableRows);
      const newVp = adjustViewport(next, expKey, expLvl, next);
      dispatchView({ type: "MOVE", cursor: next, viewport: newVp });
    } else if (key.return) {
      const curGroup = groups[Math.min(cursor, groups.length - 1)];
      if (!curGroup) return;
      if (expKey === curGroup.key && expLvl === "summary") {
        setDetailPane({ groupKey: curGroup.key, scroll: 0 });
      } else {
        const newVp = adjustViewport(cursor, curGroup.key, "summary", vpStart);
        dispatchView({ type: "EXPAND", expandedKey: curGroup.key, expandLevel: "summary", viewport: newVp });
      }
    } else if (input === "/") {
      setSearchMode(true);
    }
  });

  const visibleGroups = groups.slice(view.viewport, visibleEnd);
  const aboveCount = view.viewport;
  const belowCount = groups.length - visibleEnd;

  const lcCol = 16;
  const nameCol = Math.max(20, innerWidth - BADGE_COL - 16 - lcCol);

  // Clamp cursor to valid range (groups may shrink via search filter)
  const clampedCursor = groups.length > 0 ? Math.min(view.cursor, groups.length - 1) : 0;

  if (exportDialog) {
    return (
      <Box flexDirection="column">
        <ScoreHeader
          score={result.score}
          action={result.action}
          compact={subviewCompact}
          total={total}
          flagged={flagged.length}
          clean={clean.length}
          userStatus={headerStatus}
          scanUsage={scanUsage} usageNearLimit={usageNearLimit}
        />
        <ExportDialog options={[exportDialog]} theme={theme} cwd={process.cwd()} onDone={handleExportDone} />
      </Box>
    );
  }

  if (exportMenu) {
    const SCOPES_RENDER: Array<{ value: ExportScope; label: string }> = (
      ["all", "summary", "packages", "licenses", "findings"] as const
    ).map((value) => ({ value, label: EXPORT_SCOPE_LABELS[value] }));
    if (licenseDetailIdxRef.current !== null) {
      const focus = licenseGroups[licenseDetailIdxRef.current];
      SCOPES_RENDER.push({
        value: "current-license",
        label: `${EXPORT_SCOPE_LABELS["current-license"]} (${focus?.spdx ?? "—"})`,
      });
    }
    const FORMATS_RENDER: Array<{ value: ExportFormat; label: string }> = (
      ["json", "csv", "md", "txt"] as const
    ).map((value) => ({ value, label: EXPORT_FORMAT_LABELS[value] }));
    const stackedLayout = termCols < 80;
    const colWidth = stackedLayout ? undefined : Math.max(24, Math.floor((termCols - 8) / 2));
    const renderColumn = <T extends string>(
      title: string,
      rows: Array<{ value: T; label: string }>,
      current: T,
      isActive: boolean,
    ) => (
      <Box flexDirection="column" width={colWidth} flexShrink={1} marginBottom={stackedLayout ? 1 : 0}>
        <Text>
          {isActive ? chalk.cyan("▌ ") : "  "}
          {isActive ? chalk.bold(title) : chalk.dim(title)}
        </Text>
        {rows.map((r) => {
          const selected = r.value === current;
          const bullet = selected
            ? (isActive ? chalk.cyan("●") : chalk.green("●"))
            : chalk.dim("○");
          const text = selected ? chalk.bold(r.label) : r.label;
          return (
            <Box key={r.value}>
              <Box width={5} flexShrink={0}><Text>{"   "}{bullet}</Text></Box>
              <Box flexShrink={1}><Text wrap="truncate-end">{text}</Text></Box>
            </Box>
          );
        })}
      </Box>
    );
    return (
      <Box flexDirection="column">
        <ScoreHeader
          score={result.score}
          action={result.action}
          compact={subviewCompact}
          total={total}
          flagged={flagged.length}
          clean={clean.length}
          userStatus={headerStatus}
          scanUsage={scanUsage} usageNearLimit={usageNearLimit}
        />
        <Box flexDirection="column" borderStyle="round" borderColor="cyan" paddingLeft={2} paddingRight={2}>
          <Text bold>Export</Text>
          <Text>{""}</Text>
          <Box flexDirection={stackedLayout ? "column" : "row"}>
            {renderColumn("What", SCOPES_RENDER, exportMenu.scope, exportMenu.activeRow === "scope")}
            {renderColumn("Format", FORMATS_RENDER, exportMenu.format, exportMenu.activeRow === "format")}
          </Box>
        </Box>
        <Text dimColor>{chalk.dim("─".repeat(Math.max(20, termCols - 4)))}</Text>
        <Text>
          {" "}
          {chalk.bold.cyan("↑↓")} {chalk.dim("scroll")}{"   "}
          {chalk.bold.cyan("←→/Tab")} {chalk.dim("switch row")}{"   "}
          {chalk.bold.cyan("⏎")} {chalk.dim("export")}{"   "}
          {chalk.bold.cyan("Esc")} {chalk.dim("cancel")}
        </Text>
      </Box>
    );
  }

  if (showHelp) {
    const isDetail = detailPane !== null;
    return (
      <Box flexDirection="column">
        <ScoreHeader
          score={result.score}
          action={result.action}
          compact={subviewCompact}
          total={total}
          flagged={flagged.length}
          clean={clean.length}
          userStatus={headerStatus}
          scanUsage={scanUsage} usageNearLimit={usageNearLimit}
        />
        <Box
          flexDirection="column"
          borderStyle="round"
          borderColor="cyan"
          paddingLeft={2}
          paddingRight={2}
          width="100%"
        >
          <Text bold>Keyboard Shortcuts</Text>
          <Text>{""}</Text>
          <Text bold> Navigation</Text>
          <Text>   {chalk.cyan("\u2191 k")}     {chalk.dim("Move up")}</Text>
          <Text>   {chalk.cyan("\u2193 j")}     {chalk.dim("Move down")}</Text>
          <Text>   {chalk.cyan("g")}       {chalk.dim("Jump to top")}</Text>
          <Text>   {chalk.cyan("G")}       {chalk.dim("Jump to bottom")}</Text>
          {!isDetail && <Text>   {chalk.cyan("PgUp")}    {chalk.dim("Page up")}</Text>}
          {!isDetail && <Text>   {chalk.cyan("PgDn")}    {chalk.dim("Page down")}</Text>}
          <Text>{""}</Text>
          <Text bold> Actions</Text>
          {!isDetail && <Text>   {chalk.cyan("\u23CE")}       {chalk.dim("Expand findings (press again for full details)")}</Text>}
          {isDetail && <Text>   {chalk.cyan("Esc")}     {chalk.dim("Back to list")}</Text>}
          {!isDetail && <Text>   {chalk.cyan("/")}       {chalk.dim("Search all scanned packages (incl. passed)")}</Text>}
          {!isDetail && <Text>   {chalk.cyan("l")}       {chalk.dim("License breakdown (browse + drill-in)")}</Text>}
          {!isDetail && <Text>   {chalk.cyan("e")}       {chalk.dim("Export menu — pick scope (all / summary / packages / licenses / findings) and format (JSON / CSV / Markdown / text)")}</Text>}
          {!isDetail && <Text>   {chalk.cyan("Esc")}     {chalk.dim(onBack ? "Collapse row / clear search / back to project selector" : "Collapse row / clear search")}</Text>}
          <Text>   {chalk.cyan("q")}       {chalk.dim("Quit")}</Text>
          <Text>{""}</Text>
          <Text dimColor> Press {chalk.bold.cyan("?")} or {chalk.bold.cyan("Esc")} to close</Text>
        </Box>
      </Box>
    );
  }

  if (showLicenses) {
    const lcColor = (risk: string): ((s: string) => string) => {
      if (risk === "permissive") return chalk.green;
      if (risk === "weak-copyleft") return chalk.yellow;
      if (risk === "strong-copyleft") return chalk.yellow.bold;
      if (risk === "no-license" || risk === "network-copyleft" || risk === "unlicensed") return chalk.red;
      return chalk.dim;
    };
    const totalCount = result.packages.length;
    const maxCount = licenseGroups[0]?.count ?? 1;

    if (licenseDetailIdx !== null && licenseGroups[licenseDetailIdx]) {
      const g = licenseGroups[licenseDetailIdx];
      const color = lcColor(g.risk);
      const visibleRows = Math.max(5, termRows - 20);
      const q = licenseSearchQuery.toLowerCase();
      const filtered = q
        ? g.pkgs.filter((p) => p.name.toLowerCase().includes(q))
        : g.pkgs;
      const cursorIdx = Math.min(licenseDetailScroll, Math.max(0, filtered.length - 1));
      const top = Math.max(
        0,
        Math.min(
          cursorIdx - Math.floor((visibleRows - 1) / 2),
          Math.max(0, filtered.length - visibleRows),
        ),
      );
      const bottom = Math.min(top + visibleRows, filtered.length);
      const _above = top;
      const _below = filtered.length - bottom;
      const _slice = filtered.slice(top, bottom);
      return (
        <Box flexDirection="column">
          <ScoreHeader
            score={result.score}
            action={result.action}
            compact={subviewCompact}
            total={total}
            flagged={flagged.length}
            clean={clean.length}
            userStatus={headerStatus}
            scanUsage={scanUsage} usageNearLimit={usageNearLimit}
            />
          <Box flexDirection="column" borderStyle="round" borderColor="cyan" paddingLeft={2} paddingRight={2} width="100%">
            <Box>
              <Text bold>{color(g.spdx)}</Text>
              <Text dimColor>  ·  {g.risk}  ·  {g.count} package{g.count !== 1 ? "s" : ""}{q ? `  ·  ${filtered.length} match${filtered.length !== 1 ? "es" : ""}` : ""}</Text>
            </Box>
            {licenseSearchMode || q ? (
              <Box>
                <Text>
                  {" "}{chalk.bold.cyan("/")} {q || chalk.dim("(type to filter; Esc clears, Enter confirms)")}{licenseSearchMode ? chalk.cyan("█") : ""}
                </Text>
              </Box>
            ) : (
              <Text>{""}</Text>
            )}
            {_above > 0 && <Text dimColor>{`  ↑ ${_above} more above`}</Text>}
            {_slice.length === 0 && <Text dimColor>{`  (no packages match "${q}")`}</Text>}
            {_slice.map((p, i) => {
              const absIdx = top + i;
              const isSelected = absIdx === cursorIdx;
              const nameCol = Math.max(28, Math.floor(termCols * 0.55));
              if (isSelected) {
                return (
                  <Text key={`${p.name}@${p.version}`} backgroundColor="#1a1a2e" wrap="truncate-end">
                    {chalk.cyan("▌")} {chalk.bold(pad(truncate(p.name, nameCol - 2), nameCol))}
                    {chalk.dim(pad(truncate(p.version, 15), 16))}
                  </Text>
                );
              }
              return (
                <Text key={`${p.name}@${p.version}`} wrap="truncate-end">
                  {"  "}{pad(truncate(p.name, nameCol - 2), nameCol)}
                  {chalk.dim(pad(truncate(p.version, 15), 16))}
                </Text>
              );
            })}
            {_below > 0 && <Text dimColor>{`  ↓ ${_below} more below`}</Text>}
          </Box>
          <Text dimColor>{chalk.dim("─".repeat(Math.max(20, termCols - 4)))}</Text>
          {(() => {
            const sel = filtered[cursorIdx];
            const page = sel ? packagePageUrl(sel.ecosystem ?? "", sel.name) : null;
            return page ? <Text wrap="truncate-end">{" "}{chalk.dim(`→ ${page}`)}</Text> : null;
          })()}
          <Text>
            {" "}
            {chalk.bold.cyan("↑↓")} {chalk.dim("scroll")}{"   "}
            {chalk.bold.cyan("/")} {chalk.dim("search")}{"   "}
            {chalk.bold.cyan("e")} {chalk.dim("export")}{"   "}
            {chalk.bold.cyan("Esc")} {chalk.dim("back")}{"   "}
            {chalk.bold.cyan("q")} {chalk.dim("quit")}
            {exportMsgText && <>{"   "}{exportMsgText}</>}
          </Text>
        </Box>
      );
    }

    // Column widths: pick from terminal so long SPDX strings (e.g.
    // "(BSD-2-Clause OR MIT OR Apache-2.0)") don't blow the layout.
    const innerCols = Math.max(20, termCols - 6);
    const spdxCol = Math.min(40, Math.max(22, Math.floor(innerCols * 0.35)));
    const riskCol = 18;
    const countCol = 7;
    const barCol = Math.max(8, innerCols - spdxCol - riskCol - countCol - 4);
    const visibleRows = Math.max(5, termRows - 20);
    const cursor = Math.min(licenseCursor, licenseGroups.length - 1);
    const top = Math.max(
      0,
      Math.min(
        cursor - Math.floor((visibleRows - 1) / 2),
        licenseGroups.length - visibleRows,
      ),
    );
    const bottom = Math.min(top + visibleRows, licenseGroups.length);
    const hiddenAbove = top;
    const hiddenBelow = licenseGroups.length - bottom;
    return (
      <Box flexDirection="column">
        <ScoreHeader
          score={result.score}
          action={result.action}
          compact={subviewCompact}
          total={total}
          flagged={flagged.length}
          clean={clean.length}
          userStatus={headerStatus}
          scanUsage={scanUsage} usageNearLimit={usageNearLimit}
        />
        <Text dimColor>{chalk.dim("─".repeat(Math.max(20, termCols - 4)))}</Text>
        <Box
          flexDirection="column"
          paddingLeft={2}
          paddingRight={2}
          width="100%"
        >
          <Text bold>
            Licenses{" "}{chalk.dim(`(${licenseGroups.length} unique across ${totalCount} packages)`)}
          </Text>
          <Text>{""}</Text>
          <Box>
            <Box width={2} flexShrink={0}><Text>{" "}</Text></Box>
            <Box width={spdxCol} flexShrink={1}><Text dimColor>SPDX</Text></Box>
            <Box width={riskCol} flexShrink={0}><Text dimColor>Risk</Text></Box>
            <Box width={countCol} flexShrink={0}><Text dimColor>Count</Text></Box>
            <Box width={barCol} flexShrink={1}><Text dimColor>Share</Text></Box>
          </Box>
          {hiddenAbove > 0 && (
            <Text dimColor>{`  ↑ ${hiddenAbove} more above`}</Text>
          )}
          {licenseGroups.slice(top, bottom).map((g, i) => {
            const absIdx = top + i;
            const color = lcColor(g.risk);
            const barLen = Math.max(1, Math.round((g.count / maxCount) * (barCol - 2)));
            const bar = "█".repeat(Math.min(barLen, barCol - 2));
            const isSelected = absIdx === cursor;
            const spdxText = truncate(g.spdx, spdxCol - 1);
            const riskText = g.risk;
            if (isSelected) {
              return (
                <Text key={`${g.risk}::${g.spdx}::${absIdx}`} backgroundColor="#1a1a2e" wrap="truncate-end">
                  {chalk.cyan("▌")} {chalk.bold(color(pad(spdxText, spdxCol)))}
                  {chalk.dim(pad(riskText, riskCol))}
                  {chalk.bold(pad(String(g.count), countCol))}
                  {color(bar)}
                </Text>
              );
            }
            return (
              <Text key={`${g.risk}::${g.spdx}::${absIdx}`} wrap="truncate-end">
                {"  "}{color(pad(spdxText, spdxCol))}
                {chalk.dim(pad(riskText, riskCol))}
                {chalk.bold(pad(String(g.count), countCol))}
                {color(bar)}
              </Text>
            );
          })}
          {hiddenBelow > 0 && (
            <Text dimColor>{`  ↓ ${hiddenBelow} more below`}</Text>
          )}
        </Box>
        <Text dimColor>{chalk.dim("─".repeat(Math.max(20, termCols - 4)))}</Text>
        <Text>
          {" "}
          {chalk.bold.cyan("↑↓")} {chalk.dim("navigate")}{"   "}
          {chalk.bold.cyan("⏎")} {chalk.dim("view packages")}{"   "}
          {chalk.bold.cyan("e")} {chalk.dim("export")}{"   "}
          {chalk.bold.cyan("Esc")} {chalk.dim("close")}{"   "}
          {chalk.bold.cyan("q")} {chalk.dim("quit")}
          {exportMsgText && <>{"   "}{exportMsgText}</>}
        </Text>
      </Box>
    );
  }

  if (detailPane !== null) {
    const dpGroup = detailGroup;
    if (dpGroup) {
      const dpRep = firstPackage(dpGroup);
      const { color: dpColor } = packageBadge(dpRep);
      const dpScroll = detailPane.scroll;
      const dpAbove = dpScroll;
      const dpBelow = Math.max(0, detailLines.length - dpScroll - detailContentRows);
      const dpVisible = detailLines.slice(dpScroll, dpScroll + detailContentRows);

      return (
        <Box flexDirection="column">
          <ScoreHeader
            score={result.score}
            action={result.action}
            compact={subviewCompact}
            total={total}
            flagged={flagged.length}
            clean={clean.length}
            userStatus={headerStatus}
            scanUsage={scanUsage} usageNearLimit={usageNearLimit}
            />

          <Text dimColor>{chalk.dim("\u2500".repeat(Math.max(20, termCols - 4)))}</Text>
          <Box
            flexDirection="column"
            paddingLeft={1}
            paddingRight={1}
            width="100%"
          >
            <Box justifyContent="space-between">
              <Text bold wrap="truncate-end">{groupNames(dpGroup)}{dpRep.license ? chalk.dim(" \u00B7 ") + (dpRep.license.riskCategory === "permissive" ? chalk.green(dpRep.license.spdx ?? dpRep.license.raw ?? "") : dpRep.license.riskCategory === "no-license" || dpRep.license.riskCategory === "network-copyleft" ? chalk.red(dpRep.license.spdx ?? dpRep.license.raw ?? "No license") : chalk.yellow(dpRep.license.spdx ?? dpRep.license.raw ?? "")) : ""}</Text>
              <Text>{dpColor(`score ${dpRep.score}`)}</Text>
            </Box>

            {dpAbove > 0 && (
              <Text dimColor>
                {chalk.cyan(" \u2191")} {dpAbove} more above
              </Text>
            )}

            <Box flexDirection="column" marginLeft={2}>
              {dpVisible}
            </Box>

            {dpBelow > 0 && (
              <Text dimColor>
                {chalk.cyan(" \u2193")} {dpBelow} more below
              </Text>
            )}
          </Box>

          <Text dimColor>{chalk.dim("─".repeat(Math.max(20, termCols - 4)))}</Text>
          <Box
            flexDirection="column"
            paddingLeft={1}
            paddingRight={1}
            width="100%"
          >
            <Box justifyContent="space-between">
              {clean.length > 0 ? (
                <Text wrap="truncate-end">
                  {chalk.green("\u2713")} {chalk.green.bold(String(clean.length))} {chalk.dim(`package${clean.length !== 1 ? "s" : ""} passed`)} {chalk.dim(`\u00b7 ${(durationMs / 1000).toFixed(1)}s`)}
                </Text>
              ) : (
                <Text dimColor>{(durationMs / 1000).toFixed(1)}s</Text>
              )}
              {result.freeScansRemaining !== undefined && (
                <Text dimColor>Free tier · dg login for higher scan limits</Text>
              )}
            </Box>
          </Box>

          <Text dimColor>{chalk.dim("\u2500".repeat(Math.max(20, termCols - 4)))}</Text>
          <Text>
            {" "}
            {chalk.bold.cyan("\u2191\u2193")} {chalk.dim("scroll")}{"   "}
            {chalk.bold.cyan("Esc")} {chalk.dim("back")}{"   "}
            {chalk.bold.cyan("q")} {chalk.dim("quit")}
          </Text>
        </Box>
      );
    }
  }

  return (
    <Box flexDirection="column">
      <ScoreHeader
        score={result.score}
        action={result.action}
        compact={compact}
        total={total}
        flagged={flagged.length}
        clean={clean.length}
        userStatus={headerStatus}
        scanUsage={scanUsage} usageNearLimit={usageNearLimit}
      />

      {groups.length > 0 && (
        <>
          {!compact && <Text dimColor>{chalk.dim("─".repeat(Math.max(20, termCols - 4)))}</Text>}
        <Box
          flexDirection="column"
          paddingLeft={1}
          paddingRight={1}
          width="100%"
        >
          <Box justifyContent="space-between">
            <Text bold>
              {searchQuery ? "Search Results" : "Flagged Packages"}
            </Text>
            <Text dimColor>
              {searchQuery ? `${matchCount} of ${total} packages` : `${clampedCursor + 1}/${groups.length}`}
            </Text>
          </Box>

          {aboveCount > 0 && (
            <Text dimColor>
              {chalk.cyan(" \u2191")} {aboveCount} more above
            </Text>
          )}

          {visibleGroups.map((group, visIdx) => {
            const globalIdx = view.viewport + visIdx;
            const isCursor = globalIdx === clampedCursor;
            const level = getLevel(globalIdx);
            const rep = firstPackage(group);
            const { label, color } = packageBadge(rep);
            const names = groupNames(group);
            const scoreStr = String(rep.score);
            const lcInfo = rep.license;
            const lcStr = lcInfo ? truncate(lcInfo.spdx ?? lcInfo.raw ?? "", lcCol - 2) : "";
            const lcColor = !lcInfo ? chalk.dim
              : lcInfo.riskCategory === "permissive" ? chalk.green
              : (lcInfo.riskCategory === "no-license" || lcInfo.riskCategory === "unlicensed" || lcInfo.riskCategory === "network-copyleft") ? chalk.red
              : chalk.yellow;

            const arrow = level === "summary" ? "\u25BE" : "\u25B8"; // ▾ expanded, ▸ collapsed

            return (
              <Box key={group.key} flexDirection="column">
                {isCursor ? (
                  <Text backgroundColor="#1a1a2e" wrap="truncate-end">
                    {chalk.cyan("\u258C")} {chalk.cyan(arrow)} {` `}
                    {color(pad(label, BADGE_COL))}
                    {chalk.bold(pad(truncate(names, nameCol - 2), nameCol))}
                    {provenanceMarker(rep)}
                    {lcColor(pad(lcStr, lcCol))}
                    {color(scoreStr.padStart(3))}
                    {"  "}
                  </Text>
                ) : (
                  <Text wrap="truncate-end">
                    {`  ${chalk.dim(arrow)}  `}
                    {color(pad(label, BADGE_COL))}
                    {pad(truncate(names, nameCol - 2), nameCol)}
                    {provenanceMarker(rep)}
                    {lcColor(pad(lcStr, lcCol))}
                    {color(scoreStr.padStart(3))}
                  </Text>
                )}

                {level === "summary" && (
                  <FindingsSummary
                    group={group}
                    maxWidth={innerWidth - 8}
                    maxLines={group.key === view.expandedKey ? animVisibleLines : undefined}
                  />
                )}

              </Box>
            );
          })}

          {belowCount > 0 && (
            <Text dimColor>
              {chalk.cyan(" \u2193")} {belowCount} more below
            </Text>
          )}
        </Box>
        </>
      )}

      {searchQuery && groups.length === 0 && (
        <Text dimColor>{`  No packages match "${searchQuery}"`}</Text>
      )}

      {acked.length > 0 && !searchQuery && (
        <Box
          flexDirection="column"
          paddingLeft={1}
          paddingRight={1}
          width="100%"
        >
          <Text bold dimColor>
            {`Acknowledged (${acked.length}) \u00b7 dg.json`}
          </Text>
          {ackGroups.slice(0, ACK_PREVIEW_LIMIT).map((group) => {
            const rep = firstPackage(group);
            const ack = ackByKey.get(packageKey(rep.name, rep.version));
            const who = ack?.by ?? "unknown";
            const when = ack?.at ? ` on ${ack.at.slice(0, 10)}` : "";
            return (
              <Text key={`ack-${group.key}`} dimColor wrap="truncate-end">
                {"  "}{chalk.yellow("\u25b8")} {groupNames(group)}  {chalk.dim(`accepted by ${who}${when}`)}
              </Text>
            );
          })}
          {ackGroups.length > ACK_PREVIEW_LIMIT && (
            <Text dimColor>{`  +${ackGroups.length - ACK_PREVIEW_LIMIT} more \u2014 dg decisions`}</Text>
          )}
        </Box>
      )}

      {!compact && <Text dimColor>{chalk.dim("\u2500".repeat(Math.max(20, termCols - 4)))}</Text>}
      <Box
        flexDirection="column"
        paddingLeft={1}
        paddingRight={1}
        width="100%"
      >
        {discoveredTotal !== undefined && discoveredTotal > total && (
          <Text dimColor>
            Scanned {total} of {discoveredTotal} packages
          </Text>
        )}
        {acked.length > 0 && (
          <Text wrap="truncate-end">
            {chalk.yellow("\u26a0")} {chalk.yellow(String(acked.length))} {chalk.dim(`acknowledged warn${acked.length !== 1 ? "s" : ""} \u00b7 dg.json \u00b7 review with 'dg decisions'`)}
          </Text>
        )}
        <Box justifyContent="space-between">
          {clean.length > 0 ? (
            <Text wrap="truncate-end">
              {chalk.green("\u2713")} {chalk.green.bold(String(clean.length))} {chalk.dim(`package${clean.length !== 1 ? "s" : ""} passed`)} {chalk.dim(`\u00b7 ${(durationMs / 1000).toFixed(1)}s`)}
            </Text>
          ) : (
            <Text dimColor>{(durationMs / 1000).toFixed(1)}s</Text>
          )}
          {result.freeScansRemaining !== undefined && (
            <Text dimColor>Free tier · dg login for higher scan limits</Text>
          )}
        </Box>
      </Box>

      {!compact && <Text dimColor>{chalk.dim("\u2500".repeat(Math.max(20, termCols - 4)))}</Text>}
      {(() => {
        const cur = groups.length > 0 ? groups[Math.min(view.cursor, groups.length - 1)] : undefined;
        const page = cur ? packagePageUrl(firstPackage(cur).ecosystem ?? "", firstPackage(cur).name) : null;
        return page ? <Text wrap="truncate-end">{" "}{chalk.dim(`\u2192 ${page}`)}</Text> : null;
      })()}
      {searchMode ? (
        <Text wrap="truncate-end">
          {" "}{chalk.bold.cyan("/")} {searchQuery}{chalk.cyan("\u2588")}
          {"   "}{chalk.dim("Esc clear")}
        </Text>
      ) : exportMsg ? (
        <Text wrap="truncate-end">
          {" "}{exportMsgText}
        </Text>
      ) : searchQuery ? (
        <Text wrap="truncate-end">
          {" "}{chalk.bold.cyan("/")} {searchQuery}
          {"   "}{chalk.dim(`${matchCount} of ${total} packages`)}
          {"   "}{chalk.bold.cyan("Esc")} {chalk.dim("clear")}
          {"   "}{chalk.bold.cyan("q")} {chalk.dim("quit")}
        </Text>
      ) : (
        <Text wrap="truncate-end">
          {" "}
          {groups.length > 0 && (
            <>
              {chalk.bold.cyan("\u2191\u2193")} {chalk.dim("navigate")}{"   "}
              {chalk.bold.cyan("\u23CE")} {chalk.dim("expand")}{"   "}
            </>
          )}
          {total > 0 && (
            <>
              {chalk.bold.cyan("/")} {chalk.dim("search")}{"   "}
            </>
          )}
          {chalk.bold.cyan("l")} {chalk.dim("licenses")}{"   "}
          {chalk.bold.cyan("e")} {chalk.dim("export")}{"   "}
          {onBack && <>{chalk.bold.cyan("Esc")} {chalk.dim("back")}{"   "}</>}
          {chalk.bold.cyan("q")} {chalk.dim("quit")}
        </Text>
      )}
    </Box>
  );
};

const T = {
  branch: chalk.dim("\u251C\u2500\u2500"),
  last:   chalk.dim("\u2514\u2500\u2500"),
  pipe:   chalk.dim("\u2502"),
  blank:  " ",
};

const LICENSE_DESCRIPTIONS: Record<string, string> = {
  "permissive": "Permissive \u2014 free to use, modify, and distribute. Include the copyright notice.",
  "weak-copyleft": "Weak copyleft \u2014 changes to this library must be shared, but your code stays private.",
  "strong-copyleft": "Strong copyleft \u2014 your entire project must be open-sourced under the same license.",
  "network-copyleft": "Network copyleft \u2014 even SaaS/server use requires releasing your source code.",
  "no-license": "No license found \u2014 legally all rights reserved. Use may require permission from the author.",
  "unlicensed": "Explicitly unlicensed \u2014 proprietary software. A commercial agreement is required.",
  "unknown": "Unrecognized license \u2014 have your legal team review before using.",
  "deferred": "License declared in a file \u2014 check the LICENSE file in the package.",
};

function licenseLine(rep: APIPackageResult): React.ReactNode | null {
  const lc = rep.license;
  if (!lc) return null;
  const spdx = lc.spdx ?? lc.raw ?? "";
  const desc = LICENSE_DESCRIPTIONS[lc.riskCategory] ?? "";
  const lcColor = lc.riskCategory === "permissive" ? chalk.green
    : (lc.riskCategory === "no-license" || lc.riskCategory === "unlicensed" || lc.riskCategory === "network-copyleft") ? chalk.red
    : chalk.yellow;
  return (
    <Text key="license-info">
      {T.branch} {lcColor(spdx)} {chalk.dim("\u2014")} {chalk.dim(desc)}
    </Text>
  );
}

const FindingsSummary: React.FC<{
  group: PackageGroup;
  maxWidth: number;
  maxLines?: number | undefined;
}> = ({ group, maxWidth, maxLines }) => {
  const rep = firstPackage(group);
  const visibleFindings = rep.findings
    .filter((f) => f.severity > 1)
    .sort((a, b) => b.severity - a.severity);

  const hasAffects = group.packages.length > 3;

  const allLines: React.ReactNode[] = [];

  const lcLine = licenseLine(rep);
  if (lcLine) allLines.push(lcLine);

  const downgrade = packageDowngradeLine(rep);
  if (downgrade) {
    allLines.push(
      <Text key="provenance-downgrade" wrap="truncate-end">
        {T.branch} {chalk.yellow(downgrade)}
      </Text>
    );
  }

  // Render findings — API returns tier-gated data:
  //   Free: { category, severity } — don't show raw IDs, just upgrade prompt
  //   Pro:  { category, severity, title } — show category + title
  //   Team: { category, severity, title, evidence } — show everything
  const isFree = visibleFindings.length > 0 && !visibleFindings[0]?.title;

  if (isFree) {
    allLines.push(
      <Text key="upgrade" dimColor>
        {hasAffects ? T.branch : T.last} {chalk.yellow("\u2192")} {chalk.yellow("Upgrade to Pro")} for finding details
      </Text>
    );
  } else {
    for (let idx = 0; idx < visibleFindings.length; idx++) {
      const f = visibleFindings[idx];
      if (!f) continue;
      const isLast = !hasAffects && idx === visibleFindings.length - 1;
      const connector = isLast ? T.last : T.branch;
      const sevLabel = SEVERITY_LABELS[f.severity] ?? "INFO";
      const sevColor = SEVERITY_COLORS[f.severity] ?? SEVERITY_COLORS[1] ?? chalk.dim;
      const title = f.title ? `: ${f.title}` : "";
      allLines.push(
        <Text key={`finding-${idx}`} wrap="truncate-end">
          {connector} {sevColor(pad(sevLabel, 5))} {chalk.dim(f.category ?? "")}{title}
        </Text>
      );
    }
  }

  if (visibleFindings.length === 0 && rep.score > 0) {
    allLines.push(
      <Text key="score-only" dimColor>
        {hasAffects ? T.branch : T.last} Score: {rep.score}/100
      </Text>
    );
  }
  if (visibleFindings.length === 0 && rep.score === 0) {
    const statusLines = statusSummaryLines(rep);
    statusLines.forEach((line, i) => {
      const isLast = !hasAffects && i === statusLines.length - 1;
      allLines.push(
        <Text key={`status-${i}`} wrap="truncate-end">
          {isLast ? T.last : T.branch}{" "}
          {rep.action === "analysis_incomplete"
            ? chalk.yellow(line)
            : (rep.action ?? "pass") === "pass"
              ? chalk.green(`✓ ${line}`)
              : chalk.dim(line)}
        </Text>
      );
    });
  }
  if (hasAffects) {
    allLines.push(
      <Text key="affects" dimColor>
        {T.last} {truncate(affectsLine(group), maxWidth - 8)}
      </Text>
    );
  }

  const linesToShow = maxLines !== undefined ? allLines.slice(0, maxLines) : allLines;

  return (
    <Box flexDirection="column" marginLeft={5}>
      {linesToShow}
    </Box>
  );
};

