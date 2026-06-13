import React, { useEffect, useMemo, useRef, useState } from "react";
import { Box, Text, useInput } from "ink";
import chalk from "chalk";
import { findingLocation, type AuditFinding } from "../../audit/detectors.js";
import type { DeepResult } from "../../audit/deep.js";
import { isLoggedIn } from "../../scan-ui/shims.js";
import { clearScreen } from "../../scan-ui/alt-screen.js";
import { useTerminalSize } from "../../scan-ui/hooks/useTerminalSize.js";
import { pad, truncate } from "../../scan-ui/format-helpers.js";
import { AuditHeader } from "./AuditHeader.js";
import { DeepStatusRow } from "./DeepStatusRow.js";
import { countSummary, severityGlyph, severityRole, type VerdictAction } from "../format.js";
import { buildExport, type AuditExportFormat, type AuditExportInput } from "../export.js";
import { ExportDialog, loginRequiredToast, type ExportOption, type ExportOutcome } from "../../export-ui/ExportDialog.js";
import { resolvePresentation } from "../../presentation/mode.js";
import { createTheme } from "../../presentation/theme.js";

interface AuditResultsViewProps {
  readonly findings: readonly AuditFinding[];
  readonly action: VerdictAction;
  readonly artifact: string;
  readonly ecosystem: string;
  readonly target: string;
  readonly fileCount: number;
  readonly publishSetSource: string;
  readonly deep: DeepResult | null;
  readonly onExit: () => void;
}

const ROLE_PAINT: Record<string, (s: string) => string> = {
  block: chalk.red,
  warn: chalk.yellow,
  muted: chalk.dim
};

function glyphPaint(severity: number): (s: string) => string {
  return ROLE_PAINT[severityRole(severity)] ?? chalk.dim;
}

const FIXED_CHROME = 12;
const EXPAND_CHROME = 10;

const EXPORT_FORMATS: ReadonlyArray<{ format: AuditExportFormat; label: string }> = [
  { format: "json", label: "JSON" },
  { format: "md", label: "Markdown" },
  { format: "txt", label: "Plain text" }
];

export const AuditResultsView: React.FC<AuditResultsViewProps> = ({
  findings,
  action,
  artifact,
  ecosystem,
  target,
  fileCount,
  publishSetSource,
  deep,
  onExit
}) => {
  const { rows: termRows, cols: termCols } = useTerminalSize();

  const [cursor, setCursor] = useState(0);
  const [expanded, setExpanded] = useState(false);
  const [expandScroll, setExpandScroll] = useState(0);
  const [viewport, setViewport] = useState(0);

  const [searchMode, setSearchMode] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const searchModeRef = useRef(searchMode);
  searchModeRef.current = searchMode;

  const [showHelp, setShowHelp] = useState(false);
  const showHelpRef = useRef(showHelp);
  showHelpRef.current = showHelp;

  const [exportDialog, setExportDialog] = useState<readonly ExportOption[] | null>(null);
  const exportDialogRef = useRef(exportDialog);
  exportDialogRef.current = exportDialog;
  const theme = useMemo(() => createTheme(resolvePresentation().color), []);

  const [exportMsg, setExportMsg] = useState<{ text: string; tone: "ok" | "error" | "nudge" } | null>(null);
  const exportTimer = useRef<NodeJS.Timeout | null>(null);
  const showExportMsg = (text: string, tone: "ok" | "error" | "nudge" = "ok"): void => {
    setExportMsg({ text, tone });
    if (exportTimer.current) clearTimeout(exportTimer.current);
    exportTimer.current = setTimeout(() => setExportMsg(null), 4000);
  };

  useEffect(() => () => {
    if (exportTimer.current) clearTimeout(exportTimer.current);
  }, []);

  const filtered = useMemo(() => {
    if (!searchQuery) return findings;
    const q = searchQuery.toLowerCase();
    return findings.filter((f) => f.location.toLowerCase().includes(q) || f.title.toLowerCase().includes(q));
  }, [findings, searchQuery]);

  const expandedRef = useRef(expanded);
  expandedRef.current = expanded;
  const cursorRef = useRef(cursor);
  cursorRef.current = cursor;
  const expandScrollRef = useRef(expandScroll);
  expandScrollRef.current = expandScroll;
  const viewportRef = useRef(viewport);
  viewportRef.current = viewport;

  const innerWidth = Math.max(40, termCols - 8);
  const listRows = Math.max(3, termRows - FIXED_CHROME);
  const clampedCursor = filtered.length > 0 ? Math.min(cursor, filtered.length - 1) : 0;

  const expandLines = useMemo<string[]>(() => {
    const finding = filtered[clampedCursor];
    if (!finding) return [];
    const lines: string[] = [];
    if (finding.evidence && finding.evidence !== `path: ${finding.location}` && finding.evidence !== finding.location) {
      lines.push(chalk.dim(finding.evidence));
    }
    lines.push(`${chalk.cyan("→")} ${finding.recommendation}`);
    return lines;
  }, [filtered, clampedCursor]);

  const expandViewportRows = Math.max(2, termRows - EXPAND_CHROME);

  const moveCursor = (next: number, keepExpanded = false): void => {
    const clamped = Math.max(0, Math.min(filtered.length - 1, next));
    setCursor(clamped);
    setExpanded(keepExpanded);
    setExpandScroll(0);
    if (clamped < viewportRef.current) {
      setViewport(clamped);
    } else if (clamped >= viewportRef.current + listRows) {
      setViewport(clamped - listRows + 1);
    }
  };

  const openExport = (): void => {
    if (!isLoggedIn()) {
      showExportMsg(loginRequiredToast(), "nudge");
      return;
    }
    const input: AuditExportInput = {
      target,
      artifact,
      ecosystem,
      action,
      fileCount,
      publishSetSource,
      findings,
      deep: deep ?? { ran: false, reason: "deep behavioral scan did not run" }
    };
    setExportDialog(EXPORT_FORMATS.map(({ format, label }) => ({
      label,
      defaultName: `dg-audit.${format}`,
      render: () => buildExport(input, format).body
    })));
  };

  const handleExportDone = (result: ExportOutcome | null): void => {
    setExportDialog(null);
    clearScreen();
    if (result === null) return;
    if ("path" in result) showExportMsg(`✓ Exported to ${result.path}`);
    else showExportMsg(`Export failed: ${result.error}`, "error");
  };

  useInput((input, key) => {
    if (exportDialogRef.current) return;

    if (showHelpRef.current) {
      if (input === "?" || key.escape) setShowHelp(false);
      else if (input === "q") onExit();
      return;
    }

    if (searchModeRef.current) {
      if (key.escape) {
        setSearchMode(false);
        setSearchQuery("");
        setCursor(0);
        setViewport(0);
        setExpanded(false);
      } else if (key.return) {
        setSearchMode(false);
      } else if (key.backspace || key.delete) {
        setSearchQuery((q) => q.slice(0, -1));
        setCursor(0);
        setViewport(0);
      } else if (input && !key.upArrow && !key.downArrow && /^[\x20-\x7e]+$/.test(input)) {
        setSearchQuery((q) => q + input);
        setCursor(0);
        setViewport(0);
      }
      return;
    }

    if (expandedRef.current) {
      if (key.escape || key.return) { setExpanded(false); setExpandScroll(0); return; }
      if (input === "q") { onExit(); return; }
      if (key.upArrow || input === "k") { moveCursor(cursorRef.current - 1, true); return; }
      if (key.downArrow || input === "j") { moveCursor(cursorRef.current + 1, true); return; }
      if (input === "g") { moveCursor(0, true); return; }
      if (input === "G") { moveCursor(filtered.length - 1, true); return; }
      if (input === "/") { setSearchMode(true); setExpanded(false); setExpandScroll(0); return; }
      if (input === "?") { setShowHelp(true); return; }
      if (input === "e") { openExport(); return; }
      return;
    }

    if (input === "?") { setShowHelp(true); return; }
    if (input === "e") { openExport(); return; }
    if (input === "q") { onExit(); return; }

    if (filtered.length === 0) {
      if (input === "/") setSearchMode(true);
      else if (key.return) onExit();
      return;
    }

    if (key.upArrow || input === "k") moveCursor(cursorRef.current - 1);
    else if (key.downArrow || input === "j") moveCursor(cursorRef.current + 1);
    else if (input === "g") moveCursor(0);
    else if (input === "G") moveCursor(filtered.length - 1);
    else if (key.pageDown) moveCursor(cursorRef.current + listRows);
    else if (key.pageUp) moveCursor(cursorRef.current - listRows);
    else if (key.return) { setExpanded(true); setExpandScroll(0); }
    else if (input === "/") setSearchMode(true);
  }, { isActive: exportDialog === null });

  if (exportDialog) {
    return (
      <Box flexDirection="column">
        <AuditHeader action={action} artifact={artifact} ecosystem={ecosystem} countSummary={countSummary(findings)} fileCount={fileCount} fallback={publishSetSource === "fallback"} />
        <ExportDialog options={exportDialog} theme={theme} cwd={process.cwd()} onDone={handleExportDone} />
      </Box>
    );
  }

  if (showHelp) {
    return (
      <Box flexDirection="column">
        <AuditHeader action={action} artifact={artifact} ecosystem={ecosystem} countSummary={countSummary(findings)} fileCount={fileCount} fallback={publishSetSource === "fallback"} />
        <Box flexDirection="column" borderStyle="round" borderColor="cyan" paddingLeft={2} paddingRight={2} width="100%">
          <Text bold>Keyboard Shortcuts</Text>
          <Text>{""}</Text>
          <Text bold> Navigation</Text>
          <Text>   {chalk.cyan("↑ k")}     {chalk.dim("Move up")}</Text>
          <Text>   {chalk.cyan("↓ j")}     {chalk.dim("Move down")}</Text>
          <Text>   {chalk.cyan("g")}       {chalk.dim("Jump to top")}</Text>
          <Text>   {chalk.cyan("G")}       {chalk.dim("Jump to bottom")}</Text>
          <Text>   {chalk.cyan("PgUp")}    {chalk.dim("Page up")}</Text>
          <Text>   {chalk.cyan("PgDn")}    {chalk.dim("Page down")}</Text>
          <Text>{""}</Text>
          <Text bold> Actions</Text>
          <Text>   {chalk.cyan("⏎")}       {chalk.dim("Expand / collapse finding (evidence + recommendation)")}</Text>
          <Text>   {chalk.cyan("/")}       {chalk.dim("Search findings")}</Text>
          <Text>   {chalk.cyan("e")}       {chalk.dim("Export menu — Findings as JSON / Markdown / text")}</Text>
          <Text>   {chalk.cyan("q")}       {chalk.dim("Quit")}</Text>
          <Text>{""}</Text>
          <Text dimColor> Press {chalk.bold.cyan("?")} or {chalk.bold.cyan("Esc")} to close</Text>
        </Box>
      </Box>
    );
  }

  const visible = filtered.slice(viewport, viewport + listRows);
  const aboveCount = viewport;
  const belowCount = Math.max(0, filtered.length - viewport - listRows);
  const locCol = Math.max(20, Math.floor(innerWidth * 0.45));
  const titleCol = Math.max(16, innerWidth - locCol - 4);

  const focused = filtered[clampedCursor];

  return (
    <Box flexDirection="column">
      <AuditHeader action={action} artifact={artifact} ecosystem={ecosystem} countSummary={countSummary(findings)} fileCount={fileCount} fallback={publishSetSource === "fallback"} />

      <Text dimColor>{chalk.dim("─".repeat(Math.max(20, termCols - 4)))}</Text>
      <Box flexDirection="column" paddingLeft={1} paddingRight={1} width="100%">
        <Box justifyContent="space-between">
          <Text bold>Findings</Text>
          <Text dimColor>{searchQuery ? `${filtered.length} of ${findings.length}` : filtered.length > 0 ? `${clampedCursor + 1}/${filtered.length}` : "0"}</Text>
        </Box>

        {aboveCount > 0 && <Text dimColor>{chalk.cyan(" ↑")} {aboveCount} more above</Text>}

        {filtered.length === 0 && (
          <Text dimColor>{searchQuery ? `  (no findings match "${searchQuery}")` : "  No findings — the publish set is clean."}</Text>
        )}

        {visible.map((finding, visIdx) => {
          const globalIdx = viewport + visIdx;
          const isCursor = globalIdx === clampedCursor;
          const paint = glyphPaint(finding.severity);
          const glyph = severityGlyph(finding.severity);
          const loc = pad(truncate(findingLocation(finding), locCol - 1), locCol);
          const title = truncate(finding.title, titleCol);
          if (isCursor) {
            return (
              <Text key={`${finding.id}|${finding.location}`} backgroundColor="#1a1a2e">
                {chalk.cyan("▌")} {paint(glyph)} {chalk.bold(loc)}{chalk.dim(title)}
              </Text>
            );
          }
          return (
            <Text key={`${finding.id}|${finding.location}`}>
              {"  "}{paint(glyph)} {loc}{chalk.dim(title)}
            </Text>
          );
        })}

        {belowCount > 0 && <Text dimColor>{chalk.cyan(" ↓")} {belowCount} more below</Text>}

        {expanded && focused && (
          <Box flexDirection="column" marginTop={1} marginLeft={4}>
            <Text bold>{findingLocation(focused)}{chalk.dim(" — ")}{focused.title}</Text>
            {expandLines.slice(expandScroll, expandScroll + expandViewportRows).map((line, i) => (
              <Text key={i}>{line}</Text>
            ))}
            {expandLines.length > expandViewportRows && (
              <Text dimColor>{`  ${expandScroll + 1}-${Math.min(expandScroll + expandViewportRows, expandLines.length)} / ${expandLines.length}  (Esc collapse)`}</Text>
            )}
          </Box>
        )}
      </Box>

      <Text dimColor>{chalk.dim("─".repeat(Math.max(20, termCols - 4)))}</Text>
      <DeepStatusRow deep={deep} />

      <Text dimColor>{chalk.dim("─".repeat(Math.max(20, termCols - 4)))}</Text>
      {searchMode ? (
        <Text>
          {" "}{chalk.bold.cyan("/")} {searchQuery}{chalk.cyan("█")}
          {"   "}{chalk.dim("Esc clear · Enter confirm")}
        </Text>
      ) : (
        <Text>
          {" "}
          {filtered.length > 0 && (
            <>
              {chalk.bold.cyan("↑↓")} {chalk.dim("navigate")}{"   "}
              {chalk.bold.cyan("⏎")} {chalk.dim(expanded ? "collapse" : "expand")}{"   "}
              {chalk.bold.cyan("/")} {chalk.dim("search")}{"   "}
            </>
          )}
          {chalk.bold.cyan("e")} {chalk.dim("export")}{"   "}
          {chalk.bold.cyan("?")} {chalk.dim("help")}{"   "}
          {chalk.bold.cyan("q")} {chalk.dim("quit")}
          {exportMsg && <>{"   "}{exportMsg.tone === "nudge" ? exportMsg.text : (exportMsg.tone === "error" ? chalk.red : chalk.green)(exportMsg.text)}</>}
        </Text>
      )}
    </Box>
  );
};
