import React, { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { Box, Text, useApp, useInput } from "ink";
import chalk from "chalk";
import { useTerminalSize } from "../scan-ui/hooks/useTerminalSize.js";
import { useResizeRepaint } from "../scan-ui/hooks/useResizeRepaint.js";
import { leaveTui, showCursor, tuiIsActive } from "../scan-ui/alt-screen.js";
import { SbomHeader } from "./components/SbomHeader.js";
import { SbomList } from "./components/SbomList.js";
import { componentsCsv, componentsMarkdown, emptyFilterMessage, filterRows, tallyVerdicts, type RowEcosystem, type SbomFilter } from "./inventory.js";
import { ExportDialog, loginRequiredToast, type ExportOption, type ExportOutcome } from "../export-ui/ExportDialog.js";
import { isLoggedIn } from "../scan-ui/shims.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme } from "../presentation/theme.js";
import type { SbomStore } from "./store.js";

interface SbomAppProps {
  readonly store: SbomStore;
  readonly document: string;
  readonly cwd: string;
}

const HEADER_LINES = 9;
const FOOTER_LINES = 2;
const COUNTER_LINE = 1;
const SAFETY_LINE = 1;

const FILTER_CYCLE: readonly SbomFilter[] = ["all", "risky", "unlicensed"];
const FILTER_LABEL: Record<SbomFilter, string> = { all: "all", risky: "risky", unlicensed: "unlicensed", unpinned: "unpinned" };

function ecosystemCounts(rows: ReadonlyArray<{ ecosystem: RowEcosystem }>): Array<[RowEcosystem, number]> {
  const counts = new Map<RowEcosystem, number>();
  for (const row of rows) {
    counts.set(row.ecosystem, (counts.get(row.ecosystem) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

export const SbomApp: React.FC<SbomAppProps> = ({ store, document, cwd }) => {
  const view = useSyncExternalStore(store.subscribe, store.get, store.get);
  const { exit } = useApp();
  const { rows: termRows, cols: termCols } = useTerminalSize();
  useResizeRepaint();

  const [selected, setSelected] = useState(0);
  const [filter, setFilter] = useState<SbomFilter>("all");
  const [query, setQuery] = useState("");
  const [searching, setSearching] = useState(false);
  const [exportDialog, setExportDialog] = useState<readonly ExportOption[] | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const theme = useMemo(() => createTheme(resolvePresentation().color), []);

  const showToast = useCallback((message: string) => {
    setToast(message);
    if (toastTimer.current) {
      clearTimeout(toastTimer.current);
    }
    toastTimer.current = setTimeout(() => setToast(null), 4000);
  }, []);

  const leaveAltScreen = useCallback(() => {
    if (tuiIsActive()) {
      leaveTui();
    } else {
      showCursor();
    }
  }, []);
  useEffect(() => () => leaveAltScreen(), [leaveAltScreen]);
  useEffect(() => () => {
    if (toastTimer.current) {
      clearTimeout(toastTimer.current);
    }
  }, []);

  const visible = filterRows(view.rows, filter, query);
  const clamped = Math.min(selected, Math.max(0, visible.length - 1));
  const tally = tallyVerdicts(view.rows);
  const cargoCount = view.rows.filter((row) => row.ecosystem === "cargo").length;

  const quit = useCallback(() => {
    process.exitCode = 0;
    leaveAltScreen();
    exit();
  }, [exit, leaveAltScreen]);

  const openExport = useCallback(() => {
    if (!isLoggedIn()) {
      showToast(loginRequiredToast());
      return;
    }
    setToast(null);
    setExportDialog([
      { label: "CycloneDX JSON", defaultName: "sbom.cdx.json", render: () => document },
      { label: "Components CSV", defaultName: "sbom-components.csv", render: () => componentsCsv(view.rows) },
      { label: "Components Markdown", defaultName: "sbom-components.md", render: () => componentsMarkdown(view.rows) }
    ]);
  }, [document, view.rows, showToast]);

  const handleExportDone = useCallback((result: ExportOutcome | null) => {
    setExportDialog(null);
    if (result === null) return;
    showToast("path" in result ? chalk.green(`✓ exported ${result.path}`) : chalk.red(`export failed: ${result.error}`));
  }, [showToast]);

  useInput((input, key) => {
    if (exportDialog) return;
    if (searching) {
      if (key.escape) {
        setSearching(false);
        setQuery("");
        setSelected(0);
        return;
      }
      if (key.return) {
        setSearching(false);
        return;
      }
      if (key.backspace || key.delete) {
        setQuery((q) => q.slice(0, -1));
        return;
      }
      if (input && !key.ctrl && !key.meta && !key.upArrow && !key.downArrow && /^[\x20-\x7e]+$/.test(input)) {
        setQuery((q) => q + input);
        setSelected(0);
      }
      return;
    }
    if (key.escape && query) {
      setQuery("");
      setSelected(0);
      return;
    }
    if (input === "q" || key.escape) {
      quit();
      return;
    }
    if (input === "j" || key.downArrow) {
      setSelected((s) => Math.min(s + 1, Math.max(0, visible.length - 1)));
      return;
    }
    if (input === "k" || key.upArrow) {
      setSelected((s) => Math.max(0, s - 1));
      return;
    }
    if (input === "g") {
      setSelected(0);
      return;
    }
    if (input === "G") {
      setSelected(Math.max(0, visible.length - 1));
      return;
    }
    if (input === "/") {
      setSearching(true);
      setToast(null);
      return;
    }
    if (input === "f") {
      const next = FILTER_CYCLE[(FILTER_CYCLE.indexOf(filter) + 1) % FILTER_CYCLE.length] ?? "all";
      setFilter(next);
      setSelected(0);
      return;
    }
    if (input === "e") {
      openExport();
    }
  });

  const listHeight = Math.max(3, termRows - HEADER_LINES - FOOTER_LINES - COUNTER_LINE - SAFETY_LINE);

  if (exportDialog) {
    return (
      <Box flexDirection="column">
        <SbomHeader
          total={view.rows.length}
          ecosystems={ecosystemCounts(view.rows)}
          phase={view.phase}
          tally={tally}
          scannable={view.scannable}
          scanProgress={view.scanProgress}
          scanError={view.scanError}
          usage={view.usage}
          subject={view.subject}
          cargoCount={cargoCount}
        />
        <ExportDialog options={exportDialog} theme={theme} cwd={cwd} onDone={handleExportDone} />
      </Box>
    );
  }

  return (
    <Box flexDirection="column">
      <SbomHeader
        total={view.rows.length}
        ecosystems={ecosystemCounts(view.rows)}
        phase={view.phase}
        tally={tally}
        scannable={view.scannable}
        scanProgress={view.scanProgress}
        scanError={view.scanError}
        usage={view.usage}
        subject={view.subject}
        cargoCount={cargoCount}
      />
      <SbomList
        rows={visible}
        selected={clamped}
        height={listHeight}
        width={termCols}
        emptyMessage={emptyFilterMessage(filter, query, view.phase, tally, view.scanError)}
      />
      <Box paddingLeft={1} flexDirection="column">
        {toast ? <Text>{toast}</Text> : null}
        {searching ? (
          <Text>{chalk.cyan("/")}{query}{chalk.dim("   esc to clear")}</Text>
        ) : query ? (
          <Text>
            {chalk.cyan("/")}{query}{chalk.dim(`   ${visible.length} of ${view.rows.length} components   esc clear   q quit`)}
          </Text>
        ) : (
          <Text>
            {chalk.dim("↑↓ move   / search   f ")}{chalk.dim(`filter: ${FILTER_LABEL[filter]}`)}{chalk.dim("   ")}{chalk.bold("e")}{chalk.dim(" export   q quit")}
          </Text>
        )}
      </Box>
    </Box>
  );
};
