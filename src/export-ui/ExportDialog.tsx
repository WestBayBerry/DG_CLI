import React, { useMemo, useState } from "react";
import { Box, Text, useInput } from "ink";
import chalk from "chalk";
import { existsSync, readdirSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";
import type { Theme } from "../presentation/theme.js";
import { exportDestinations, resolveExportPath, userHomeDir, writeReportAtomic, type ExportDestination } from "../util/report-writer.js";

export interface ExportOption {
  readonly label: string;
  readonly defaultName: string;
  render(): string;
}

export type ExportOutcome = { readonly path: string } | { readonly error: string };

export function loginRequiredToast(): string {
  return `${chalk.yellow("Sign in to export:")} ${chalk.cyan.bold("dg login")} ${chalk.dim("(free account)")}`;
}

interface ExportDialogProps {
  readonly options: readonly ExportOption[];
  readonly theme: Theme;
  readonly cwd: string;
  readonly onDone: (result: ExportOutcome | null) => void;
  readonly env?: NodeJS.ProcessEnv;
}

interface PathField {
  readonly value: string;
  readonly cursor: number;
}

const PATH_DISPLAY_MAX = 48;

function cursorBeforeExtension(name: string): number {
  const slash = name.lastIndexOf("/");
  const dot = name.indexOf(".", slash + 2);
  return dot > slash + 1 ? dot : name.length;
}

function fieldFor(name: string): PathField {
  return { value: name, cursor: cursorBeforeExtension(name) };
}

function abbreviateHome(dir: string, home: string): string {
  if (dir === home) return "~";
  if (dir.startsWith(home + sep)) return `~${dir.slice(home.length)}`;
  return dir;
}

function truncatePath(text: string): string {
  if (text.length <= PATH_DISPLAY_MAX) return text;
  return `…${text.slice(text.length - PATH_DISPLAY_MAX + 1)}`;
}

function prefillFor(dir: string, cwd: string, home: string, filename: string): string {
  if (resolve(dir) === resolve(cwd)) return filename;
  if (dir === home) return `~/${filename}`;
  if (dir.startsWith(home + sep)) return `~${dir.slice(home.length)}/${filename}`;
  return join(dir, filename);
}

function completePath(value: string, cwd: string): string {
  const slash = value.lastIndexOf("/");
  const dir = slash < 0 ? "" : value.slice(0, slash + 1);
  const fragment = slash < 0 ? value : value.slice(slash + 1);
  let entries: readonly { name: string; isDir: boolean }[];
  try {
    entries = readdirSync(resolveExportPath(dir === "" ? "." : dir, cwd), { withFileTypes: true })
      .map((entry) => ({ name: entry.name, isDir: entry.isDirectory() }));
  } catch {
    return value;
  }
  const match = entries
    .filter((entry) => entry.name.toLowerCase().startsWith(fragment.toLowerCase()))
    .sort((a, b) => (a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1))[0];
  if (!match) return value;
  return `${dir}${match.name}${match.isDir ? "/" : ""}`;
}

export const ExportDialog: React.FC<ExportDialogProps> = ({ options, theme, cwd, onDone, env = process.env }) => {
  const multi = options.length > 1;
  const [stage, setStage] = useState<"format" | "dest" | "path">(multi ? "format" : "dest");
  const [selected, setSelected] = useState(0);
  const [destIndex, setDestIndex] = useState(0);
  const [field, setField] = useState<PathField>({ value: "", cursor: 0 });

  const home = useMemo(() => userHomeDir(env), [env]);
  const destinations = useMemo(() => exportDestinations(cwd, env), [cwd, env]);
  const option = options[selected];
  const filename = basename(option?.defaultName ?? "");
  const rowCount = destinations.length + 1;

  const writeTo = (target: string): void => {
    if (!option) return;
    try {
      writeReportAtomic(target, option.render());
      onDone({ path: target });
    } catch (error) {
      onDone({ error: error instanceof Error ? error.message : "write failed" });
    }
  };

  const openEditor = (dest: ExportDestination | undefined): void => {
    const prefill = dest ? prefillFor(dest.dir, cwd, home, filename) : filename;
    setField(fieldFor(prefill));
    setStage("path");
  };

  const insertAtCursor = (text: string): void => {
    setField((f) => ({ value: f.value.slice(0, f.cursor) + text + f.value.slice(f.cursor), cursor: f.cursor + text.length }));
  };

  const moveCursor = (to: (f: PathField) => number): void => {
    setField((f) => ({ ...f, cursor: Math.max(0, Math.min(f.value.length, to(f))) }));
  };

  useInput((input, key) => {
    if (stage === "format") {
      if (key.escape || input === "q") { onDone(null); return; }
      if (key.return) { setStage("dest"); return; }
      if (key.upArrow || input === "k") { setSelected((s) => Math.max(0, s - 1)); return; }
      if (key.downArrow || input === "j") { setSelected((s) => Math.min(options.length - 1, s + 1)); return; }
      return;
    }
    if (stage === "dest") {
      if (key.escape) { if (multi) setStage("format"); else onDone(null); return; }
      if (input === "t") { openEditor(destinations[destIndex]); return; }
      if (key.upArrow || input === "k") { setDestIndex((d) => Math.max(0, d - 1)); return; }
      if (key.downArrow || input === "j") { setDestIndex((d) => Math.min(rowCount - 1, d + 1)); return; }
      if (key.return) {
        const dest = destinations[destIndex];
        if (dest) writeTo(join(dest.dir, filename));
        else openEditor(destinations[destIndex - 1] ?? destinations[0]);
      }
      return;
    }
    if (key.escape) { setStage("dest"); return; }
    if (key.return) {
      const trimmed = field.value.trim();
      if (trimmed.length > 0) writeTo(resolveExportPath(trimmed, cwd));
      return;
    }
    if (key.tab) { setField((f) => fieldFor(completePath(f.value, cwd))); return; }
    if (key.leftArrow) { moveCursor((f) => f.cursor - 1); return; }
    if (key.rightArrow) { moveCursor((f) => f.cursor + 1); return; }
    if (key.ctrl && input === "a") { moveCursor(() => 0); return; }
    if (key.ctrl && input === "e") { moveCursor((f) => f.value.length); return; }
    if (key.delete || key.backspace) {
      setField((f) => (f.cursor === 0 ? f : { value: f.value.slice(0, f.cursor - 1) + f.value.slice(f.cursor), cursor: f.cursor - 1 }));
      return;
    }
    if (input && !key.ctrl && !key.meta && /^[\x20-\x7e]+$/.test(input)) {
      insertAtCursor(input);
    }
  });

  const target = field.value.trim().length > 0 ? resolveExportPath(field.value, cwd) : null;
  const targetExists = target !== null && existsSync(target);
  const beforeCursor = field.value.slice(0, field.cursor);
  const atCursor = field.value.charAt(field.cursor);
  const afterCursor = field.value.slice(field.cursor + 1);

  return (
    <Box flexDirection="column">
      <Box flexDirection="column" borderStyle="round" borderColor="cyan" paddingLeft={2} paddingRight={2}>
        <Text bold>Export</Text>
        <Text>{""}</Text>
        {stage === "format" && options.map((opt, idx) => {
          const isSelected = idx === selected;
          return (
            <Box key={opt.label}>
              <Box width={5} flexShrink={0}><Text>{"   "}{isSelected ? chalk.cyan("●") : chalk.dim("○")}</Text></Box>
              <Box flexShrink={1}><Text wrap="truncate-end">{isSelected ? chalk.bold(opt.label) : opt.label}</Text></Box>
            </Box>
          );
        })}
        {stage === "dest" && (
          <>
            {destinations.map((dest, idx) => {
              const isSelected = idx === destIndex;
              const replaces = existsSync(join(dest.dir, filename));
              const shown = truncatePath(`${abbreviateHome(dest.dir, home)}/${filename}`.replace(/\/+/g, "/"));
              return (
                <Box key={dest.label}>
                  <Box width={3} flexShrink={0}><Text>{" "}{isSelected ? chalk.cyan("▸") : " "}</Text></Box>
                  <Box width={14} flexShrink={0}><Text>{isSelected ? chalk.bold(dest.label) : dest.label}</Text></Box>
                  <Box flexShrink={1}>
                    <Text wrap="truncate-start">
                      {theme.paint("muted", shown)}
                      {replaces ? theme.paint("warn", " (replaces)") : ""}
                    </Text>
                  </Box>
                </Box>
              );
            })}
            <Box>
              <Box width={3} flexShrink={0}><Text>{" "}{destIndex === destinations.length ? chalk.cyan("▸") : " "}</Text></Box>
              <Box flexShrink={1}><Text>{destIndex === destinations.length ? chalk.bold("Type a path…") : theme.paint("muted", "Type a path…")}</Text></Box>
            </Box>
          </>
        )}
        {stage === "path" && (
          <>
            {option && <Text dimColor wrap="truncate-end">{option.label}</Text>}
            <Text wrap="truncate-start">
              {chalk.cyan("▌ ")}{chalk.bold("Save as")}  {beforeCursor}{atCursor === "" ? chalk.cyan("█") : chalk.inverse(atCursor) + afterCursor}
            </Text>
            <Text wrap="truncate-start">
              {target === null
                ? theme.paint("muted", "enter a file name")
                : targetExists
                  ? theme.paint("warn", `${target} exists — Enter overwrites`)
                  : theme.paint("muted", `→ ${target}`)}
            </Text>
          </>
        )}
      </Box>
      <Text>
        {" "}
        {stage === "format" ? (
          <>
            {chalk.bold.cyan("↑↓")} {chalk.dim("choose")}{"   "}
            {chalk.bold.cyan("⏎")} {chalk.dim("next")}{"   "}
            {chalk.bold.cyan("Esc")} {chalk.dim("cancel")}
          </>
        ) : stage === "dest" ? (
          <>
            {chalk.bold.cyan("↑↓")} {chalk.dim("choose")}{"   "}
            {chalk.bold.cyan("⏎")} {chalk.dim(`save ${filename}`)}{"   "}
            {chalk.bold.cyan("t")} {chalk.dim("type path")}{"   "}
            {chalk.bold.cyan("Esc")} {chalk.dim(multi ? "back" : "cancel")}
          </>
        ) : (
          <>
            {chalk.bold.cyan("⏎")} {chalk.dim("save")}{"   "}
            {chalk.bold.cyan("Tab")} {chalk.dim("complete")}{"   "}
            {chalk.bold.cyan("Esc")} {chalk.dim("back")}
          </>
        )}
      </Text>
    </Box>
  );
};
