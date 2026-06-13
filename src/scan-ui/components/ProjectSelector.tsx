import React, { useState } from "react";
import { Box, Text, useInput } from "ink";
import chalk from "chalk";
import { FoundProject } from "../shims.js";
import { sanitize } from "../../security/sanitize.js";
import { useTerminalSize } from "../hooks/useTerminalSize.js";

interface Props {
  projects: FoundProject[];
  onConfirm: (selected: FoundProject[]) => void;
  onCancel: () => void;
  userStatus?: string | undefined;
}

export const ProjectSelector: React.FC<Props> = ({ projects, onConfirm, onCancel, userStatus }) => {
  const [cursor, setCursor] = useState(0);
  const [selected, setSelected] = useState<Set<number>>(() => new Set(projects.map((_, i) => i)));
  const { cols: termCols } = useTerminalSize();

  useInput((input, key) => {
    if (key.upArrow || input === "k") {
      setCursor((c) => Math.max(0, c - 1));
    } else if (key.downArrow || input === "j") {
      setCursor((c) => Math.min(projects.length - 1, c + 1));
    } else if (input === " ") {
      setSelected((prev) => {
        const next = new Set(prev);
        if (next.has(cursor)) next.delete(cursor);
        else next.add(cursor);
        return next;
      });
    } else if (input === "a") {
      setSelected((prev) => {
        if (prev.size === projects.length) return new Set();
        return new Set(projects.map((_, i) => i));
      });
    } else if (key.return) {
      const picked = projects.filter((_, i) => selected.has(i));
      if (picked.length > 0) onConfirm(picked);
    } else if (input === "q" || key.escape) {
      onCancel();
    }
  });

  const ecosystemLabel = (eco: string) =>
    eco === "npm" ? chalk.magenta("npm") : chalk.blue("pip");

  return (
    <Box flexDirection="column" paddingLeft={1}>
      <Text>{chalk.bold("Dependency Guardian")}  {userStatus ?? ""}</Text>
      <Text>{""}</Text>
      <Text bold>Found {projects.length} project{projects.length !== 1 ? "s" : ""}</Text>
      <Text>{""}</Text>
      {projects.map((proj, i) => {
        const isCursor = i === cursor;
        const isSelected = selected.has(i);
        const prefix = isCursor ? chalk.cyan("\u258C") : " ";
        const check = isSelected ? chalk.green("\u25C9") : chalk.dim("\u25CB");
        const ecoCount = `${ecosystemLabel(proj.ecosystem)} ${proj.packageCount} packages`;
        const ecoCountPlainLen = `${proj.ecosystem} ${proj.packageCount} packages`.length;
        const fixedPrefixLen = 4;
        const pathColWidth = Math.max(20, termCols - fixedPrefixLen - ecoCountPlainLen - 3);
        const path = sanitize(proj.relativePath);
        const pathTruncated = path.length > pathColWidth
          ? path.slice(0, Math.max(1, pathColWidth - 1)) + "\u2026"
          : path.padEnd(pathColWidth);
        return (
          <Text key={i} {...(isCursor ? { backgroundColor: "#1a1a2e" } : {})} wrap="truncate-end">
            {prefix}{check}  {pathTruncated} {ecoCount}
          </Text>
        );
      })}
      <Text>{""}</Text>
      <Text dimColor>
        {selected.size === 0
          ? chalk.yellow("Select at least 1 project to scan")
          : `${selected.size} of ${projects.length} selected`}
      </Text>
      <Text>{""}</Text>
      <Text>
        {chalk.bold.cyan("space")} {chalk.dim("toggle")}{"   "}
        {chalk.bold.cyan("a")} {chalk.dim("all")}{"   "}
        {chalk.bold.hex('#FFD700')("\u23CE")} {chalk.bold.hex('#FFD700')("scan")}{"   "}
        {chalk.bold.cyan("q")} {chalk.dim("quit")}
      </Text>
    </Box>
  );
};
