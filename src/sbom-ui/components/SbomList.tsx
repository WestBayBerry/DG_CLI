import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { pad, truncate } from "../../scan-ui/format-helpers.js";
import type { SbomRow } from "../inventory.js";

interface SbomListProps {
  readonly rows: readonly SbomRow[];
  readonly selected: number;
  readonly height: number;
  readonly width: number;
  readonly emptyMessage: string;
}

export function verdictGlyph(row: SbomRow): string {
  if (!row.scannable) {
    return chalk.dim("·");
  }
  if (!row.verdict) {
    return chalk.dim("…");
  }
  switch (row.verdict.action) {
    case "block":
      return chalk.red.bold("✘");
    case "warn":
      return chalk.yellow("⚠");
    case "pass":
      return chalk.green("✓");
    default:
      return chalk.cyan("?");
  }
}

function windowStart(selected: number, count: number, height: number): number {
  if (count <= height) {
    return 0;
  }
  const half = Math.floor(height / 2);
  return Math.min(Math.max(0, selected - half), count - height);
}

export const SbomList: React.FC<SbomListProps> = ({ rows, selected, height, width, emptyMessage }) => {
  if (rows.length === 0) {
    return (
      <Box paddingLeft={1}>
        <Text>{chalk.dim(emptyMessage)}</Text>
      </Box>
    );
  }
  const ecoWidth = 6;
  const licenseWidth = Math.min(20, Math.max(10, Math.floor(width * 0.22)));
  const hashWidth = 11;
  const nameWidth = Math.max(12, width - 2 - 2 - ecoWidth - 1 - licenseWidth - 1 - hashWidth - 2);
  const start = windowStart(selected, rows.length, height);
  const shown = rows.slice(start, start + height);

  return (
    <Box flexDirection="column">
      {shown.map((row, index) => {
        const isSelected = start + index === selected;
        const cursor = isSelected ? chalk.cyan("›") : " ";
        const id = truncate(`${row.name}@${row.version}`, nameWidth);
        const name = isSelected ? chalk.bold(pad(id, nameWidth)) : pad(id, nameWidth);
        const eco = chalk.dim(pad(row.ecosystem, ecoWidth));
        const license = row.license
          ? chalk.dim(pad(truncate(row.license, licenseWidth), licenseWidth))
          : chalk.yellow(pad("no license", licenseWidth));
        const hash = row.hasHash ? chalk.dim(pad("checksum", hashWidth)) : chalk.yellow(pad("no checksum", hashWidth));
        return (
          <Text key={row.key}>
            {cursor} {verdictGlyph(row)} {name} {eco} {license} {hash}
          </Text>
        );
      })}
      {rows.length > height ? (
        <Text>{chalk.dim(`  ${start + 1}–${Math.min(start + height, rows.length)} of ${rows.length}`)}</Text>
      ) : null}
    </Box>
  );
};
