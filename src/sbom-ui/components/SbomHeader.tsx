import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { renderLogo, type LogoAction } from "../../scan-ui/logo.js";
import { useTerminalSize } from "../../scan-ui/hooks/useTerminalSize.js";
import type { ScannerUsage } from "../../api/analyze.js";
import type { SbomPhase } from "../store.js";
import type { RowEcosystem, VerdictTally } from "../inventory.js";

const LOGO_MIN_COLS = 76;
const LOGO_MIN_ROWS = 16;

interface SbomHeaderProps {
  readonly total: number;
  readonly ecosystems: ReadonlyArray<readonly [RowEcosystem, number]>;
  readonly phase: SbomPhase;
  readonly tally: VerdictTally;
  readonly scannable: number;
  readonly scanProgress: number;
  readonly scanError: string | null;
  readonly usage: ScannerUsage | null;
  readonly subject: string;
  readonly cargoCount: number;
}

function logoAction(phase: SbomPhase, tally: VerdictTally, scanError: string | null): LogoAction {
  if (phase !== "done" || scanError) {
    return "analysis_incomplete";
  }
  if (tally.block > 0) return "block";
  if (tally.warn > 0) return "warn";
  if (tally.scanned > 0) return "pass";
  return "analysis_incomplete";
}

function verdictLine(tally: VerdictTally, scanError: string | null): React.ReactNode {
  if (scanError) {
    return <Text>{chalk.dim(scanError)}</Text>;
  }
  return (
    <Text>
      {tally.block > 0 ? chalk.red.bold(`${tally.block} BLOCK`) : chalk.dim("0 BLOCK")}
      {chalk.dim("  ·  ")}
      {tally.warn > 0 ? chalk.yellow(`${tally.warn} WARN`) : chalk.dim("0 WARN")}
      {chalk.dim("  ·  ")}
      {chalk.dim(`${tally.pass} PASS`)}
    </Text>
  );
}

export const SbomHeader: React.FC<SbomHeaderProps> = ({
  total,
  ecosystems,
  phase,
  tally,
  scannable,
  scanProgress,
  scanError,
  usage,
  subject,
  cargoCount
}) => {
  const { cols, rows } = useTerminalSize();
  const breakdown = ecosystems.map(([name, count]) => `${count} ${name}`).join(chalk.dim(" · "));
  const logo = renderLogo(logoAction(phase, tally, scanError));
  const showLogo = cols >= LOGO_MIN_COLS && rows >= LOGO_MIN_ROWS;
  return (
    <Box flexDirection="column" borderStyle="round" borderColor="gray" paddingLeft={1} paddingRight={1}>
      <Box flexDirection="row">
        <Box flexDirection="column" flexGrow={1}>
          <Text>
            {chalk.bold("Dependency Guardian")}{chalk.dim("  ·  SBOM")}
          </Text>
          <Text> </Text>
          <Text>
            {chalk.bold(String(total))} {total === 1 ? "component" : "components"}   {chalk.dim(breakdown)}
          </Text>
          {phase === "inventory" ? null : (
            <>
              {phase === "scanning" && !scanError ? (
                <Text>{chalk.cyan(`scanning ${scanProgress} / ${scannable}`)}{chalk.dim("  npm + pypi")}</Text>
              ) : (
                verdictLine(tally, scanError)
              )}
              {cargoCount > 0 ? <Text>{chalk.dim(`${cargoCount} cargo: inventory only, not verdict-checked`)}</Text> : null}
            </>
          )}
          <Text> </Text>
          <Text>{chalk.dim(`CycloneDX 1.5 · ${subject}${usage ? ` · ${usage.used.toLocaleString()}${usage.limit === null ? "" : ` / ${usage.limit.toLocaleString()}`} scanned this month` : ""}`)}</Text>
        </Box>
        {showLogo ? (
          <Box flexDirection="column" marginLeft={2}>
            {logo.map((line, index) => (
              <Text key={index}>{line}</Text>
            ))}
          </Box>
        ) : null}
      </Box>
    </Box>
  );
};
