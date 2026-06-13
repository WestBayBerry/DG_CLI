import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { renderLogo } from "../../scan-ui/logo.js";
import { useTerminalSize } from "../../scan-ui/hooks/useTerminalSize.js";
import { verdictGlyph, type VerdictAction } from "../format.js";

interface AuditHeaderProps {
  readonly action: VerdictAction;
  readonly artifact: string;
  readonly ecosystem: string;
  readonly countSummary: string;
  readonly fileCount: number;
  readonly fallback: boolean;
}

const ACTION_COLOR: Record<VerdictAction, string> = {
  block: "red",
  warn: "yellow",
  pass: "green"
};

const ACTION_PAINT: Record<VerdictAction, (s: string) => string> = {
  block: chalk.red.bold,
  warn: chalk.yellow.bold,
  pass: chalk.green.bold
};

export const AuditHeader: React.FC<AuditHeaderProps> = ({ action, artifact, ecosystem, countSummary, fileCount, fallback }) => {
  const logo = renderLogo(action);
  const { cols } = useTerminalSize();
  const showLogo = cols >= 60;
  const fileLabel = `${fileCount} file${fileCount === 1 ? "" : "s"}`;
  const paint = ACTION_PAINT[action];

  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={ACTION_COLOR[action]}
      paddingLeft={1}
      paddingRight={1}
      width="100%"
    >
      <Box flexDirection="row">
        <Box flexDirection="column" flexGrow={1}>
          <Text>
            {paint(`${verdictGlyph(action)} ${action.toUpperCase()}`)}   {chalk.bold(artifact)} {chalk.dim(`· ${ecosystem}`)}
          </Text>
          <Text>{chalk.dim(`${countSummary} in ${fileLabel}`)}</Text>
          {fallback && <Text>{chalk.dim("publish set approximated")}</Text>}
        </Box>
        {showLogo && (
          <Box flexDirection="column" marginLeft={2}>
            {logo.map((line, i) => <Text key={i}>{line}</Text>)}
          </Box>
        )}
      </Box>
    </Box>
  );
};
