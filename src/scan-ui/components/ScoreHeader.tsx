import React from "react";
import { Text, Box } from "ink";
import chalk from "chalk";
import { useTerminalSize } from "../hooks/useTerminalSize.js";
import { renderLogo } from "../logo.js";

export const COMPACT_ROWS = 24;
// Below ~75 cols the side-by-side logo column garbles the header layout.
export const LOGO_MIN_COLS = 75;

interface ScoreHeaderProps {
  score: number;
  action: "block" | "warn" | "pass" | "analysis_incomplete";
  compact: boolean;
  total?: number | undefined;
  flagged?: number | undefined;
  clean?: number | undefined;
  userStatus?: string | undefined;
  scanUsage?: string | undefined;
  usageNearLimit?: boolean | undefined;
}

function scoreColor(score: number, action: "block" | "warn" | "pass" | "analysis_incomplete"): string {
  const colorFn =
    action === "block" ? chalk.red.bold :
    action === "warn" ? chalk.yellow.bold :
    action === "analysis_incomplete" ? chalk.cyan.bold :
    chalk.green.bold;
  return colorFn(String(score));
}

export const ScoreHeader: React.FC<ScoreHeaderProps> = ({
  score,
  action,
  compact,
  total,
  flagged,
  clean,
  userStatus,
  scanUsage,
  usageNearLimit,
}) => {
  const logo = renderLogo(action);
  const { cols } = useTerminalSize();
  const showLogo = cols >= LOGO_MIN_COLS && !compact;

  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={action === "block" ? "red" : action === "warn" ? "yellow" : action === "analysis_incomplete" ? "cyan" : "green"}
      paddingLeft={1}
      paddingRight={1}
      width="100%"
    >
      <Box flexDirection="row">
        <Box flexDirection="column" flexGrow={1}>
          <Text bold>Dependency Guardian  {userStatus ?? ""}</Text>
          {!compact && <Text>{" "}</Text>}
          <Text>
            {chalk.dim("Score")}  {scoreColor(score, action)}
          </Text>
          {total !== undefined && (
            <>
              {!compact && <Text>{" "}</Text>}
              <Text>
                {chalk.dim(`${total} package${total !== 1 ? "s" : ""} scanned`)}
                {flagged !== undefined && flagged > 0 ? (
                  <>
                    {"    "}
                    {chalk.yellow(`${flagged} flagged`)}
                    {"    "}
                    {chalk.green(`${clean ?? 0} clean`)}
                  </>
                ) : (
                  <>
                    {"    "}
                    {chalk.green("all clean")}
                  </>
                )}
              </Text>
              {scanUsage && (
                usageNearLimit
                  ? <Text color="yellow">{scanUsage}  ↑ Pro: westbayberry.com/pricing</Text>
                  : <Text dimColor>{scanUsage}</Text>
              )}
            </>
          )}
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
