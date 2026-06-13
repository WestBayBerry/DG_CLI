import React, { useState, useEffect, useRef } from "react";
import { Text, Box } from "ink";
import InkSpinner from "ink-spinner";
import chalk from "chalk";
import { useTerminalSize } from "../hooks/useTerminalSize.js";

interface ProgressBarProps {
  value: number;
  total: number;
  label?: string | undefined;
}

export interface EtaState {
  /** Whole-second ETA from now until completion, or null when not yet measurable. */
  remainingSeconds: number | null;
  /** Packages per second (float), or null until the first non-zero tick. */
  ratePerSec: number | null;
}

// Null fields until value/elapsed are non-zero so the UI shows "calculating…".
export function computeEta(
  value: number,
  total: number,
  elapsedSeconds: number,
): EtaState {
  if (value <= 0 || elapsedSeconds <= 0 || total <= 0) {
    return { remainingSeconds: null, ratePerSec: null };
  }
  const ratePerSec = value / elapsedSeconds;
  if (ratePerSec <= 0 || !Number.isFinite(ratePerSec)) {
    return { remainingSeconds: null, ratePerSec: null };
  }
  if (value >= total) {
    return { remainingSeconds: 0, ratePerSec };
  }
  const remaining = (total - value) / ratePerSec;
  return { remainingSeconds: Math.max(1, Math.ceil(remaining)), ratePerSec };
}

export function formatTime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
}

export function formatRate(ratePerSec: number): string {
  if (ratePerSec >= 1) return `${Math.round(ratePerSec)} pkg/s`;
  return `${ratePerSec.toFixed(1)} pkg/s`;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  value,
  total,
  label,
}) => {
  const startRef = useRef(Date.now());
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startRef.current) / 1000));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Subscribe to terminal resizes so the bar re-lays-out when the user
  // resizes the window mid-scan. Reading process.stdout.columns directly
  // only captures the width at mount time and goes stale on resize.
  const { cols: termWidth } = useTerminalSize();
  const percent = total > 0 ? Math.round((value / total) * 100) : 0;

  // Use a sub-second elapsed for the ETA math so the first tick after batch-1
  // completes can produce a real number (the 1s setInterval would otherwise
  // make elapsed=0 for the whole first second).
  const elapsedPrecise = (Date.now() - startRef.current) / 1000;
  const eta = computeEta(value, total, elapsedPrecise);

  const done = total > 0 && value >= total;
  const rateSuffix = eta.ratePerSec === null ? "" : `  (${formatRate(eta.ratePerSec)})`;
  const rateInline = eta.ratePerSec === null ? "" : ` · ${formatRate(eta.ratePerSec)}`;
  let timeInfo: string;
  if (done) {
    timeInfo = `in ${formatTime(elapsed)}${rateSuffix}`;
  } else if (eta.remainingSeconds === null) {
    timeInfo = `${formatTime(elapsed)} elapsed · calculating…${rateInline}`;
  } else {
    timeInfo = `${formatTime(elapsed)} elapsed · ~${formatTime(eta.remainingSeconds)} left${rateInline}`;
  }
  const counter = `${value}/${total}  ${percent}%`;

  // Below 30 cols the bar would soft-wrap and break Ink's line-count
  // tracker, leaving stale lines above on the next redraw.
  const compact = termWidth < 30;
  const narrow = !compact && termWidth < 60;

  const barWidth = Math.max(6, termWidth - counter.length - 8);
  const fraction = total > 0 ? Math.min(1, value / total) : 0;
  const filled = Math.round(fraction * barWidth);
  const empty = barWidth - filled;

  const filledBar = "━".repeat(filled);
  const emptyBar = "━".repeat(empty);

  return (
    <Box flexDirection="column" paddingLeft={2}>
      <Text>{chalk.bold("Dependency Guardian")}</Text>
      <Text>{""}</Text>
      <Box>
        {done ? (
          <Text color="green">✓</Text>
        ) : (
          <Text color="cyan">
            <InkSpinner type="dots" />
          </Text>
        )}
        <Text> {done ? "Scanned" : "Scanning"} {total} packages{done ? "" : "..."}  </Text>
        {!narrow && !compact && <Text dimColor>{timeInfo}</Text>}
      </Box>
      {compact ? (
        <Box>
          <Text>{"  "}</Text>
          <Text>{counter}</Text>
        </Box>
      ) : (
        <Box>
          <Text>{"  "}</Text>
          <Text color="green">{filledBar}</Text>
          <Text dimColor>{emptyBar}</Text>
          <Text>{"  "}{counter}</Text>
        </Box>
      )}
      {label && !compact && (
        <Box>
          <Text dimColor>{"  "}{chalk.dim("›")} {label}</Text>
        </Box>
      )}
    </Box>
  );
};
