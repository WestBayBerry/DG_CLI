import React, { useEffect, useCallback } from "react";
import { Box, Text, useApp, useInput } from "ink";
import { EXIT_ANALYSIS_INCOMPLETE, EXIT_NOTHING_TO_SCAN } from "../commands/types.js";
import { CLIConfig } from "./shims.js";
import { useScan } from "./hooks/useScan.js";
import { Spinner } from "./components/Spinner.js";
import { ProgressBar } from "./components/ProgressBar.js";
import { InteractiveResultsView } from "./components/InteractiveResultsView.js";
import { ErrorView } from "./components/ErrorView.js";
import { ProjectSelector } from "./components/ProjectSelector.js";
import { SetupBanner } from "./components/SetupBanner.js";
import { useResizeRepaint } from "./hooks/useResizeRepaint.js";
import { effectiveScanAction, scanExitCode } from "./shims.js";
import { leaveTui, showCursor, tuiIsActive } from "./alt-screen.js";
import { formatResetDate } from "../install-ui/block-render.js";
import { accountHeaderLine, type SetupIssue } from "./shims.js";

interface AppProps {
  config: CLIConfig;
  setupIssues?: SetupIssue[] | undefined;
  initialView?: "results" | "licenses" | undefined;
  updateAvailable?: string | undefined;
}

export const App: React.FC<AppProps> = ({ config, setupIssues = [], initialView, updateAvailable }) => {
  const { state, scanSelectedProjects, restartSelection } = useScan(config);
  const { exit } = useApp();
  useResizeRepaint();

  const leaveAltScreen = useCallback(() => {
    if (tuiIsActive()) {
      leaveTui();
    } else {
      showCursor();
    }
  }, []);

  useEffect(() => () => leaveAltScreen(), [leaveAltScreen]);

  const handleResultsExit = useCallback(() => {
    if (state.phase === "results") {
      process.exitCode = scanExitCode(effectiveScanAction(state.result.action, state.decisions?.effectiveAction, config.mode), config.mode);
    }
    leaveAltScreen();
    exit();
  }, [state, config, exit, leaveAltScreen]);

  // Exit alt screen BEFORE writing messages so they appear on the main screen.
  const exitWithMessage = useCallback((message: string, exitCode: number, delayMs = 0) => {
    process.exitCode = exitCode;
    if (delayMs === 0) {
      leaveAltScreen();
      process.stderr.write(message);
      return setTimeout(() => exit(), 0);
    }
    return setTimeout(() => {
      leaveAltScreen();
      process.stderr.write(message);
      exit();
    }, delayMs);
  }, [exit, leaveAltScreen]);

  useEffect(() => {
    if (state.phase === "empty") {
      const timer = exitWithMessage(`${state.message}\n`, EXIT_NOTHING_TO_SCAN);
      return () => clearTimeout(timer);
    }

    if (state.phase === "error") {
      const timer = exitWithMessage(`Error: ${state.error.message}\n`, EXIT_ANALYSIS_INCOMPLETE);
      return () => clearTimeout(timer);
    }

    // Reflect the verdict in the process exit code as soon as results render,
    // not only when the user dismisses the view — a piped/killed/non-TTY exit
    // must still carry the right code (an unverified scan is never a silent 0).
    if (state.phase === "results") {
      process.exitCode = scanExitCode(effectiveScanAction(state.result.action, state.decisions?.effectiveAction, config.mode), config.mode);
    }
  }, [state, config, exitWithMessage]);

  useInput((input: string, key: { escape: boolean; return: boolean }) => {
    if (state.phase === "discovering" || state.phase === "scanning") {
      if (input === "q" || key.escape) {
        process.exitCode = 0;
        leaveAltScreen();
        exit();
      }
    }
    if (state.phase === "free_cap_reached") {
      if (input === "q" || key.escape || key.return) {
        process.exitCode = 1;
        leaveAltScreen();
        exit();
      }
    }
  });

  const content = (() => {
    switch (state.phase) {
      case "discovering": {
        if (!state.found || !state.path) {
          return <Spinner label="Scanning for projects…" />;
        }
        const path = state.path.length > 52 ? `…${state.path.slice(-51)}` : state.path;
        return <Spinner label={`Found ${state.found} · ${path}`} />;
      }

      case "selecting":
        return (
          <ProjectSelector
            projects={state.projects}
            onConfirm={scanSelectedProjects}
            onCancel={() => { process.exitCode = 0; leaveAltScreen(); exit(); }}
            userStatus={accountHeaderLine()}
          />
        );

      case "scanning":
        return (
          <ProgressBar
            value={state.done}
            total={state.total}
            label={
              state.batchCount > 1 && state.batchIndex >= 1
                ? `batch ${state.batchIndex}/${state.batchCount}`
                : undefined
            }
          />
        );

      case "results":
        return (
          <InteractiveResultsView
            result={state.result}
            config={config}
            durationMs={state.durationMs}
            onExit={handleResultsExit}
            onBack={restartSelection ?? undefined}
            discoveredTotal={state.discoveredTotal}
            initialView={initialView}
            decisions={state.decisions}
          />
        );

      case "empty":
        return <Text dimColor>{state.message}</Text>;

      case "error":
        return <ErrorView error={state.error} />;

      case "free_cap_reached": {
        return (
          <Box flexDirection="column" paddingLeft={2}>
            {state.capReason === "prefix_cap" ? (
              <>
                <Text color="yellow" bold>Too many anonymous devices from your network this month.</Text>
                <Text>Sign in with <Text color="cyan" bold>dg login</Text> to keep scanning.</Text>
              </>
            ) : (
              <>
                <Text color="yellow" bold>Free monthly limit reached ({state.scansUsed.toLocaleString()}/{state.maxScans.toLocaleString()} packages).</Text>
                {formatResetDate(state.resetsAt) ? <Text dimColor>Resets {formatResetDate(state.resetsAt)}.</Text> : null}
                <Text>Upgrade to Pro at <Text color="cyan" bold>westbayberry.com/pricing</Text> for 250k packages/month.</Text>
              </>
            )}
            <Text> </Text>
            <Text dimColor>[q] quit</Text>
          </Box>
        );
      }
    }
  })();

  const showBanner =
    state.phase === "selecting" &&
    setupIssues.length > 0;

  // Results fill the terminal height exactly; an extra line there overflows the alt screen.
  const showUpdateLine =
    updateAvailable !== undefined &&
    (state.phase === "selecting" || state.phase === "scanning");

  return (
    <Box flexDirection="column">
      {showBanner ? <SetupBanner issues={setupIssues} /> : null}
      {content}
      {showUpdateLine ? <Box paddingLeft={1}><Text dimColor>{updateAvailable}</Text></Box> : null}
    </Box>
  );
};
