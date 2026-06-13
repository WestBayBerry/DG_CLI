import React, { useCallback, useEffect, useState } from "react";
import { Box, useApp } from "ink";
import { combineAction, auditExitCode, displayTarget, type Gathered } from "../commands/audit.js";
import type { DeepResult } from "../audit/deep.js";
import { AuditResultsView } from "./components/AuditResultsView.js";
import { useResizeRepaint } from "../scan-ui/hooks/useResizeRepaint.js";
import type { VerdictAction } from "./format.js";

export interface AuditAppProps {
  readonly gathered: Gathered;
  readonly initialDeep: DeepResult | null;
  readonly deepPromise: Promise<DeepResult> | null;
  readonly onExitCode?: ((code: number) => void) | undefined;
}

export const AuditApp: React.FC<AuditAppProps> = ({ gathered, initialDeep, deepPromise, onExitCode }) => {
  const { exit } = useApp();
  useResizeRepaint();
  const [deep, setDeep] = useState<DeepResult | null>(initialDeep);

  useEffect(() => {
    if (!deepPromise) return;
    let live = true;
    deepPromise
      .then((result) => { if (live) setDeep(result); })
      .catch((error: unknown) => {
        if (live) setDeep({ ran: false, reason: error instanceof Error ? error.message : "deep audit failed" });
      });
    return () => { live = false; };
  }, [deepPromise]);

  const { parsed, scope, localAction, findings, publishSetSource, fileCount } = gathered;
  const policy = { requireDeep: parsed.requireDeep, failOn: parsed.failOn };
  const resolvedDeep: DeepResult = deep ?? { ran: false, reason: "deep audit required but unavailable" };
  const exitCode = auditExitCode(localAction, resolvedDeep, policy);
  const combined = combineAction(localAction, resolvedDeep) as VerdictAction;

  useEffect(() => {
    process.exitCode = exitCode;
    onExitCode?.(exitCode);
  }, [exitCode, onExitCode]);

  const handleExit = useCallback(() => {
    const finalDeep: DeepResult = deep ?? { ran: false, reason: "deep audit required but unavailable" };
    const code = auditExitCode(localAction, finalDeep, policy);
    process.exitCode = code;
    onExitCode?.(code);
    exit();
  }, [deep, localAction, policy, onExitCode, exit]);

  return (
    <Box flexDirection="column">
      <AuditResultsView
        findings={findings}
        action={combined}
        artifact={scope.artifact}
        ecosystem={scope.ecosystem}
        target={displayTarget(scope.root)}
        fileCount={fileCount}
        publishSetSource={publishSetSource}
        deep={deep}
        onExit={handleExit}
      />
    </Box>
  );
};
