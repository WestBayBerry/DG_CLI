import React from "react";
import { Box, Text } from "ink";
import InkSpinner from "ink-spinner";
import { formatResetDate } from "./block-render.js";
import { sanitizeLine } from "../security/sanitize.js";
import type { EnforcementCause } from "../proxy/enforcement.js";

export interface LiveInstallBlocked {
  readonly kind: "blocked" | "unverified";
  readonly packageName: string;
  readonly headline: string;
  readonly reason: string;
  readonly nextStep?: string | undefined;
  readonly override?: string | undefined;
  readonly cause?: EnforcementCause | undefined;
  readonly resetsAt?: string | undefined;
}

export interface LiveInstallView {
  readonly phase: "scanning" | "done";
  readonly total: number;
  readonly verified: number;
  readonly flagged: number;
  readonly flaggedItems?: ReadonlyArray<{ readonly packageName: string; readonly reason: string }> | undefined;
  readonly resolvedTotal?: number | undefined;
  readonly current?: string | undefined;
  readonly blocked?: LiveInstallBlocked | undefined;
}

function packageCount(n: number): string {
  return n === 1 ? "1 package" : `${n} packages`;
}

function rule(): string {
  const width = Math.max(20, Math.min((process.stdout.columns ?? 80) - 4, 56));
  return "─".repeat(width);
}

export const LiveInstall: React.FC<{ readonly view: LiveInstallView }> = ({ view }) => {
  if (view.phase === "scanning") {
    return (
      <Box paddingX={1}>
        <Text color="cyan">
          <InkSpinner type="dots" />
        </Text>
        <Text> {view.total === 0
          ? "DG starting protection…"
          : view.resolvedTotal !== undefined && view.total <= view.resolvedTotal
            ? `DG verifying ${view.total}/${view.resolvedTotal}…`
            : `DG verifying ${packageCount(view.total)}…`}</Text>
        {view.current ? <Text dimColor>  {sanitizeLine(view.current)}</Text> : null}
      </Box>
    );
  }

  if (view.total === 0 && !view.blocked) {
    return null;
  }

  if (view.blocked) {
    const blocked = view.blocked;
    if (blocked.cause === "quota-exceeded") {
      const reset = formatResetDate(blocked.resetsAt);
      return (
        <Box flexDirection="column" paddingX={1}>
          <Text color="gray">{rule()}</Text>
          <Text color="yellow">Quota hit{reset ? ` — resets ${reset}` : ""}</Text>
          <Text dimColor>{"   "}Override:  {blocked.override ?? "--dg-force-install"}</Text>
        </Box>
      );
    }
    return (
      <Box flexDirection="column" paddingX={1}>
        <Text color="gray">{rule()}</Text>
        {blocked.kind === "blocked" ? (
          <Text color="red">✘  DG blocked install — {blocked.headline}</Text>
        ) : (
          <Text color="yellow">?  DG could not verify {blocked.packageName} — {blocked.headline}</Text>
        )}
        <Text>
          {"   "}
          {blocked.packageName}
          {"   "}
          {blocked.reason}
        </Text>
        {blocked.override ? <Text dimColor>{"   "}Override: {blocked.override}</Text> : null}
        {blocked.nextStep ? <Text dimColor>{"   "}Next: {blocked.nextStep}</Text> : null}
      </Box>
    );
  }

  const total = view.verified + view.flagged;
  if (view.flagged > 0) {
    return (
      <Box flexDirection="column" paddingX={1}>
        <Text color="yellow">
          ⚠  DG verified {packageCount(total)} — {view.flagged} flagged
        </Text>
        {(view.flaggedItems ?? []).map((item, index) => (
          <Text key={`${item.packageName}-${index}`} dimColor>
            {"   "}{sanitizeLine(item.packageName)}   {sanitizeLine(item.reason)}
          </Text>
        ))}
      </Box>
    );
  }
  return (
    <Box paddingX={1}>
      <Text color="green">✓  DG verified {packageCount(total)} — clean</Text>
    </Box>
  );
};
