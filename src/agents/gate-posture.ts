import { readServiceState } from "../service/state.js";

export type GatePosture =
  | { readonly live: false }
  | { readonly live: true; readonly proxyUrl: string };

export function readNetworkGatePosture(env: NodeJS.ProcessEnv = process.env): GatePosture {
  try {
    const { state } = readServiceState(env);
    if (state.running && state.proxy) {
      return { live: true, proxyUrl: state.proxy.proxyUrl };
    }
  } catch {
    // fall through to the off posture; a missing/unreadable service state means
    // the gate is not live, which is exactly what we report.
  }
  return { live: false };
}

export const GATE_OFF_COVERAGE_GAPS: readonly string[] = [
  "absolute-path installs (e.g. /usr/local/bin/npm install evil)",
  "manifest-only installs (npm ci, npm install with no package named)",
  "dynamically-built or stdin-fed commands the static parser defers on",
  "recognized-but-unsupported managers (bun, deno, poetry, pdm)",
];

export const GATE_ENABLE_HINT = "dg setup --service --yes && dg service start";
