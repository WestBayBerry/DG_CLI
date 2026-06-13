import { resolvePresentation } from "../presentation/mode.js";
import type { DgPathEnvironment } from "../state/index.js";
import { createSbomStore } from "./store.js";
import { runSbomScan } from "./run.js";
import type { SbomRow } from "./inventory.js";

export function shouldLaunchSbomTui(options: { readonly json: boolean; readonly outputPath: string | null }): boolean {
  if (options.json || options.outputPath) {
    return false;
  }
  if (process.env.TERM === "dumb") {
    return false;
  }
  if (!process.stdin.isTTY) {
    return false;
  }
  return resolvePresentation().mode === "rich";
}

export interface LaunchSbomTuiPayload {
  readonly rows: readonly SbomRow[];
  readonly dropped: readonly string[];
  readonly subject: string;
  readonly document: string;
  readonly env: DgPathEnvironment;
  readonly cwd: string;
}

export async function launchSbomTui(payload: LaunchSbomTuiPayload): Promise<void> {
  const ci = process.env.CI;
  const ciCleared = ci === "" || ci === "0" || ci === "false";
  if (ciCleared) {
    delete process.env.CI;
  }
  const [{ render }, react, app, altScreen] = await Promise.all([
    import("ink"),
    import("react"),
    import("./SbomApp.js"),
    import("../scan-ui/alt-screen.js")
  ]);
  const store = createSbomStore({
    phase: "inventory",
    rows: payload.rows,
    subject: payload.subject,
    dropped: payload.dropped,
    scannable: payload.rows.filter((row) => row.scannable).length,
    scanProgress: 0,
    scanError: null,
    usage: null
  });
  const controller = new AbortController();
  altScreen.enterTui();
  try {
    const instance = render(
      react.default.createElement(app.SbomApp, { store, document: payload.document, cwd: payload.cwd }),
      { exitOnCtrlC: true }
    );
    void runSbomScan(store, payload.env, controller.signal);
    await instance.waitUntilExit();
  } finally {
    if (ciCleared) process.env.CI = ci;
    controller.abort();
    altScreen.leaveTui();
  }
}
