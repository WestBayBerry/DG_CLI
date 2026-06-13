import { resolvePresentation } from "../presentation/mode.js";
import type { DeepResult } from "../audit/deep.js";
import type { Gathered } from "../commands/audit.js";

export function shouldLaunchAuditTui(options: {
  readonly format: string;
  readonly outputPath: string | null;
}): boolean {
  if (options.format !== "text" || options.outputPath) {
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

export interface LaunchAuditTuiProps {
  readonly gathered: Gathered;
  readonly initialDeep: DeepResult | null;
  readonly deepPromise: Promise<DeepResult> | null;
}

export async function launchAuditTui(props: LaunchAuditTuiProps): Promise<number> {
  const ci = process.env.CI;
  const ciCleared = ci === "" || ci === "0" || ci === "false";
  if (ciCleared) {
    delete process.env.CI;
  }
  const [{ render }, react, app, altScreen] = await Promise.all([
    import("ink"),
    import("react"),
    import("./AuditApp.js"),
    import("../scan-ui/alt-screen.js")
  ]);
  let exitCode = 0;
  altScreen.enterTui();
  try {
    const instance = render(
      react.default.createElement(app.AuditApp, {
        gathered: props.gathered,
        initialDeep: props.initialDeep,
        deepPromise: props.deepPromise,
        onExitCode: (code: number) => { exitCode = code; }
      }),
      { exitOnCtrlC: true }
    );
    await instance.waitUntilExit();
  } finally {
    if (ciCleared) process.env.CI = ci;
    altScreen.leaveTui();
  }
  return exitCode;
}
