import type { CommandSpec } from "./types.js";
import { EXIT_TOOL_ERROR, EXIT_USAGE, type CommandResult } from "./types.js";
import { clearAuthState } from "../auth/store.js";

export const logoutCommand: CommandSpec = {
  name: "logout",
  summary: "Remove local Dependency Guardian authentication.",
  usage: "dg logout",
  flags: [{ flag: "--yes", summary: "Accepted for scripts; logout no longer needs confirmation." }],
  details: ["Removes the dg-owned local auth token only. Config and setup files are not changed; log back in with dg login."],
  handler: (context) => logoutHandler(context.args)
};

function logoutHandler(args: readonly string[], env: NodeJS.ProcessEnv = process.env): CommandResult {
  const unknown = args.find((arg) => arg !== "--yes");
  if (unknown) {
    return {
      exitCode: EXIT_USAGE,
      stdout: "",
      stderr: `dg logout: unknown option '${unknown}'. Run 'dg logout --help'.\n`
    };
  }
  let removed: boolean;
  try {
    removed = clearAuthState();
  } catch (error) {
    return {
      exitCode: EXIT_TOOL_ERROR,
      stdout: "",
      stderr: `dg logout: could not remove the local auth token: ${error instanceof Error ? error.message : "unknown error"}\n`
    };
  }
  const lines = [removed ? "Logged out." : "Already logged out."];
  const activeEnvVars = ["DG_API_KEY", "DG_API_TOKEN"].filter((name) => env[name]);
  if (activeEnvVars.length > 0) {
    lines.push(`${activeEnvVars.join(" and ")} ${activeEnvVars.length === 1 ? "is" : "are"} still set, so env-var auth remains active (file token removed only).`);
  }
  return {
    exitCode: 0,
    stdout: `${lines.join("\n")}\n`,
    stderr: ""
  };
}
