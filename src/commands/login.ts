import type { CommandSpec } from "./types.js";
import { EXIT_TOOL_ERROR, EXIT_USAGE, type CommandResult } from "./types.js";
import { AuthError, writeAuthState } from "../auth/store.js";
import { ConfigError, loadUserConfig } from "../config/settings.js";

export const loginCommand: CommandSpec = {
  name: "login",
  summary: "Authenticate this machine with Dependency Guardian.",
  usage: "dg login [--token <token>]",
  flags: [
    { flag: "--token", value: "<token>", summary: "Authenticate with an API key instead of the browser (for CI/headless)." }
  ],
  examples: ["dg login", "dg login --token dg_live_…", "DG_API_TOKEN=dg_live_… dg login"],
  details: [
    "In a terminal, 'dg login' opens your browser to sign in — no token to copy.",
    "For CI and headless shells, pass --token <key> or set the DG_API_TOKEN environment variable instead.",
    "Stores dg-owned auth state under the user config directory; never executes project-local code or weakens install enforcement."
  ],
  handler: (context) => loginHandler(context.args)
};

function loginHandler(args: readonly string[]): CommandResult {
  const parsed = parseLoginArgs(args);
  if ("error" in parsed) {
    return {
      exitCode: EXIT_USAGE,
      stdout: "",
      stderr: `dg login: ${parsed.error}. Run 'dg login --help'.\n`
    };
  }
  try {
    const config = loadUserConfig();
    const state = writeAuthState({
      token: parsed.token,
      apiBaseUrl: config.api.baseUrl,
      orgId: config.org.id
    });
    return {
      exitCode: 0,
      stdout: `Logged in to ${state.apiBaseUrl}${state.orgId ? ` for org ${state.orgId}` : ""} with token ${state.tokenPreview}\n`,
      stderr: ""
    };
  } catch (error) {
    if (error instanceof AuthError || error instanceof ConfigError) {
      return {
        exitCode: EXIT_USAGE,
        stdout: "",
        stderr: `dg login: ${error.message}\n`
      };
    }
    return {
      exitCode: EXIT_TOOL_ERROR,
      stdout: "",
      stderr: `dg login: could not save auth state: ${error instanceof Error ? error.message : "unknown error"}\n`
    };
  }
}

function parseLoginArgs(args: readonly string[]):
  | { readonly token: string }
  | { readonly error: string } {
  let token = "";
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--token") {
      const value = args[index + 1];
      if (!value) {
        return {
          error: "--token requires a value"
        };
      }
      token = value;
      index += 1;
    } else if (arg?.startsWith("--token=")) {
      token = arg.slice("--token=".length);
    } else if (arg?.startsWith("-")) {
      return {
        error: `unknown option '${arg}'`
      };
    } else {
      return {
        error: `unexpected argument '${arg ?? ""}'. dg login takes no arguments: run 'dg login' for browser sign-in, or 'dg login --token <key>' for CI`
      };
    }
  }
  if (!token) {
    return {
      error: "run 'dg login' in a terminal to sign in via your browser, or pass --token <key> (or set DG_API_TOKEN) for CI"
    };
  }
  return { token };
}
