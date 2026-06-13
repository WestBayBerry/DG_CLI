import { spawnSync } from "node:child_process";
import { toolInvocation } from "./external-tool.js";

export interface GitResult {
  readonly ok: boolean;
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

const DEFAULT_MAX_BUFFER = 256 * 1024 * 1024;

export function gitSync(
  args: readonly string[],
  options: { readonly cwd: string; readonly env?: NodeJS.ProcessEnv; readonly maxBuffer?: number }
): GitResult {
  const env = options.env ?? process.env;
  const invocation = toolInvocation("git", args, env);
  if (!invocation) {
    return { ok: false, code: null, stdout: "", stderr: "git executable not found on PATH" };
  }
  const result = spawnSync(invocation.command, [...invocation.args], {
    cwd: options.cwd,
    env,
    encoding: "utf8",
    maxBuffer: options.maxBuffer ?? DEFAULT_MAX_BUFFER,
    windowsVerbatimArguments: invocation.windowsVerbatimArguments
  });
  return {
    ok: result.status === 0,
    code: result.status,
    stdout: result.stdout ?? "",
    stderr: (result.stderr ?? "").trim()
  };
}

export function gitTrimmed(
  args: readonly string[],
  options: { readonly cwd: string; readonly env?: NodeJS.ProcessEnv }
): string | null {
  const result = gitSync(args, options);
  return result.ok ? result.stdout.trim() : null;
}
