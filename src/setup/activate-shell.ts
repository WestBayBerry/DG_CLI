import { spawnSync } from "node:child_process";
import { basename } from "node:path";
import { isCiEnv } from "../presentation/mode.js";

export interface ShellSpawnRequest {
  readonly binary: string;
  readonly args: readonly string[];
  readonly env: NodeJS.ProcessEnv;
}

export type ShellSpawner = (request: ShellSpawnRequest) => number;

export type ActivationOffer = "prompt" | "hint" | "none";

type Stream = { isTTY?: boolean };

export interface ActivationOfferOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly stdin?: Stream;
  readonly stdout?: Stream;
}

export function activationOffer(options: ActivationOfferOptions = {}): ActivationOffer {
  const env = options.env ?? process.env;
  if (env.DG_ACTIVATED_SHELL) {
    return "none";
  }
  const stdin = options.stdin ?? process.stdin;
  const stdout = options.stdout ?? process.stdout;
  if (!stdin.isTTY || !stdout.isTTY || isCiEnv(env)) {
    return "hint";
  }
  return "prompt";
}

export interface ActivateShellOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly spawner?: ShellSpawner;
}

// dg cannot mutate the parent shell's environment, so activation nests a protected interactive child shell.
export function activateShell(options: ActivateShellOptions = {}): number {
  const env = options.env ?? process.env;
  const spawner = options.spawner ?? defaultShellSpawner;
  const binary = env.SHELL || "/bin/sh";
  const name = basename(binary);
  return spawner({
    binary,
    args: name === "bash" || name === "zsh" ? ["-i"] : [],
    env: { ...env, DG_ACTIVATED_SHELL: "1" }
  });
}

const defaultShellSpawner: ShellSpawner = (request) =>
  spawnSync(request.binary, request.args, { stdio: "inherit", env: request.env }).status ?? 0;
