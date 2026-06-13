import { authStatus } from "../auth/store.js";
import type { DgPathEnvironment } from "../state/index.js";
import type { ScannerAction } from "../api/analyze.js";
import { formatAccountStatus } from "./format-helpers.js";

export type ScanMode = "warn" | "block" | "off" | "strict";

export interface CLIConfig {
  readonly mode: ScanMode;
}

export type Ecosystem = "npm" | "pypi";

export interface FoundProject {
  path: string;
  relativePath: string;
  ecosystem: Ecosystem;
  depFile: string;
  packageCount: number;
}

export interface SetupIssue {
  id: "no_api_key" | "no_hook";
  label: string;
  fix: string;
}

export function isLoggedIn(): boolean {
  try {
    return authStatus().authenticated;
  } catch {
    return false;
  }
}

export function accountHeaderLine(usageTier?: string, env: DgPathEnvironment = process.env): string {
  let loggedIn = false;
  let name: string | undefined;
  let storedTier: string | undefined;
  try {
    const status = authStatus(env);
    loggedIn = status.authenticated;
    name = status.name ?? status.email;
    storedTier = status.tier;
  } catch {
    loggedIn = false;
  }
  return formatAccountStatus(usageTier ?? storedTier ?? "", loggedIn, name);
}

export function effectiveScanAction(
  raw: ScannerAction,
  effective: ScannerAction | undefined,
  mode: string
): ScannerAction {
  return mode === "strict" || effective === undefined ? raw : effective;
}

export function scanExitCode(action: ScannerAction | string | undefined, mode: string): number {
  if (action === "block") {
    return 2;
  }
  if (action === "warn") {
    return mode === "strict" ? 2 : 1;
  }
  if (action === "analysis_incomplete") {
    return 4;
  }
  return 0;
}
