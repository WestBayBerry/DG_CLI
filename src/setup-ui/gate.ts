import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { isCiEnv } from "../presentation/mode.js";
import { resolveDgPaths, type DgPathEnvironment } from "../state/index.js";

type Stream = { isTTY?: boolean };

export function setupApplied(env: DgPathEnvironment = process.env): boolean {
  return existsSync(join(resolveDgPaths(env).homeDir, ".dg", "shims", "npm"));
}

export function securityNotesMarkerPath(env: DgPathEnvironment = process.env): string {
  return join(resolveDgPaths(env).stateDir, "security-notes-shown");
}

export function wizardSkippedMarkerPath(env: DgPathEnvironment = process.env): string {
  return join(resolveDgPaths(env).stateDir, "setup-wizard-skipped");
}

export function securityNotesShown(env: DgPathEnvironment = process.env): boolean {
  return existsSync(securityNotesMarkerPath(env));
}

export function markSecurityNotesShown(env: DgPathEnvironment = process.env, now = new Date()): void {
  writeMarker(securityNotesMarkerPath(env), now);
}

export function markWizardSkipped(env: DgPathEnvironment = process.env, now = new Date()): void {
  writeMarker(wizardSkippedMarkerPath(env), now);
}

export function shouldOfferSetupWizard(
  env: DgPathEnvironment = process.env,
  stdin: Stream = process.stdin,
  stderr: Stream = process.stderr
): boolean {
  return (
    process.platform !== "win32" &&
    Boolean(stdin.isTTY) &&
    Boolean(stderr.isTTY) &&
    !isCiEnv(env) &&
    !setupApplied(env) &&
    !existsSync(wizardSkippedMarkerPath(env))
  );
}

function writeMarker(path: string, now: Date): void {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, `${now.toISOString()}\n`, { encoding: "utf8", mode: 0o600 });
  } catch {
    return;
  }
}
