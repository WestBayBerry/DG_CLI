import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { resolveDgPaths, type DgPathEnvironment, type DgPaths } from "../state/index.js";

export interface AuditEvent {
  readonly type: "install.blocked" | "install.force_override" | "decision.accepted" | "decision.revoked";
  readonly packageName: string;
  readonly reason: string;
  readonly policyMode: string;
  readonly createdAt: string;
}

export function auditLogPath(paths: DgPaths): string {
  return join(paths.stateDir, "audit.jsonl");
}

export function recordAuditEvent(event: AuditEvent, env: DgPathEnvironment = process.env): boolean {
  try {
    appendJsonLine(auditLogPath(resolveDgPaths(env)), event);
    return true;
  } catch {
    return false;
  }
}

function appendJsonLine(path: string, value: unknown): void {
  mkdirSync(dirname(path), {
    recursive: true,
    mode: 0o700
  });
  appendFileSync(path, `${JSON.stringify(value)}\n`, {
    encoding: "utf8",
    mode: 0o600
  });
}
