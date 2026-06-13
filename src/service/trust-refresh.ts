import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  applyTrustInstall,
  applyTrustUninstall,
  readServiceTrustRecord,
  resolveTrustInstallPlan,
  writeServiceTrustRecord
} from "./trust-store.js";

export const TRUST_REFRESH_ERROR_FILENAME = "trust-refresh-error.json";

export interface TrustRefreshError {
  readonly at: string;
  readonly message: string;
}

export function trustRefreshErrorPath(serviceDir: string): string {
  return join(serviceDir, TRUST_REFRESH_ERROR_FILENAME);
}

export function readTrustRefreshError(serviceDir: string): TrustRefreshError | undefined {
  try {
    const path = trustRefreshErrorPath(serviceDir);
    if (!existsSync(path)) {
      return undefined;
    }
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<TrustRefreshError>;
    if (typeof parsed.at !== "string" || typeof parsed.message !== "string") {
      return undefined;
    }
    return {
      at: parsed.at,
      message: parsed.message
    };
  } catch {
    return undefined;
  }
}

export function clearTrustRefreshError(serviceDir: string): void {
  rmSync(trustRefreshErrorPath(serviceDir), {
    force: true
  });
}

export function refreshServiceTrustAfterCaRotation(options: {
  readonly serviceDir: string;
  readonly trustRecordPath: string;
  readonly sentinel: string;
  readonly caPath: string;
  readonly env: NodeJS.ProcessEnv;
  readonly now?: Date;
}): void {
  const record = readServiceTrustRecord(options.trustRecordPath, options.sentinel);
  if (!record) {
    return;
  }
  try {
    const plan = resolveTrustInstallPlan(options.caPath, options.env);
    applyTrustUninstall(record);
    const next = applyTrustInstall(plan, options.now ?? new Date(), options.sentinel);
    sweepStaleDgTrustFiles(next.provider, next.target);
    writeServiceTrustRecord(options.trustRecordPath, next);
    clearTrustRefreshError(options.serviceDir);
  } catch (error) {
    writeTrustRefreshError(options.serviceDir, error, options.now ?? new Date());
  }
}

function sweepStaleDgTrustFiles(provider: string, targetPath: string): void {
  if (provider === "darwin-user-keychain") {
    return;
  }
  const dir = dirname(targetPath);
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (!/^dependency-guardian-[0-9a-f]{16}\.(pem|crt)$/.test(entry)) {
      continue;
    }
    const path = join(dir, entry);
    if (path === targetPath) {
      continue;
    }
    rmSync(path, {
      force: true
    });
  }
}

function writeTrustRefreshError(serviceDir: string, error: unknown, now: Date): void {
  try {
    mkdirSync(serviceDir, {
      recursive: true,
      mode: 0o700
    });
    const record: TrustRefreshError = {
      at: now.toISOString(),
      message: error instanceof Error ? error.message : String(error)
    };
    writeFileSync(trustRefreshErrorPath(serviceDir), `${JSON.stringify(record, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600
    });
  } catch {
    return;
  }
}
