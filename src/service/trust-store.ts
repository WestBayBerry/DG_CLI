import { X509Certificate } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { writeJsonAtomic } from "../util/json-file.js";

export type TrustStoreProvider = "darwin-user-keychain" | "linux-system-ca" | "file";

export interface TrustStorePlan {
  readonly provider: TrustStoreProvider | "unsupported";
  readonly supported: boolean;
  readonly adminRequired: boolean;
  readonly native: boolean;
  readonly caPath: string;
  readonly target: string;
  readonly fingerprintSha256: string;
  readonly fingerprintSha1: string;
  readonly installCommand: readonly string[];
  readonly uninstallCommand: readonly string[];
  readonly reason: string | undefined;
}

export interface ServiceTrustRecord {
  readonly version: 1;
  readonly sentinel: string;
  readonly installedAt: string;
  readonly scope: "os-user-trust-store" | "ci-file-trust-store";
  readonly provider: TrustStoreProvider;
  readonly native: boolean;
  readonly adminRequired: boolean;
  readonly caPath: string;
  readonly target: string;
  readonly fingerprintSha256: string;
  readonly fingerprintSha1: string;
}

export class TrustStoreError extends Error {
  constructor(message: string) {
    super(message);
  }
}

export class TrustToolMissingError extends TrustStoreError {
  constructor(public readonly tool: string) {
    super(`native trust tool '${tool}' is not available on this system`);
  }
}

export function resolveTrustInstallPlan(
  caPath: string,
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform
): TrustStorePlan {
  const cert = readCertificateInfo(caPath);
  const backend = env.DG_SERVICE_TRUST_STORE_BACKEND ?? "native";
  if (backend === "file") {
    const root = env.DG_SERVICE_TRUST_STORE_DIR;
    if (!root) {
      return unsupportedPlan(caPath, cert, "DG_SERVICE_TRUST_STORE_BACKEND=file requires DG_SERVICE_TRUST_STORE_DIR.");
    }
    const target = join(root, `dependency-guardian-${cert.fingerprintSha256.slice(0, 16)}.pem`);
    return {
      provider: "file",
      supported: true,
      adminRequired: false,
      native: false,
      caPath,
      target,
      fingerprintSha256: cert.fingerprintSha256,
      fingerprintSha1: cert.fingerprintSha1,
      installCommand: ["copy", caPath, target],
      uninstallCommand: ["remove", target],
      reason: undefined
    };
  }
  if (backend !== "native") {
    return unsupportedPlan(caPath, cert, `Unsupported DG_SERVICE_TRUST_STORE_BACKEND '${backend}'.`);
  }
  if (platform === "darwin") {
    const keychain = env.DG_SERVICE_TRUST_KEYCHAIN ?? join(env.HOME ?? homedir(), "Library", "Keychains", "login.keychain-db");
    return {
      provider: "darwin-user-keychain",
      supported: true,
      adminRequired: false,
      native: true,
      caPath,
      target: keychain,
      fingerprintSha256: cert.fingerprintSha256,
      fingerprintSha1: cert.fingerprintSha1,
      installCommand: ["security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", keychain, caPath],
      uninstallCommand: ["security", "delete-certificate", "-Z", cert.fingerprintSha1, keychain],
      reason: undefined
    };
  }
  if (platform === "linux") {
    const target = join("/usr/local/share/ca-certificates", `dependency-guardian-${cert.fingerprintSha256.slice(0, 16)}.crt`);
    const adminRequired = typeof process.getuid === "function" && process.getuid() !== 0;
    return {
      provider: adminRequired ? "unsupported" : "linux-system-ca",
      supported: !adminRequired,
      adminRequired,
      native: true,
      caPath,
      target,
      fingerprintSha256: cert.fingerprintSha256,
      fingerprintSha1: cert.fingerprintSha1,
      installCommand: ["install", "-m", "0644", caPath, target, "&&", "update-ca-certificates"],
      uninstallCommand: ["rm", "-f", target, "&&", "update-ca-certificates"],
      reason: adminRequired ? "Linux system trust-store installation requires admin/root privileges." : undefined
    };
  }
  return unsupportedPlan(caPath, cert, `Native service trust-store mutation is not supported on ${platform} in this build.`);
}

export function renderTrustStorePlanLines(plan: TrustStorePlan | undefined): readonly string[] {
  if (!plan) {
    return ["active service CA certificate: unavailable; run dg service start before trust install"];
  }
  const lines = [
    `active service CA certificate: ${plan.caPath}`,
    `certificate SHA-256 fingerprint: ${plan.fingerprintSha256}`,
    `trust provider: ${plan.provider}`,
    `trust target: ${plan.target}`,
    `requires admin/root: ${plan.adminRequired ? "yes" : "no"}`,
    `install action: ${plan.installCommand.join(" ")}`,
    `uninstall action: ${plan.uninstallCommand.join(" ")}`
  ];
  return plan.reason ? [...lines, `support note: ${plan.reason}`] : lines;
}

export function applyTrustInstall(plan: TrustStorePlan, installedAt: Date, sentinel: string): ServiceTrustRecord {
  if (!plan.supported || plan.provider === "unsupported") {
    throw new TrustStoreError(plan.reason ?? "Service trust-store installation is unsupported on this platform.");
  }
  if (plan.provider === "file") {
    mkdirSync(dirname(plan.target), {
      recursive: true,
      mode: 0o700
    });
    copyFileSync(plan.caPath, plan.target);
  } else if (plan.provider === "darwin-user-keychain") {
    runNativeCommand(plan.installCommand, "macOS user keychain trust installation failed");
  } else {
    mkdirSync(dirname(plan.target), {
      recursive: true,
      mode: 0o755
    });
    copyFileSync(plan.caPath, plan.target);
    try {
      runNativeCommand(["update-ca-certificates"], "Linux trust-store refresh failed");
    } catch (error) {
      rmSync(plan.target, {
        force: true
      });
      throw error;
    }
  }
  return {
    version: 1,
    sentinel,
    installedAt: installedAt.toISOString(),
    scope: plan.native ? "os-user-trust-store" : "ci-file-trust-store",
    provider: plan.provider,
    native: plan.native,
    adminRequired: plan.adminRequired,
    caPath: plan.caPath,
    target: plan.target,
    fingerprintSha256: plan.fingerprintSha256,
    fingerprintSha1: plan.fingerprintSha1
  };
}

export function applyTrustUninstall(record: ServiceTrustRecord): void {
  if (record.provider === "file") {
    rmSync(record.target, {
      force: true
    });
    return;
  }
  if (record.provider === "darwin-user-keychain") {
    runNativeCommand(["security", "delete-certificate", "-Z", record.fingerprintSha1, record.target], "macOS user keychain trust removal failed");
    return;
  }
  rmSync(record.target, {
    force: true
  });
  runNativeCommand(["update-ca-certificates"], "Linux trust-store refresh failed");
}

export function readServiceTrustRecord(path: string, sentinel: string): ServiceTrustRecord | undefined {
  try {
    if (!existsSync(path)) {
      return undefined;
    }
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<ServiceTrustRecord>;
    if (
      parsed.version !== 1 ||
      parsed.sentinel !== sentinel ||
      !isTrustStoreProvider(parsed.provider) ||
      typeof parsed.installedAt !== "string" ||
      typeof parsed.native !== "boolean" ||
      typeof parsed.adminRequired !== "boolean" ||
      typeof parsed.caPath !== "string" ||
      typeof parsed.target !== "string" ||
      typeof parsed.fingerprintSha256 !== "string" ||
      typeof parsed.fingerprintSha1 !== "string"
    ) {
      return undefined;
    }
    return {
      version: 1,
      sentinel,
      installedAt: parsed.installedAt,
      scope: parsed.provider === "file" ? "ci-file-trust-store" : "os-user-trust-store",
      provider: parsed.provider,
      native: parsed.native,
      adminRequired: parsed.adminRequired,
      caPath: parsed.caPath,
      target: parsed.target,
      fingerprintSha256: parsed.fingerprintSha256,
      fingerprintSha1: parsed.fingerprintSha1
    };
  } catch {
    return undefined;
  }
}

export function readCertificateFingerprints(path: string): {
  readonly fingerprintSha256: string;
  readonly fingerprintSha1: string;
} {
  return readCertificateInfo(path);
}

export function writeServiceTrustRecord(path: string, record: ServiceTrustRecord): void {
  // Atomic write so a torn write can't drop the trustInstalled state while the OS
  // still trusts the CA.
  writeJsonAtomic(path, record, { fileMode: 0o600, dirMode: 0o700 });
}

function readCertificateInfo(path: string): {
  readonly fingerprintSha256: string;
  readonly fingerprintSha1: string;
} {
  try {
    const certificate = new X509Certificate(readFileSync(path));
    return {
      fingerprintSha256: normalizeFingerprint(certificate.fingerprint256),
      fingerprintSha1: normalizeFingerprint(certificate.fingerprint)
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new TrustStoreError(`Cannot read active service CA certificate at ${path}: ${message}`);
  }
}

function unsupportedPlan(
  caPath: string,
  cert: { readonly fingerprintSha256: string; readonly fingerprintSha1: string },
  reason: string
): TrustStorePlan {
  return {
    provider: "unsupported",
    supported: false,
    adminRequired: false,
    native: true,
    caPath,
    target: "unsupported",
    fingerprintSha256: cert.fingerprintSha256,
    fingerprintSha1: cert.fingerprintSha1,
    installCommand: [],
    uninstallCommand: [],
    reason
  };
}

function normalizeFingerprint(value: string): string {
  return value.replaceAll(":", "").toLowerCase();
}

function isTrustStoreProvider(value: unknown): value is TrustStoreProvider {
  return value === "darwin-user-keychain" || value === "linux-system-ca" || value === "file";
}

function runNativeCommand(command: readonly string[], failureMessage: string): void {
  const [program, ...args] = command;
  if (!program) {
    throw new TrustStoreError(failureMessage);
  }
  const result = spawnSync(program, args, {
    encoding: "utf8"
  });
  if (result.error) {
    if ((result.error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new TrustToolMissingError(program);
    }
    throw new TrustStoreError(`${failureMessage}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const detail = result.stderr?.trim() || result.stdout?.trim() || `exit ${result.status ?? "unknown"}`;
    throw new TrustStoreError(`${failureMessage}: ${detail}`);
  }
}
