import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative } from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { loadUserConfig } from "../config/settings.js";
import {
  applyTrustInstall,
  applyTrustUninstall,
  readCertificateFingerprints,
  readServiceTrustRecord,
  renderTrustStorePlanLines,
  resolveTrustInstallPlan,
  TrustStoreError,
  TrustToolMissingError,
  writeServiceTrustRecord,
  type ServiceTrustRecord
} from "./trust-store.js";
import { clearTrustRefreshError, readTrustRefreshError } from "./trust-refresh.js";
import {
  acquireLockSync,
  cleanupSessionSync,
  createSessionSync,
  preserveCorruptCleanupRegistrySync,
  resolveDgPaths,
  CLEANUP_REGISTRY_LOCK,
  type CleanupRegistry,
  type CleanupRegistryEntry,
  type DgPaths
} from "../state/index.js";

export const SERVICE_SENTINEL = "dg-service-mode-v1";
export const TRUST_SENTINEL = "dg-service-trust-v1";
export const SERVICE_LOCK = "service-control";
export const SERVICE_LOCK_STALE_MS = 30 * 60 * 1000;

export interface ServiceState {
  readonly version: 1;
  readonly configured: boolean;
  readonly running: boolean;
  readonly trustInstalled: boolean;
  readonly trust: ServiceTrustRecord | undefined;
  readonly trustDrift: ServiceTrustDrift | undefined;
  readonly proxy: ServiceProxyRuntime | undefined;
  readonly lastError: string | undefined;
  readonly policySyncedAt: string | undefined;
  readonly configuredAt: string | undefined;
  readonly startedAt: string | undefined;
  readonly stoppedAt: string | undefined;
  readonly trustInstalledAt: string | undefined;
  readonly trustUninstalledAt: string | undefined;
}

export interface ServiceTrustDrift {
  readonly installedFingerprintSha256: string;
  readonly activeFingerprintSha256: string | undefined;
  readonly message: string;
}

export interface ServiceProxyRuntime {
  readonly pid: number;
  readonly proxyUrl: string;
  readonly healthUrl: string;
  readonly sessionDir: string;
  readonly caPath: string;
  readonly startedAt: string;
}

export interface ServicePaths {
  readonly paths: DgPaths;
  readonly serviceDir: string;
  readonly statePath: string;
  readonly trustRecordPath: string;
  readonly runtimePath: string;
  readonly logPath: string;
}

export interface ServicePlan {
  readonly kind: "setup" | "trust-install" | "trust-uninstall" | "uninstall";
  readonly writes: readonly ServicePlannedWrite[];
}

export interface ServicePlannedWrite {
  readonly action: string;
  readonly path: string;
}

export interface ServiceCommandResult {
  readonly state: ServiceState;
  readonly paths: ServicePaths;
  readonly changed: boolean;
}

export interface ServiceUninstallResult {
  readonly removed: readonly string[];
  readonly missing: readonly string[];
  readonly state: ServiceState;
}

const EMPTY_SERVICE_STATE: ServiceState = {
  version: 1,
  configured: false,
  running: false,
  trustInstalled: false,
  trust: undefined,
  trustDrift: undefined,
  proxy: undefined,
  lastError: undefined,
  policySyncedAt: undefined,
  configuredAt: undefined,
  startedAt: undefined,
  stoppedAt: undefined,
  trustInstalledAt: undefined,
  trustUninstalledAt: undefined
};

export function resolveServicePaths(env: NodeJS.ProcessEnv = process.env): ServicePaths {
  const paths = resolveDgPaths(env);
  const serviceDir = join(paths.stateDir, "service");
  return {
    paths,
    serviceDir,
    statePath: join(serviceDir, "service.json"),
    trustRecordPath: join(serviceDir, "trust-store.json"),
    runtimePath: join(serviceDir, "runtime.json"),
    logPath: join(serviceDir, "service.log.jsonl")
  };
}

export function buildServiceSetupPlan(env?: NodeJS.ProcessEnv): ServicePlan {
  const paths = resolveServicePaths(env);
  return {
    kind: "setup",
    writes: [
      {
        action: "create dg-owned service state directory",
        path: paths.serviceDir
      },
      {
        action: "record explicit service-mode configuration",
        path: paths.statePath
      },
      {
        action: "record dg-owned service writes for uninstall",
        path: paths.paths.cleanupRegistryPath
      }
    ]
  };
}

export function buildTrustInstallPlan(env?: NodeJS.ProcessEnv): ServicePlan {
  const paths = resolveServicePaths(env);
  const current = readState(paths);
  const runtime = readRuntime(paths) ?? current.proxy;
  const trustPlan = runtime?.caPath && existsSync(runtime.caPath) ? resolveTrustInstallPlan(runtime.caPath, env) : undefined;
  return {
    kind: "trust-install",
    writes: [
      ...renderTrustStorePlanLines(trustPlan).map((line) => ({
        action: line,
        path: ""
      })),
      {
        action: "write dg-owned managed trust record after trust-store mutation succeeds",
        path: paths.trustRecordPath
      },
      {
        action: "record trust reversal in cleanup registry",
        path: paths.paths.cleanupRegistryPath
      }
    ]
  };
}

export function buildTrustUninstallPlan(env?: NodeJS.ProcessEnv): ServicePlan {
  const paths = resolveServicePaths(env);
  const record = readServiceTrustRecord(paths.trustRecordPath, TRUST_SENTINEL);
  return {
    kind: "trust-uninstall",
    writes: [
      ...(record
        ? [
            {
              action: `remove ${record.provider} trust for certificate SHA-256 ${record.fingerprintSha256}`,
              path: record.target
            }
          ]
        : []),
      {
        action: "remove dg-owned managed trust record",
        path: paths.trustRecordPath
      },
      {
        action: "remove trust cleanup registry entry",
        path: paths.paths.cleanupRegistryPath
      }
    ]
  };
}

export function buildServiceUninstallPlan(env?: NodeJS.ProcessEnv): ServicePlan {
  const paths = resolveServicePaths(env);
  return {
    kind: "uninstall",
    writes: [
      {
        action: "stop explicit service mode if running",
        path: paths.statePath
      },
      {
        action: "remove dg-owned managed trust record if present",
        path: paths.trustRecordPath
      },
      {
        action: "remove dg-owned service state directory",
        path: paths.serviceDir
      },
      {
        action: "remove service and trust cleanup registry entries",
        path: paths.paths.cleanupRegistryPath
      }
    ]
  };
}

export function renderServicePlan(title: string, plan: { readonly writes: readonly ServicePlannedWrite[] }): string {
  const lines = [
    title,
    "",
    "No service or trust-store state is changed until this plan is confirmed.",
    ...plan.writes.map((write) => (write.path ? `- ${write.action}: ${write.path}` : `- ${write.action}`))
  ];
  return `${lines.join("\n")}\n`;
}

export function readServiceState(env?: NodeJS.ProcessEnv): ServiceCommandResult {
  const paths = resolveServicePaths(env);
  const state = applyRuntimeDiagnostics(paths, readState(paths));
  return {
    paths,
    state,
    changed: false
  };
}

export function configureService(env?: NodeJS.ProcessEnv, now = new Date()): ServiceCommandResult {
  const paths = resolveServicePaths(env);
  return withServiceLock(paths, () => {
    const current = readState(paths);
    const state: ServiceState = {
      ...current,
      configured: true,
      configuredAt: current.configuredAt ?? now.toISOString(),
      policySyncedAt: now.toISOString()
    };
    writeState(paths, state);
    writeLog(paths, "service.configured", now);
    withRegistryLock(paths.paths, () => {
      writeRegistry(paths.paths, mergeRegistry(readRegistry(paths.paths), [registryEntry("service", paths.statePath, SERVICE_SENTINEL, now)]));
    });
    return {
      paths,
      state,
      changed: !current.configured
    };
  });
}

export function startService(env?: NodeJS.ProcessEnv, now = new Date()): ServiceCommandResult {
  const paths = resolveServicePaths(env);
  return withServiceLock(paths, () => {
    const current = readState(paths);
    if (!current.configured) {
      throw new ServiceNotConfiguredError();
    }
    const existingRuntime = readRuntime(paths);
    if (current.running && existingRuntime && runtimeHealth(existingRuntime).healthy) {
      const state: ServiceState = {
        ...current,
        running: true,
        proxy: existingRuntime,
        trustDrift: detectTrustDrift(current.trust, existingRuntime),
        lastError: undefined
      };
      writeState(paths, state);
      writeLog(paths, "service.start.noop", now);
      return {
        paths,
        state,
        changed: false
      };
    }
    cleanupRuntime(paths, existingRuntime ?? current.proxy);
    const runtime = startServiceProxyRuntime(paths, env ?? process.env, now);
    const trustRemoval = removeTrustRecordIfDrifted(paths, current.trust, runtime, now);
    const state: ServiceState = {
      ...current,
      running: true,
      startedAt: current.running ? current.startedAt : now.toISOString(),
      policySyncedAt: now.toISOString(),
      proxy: runtime,
      trustInstalled: trustRemoval.removed ? false : current.trustInstalled,
      trust: trustRemoval.removed ? undefined : current.trust,
      trustDrift: undefined,
      trustUninstalledAt: trustRemoval.removed ? now.toISOString() : current.trustUninstalledAt,
      lastError: trustRemoval.message
    };
    writeState(paths, state);
    writeLog(paths, "service.started", now);
    return {
      paths,
      state,
      changed: !current.running
    };
  });
}

export function stopService(env?: NodeJS.ProcessEnv, now = new Date()): ServiceCommandResult {
  const paths = resolveServicePaths(env);
  return withServiceLock(paths, () => {
    const current = readState(paths);
    if (!current.configured) {
      return {
        paths,
        state: current,
        changed: false
      };
    }
    const state: ServiceState = {
      ...current,
      running: false,
      stoppedAt: current.running ? now.toISOString() : current.stoppedAt,
      proxy: undefined,
      lastError: undefined
    };
    cleanupRuntime(paths, readRuntime(paths) ?? current.proxy);
    writeState(paths, state);
    writeLog(paths, current.running ? "service.stopped" : "service.stop.noop", now);
    return {
      paths,
      state,
      changed: current.running
    };
  });
}

export function restartService(env?: NodeJS.ProcessEnv, now = new Date()): ServiceCommandResult {
  const paths = resolveServicePaths(env);
  return withServiceLock(paths, () => {
    const current = readState(paths);
    if (!current.configured) {
      throw new ServiceNotConfiguredError();
    }
    cleanupRuntime(paths, readRuntime(paths) ?? current.proxy);
    const runtime = startServiceProxyRuntime(paths, env ?? process.env, now);
    const trustRemoval = removeTrustRecordIfDrifted(paths, current.trust, runtime, now);
    const state: ServiceState = {
      ...current,
      running: true,
      startedAt: now.toISOString(),
      stoppedAt: current.running ? now.toISOString() : current.stoppedAt,
      policySyncedAt: now.toISOString(),
      proxy: runtime,
      trustInstalled: trustRemoval.removed ? false : current.trustInstalled,
      trust: trustRemoval.removed ? undefined : current.trust,
      trustDrift: undefined,
      trustUninstalledAt: trustRemoval.removed ? now.toISOString() : current.trustUninstalledAt,
      lastError: trustRemoval.message
    };
    writeState(paths, state);
    writeLog(paths, "service.restarted", now);
    return {
      paths,
      state,
      changed: true
    };
  });
}

export function installServiceTrust(env?: NodeJS.ProcessEnv, now = new Date()): ServiceCommandResult {
  const paths = resolveServicePaths(env);
  return withServiceLock(paths, () => {
    const current = readState(paths);
    if (!current.configured) {
      throw new ServiceNotConfiguredError();
    }
    const runtime = readRuntime(paths) ?? current.proxy;
    if (!runtime?.caPath || !existsSync(runtime.caPath)) {
      throw new ServiceTrustStoreError("dg service trust install requires a running service proxy with an active CA certificate. Run 'dg service start' first.");
    }
    const plan = trustStoreOperation(() => resolveTrustInstallPlan(runtime.caPath, env ?? process.env));
    const existing = readServiceTrustRecord(paths.trustRecordPath, TRUST_SENTINEL);
    if (existing && existing.fingerprintSha256 === plan.fingerprintSha256 && existing.provider === plan.provider && existing.target === plan.target) {
      clearTrustRefreshError(paths.serviceDir);
      const state: ServiceState = {
        ...current,
      trustInstalled: true,
      trust: existing,
      trustDrift: undefined,
      trustInstalledAt: current.trustInstalledAt ?? existing.installedAt
      };
      writeState(paths, state);
      writeLog(paths, "service.trust.install.noop", now);
      return {
        paths,
        state,
        changed: false
      };
    }
    if (existing) {
      trustStoreOperation(() => applyTrustUninstall(existing));
    }
    const record = trustStoreOperation(() => applyTrustInstall(plan, now, TRUST_SENTINEL));
    clearTrustRefreshError(paths.serviceDir);
    const state: ServiceState = {
      ...current,
      trustInstalled: true,
      trust: record,
      trustDrift: undefined,
      trustInstalledAt: current.trustInstalledAt ?? now.toISOString()
    };
    writeServiceTrustRecord(paths.trustRecordPath, record);
    writeState(paths, state);
    writeLog(paths, "service.trust.installed", now);
    withRegistryLock(paths.paths, () => {
      writeRegistry(paths.paths, mergeRegistry(readRegistry(paths.paths), [registryEntry("trust-store", paths.trustRecordPath, TRUST_SENTINEL, now)]));
    });
    return {
      paths,
      state,
      changed: !current.trustInstalled
    };
  });
}

export function uninstallServiceTrust(env?: NodeJS.ProcessEnv, now = new Date()): ServiceCommandResult {
  const paths = resolveServicePaths(env);
  return withServiceLock(paths, () => {
    const current = readState(paths);
    const record = readServiceTrustRecord(paths.trustRecordPath, TRUST_SENTINEL);
    if (record) {
      trustStoreOperation(() => applyTrustUninstall(record));
    }
    clearTrustRefreshError(paths.serviceDir);
    const removedTrust = removeFile(paths.trustRecordPath);
    if (!current.configured && !removedTrust) {
      return {
        paths,
        state: current,
        changed: false
      };
    }
    const state: ServiceState = {
      ...current,
      trustInstalled: false,
      trust: undefined,
      trustDrift: undefined,
      trustUninstalledAt: current.trustInstalled || removedTrust ? now.toISOString() : current.trustUninstalledAt
    };
    writeState(paths, state);
    writeLog(paths, current.trustInstalled || removedTrust ? "service.trust.uninstalled" : "service.trust.uninstall.noop", now);
    withRegistryLock(paths.paths, () => {
      writeRegistryIfChanged(paths.paths, readRegistry(paths.paths), [{ kind: "trust-store", path: paths.trustRecordPath }]);
    });
    return {
      paths,
      state,
      changed: current.trustInstalled || removedTrust
    };
  });
}

export function uninstallService(env?: NodeJS.ProcessEnv, now = new Date()): ServiceUninstallResult {
  const paths = resolveServicePaths(env);
  return withServiceLock(paths, () => {
    const current = readState(paths);
    const removed: string[] = [];
    const missing: string[] = [];
    cleanupRuntime(paths, readRuntime(paths) ?? current.proxy);
    const record = readServiceTrustRecord(paths.trustRecordPath, TRUST_SENTINEL);
    if (record) {
      trustStoreOperation(() => applyTrustUninstall(record));
    }
    if (existsSync(paths.trustRecordPath)) {
      rmSync(paths.trustRecordPath, {
        force: true
      });
      removed.push(paths.trustRecordPath);
    } else {
      missing.push(paths.trustRecordPath);
    }
    if (existsSync(paths.serviceDir)) {
      rmSync(paths.serviceDir, {
        force: true,
        recursive: true
      });
      removed.push(paths.serviceDir);
    } else {
      missing.push(paths.serviceDir);
    }
    withRegistryLock(paths.paths, () => {
      writeRegistryIfChanged(paths.paths, readRegistry(paths.paths), [
        {
          kind: "service",
          path: paths.statePath
        },
        {
          kind: "trust-store",
          path: paths.trustRecordPath
        }
      ]);
    });
    return {
      removed,
      missing,
      state: {
        ...current,
        configured: false,
        running: false,
        trustInstalled: false,
        trust: undefined,
        trustDrift: undefined,
        proxy: undefined,
        lastError: undefined,
        stoppedAt: current.running ? now.toISOString() : current.stoppedAt
      }
    };
  });
}

export class ServiceNotConfiguredError extends Error {
  constructor() {
    super("Service mode is not configured");
  }
}

export class ServiceTrustStoreError extends Error {
  constructor(message: string) {
    super(message);
  }
}

export class ServiceTrustToolMissingError extends ServiceTrustStoreError {
  constructor(public readonly tool: string) {
    super(`native trust tool '${tool}' is not available on this system`);
  }
}

export class ServiceProxyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ServiceProxyError";
  }
}

function trustStoreOperation<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof TrustToolMissingError) {
      throw new ServiceTrustToolMissingError(error.tool);
    }
    if (error instanceof TrustStoreError) {
      throw new ServiceTrustStoreError(error.message);
    }
    throw error;
  }
}

export function withServiceLock<T>(paths: ServicePaths, run: () => T): T {
  const lock = acquireLockSync(paths.paths, SERVICE_LOCK, {
    staleMs: SERVICE_LOCK_STALE_MS
  });
  try {
    return run();
  } finally {
    lock.release();
  }
}

function withRegistryLock<T>(paths: DgPaths, run: () => T): T {
  const lock = acquireLockSync(paths, CLEANUP_REGISTRY_LOCK, {
    staleMs: SERVICE_LOCK_STALE_MS
  });
  try {
    return run();
  } finally {
    lock.release();
  }
}

function readState(paths: ServicePaths): ServiceState {
  try {
    if (!existsSync(paths.statePath)) {
      return EMPTY_SERVICE_STATE;
    }
    const parsed = JSON.parse(readFileSync(paths.statePath, "utf8")) as Partial<ServiceState>;
    if (parsed.version !== 1) {
      return EMPTY_SERVICE_STATE;
    }
    const trust = readServiceTrustRecord(paths.trustRecordPath, TRUST_SENTINEL);
    return {
      version: 1,
      configured: parsed.configured === true,
      running: parsed.running === true,
      trustInstalled: parsed.trustInstalled === true && trust !== undefined,
      trust,
      trustDrift: undefined,
      proxy: serviceProxyRuntime(parsed.proxy),
      lastError: typeof parsed.lastError === "string" ? parsed.lastError : undefined,
      policySyncedAt: parsed.policySyncedAt,
      configuredAt: parsed.configuredAt,
      startedAt: parsed.startedAt,
      stoppedAt: parsed.stoppedAt,
      trustInstalledAt: parsed.trustInstalledAt,
      trustUninstalledAt: parsed.trustUninstalledAt
    };
  } catch {
    return EMPTY_SERVICE_STATE;
  }
}

function applyRuntimeDiagnostics(paths: ServicePaths, state: ServiceState): ServiceState {
  const runtime = readRuntime(paths) ?? state.proxy;
  if (!runtime) {
    return withTrustRefreshError(paths, state);
  }
  const drift = detectTrustDrift(state.trust, runtime);
  if (!state.running) {
    return withTrustRefreshError(paths, {
      ...state,
      proxy: runtime,
      trustDrift: drift,
      lastError: "stale service runtime state: runtime file exists while service is stopped"
    });
  }
  const health = runtimeHealth(runtime);
  if (!health.healthy) {
    return withTrustRefreshError(paths, {
      ...state,
      running: false,
      proxy: runtime,
      trustDrift: drift,
      lastError: `stale service runtime state: ${health.reason}`
    });
  }
  return withTrustRefreshError(paths, {
    ...state,
    proxy: runtime,
    trustDrift: drift
  });
}

function withTrustRefreshError(paths: ServicePaths, state: ServiceState): ServiceState {
  const refreshError = readTrustRefreshError(paths.serviceDir);
  if (!refreshError) {
    return state;
  }
  return {
    ...state,
    lastError: state.lastError
      ?? `service CA trust refresh failed at ${refreshError.at}: ${refreshError.message}. Run 'dg service trust install --yes' to repair OS trust for the rotated CA.`
  };
}

function runtimeHealth(runtime: ServiceProxyRuntime): {
  readonly healthy: boolean;
  readonly reason: string | undefined;
} {
  if (!processIsAlive(runtime.pid)) {
    return {
      healthy: false,
      reason: `recorded service worker pid ${runtime.pid} is not running`
    };
  }
  if (!healthEndpointReachable(runtime.healthUrl)) {
    return {
      healthy: false,
      reason: `health endpoint is unreachable at ${runtime.healthUrl}`
    };
  }
  return {
    healthy: true,
    reason: undefined
  };
}

function healthEndpointReachable(healthUrl: string): boolean {
  const script = `
const http = require("node:http");
const https = require("node:https");
const target = process.argv[1];
const client = target.startsWith("https:") ? https : http;
const request = client.get(target, { timeout: 500 }, (response) => {
  response.resume();
  response.on("end", () => process.exit(response.statusCode === 200 ? 0 : 1));
});
request.on("timeout", () => request.destroy(new Error("timeout")));
request.on("error", () => process.exit(1));
`;
  const result = spawnSync(process.execPath, ["-e", script, healthUrl], {
    stdio: "ignore",
    timeout: 1_000
  });
  return result.status === 0;
}

function detectTrustDrift(trust: ServiceTrustRecord | undefined, runtime: ServiceProxyRuntime | undefined): ServiceTrustDrift | undefined {
  if (!trust || !runtime?.caPath || !existsSync(runtime.caPath)) {
    return undefined;
  }
  try {
    const active = readCertificateFingerprints(runtime.caPath);
    if (active.fingerprintSha256 === trust.fingerprintSha256) {
      return undefined;
    }
    return {
      installedFingerprintSha256: trust.fingerprintSha256,
      activeFingerprintSha256: active.fingerprintSha256,
      message:
        `Installed service trust fingerprint ${trust.fingerprintSha256} does not match active service CA fingerprint ${active.fingerprintSha256}. Run dg service trust install --yes to trust the active CA.`
    };
  } catch {
    return {
      installedFingerprintSha256: trust.fingerprintSha256,
      activeFingerprintSha256: undefined,
      message:
        `Installed service trust fingerprint ${trust.fingerprintSha256} cannot be compared because the active service CA is unreadable. Run dg service restart before reinstalling trust.`
    };
  }
}

function removeTrustRecordIfDrifted(
  paths: ServicePaths,
  trust: ServiceTrustRecord | undefined,
  runtime: ServiceProxyRuntime | undefined,
  now: Date
): {
  readonly removed: boolean;
  readonly message: string | undefined;
} {
  const drift = detectTrustDrift(trust, runtime);
  if (!trust || !drift) {
    return {
      removed: false,
      message: undefined
    };
  }
  trustStoreOperation(() => applyTrustUninstall(trust));
  removeFile(paths.trustRecordPath);
  withRegistryLock(paths.paths, () => {
    writeRegistryIfChanged(paths.paths, readRegistry(paths.paths), [{ kind: "trust-store", path: paths.trustRecordPath }]);
  });
  writeLog(paths, "service.trust.removed-after-ca-drift", now);
  return {
    removed: true,
    message: `${drift.message} The stale dg-owned trust record was removed during service restart.`
  };
}

function startServiceProxyRuntime(paths: ServicePaths, env: NodeJS.ProcessEnv, now: Date): ServiceProxyRuntime {
  const workerPath = env.DG_SERVICE_WORKER_PATH ?? fileURLToPath(new URL("./worker.js", import.meta.url));
  if (!existsSync(workerPath)) {
    throw new ServiceProxyError("service proxy worker is unavailable until the CLI package is built");
  }
  const session = createSessionSync(paths.paths);
  const sessionBootstrapPath = join(session.dir, "session.json");
  writeFileSync(sessionBootstrapPath, `${JSON.stringify(session)}\n`, {
    encoding: "utf8",
    mode: 0o600
  });
  const config = loadUserConfig(env);
  const child = spawn(process.execPath, [workerPath, sessionBootstrapPath, config.api.baseUrl, paths.runtimePath], {
    detached: true,
    env: {
      ...env,
      DG_SERVICE_CLASSIFICATION: JSON.stringify({
        kind: "protected",
        manager: "npm",
        realBinaryName: "npm",
        action: "service-proxy",
        args: []
      })
    },
    stdio: "ignore"
  });
  child.unref();
  const runtime = waitForRuntime(paths, child.pid);
  if (!runtime) {
    if (child.pid) {
      killProcess(child.pid);
    }
    cleanupSessionSync(session);
    throw new ServiceProxyError("service proxy worker did not become healthy");
  }
  void now;
  return runtime;
}

function waitForRuntime(paths: ServicePaths, pid: number | undefined): ServiceProxyRuntime | undefined {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    const runtime = readRuntime(paths);
    if (runtime && (!pid || runtime.pid === pid) && runtime.proxyUrl && runtime.healthUrl) {
      return runtime;
    }
    sleep(25);
  }
  return undefined;
}

function readRuntime(paths: ServicePaths): ServiceProxyRuntime | undefined {
  try {
    if (!existsSync(paths.runtimePath)) {
      return undefined;
    }
    const parsed = JSON.parse(readFileSync(paths.runtimePath, "utf8")) as unknown;
    return serviceProxyRuntime(parsed);
  } catch {
    return undefined;
  }
}

function serviceProxyRuntime(value: unknown): ServiceProxyRuntime | undefined {
  if (typeof value !== "object" || value === null) {
    return undefined;
  }
  const runtime = value as Partial<ServiceProxyRuntime>;
  if (
    typeof runtime.pid !== "number" ||
    typeof runtime.proxyUrl !== "string" ||
    typeof runtime.healthUrl !== "string" ||
    typeof runtime.sessionDir !== "string" ||
    typeof runtime.caPath !== "string" ||
    typeof runtime.startedAt !== "string"
  ) {
    return undefined;
  }
  return {
    pid: runtime.pid,
    proxyUrl: runtime.proxyUrl,
    healthUrl: runtime.healthUrl,
    sessionDir: runtime.sessionDir,
    caPath: runtime.caPath,
    startedAt: runtime.startedAt
  };
}

function cleanupRuntime(paths: ServicePaths, runtime: ServiceProxyRuntime | undefined): void {
  if (runtime?.pid && processIsAlive(runtime.pid)) {
    killProcess(runtime.pid);
  }
  if (runtime?.sessionDir && isContainedIn(paths.paths.sessionsDir, runtime.sessionDir)) {
    rmSync(runtime.sessionDir, {
      force: true,
      recursive: true
    });
  }
  removeFile(paths.runtimePath);
}

function isContainedIn(parent: string, child: string): boolean {
  const related = relative(parent, child);
  return related.length > 0 && !related.startsWith("..") && !isAbsolute(related);
}

function processIsAlive(pid: number): boolean {
  if (pid <= 0) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function killProcess(pid: number): void {
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    return;
  }
}

function sleep(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function writeJsonAtomicSync(path: string, value: unknown): void {
  mkdirSync(dirname(path), {
    recursive: true,
    mode: 0o700
  });
  const tempPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    writeFileSync(tempPath, `${JSON.stringify(value, null, 2)}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600
    });
    renameSync(tempPath, path);
  } catch (error) {
    rmSync(tempPath, {
      force: true
    });
    throw error;
  }
}

function writeState(paths: ServicePaths, state: ServiceState): void {
  writeJsonAtomicSync(paths.statePath, state);
}

function writeLog(paths: ServicePaths, event: string, now: Date): void {
  mkdirSync(dirname(paths.logPath), {
    recursive: true,
    mode: 0o700
  });
  writeFileSync(paths.logPath, `${JSON.stringify({ event, at: now.toISOString() })}\n`, {
    encoding: "utf8",
    flag: "a",
    mode: 0o600
  });
}

function readRegistry(paths: DgPaths): CleanupRegistry {
  try {
    if (!existsSync(paths.cleanupRegistryPath)) {
      return {
        version: 1,
        entries: []
      };
    }
    const parsed = JSON.parse(readFileSync(paths.cleanupRegistryPath, "utf8")) as CleanupRegistry;
    if (parsed.version !== 1 || !Array.isArray(parsed.entries)) {
      throw new Error("unsupported cleanup registry");
    }
    return parsed;
  } catch {
    preserveCorruptCleanupRegistrySync(paths);
    return {
      version: 1,
      entries: []
    };
  }
}

function writeRegistry(paths: DgPaths, registry: CleanupRegistry): void {
  writeJsonAtomicSync(paths.cleanupRegistryPath, registry);
}

function writeRegistryIfChanged(paths: DgPaths, registry: CleanupRegistry, targets: readonly Pick<CleanupRegistryEntry, "kind" | "path">[]): void {
  const next = removeRegistryTargets(registry, targets);
  if (!existsSync(paths.cleanupRegistryPath) && registry.entries.length === next.entries.length) {
    return;
  }
  if (registry.entries.length === next.entries.length) {
    return;
  }
  writeRegistry(paths, next);
}

function registryEntry(kind: CleanupRegistryEntry["kind"], path: string, sentinel: string, now: Date): CleanupRegistryEntry {
  return {
    kind,
    path,
    mode: "mode2",
    sentinel,
    installedAt: now.toISOString(),
    owner: "dg"
  };
}

function mergeRegistry(registry: CleanupRegistry, entries: readonly CleanupRegistryEntry[]): CleanupRegistry {
  return {
    version: 1,
    entries: [
      ...registry.entries.filter(
        (entry) => !entries.some((next) => entry.kind === next.kind && entry.path === next.path && entry.sentinel === next.sentinel)
      ),
      ...entries
    ]
  };
}

function removeRegistryTargets(
  registry: CleanupRegistry,
  targets: readonly Pick<CleanupRegistryEntry, "kind" | "path">[]
): CleanupRegistry {
  return {
    version: 1,
    entries: registry.entries.filter((entry) => !targets.some((target) => entry.kind === target.kind && entry.path === target.path))
  };
}

function removeFile(path: string): boolean {
  if (!existsSync(path)) {
    return false;
  }
  rmSync(path, {
    force: true
  });
  return true;
}
