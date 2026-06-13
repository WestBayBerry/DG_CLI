import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { readAuthStateOrWarn } from "../auth/store.js";
import { envAuthToken } from "../auth/env-token.js";
import { loadUserConfig } from "../config/settings.js";
import { sanitize, sanitizeResponse } from "../security/sanitize.js";
import { resolveDgPaths, type DgPathEnvironment } from "../state/index.js";
import { dgVersion } from "../commands/version.js";
import type { ScannerError } from "../scan/types.js";

export type ScannerAction = "block" | "warn" | "pass" | "analysis_incomplete";

export interface ScannerFinding {
  readonly id?: string;
  readonly category?: string;
  readonly severity: 1 | 2 | 3 | 4 | 5;
  readonly title?: string;
  readonly evidence?: readonly string[];
}

export interface ScannerLicense {
  readonly spdx: string | null;
  readonly raw: string | null;
  readonly riskCategory: string;
  readonly label: string;
}

export interface ScannerCooldown {
  readonly status: "ok" | "quarantine" | "unknown";
  readonly requiredDays?: number;
  readonly ageDays?: number;
  readonly publishedAt?: string;
  readonly eligibleAt?: string;
}

export type ScannerProvenanceStatus = "attested" | "none" | "unknown";

export interface ScannerProvenance {
  readonly status: ScannerProvenanceStatus;
  readonly predicateType?: string;
  readonly downgrade?: { readonly fromVersion: string };
}

export interface ScannerPackageResult {
  readonly name: string;
  readonly version: string;
  readonly score: number;
  readonly action?: ScannerAction;
  readonly findings: readonly ScannerFinding[];
  readonly reasons: readonly string[];
  readonly recommendation?: string;
  readonly cached: boolean;
  readonly license?: ScannerLicense;
  readonly cooldown?: ScannerCooldown;
  readonly provenance?: ScannerProvenance;
  readonly artifactSha256?: string | null;
  // Set by the scan path (the analyze response itself is per-ecosystem and does
  // not carry this); used to link a flagged package to its public page.
  readonly ecosystem?: string;
}

export interface ScannerUsage {
  readonly used: number;
  readonly limit: number | null;
  readonly tier: string;
}

export interface AnalyzeResponse {
  readonly score: number;
  readonly action: ScannerAction;
  readonly packages: readonly ScannerPackageResult[];
  readonly safeVersions: Readonly<Record<string, string>>;
  readonly durationMs: number;
  readonly freeScansRemaining?: number;
  readonly usage?: ScannerUsage;
}

export interface AnalyzePackageInput {
  readonly name: string;
  readonly version: string;
}

export type AnalyzeErrorCode =
  | "quota_exceeded"
  | "rate_limited"
  | "auth"
  | "server"
  | "network"
  | "timeout"
  | "invalid_response";

export class AnalyzeError extends Error {
  public readonly code: AnalyzeErrorCode;
  public readonly scansUsed?: number;
  public readonly scansLimit?: number;

  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly body?: unknown,
    code?: AnalyzeErrorCode
  ) {
    super(message);
    this.name = "AnalyzeError";
    const quota = quotaBodyFields(body);
    if (quota?.scansUsed !== undefined) {
      this.scansUsed = quota.scansUsed;
    }
    if (quota?.scansLimit !== undefined) {
      this.scansLimit = quota.scansLimit;
    }
    this.code = code ?? classifyAnalyzeError(statusCode, body, quota !== undefined);
  }
}

type QuotaBodyShape = {
  code?: unknown;
  reason?: unknown;
  scansUsed?: unknown;
  scansLimit?: unknown;
  maxScans?: unknown;
};

function quotaBodyFields(body: unknown): { scansUsed?: number; scansLimit?: number } | undefined {
  if (!body || typeof body !== "object") {
    return undefined;
  }
  const candidate = body as QuotaBodyShape;
  const quotaShaped =
    candidate.code === "quota_exceeded"
    || candidate.reason === "monthly_limit"
    || candidate.reason === "prefix_cap"
    || typeof candidate.scansUsed === "number"
    || typeof candidate.scansLimit === "number"
    || typeof candidate.maxScans === "number";
  if (!quotaShaped) {
    return undefined;
  }
  const limit = typeof candidate.scansLimit === "number"
    ? candidate.scansLimit
    : typeof candidate.maxScans === "number"
      ? candidate.maxScans
      : undefined;
  return {
    ...(typeof candidate.scansUsed === "number" ? { scansUsed: candidate.scansUsed } : {}),
    ...(limit !== undefined ? { scansLimit: limit } : {})
  };
}

function classifyAnalyzeError(statusCode: number, body: unknown, quotaShaped: boolean): AnalyzeErrorCode {
  const bodyCode = body && typeof body === "object" ? (body as QuotaBodyShape).code : undefined;
  if (bodyCode === "rate_limited") {
    return "rate_limited";
  }
  if (statusCode === 402 || (quotaShaped && (statusCode === 403 || statusCode === 429))) {
    return "quota_exceeded";
  }
  if (statusCode === 429) {
    return "rate_limited";
  }
  if (statusCode === 401 || statusCode === 403) {
    return "auth";
  }
  if (statusCode === 0) {
    return "network";
  }
  return "server";
}

export function scannerErrorFromUnknown(error: unknown): ScannerError {
  if (error instanceof AnalyzeError) {
    return {
      kind: error.code,
      message: error.message,
      statusCode: error.statusCode,
      ...(error.scansUsed !== undefined ? { scansUsed: error.scansUsed } : {}),
      ...(error.scansLimit !== undefined ? { scansLimit: error.scansLimit } : {})
    };
  }
  return {
    kind: "worker",
    message: error instanceof Error ? error.message : String(error)
  };
}

export type AnalyzeEcosystem = "npm" | "pypi";

const ANALYZE_PATHS: Record<AnalyzeEcosystem, string> = {
  npm: "/v1/analyze",
  pypi: "/v1/pypi/analyze"
};

const BATCH_SIZE = 200;
const DEFAULT_TIMEOUT_MS = 180_000;
const BATCH_CONCURRENCY = Math.max(1, Number(process.env.DG_ANALYZE_CONCURRENCY) || 4);

export interface AnalyzeProgress {
  readonly done: number;
  readonly total: number;
  readonly batchIndex: number;
  readonly batchCount: number;
}

export interface AnalyzeCooldownParam {
  readonly minAgeDays: number;
  readonly onUnknown: "allow" | "block";
}

export interface AnalyzeOptions {
  readonly ecosystem: AnalyzeEcosystem;
  readonly env?: DgPathEnvironment;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
  readonly scanId?: string;
  readonly signal?: AbortSignal;
  readonly cooldown?: AnalyzeCooldownParam;
  readonly onProgress?: (progress: AnalyzeProgress) => void;
}

type BatchContext = {
  readonly url: string;
  readonly token: string | undefined;
  readonly deviceId: string;
  readonly scanId: string;
  readonly fetchImpl: typeof fetch;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
  readonly cooldown?: AnalyzeCooldownParam;
};

export async function analyzePackages(
  packages: readonly AnalyzePackageInput[],
  options: AnalyzeOptions
): Promise<AnalyzeResponse> {
  const env = options.env ?? process.env;
  const baseUrl = resolveApiBaseUrl(env);
  const context: BatchContext = {
    url: `${baseUrl}${ANALYZE_PATHS[options.ecosystem]}`,
    token: resolveToken(env),
    deviceId: getOrCreateDeviceId(env),
    scanId: options.scanId ?? randomUUID(),
    fetchImpl: options.fetchImpl ?? fetch,
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    ...(options.signal ? { signal: options.signal } : {}),
    ...(options.cooldown ? { cooldown: options.cooldown } : {})
  };
  const total = packages.length;

  const batches: AnalyzePackageInput[][] = [];
  for (let index = 0; index < packages.length; index += BATCH_SIZE) {
    batches.push(packages.slice(index, index + BATCH_SIZE) as AnalyzePackageInput[]);
  }
  const batchCount = Math.max(1, batches.length);
  options.onProgress?.({ done: 0, total, batchIndex: 0, batchCount });

  const perBatchDone = new Array<number>(batches.length).fill(0);
  const responses: AnalyzeResponse[] = new Array(batches.length);
  let batchesFinished = 0;
  const reportProgress = (): void => {
    const done = perBatchDone.reduce((sum, n) => sum + n, 0);
    options.onProgress?.({ done, total, batchIndex: batchesFinished, batchCount });
  };

  let cursor = 0;
  const runWorker = async (): Promise<void> => {
    for (let i = cursor++; i < batches.length; i = cursor++) {
      const batch = batches[i];
      if (!batch) continue;
      const response = await analyzeBatchWithRetry(
        context, batch,
        (batchDone) => {
          perBatchDone[i] = Math.min(batchDone, batch.length);
          reportProgress();
        }
      );
      perBatchDone[i] = batch.length;
      batchesFinished += 1;
      responses[i] = response;
      reportProgress();
    }
  };

  const workers = Math.min(BATCH_CONCURRENCY, Math.max(1, batches.length));
  await Promise.all(Array.from({ length: workers }, () => runWorker()));
  return mergeAnalyzeResponses(responses);
}

const MAX_BATCH_ATTEMPTS = 3;

async function analyzeBatchWithRetry(
  context: BatchContext,
  batch: readonly AnalyzePackageInput[],
  onBatchProgress: (done: number) => void
): Promise<AnalyzeResponse> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= MAX_BATCH_ATTEMPTS; attempt += 1) {
    try {
      return await analyzeBatch(context, batch, onBatchProgress);
    } catch (error) {
      lastError = error;
      if (context.signal?.aborted || attempt === MAX_BATCH_ATTEMPTS || !isRetryableAnalyzeError(error)) {
        break;
      }
      await delay(300 * attempt);
    }
  }
  if (context.signal?.aborted || lastError instanceof AnalyzeError) {
    throw lastError;
  }
  if (isNetworkFailure(lastError)) {
    throw new AnalyzeError("could not reach the scanner — check your connection and try again", 0);
  }
  throw lastError;
}

function isNetworkFailure(error: unknown): boolean {
  if (error instanceof TypeError && error.message.toLowerCase().includes("fetch failed")) {
    return true;
  }
  return error instanceof Error && error.name === "AbortError";
}

function isRetryableAnalyzeError(error: unknown): boolean {
  if (error instanceof AnalyzeError) {
    return error.statusCode === 0 || error.statusCode >= 500;
  }
  return isNetworkFailure(error);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function analyzeBatch(
  context: BatchContext,
  batch: readonly AnalyzePackageInput[],
  onBatchProgress: (done: number) => void
): Promise<AnalyzeResponse> {
  const { url, token, deviceId, scanId, fetchImpl, timeoutMs, signal, cooldown } = context;
  const controller = new AbortController();
  let timedOut = false;
  let silenceTimer: NodeJS.Timeout | undefined;
  const armSilenceTimer = (): void => {
    clearTimeout(silenceTimer);
    silenceTimer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
  };
  const forwardAbort = (): void => controller.abort();
  signal?.addEventListener("abort", forwardAbort, { once: true });
  if (signal?.aborted) {
    controller.abort();
  }
  armSilenceTimer();
  try {
    const response = await fetchImpl(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/x-ndjson",
        "X-Device-Id": deviceId,
        "X-Scan-Id": scanId,
        "X-Dg-Version": dgVersion(),
        ...(token ? { Authorization: `Bearer ${token}` } : {})
      },
      body: JSON.stringify({
        packages: batch.map((entry) => ({ name: entry.name, version: entry.version })),
        ...(cooldown ? { cooldown } : {})
      }),
      signal: controller.signal
    });
    armSilenceTimer();
    if (!response.ok) {
      const body = await response.json().catch(() => undefined);
      throw analyzeErrorFromResponse(response.status, body);
    }
    const headers = response.headers as Headers | undefined;
    const contentType = headers?.get("content-type") ?? "";
    if (contentType.includes("application/x-ndjson") && response.body) {
      return await consumeAnalyzeStream(response.body as ReadableStream<Uint8Array>, onBatchProgress, armSilenceTimer);
    }
    const payload = await response.json().catch(() => {
      throw new AnalyzeError("scanner returned an unreadable response", response.status, undefined, "invalid_response");
    });
    return normalizeAnalyzeResponse(payload);
  } catch (error) {
    if (timedOut && error instanceof Error && error.name === "AbortError") {
      throw new AnalyzeError(`scanner sent no data for ${timeoutMs}ms — scan timed out`, 0, undefined, "timeout");
    }
    throw error;
  } finally {
    clearTimeout(silenceTimer);
    signal?.removeEventListener("abort", forwardAbort);
  }
}

function analyzeErrorFromResponse(status: number, body: unknown): AnalyzeError {
  const serverMessage =
    body && typeof body === "object" && "error" in body && typeof (body as { error: unknown }).error === "string"
      ? sanitize((body as { error: string }).error)
      : undefined;
  const probe = new AnalyzeError(serverMessage ?? `scanner returned ${status}`, status, body);
  if (serverMessage) {
    return probe;
  }
  if (probe.code === "quota_exceeded") {
    return new AnalyzeError("scan limit reached", status, body);
  }
  if (probe.code === "rate_limited") {
    return new AnalyzeError("scanner rate limit reached — wait a moment and retry", status, body);
  }
  return probe;
}

async function consumeAnalyzeStream(
  body: ReadableStream<Uint8Array>,
  onBatchProgress: (done: number) => void,
  onActivity: () => void
): Promise<AnalyzeResponse> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let result: AnalyzeResponse | undefined;
  const handleLine = (line: string): void => {
    if (!line) return;
    let event: { type?: string; done?: number; error?: string; statusCode?: number; payload?: unknown };
    try {
      event = JSON.parse(line);
    } catch {
      return;
    }
    if (event.type === "progress" || event.type === "cache_hit") {
      if (typeof event.done === "number") onBatchProgress(event.done);
    } else if (event.type === "error") {
      throw new AnalyzeError(
        typeof event.error === "string" ? sanitize(event.error) : `scanner returned ${event.statusCode ?? 500}`,
        typeof event.statusCode === "number" ? event.statusCode : 0,
        event
      );
    } else if (event.type === "result") {
      result = normalizeAnalyzeResponse(event.payload);
    }
  };
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      onActivity();
      buffer += decoder.decode(value, { stream: true });
      let newline: number;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        handleLine(buffer.slice(0, newline).trim());
        buffer = buffer.slice(newline + 1);
      }
    }
    handleLine(buffer.trim());
  } finally {
    reader.cancel().catch(() => undefined);
  }
  if (!result) {
    throw new AnalyzeError("scanner stream ended without a result", 0);
  }
  return result;
}

export function normalizeAnalyzeResponse(raw: unknown): AnalyzeResponse {
  const candidate = raw as Partial<AnalyzeResponse> | null;
  if (!candidate || typeof candidate.score !== "number" || !Array.isArray(candidate.packages)) {
    throw new AnalyzeError("invalid scanner response shape", 0);
  }
  return sanitizeResponse({
    score: candidate.score,
    action: normalizeAction(candidate.action),
    packages: candidate.packages.map((entry) => ({
      ...entry,
      action: entry.action === undefined ? undefined : normalizeAction(entry.action),
      findings: Array.isArray(entry.findings) ? entry.findings : [],
      reasons: Array.isArray(entry.reasons) ? entry.reasons : []
    })),
    safeVersions: candidate.safeVersions ?? {},
    durationMs: typeof candidate.durationMs === "number" ? candidate.durationMs : 0,
    ...(candidate.freeScansRemaining !== undefined ? { freeScansRemaining: candidate.freeScansRemaining } : {}),
    ...(candidate.usage !== undefined ? { usage: candidate.usage } : {})
  });
}

function normalizeAction(action: unknown): ScannerAction {
  if (action === "block" || action === "warn" || action === "analysis_incomplete" || action === "pass") {
    return action;
  }
  return "analysis_incomplete";
}

export function mergeAnalyzeResponses(responses: readonly AnalyzeResponse[]): AnalyzeResponse {
  const first = responses[0];
  if (!first) {
    return {
      score: 0,
      action: "pass",
      packages: [],
      safeVersions: {},
      durationMs: 0
    };
  }
  if (responses.length === 1) {
    return first;
  }
  const rank: Record<ScannerAction, number> = {
    pass: 0,
    analysis_incomplete: 1,
    warn: 2,
    block: 3
  };
  return responses.reduce((merged, next) => ({
    score: Math.max(merged.score, next.score),
    action: rank[next.action] > rank[merged.action] ? next.action : merged.action,
    packages: [...merged.packages, ...next.packages],
    safeVersions: { ...merged.safeVersions, ...next.safeVersions },
    durationMs: merged.durationMs + next.durationMs,
    ...(next.freeScansRemaining !== undefined
      ? { freeScansRemaining: next.freeScansRemaining }
      : merged.freeScansRemaining !== undefined
        ? { freeScansRemaining: merged.freeScansRemaining }
        : {}),
    ...(next.usage !== undefined ? { usage: next.usage } : merged.usage !== undefined ? { usage: merged.usage } : {})
  }));
}

function resolveApiBaseUrl(env: DgPathEnvironment): string {
  const auth = readAuthStateOrWarn(env);
  if (auth?.apiBaseUrl) {
    return auth.apiBaseUrl;
  }
  return loadUserConfig(env).api.baseUrl;
}

function resolveToken(env: DgPathEnvironment): string | undefined {
  return envAuthToken(env) ?? readAuthStateOrWarn(env)?.token;
}

export function identityHeaders(env: DgPathEnvironment): Record<string, string> {
  const headers: Record<string, string> = { "X-Device-Id": getOrCreateDeviceId(env) };
  const token = resolveToken(env);
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

function getOrCreateDeviceId(env: DgPathEnvironment): string {
  const path = join(resolveDgPaths(env).stateDir, "device-id");
  try {
    if (existsSync(path)) {
      const existing = readFileSync(path, "utf8").trim();
      if (existing) {
        return existing;
      }
    }
    const id = randomUUID();
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, `${id}\n`, { encoding: "utf8", mode: 0o600 });
    return id;
  } catch {
    return "anonymous";
  }
}
