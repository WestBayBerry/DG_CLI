import { authStatus, readAuthState } from "../auth/store.js";
import { envAuthToken } from "../auth/env-token.js";
import { loadUserConfig } from "../config/settings.js";
import { packNpmArtifact } from "../publish-set/pack.js";

export type DeepAction = "pass" | "warn" | "block" | "analysis_incomplete";

export type DeepResult =
  | { readonly ran: false; readonly reason: string }
  | { readonly ran: true; readonly action: DeepAction; readonly reason: string };

export interface DeepScope {
  readonly root: string;
  readonly ecosystem: string;
  readonly artifact: string;
}

export interface DeepDecision {
  readonly upload: boolean;
  readonly reason: string;
}

export function deepDecision(scope: DeepScope, local: boolean, env: NodeJS.ProcessEnv = process.env): DeepDecision {
  if (local) {
    return { upload: false, reason: "local mode (--local)" };
  }
  if (scope.ecosystem !== "npm") {
    return { upload: false, reason: `npm packages only (this is ${scope.ecosystem})` };
  }
  let authed = false;
  try {
    authed = authStatus(env).authenticated;
  } catch {
    authed = false;
  }
  if (!authed) {
    return { upload: false, reason: "not signed in — run dg login to enable" };
  }
  if (!consentGiven(env)) {
    return { upload: false, reason: "upload not enabled — set DG_AUDIT_UPLOAD=1 or consent in a terminal" };
  }
  return { upload: true, reason: "" };
}

export function consentGiven(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.DG_AUDIT_UPLOAD === "1" || env.DG_AUDIT_UPLOAD === "true") {
    return true;
  }
  try {
    return loadUserConfig(env).audit.upload === true;
  } catch {
    return false;
  }
}

export interface DeepUploadDeps {
  readonly fetchImpl?: typeof fetch;
  readonly env?: NodeJS.ProcessEnv;
  readonly signal?: AbortSignal;
}

export async function runDeepUpload(
  scope: DeepScope,
  packageJson: Record<string, unknown> | null,
  deps: DeepUploadDeps = {}
): Promise<DeepResult> {
  const env = deps.env ?? process.env;
  const fetchImpl = deps.fetchImpl ?? fetch;

  const packed = packNpmArtifact(scope.root, env);
  if ("error" in packed) {
    return { ran: false, reason: `could not pack the package (${packed.error})` };
  }

  const token = resolveToken(env);
  if (!token) {
    return { ran: false, reason: "not signed in — run dg login to enable" };
  }
  const baseUrl = resolveBaseUrl(env);
  const name = typeof packageJson?.name === "string" ? packageJson.name : scope.artifact.split("@")[0] ?? "unknown";
  const version = typeof packageJson?.version === "string" ? packageJson.version : "0.0.0";

  let response: Response;
  const controller = new AbortController();
  const abortUpstream = (): void => controller.abort();
  if (deps.signal?.aborted) {
    controller.abort();
  }
  deps.signal?.addEventListener("abort", abortUpstream, { once: true });
  try {
    const timeout = setTimeout(() => controller.abort(), 600_000);
    try {
      response = await fetchImpl(`${baseUrl}/v1/scan-tarball`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/octet-stream",
          "X-DG-Action": "audit",
          "X-DG-Artifact-SHA256": packed.sha256,
          "X-DG-Cache-Key": `sha256:${packed.sha256}`,
          "X-DG-Ecosystem": "npm",
          "X-DG-Manager": "dg-audit",
          "X-DG-Package-Name": name,
          "X-DG-Package-Version": version,
          "X-DG-Privacy": "private-artifact",
          "X-DG-Registry-Host": "registry.npmjs.org",
          "X-DG-Source-Kind": "pre-publish"
        },
        body: packed.bytes,
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeout);
    }
  } catch {
    return { ran: false, reason: "offline — could not reach the scanner (basic audit still ran)" };
  } finally {
    deps.signal?.removeEventListener("abort", abortUpstream);
  }

  if (response.status === 402 || response.status === 403) {
    const body = await safeJson(response);
    return { ran: false, reason: deniedReason(body?.code) };
  }
  if (!response.ok) {
    return { ran: true, action: "analysis_incomplete", reason: `scanner error (HTTP ${response.status})` };
  }

  const body = await safeJson(response);
  const verdict = body?.verdict;
  if (verdict === "pass" || verdict === "warn" || verdict === "block") {
    return { ran: true, action: verdict, reason: typeof body?.reason === "string" ? body.reason : `behavioral verdict: ${verdict}` };
  }
  return { ran: true, action: "analysis_incomplete", reason: "scanner returned an incomplete verdict" };
}

export function deepSummary(deep: DeepResult): string {
  if (!deep.ran) {
    return deep.reason;
  }
  const redundant = !deep.reason || deep.reason.startsWith("behavioral verdict");
  return redundant ? deep.action : `${deep.action} — ${deep.reason}`;
}

export async function teamPolicyBlocksUpload(
  env: NodeJS.ProcessEnv = process.env,
  fetchImpl: typeof fetch = fetch
): Promise<boolean> {
  const token = resolveToken(env);
  if (!token) {
    return false;
  }
  const baseUrl = resolveBaseUrl(env);
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3_000);
    let response: Response;
    try {
      response = await fetchImpl(`${baseUrl}/v1/cli/policy`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
        signal: controller.signal
      });
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      return false;
    }
    const body = (await response.json()) as { source?: string; privateArtifactUpload?: string };
    return body.source === "org" && body.privateArtifactUpload === "disabled";
  } catch {
    return false;
  }
}

function resolveToken(env: NodeJS.ProcessEnv): string | null {
  const fromEnv = envAuthToken(env);
  if (fromEnv) {
    return fromEnv;
  }
  try {
    const state = readAuthState(env);
    return state && typeof state.token === "string" && state.token.length > 0 ? state.token : null;
  } catch {
    return null;
  }
}

function resolveBaseUrl(env: NodeJS.ProcessEnv): string {
  try {
    return loadUserConfig(env).api.baseUrl.replace(/\/$/u, "");
  } catch {
    return "https://api.westbayberry.com";
  }
}

function deniedReason(code: string | undefined): string {
  if (code === "artifact-upload-disabled") {
    return "your team disabled artifact uploads — a team admin can re-enable it in dashboard policy settings";
  }
  if (code === "org-policy-required") {
    return "your team hasn't enabled artifact uploads — a team admin can enable it in dashboard policy settings";
  }
  return "deep behavioral scan requires a paid plan";
}

async function safeJson(response: Response): Promise<{ verdict?: string; reason?: string; code?: string; error?: string } | null> {
  try {
    return (await response.json()) as { verdict?: string; reason?: string; code?: string; error?: string };
  } catch {
    return null;
  }
}
