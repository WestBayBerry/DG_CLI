import { spawn } from "node:child_process";
import { closeSync, openSync, readSync } from "node:fs";
import { displayTier, writeAuthState } from "./store.js";
import { loadUserConfig } from "../config/settings.js";
import { createTheme } from "../presentation/theme.js";
import { resolvePresentation } from "../presentation/mode.js";
import type { DgPathEnvironment } from "../state/index.js";
import type { CommandResult } from "../commands/types.js";

const DEFAULT_WEB_BASE = "https://westbayberry.com";
export const POLL_INTERVAL_MS = 2000;
export const POLL_TIMEOUT_MS = 5 * 60_000;

export function resolveWebBase(env: DgPathEnvironment): string {
  const override = env.DG_AUTH_BASE;
  if (override) {
    try {
      const url = new URL(override);
      const localhost = url.hostname === "localhost" || url.hostname === "127.0.0.1";
      if (url.protocol === "https:" || (url.protocol === "http:" && localhost)) {
        return override.replace(/\/$/, "");
      }
    } catch {
      // fall through to derived/default base
    }
  }
  try {
    const url = new URL(loadUserConfig(env).api.baseUrl);
    if (url.hostname.startsWith("api.")) {
      return `${url.protocol}//${url.hostname.slice(4)}`;
    }
  } catch {
    // fall through to default base
  }
  return DEFAULT_WEB_BASE;
}

export type AuthSession = { sessionId: string; verifyUrl: string; expiresIn: number };
export type PollResult = { status: "pending" | "complete" | "expired"; apiKey?: string | undefined; email?: string | undefined };

function isSameOrSubdomain(host: string, base: string): boolean {
  return host === base || host.endsWith(`.${base}`);
}

export function assertTrustedVerifyUrl(verifyUrl: string, webBase: string): string {
  let verify: URL;
  try {
    verify = new URL(verifyUrl);
  } catch {
    throw new Error("login server returned an invalid verify URL");
  }
  if (verify.protocol !== "https:" && verify.protocol !== "http:") {
    throw new Error("login server returned an unsupported verify URL");
  }
  const baseHost = new URL(webBase).hostname;
  if (!isSameOrSubdomain(verify.hostname, baseHost)) {
    throw new Error(`refusing to open verify URL on untrusted host '${verify.hostname}'`);
  }
  return verifyUrl;
}

export async function createAuthSession(webBase: string, fetchImpl: typeof fetch): Promise<AuthSession> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetchImpl(`${webBase}/cli/auth/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal
    });
    if (!response.ok) {
      throw new Error(`could not start login (HTTP ${response.status})`);
    }
    const json = (await response.json()) as { session_id: string; verify_url: string; expires_in: number };
    const verifyUrl = assertTrustedVerifyUrl(json.verify_url, webBase);
    return { sessionId: json.session_id, verifyUrl, expiresIn: json.expires_in };
  } finally {
    clearTimeout(timeout);
  }
}

export async function pollAuthSession(webBase: string, sessionId: string, fetchImpl: typeof fetch): Promise<PollResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  try {
    const response = await fetchImpl(`${webBase}/cli/auth/sessions/${sessionId}/token`, { signal: controller.signal });
    if (response.status >= 500) {
      return { status: "pending" };
    }
    if (response.status === 404 || !response.ok) {
      return { status: "expired" };
    }
    const json = (await response.json()) as { status: "pending" | "complete" | "expired"; api_key?: string; email?: string };
    return { status: json.status, apiKey: json.api_key, email: json.email };
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      return { status: "pending" };
    }
    return { status: "expired" };
  } finally {
    clearTimeout(timeout);
  }
}

export function openBrowser(url: string): void {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return;
    }
  } catch {
    return;
  }
  let command: string;
  let args: string[];
  switch (process.platform) {
    case "darwin":
      command = "open";
      args = [url];
      break;
    case "linux":
      command = "xdg-open";
      args = [url];
      break;
    case "win32":
      command = "cmd.exe";
      args = ["/c", "start", "", url];
      break;
    default:
      return;
  }
  try {
    const child = spawn(command, args, { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
  } catch {
    // a failed browser open is non-fatal; the verify URL is printed too
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function waitForEnter(): void {
  let tty: number;
  try {
    tty = openSync("/dev/tty", "rs");
  } catch {
    return;
  }
  try {
    const byte = Buffer.alloc(1);
    for (;;) {
      let read = 0;
      try {
        read = readSync(tty, byte, 0, 1, null);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EAGAIN") {
          continue;
        }
        break;
      }
      if (read === 0) {
        break;
      }
      const char = byte.toString("utf8");
      if (char === "\n" || char === "\r") {
        break;
      }
    }
  } finally {
    closeSync(tty);
  }
}

export interface DeviceLoginIo {
  readonly env?: DgPathEnvironment;
  readonly fetchImpl?: typeof fetch;
  readonly stderr?: { write(text: string): unknown };
  readonly open?: (url: string) => void;
  readonly confirm?: () => void;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
}

export interface AccountStatus {
  readonly tier: string | null;
  readonly name: string | null;
  readonly scansUsed: number | null;
  readonly scansLimit: number | null;
}

export async function fetchAccountStatus(
  token: string,
  env: DgPathEnvironment,
  fetchImpl: typeof fetch,
  timeoutMs = 5_000
): Promise<AccountStatus | null> {
  let apiBase: string;
  try {
    apiBase = loadUserConfig(env).api.baseUrl.replace(/\/$/, "");
  } catch {
    return null;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(`${apiBase}/v1/auth/status`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal
    });
    if (!response.ok) {
      return null;
    }
    const body = (await response.json()) as { tier?: unknown; name?: unknown; scansUsed?: unknown; scansLimit?: unknown };
    return {
      tier: typeof body.tier === "string" && body.tier.length > 0 ? body.tier.toLowerCase() : null,
      name: typeof body.name === "string" && body.name.trim().length > 0 ? body.name.trim() : null,
      scansUsed: typeof body.scansUsed === "number" && Number.isFinite(body.scansUsed) ? body.scansUsed : null,
      scansLimit: typeof body.scansLimit === "number" && Number.isFinite(body.scansLimit) ? body.scansLimit : null
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function runDeviceLogin(io: DeviceLoginIo = {}): Promise<CommandResult> {
  const env = io.env ?? process.env;
  const fetchImpl = io.fetchImpl ?? fetch;
  const stderr = io.stderr ?? process.stderr;
  const open = io.open ?? openBrowser;
  const confirm = io.confirm ?? waitForEnter;
  const now = io.now ?? Date.now;
  const sleep = io.sleep ?? delay;
  const webBase = resolveWebBase(env);
  const theme = createTheme(resolvePresentation().color);
  const accent = (text: string): string => theme.paint("accent", text);
  const muted = (text: string): string => theme.paint("muted", text);

  let session: AuthSession;
  try {
    session = await createAuthSession(webBase, fetchImpl);
  } catch (error) {
    return {
      exitCode: 1,
      stdout: "",
      stderr: `dg login: ${error instanceof Error ? error.message : "could not start login"}.\n`
    };
  }

  stderr.write(`\n  Sign in at:\n  ${accent(session.verifyUrl)}\n\n  ${muted("Press Enter to open it in your browser…")}`);
  confirm();
  open(session.verifyUrl);
  stderr.write(`\n  ${muted("Waiting for you to approve in the browser…")}\n\n`);

  const deadline = now() + POLL_TIMEOUT_MS;
  for (;;) {
    const result = await pollAuthSession(webBase, session.sessionId, fetchImpl);
    if (result.status === "complete" && result.apiKey) {
      const account = await fetchAccountStatus(result.apiKey, env, fetchImpl);
      const tier = account?.tier ?? null;
      writeAuthState({ token: result.apiKey, email: result.email, tier: tier ?? undefined, name: account?.name ?? undefined });
      const who = result.email ? ` as ${result.email}` : "";
      return {
        exitCode: 0,
        stdout: `✓ Logged in${who}${tier ? ` ${muted(`(${displayTier(tier)} plan)`)}` : ""}.\n`,
        stderr: ""
      };
    }
    if (result.status === "expired") {
      return { exitCode: 1, stdout: "", stderr: "dg login: that login link expired. Run 'dg login' again.\n" };
    }
    if (now() >= deadline) {
      return { exitCode: 1, stdout: "", stderr: "dg login: timed out waiting for browser approval. Run 'dg login' again.\n" };
    }
    await sleep(POLL_INTERVAL_MS);
  }
}

export async function maybeDeviceLogin(args: readonly string[]): Promise<{ handled: boolean; result: CommandResult }> {
  const noop: CommandResult = { exitCode: 0, stdout: "", stderr: "" };
  if (args[0] !== "login") {
    return { handled: false, result: noop };
  }
  if (args.length > 1) {
    return { handled: false, result: noop };
  }
  if (!process.stdin.isTTY || !process.stderr.isTTY) {
    return { handled: false, result: noop };
  }
  const { resolvePresentation } = await import("../presentation/mode.js");
  if (resolvePresentation().mode === "rich") {
    const { runDeviceLoginTui } = await import("./login-app.js");
    const exitCode = await runDeviceLoginTui();
    return { handled: true, result: { exitCode, stdout: "", stderr: "" } };
  }
  return { handled: true, result: await runDeviceLogin() };
}
