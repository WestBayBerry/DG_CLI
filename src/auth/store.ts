import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { loadUserConfig, parseUrl, saveUserConfig, withUserConfigLock } from "../config/settings.js";
import { resolveDgPaths, type DgPathEnvironment, type DgPaths } from "../state/index.js";
import { envAuthToken } from "./env-token.js";

export interface AuthState {
  readonly version: 1;
  readonly token: string;
  readonly tokenPreview: string;
  readonly apiBaseUrl: string;
  readonly orgId: string;
  readonly loggedInAt: string;
  readonly email?: string;
  readonly tier?: string;
  readonly name?: string;
}

export interface AuthStatus {
  readonly authenticated: boolean;
  readonly source: "file" | "env" | "none";
  readonly tokenPreview: string;
  readonly apiBaseUrl: string;
  readonly orgId: string;
  readonly email?: string;
  readonly tier?: string;
  readonly name?: string;
}

export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthError";
  }
}

export function authPath(paths: DgPaths): string {
  return join(paths.configDir, "auth.json");
}

export function readAuthState(env: DgPathEnvironment = process.env): AuthState | undefined {
  const paths = resolveDgPaths(env);
  const path = authPath(paths);
  if (!existsSync(path)) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<AuthState>;
    if (parsed.version !== 1 || !parsed.token || !parsed.apiBaseUrl || parsed.loggedInAt === undefined) {
      throw new AuthError("unsupported auth state");
    }
    let apiBaseUrl: string;
    try {
      apiBaseUrl = parseUrl(parsed.apiBaseUrl);
    } catch {
      throw new AuthError("auth state has an invalid api base URL; run 'dg login' again");
    }
    const email = typeof parsed.email === "string" && parsed.email.length > 0 ? parsed.email : undefined;
    const tier = typeof parsed.tier === "string" && parsed.tier.length > 0 ? parsed.tier : undefined;
    const name = typeof parsed.name === "string" && parsed.name.length > 0 ? parsed.name : undefined;
    return {
      version: 1,
      token: parsed.token,
      tokenPreview: parsed.tokenPreview ?? redactToken(parsed.token),
      apiBaseUrl,
      orgId: parsed.orgId ?? "",
      loggedInAt: parsed.loggedInAt,
      ...(email ? { email } : {}),
      ...(tier ? { tier } : {}),
      ...(name ? { name } : {})
    };
  } catch (error) {
    throw new AuthError(`Malformed dg auth state at ${path}: ${error instanceof Error ? error.message : "unknown error"}`);
  }
}

const warnedAuthPaths = new Set<string>();

export function readAuthStateOrWarn(
  env: DgPathEnvironment = process.env,
  options: { readonly stderr?: { write(text: string): unknown } } = {}
): AuthState | undefined {
  try {
    return readAuthState(env);
  } catch {
    const path = authPath(resolveDgPaths(env));
    if (!warnedAuthPaths.has(path)) {
      warnedAuthPaths.add(path);
      const stderr = options.stderr ?? process.stderr;
      stderr.write(`dg: auth state at ${path} is unreadable; continuing without your account. Run 'dg login' to repair it.\n`);
    }
    return undefined;
  }
}

export function writeAuthState(
  options: {
    readonly token: string;
    readonly apiBaseUrl?: string;
    readonly orgId?: string;
    readonly email?: string | undefined;
    readonly tier?: string | undefined;
    readonly name?: string | undefined;
    readonly now?: Date;
  },
  env: DgPathEnvironment = process.env
): AuthState {
  const token = options.token.trim();
  if (token.length < 8) {
    throw new AuthError("token must be at least 8 characters");
  }
  const email = typeof options.email === "string" && options.email.length > 0 ? options.email : undefined;
  const tier = typeof options.tier === "string" && options.tier.length > 0 ? options.tier : undefined;
  const name = typeof options.name === "string" && options.name.length > 0 ? options.name : undefined;
  return withUserConfigLock(env, () => {
    const config = loadUserConfig(env);
    const apiBaseUrl = options.apiBaseUrl ?? config.api.baseUrl;
    const orgId = options.orgId ?? config.org.id;
    const state: AuthState = {
      version: 1,
      token,
      tokenPreview: redactToken(token),
      apiBaseUrl,
      orgId,
      loggedInAt: (options.now ?? new Date()).toISOString(),
      ...(email ? { email } : {}),
      ...(tier ? { tier } : {}),
      ...(name ? { name } : {})
    };
    const paths = resolveDgPaths(env);
    writeJsonAtomic(authPath(paths), state);
    saveUserConfig(
      {
        ...config,
        api: {
          baseUrl: apiBaseUrl
        },
        org: {
          id: orgId
        }
      },
      env
    );
    return state;
  });
}

export function clearAuthState(env: DgPathEnvironment = process.env): boolean {
  const path = authPath(resolveDgPaths(env));
  if (!existsSync(path)) {
    return false;
  }
  unlinkSync(path);
  return true;
}

export function authStatus(env: DgPathEnvironment = process.env): AuthStatus {
  const config = loadUserConfig(env);
  const envToken = envAuthToken(env);
  if (envToken) {
    return {
      authenticated: true,
      source: "env",
      tokenPreview: redactToken(envToken),
      apiBaseUrl: config.api.baseUrl,
      orgId: config.org.id
    };
  }
  const state = readAuthState(env);
  if (state) {
    return {
      authenticated: true,
      source: "file",
      tokenPreview: state.tokenPreview,
      apiBaseUrl: state.apiBaseUrl,
      orgId: state.orgId,
      ...(state.email ? { email: state.email } : {}),
      ...(state.tier ? { tier: state.tier } : {}),
      ...(state.name ? { name: state.name } : {})
    };
  }
  return {
    authenticated: false,
    source: "none",
    tokenPreview: "",
    apiBaseUrl: config.api.baseUrl,
    orgId: config.org.id
  };
}

export function displayTier(tier: string): string {
  return tier.charAt(0).toUpperCase() + tier.slice(1);
}

export function redactToken(token: string): string {
  const trimmed = token.trim();
  if (trimmed.length <= 8) {
    return "<redacted>";
  }
  return `${trimmed.slice(0, 4)}...${trimmed.slice(-4)}`;
}

function writeJsonAtomic(path: string, value: unknown): void {
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
