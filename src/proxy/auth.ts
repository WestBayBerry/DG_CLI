import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const PROXY_AUTH_TOKEN_FILENAME = "proxy-auth-token";
export const PROXY_AUTH_USER = "dg";

export function generateProxyAuthToken(): string {
  return randomBytes(32).toString("hex");
}

export function proxyAuthTokenPath(sessionDir: string): string {
  return join(sessionDir, PROXY_AUTH_TOKEN_FILENAME);
}

export function writeProxyAuthToken(sessionDir: string, token: string): void {
  writeFileSync(proxyAuthTokenPath(sessionDir), `${token}\n`, {
    encoding: "utf8",
    mode: 0o600
  });
}

export function readProxyAuthToken(sessionDir: string): string | undefined {
  try {
    const token = readFileSync(proxyAuthTokenPath(sessionDir), "utf8").trim();
    return token.length > 0 ? token : undefined;
  } catch {
    return undefined;
  }
}

export function proxyUrlWithAuth(proxyUrl: string, token: string): string {
  const url = new URL(proxyUrl);
  return `${url.protocol}//${PROXY_AUTH_USER}:${token}@${url.host}`;
}

export function proxyAuthorizationValue(token: string): string {
  return `Basic ${Buffer.from(`${PROXY_AUTH_USER}:${token}`, "utf8").toString("base64")}`;
}

export function verifyProxyAuthorization(header: string | undefined, token: string): boolean {
  if (typeof header !== "string" || header.length === 0) {
    return false;
  }
  return timingSafeEqual(digest(header), digest(proxyAuthorizationValue(token)));
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}
