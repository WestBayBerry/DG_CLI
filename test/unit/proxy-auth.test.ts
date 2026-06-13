import { statSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  generateProxyAuthToken,
  proxyAuthorizationValue,
  proxyAuthTokenPath,
  proxyUrlWithAuth,
  readProxyAuthToken,
  verifyProxyAuthorization,
  writeProxyAuthToken
} from "../../src/proxy/auth.js";
import { buildProxyChildEnv } from "../../src/launcher/env.js";

const tempRoots: string[] = [];

async function tempDir(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-proxy-auth-"));
  tempRoots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("proxy auth token", () => {
  it("generates unique 64-hex tokens", () => {
    const first = generateProxyAuthToken();
    const second = generateProxyAuthToken();
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(second).toMatch(/^[0-9a-f]{64}$/);
    expect(first).not.toBe(second);
  });

  it("round-trips through the session dir with 0600 permissions", async () => {
    const dir = await tempDir();
    const token = generateProxyAuthToken();
    writeProxyAuthToken(dir, token);

    expect(readProxyAuthToken(dir)).toBe(token);
    expect(statSync(proxyAuthTokenPath(dir)).mode & 0o777).toBe(0o600);
  });

  it("returns undefined for a missing or empty token file", async () => {
    const dir = await tempDir();
    expect(readProxyAuthToken(dir)).toBeUndefined();
    writeProxyAuthToken(dir, "");
    expect(readProxyAuthToken(dir)).toBeUndefined();
  });

  it("verifies only the exact Basic credential for the token", () => {
    const token = generateProxyAuthToken();
    const header = proxyAuthorizationValue(token);

    expect(header).toMatch(/^Basic /);
    expect(Buffer.from(header.slice("Basic ".length), "base64").toString("utf8")).toBe(`dg:${token}`);
    expect(verifyProxyAuthorization(header, token)).toBe(true);
    expect(verifyProxyAuthorization(undefined, token)).toBe(false);
    expect(verifyProxyAuthorization("", token)).toBe(false);
    expect(verifyProxyAuthorization(header.slice(0, -2), token)).toBe(false);
    expect(verifyProxyAuthorization(proxyAuthorizationValue(generateProxyAuthToken()), token)).toBe(false);
  });

  it("embeds the credential as userinfo in the proxy URL", () => {
    expect(proxyUrlWithAuth("http://127.0.0.1:19000", "tok123")).toBe("http://dg:tok123@127.0.0.1:19000");
  });
});

describe("buildProxyChildEnv proxy-auth wiring", () => {
  it("hands the package manager an authenticated proxy URL when the session token exists", async () => {
    const dir = await tempDir();
    const token = generateProxyAuthToken();
    writeProxyAuthToken(dir, token);

    const env = buildProxyChildEnv({
      manager: "npm",
      baseEnv: {},
      proxyUrl: "http://127.0.0.1:19000",
      caBundlePath: join(dir, "ca.pem")
    });

    expect(env.HTTP_PROXY).toBe(`http://dg:${token}@127.0.0.1:19000`);
    expect(env.HTTPS_PROXY).toBe(`http://dg:${token}@127.0.0.1:19000`);
    expect(env.npm_config_proxy).toBe(`http://dg:${token}@127.0.0.1:19000`);

    const pip = buildProxyChildEnv({
      manager: "pip",
      baseEnv: {},
      proxyUrl: "http://127.0.0.1:19000",
      caBundlePath: join(dir, "ca.pem")
    });
    expect(pip.https_proxy).toBe(`http://dg:${token}@127.0.0.1:19000`);
  });

  it("leaves the proxy URL untouched when no session token exists", async () => {
    const dir = await tempDir();
    const env = buildProxyChildEnv({
      manager: "npm",
      baseEnv: {},
      proxyUrl: "http://127.0.0.1:19000",
      caBundlePath: join(dir, "ca.pem")
    });
    expect(env.HTTP_PROXY).toBe("http://127.0.0.1:19000");
  });
});
