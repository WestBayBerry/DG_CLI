import { dirname } from "node:path";
import { proxyUrlWithAuth, readProxyAuthToken } from "../proxy/auth.js";
import type { SupportedPackageManager } from "./classify.js";

export interface ProxyEnvironmentOptions {
  readonly manager: SupportedPackageManager;
  readonly baseEnv: NodeJS.ProcessEnv;
  readonly proxyUrl: string;
  readonly caBundlePath: string;
  readonly noProxyHosts?: readonly string[];
  // Throwaway cache dir: pointing the manager's download cache here forces a
  // re-fetch through the proxy so cached installs are still verified, not skipped.
  readonly cacheDir?: string;
}

// The client read timeout must exceed the proxy's per-artifact verdict ceiling
// (DG_INSTALL_VERDICT_TIMEOUT_MS, default 240s) plus download headroom, so the
// package manager never gives up on a legitimately-slow verify. Overridable for
// constrained environments via DG_CLIENT_READ_TIMEOUT_S.
function clientReadTimeoutSeconds(env: NodeJS.ProcessEnv): number {
  const override = Number(env.DG_CLIENT_READ_TIMEOUT_S);
  if (Number.isFinite(override) && override > 0) {
    return Math.ceil(override);
  }
  const verdictMs = Number(env.DG_INSTALL_VERDICT_TIMEOUT_MS);
  const verdictSeconds = Number.isFinite(verdictMs) && verdictMs > 0 ? verdictMs / 1000 : 240;
  return Math.ceil(verdictSeconds + 60);
}

export function buildProxyChildEnv(options: ProxyEnvironmentOptions): NodeJS.ProcessEnv {
  const authToken = readProxyAuthToken(dirname(options.caBundlePath));
  const proxyUrl = authToken ? proxyUrlWithAuth(options.proxyUrl, authToken) : options.proxyUrl;
  const env: NodeJS.ProcessEnv = {
    ...options.baseEnv,
    DG_PROXY_ACTIVE: "1"
  };
  // The wrapped package manager and every lifecycle/postinstall script it runs
  // are untrusted. The dg account credential must never reach them; only the
  // trusted proxy worker (which makes the authenticated API calls) keeps it.
  delete env.DG_API_KEY;
  delete env.DG_API_TOKEN;
  // dg fully controls NO_PROXY (loopback only). An inherited NO_PROXY that names
  // the registry (or a `*`/`.org` glob) would route the manager straight past the
  // firewall, so the inherited value is dropped, not merged.
  const noProxy = (options.noProxyHosts ?? ["127.0.0.1", "localhost"]).join(",");
  env.NO_PROXY = noProxy;
  env.no_proxy = noProxy;

  const readTimeoutSeconds = clientReadTimeoutSeconds(options.baseEnv);

  if (["npm", "npx", "pnpm", "pnpx", "yarn"].includes(options.manager)) {
    env.HTTP_PROXY = proxyUrl;
    env.HTTPS_PROXY = proxyUrl;
    env.npm_config_proxy = proxyUrl;
    env.npm_config_https_proxy = proxyUrl;
    env.NODE_EXTRA_CA_CERTS = options.caBundlePath;
    // The proxy withholds every artifact byte until its verdict resolves, so the
    // package manager sees no response data until then. Its own network read
    // timeout must outlast the proxy's worst-case verdict wait or it aborts a
    // legitimate install mid-verify (pip's 15s default is what made large cold
    // installs fail). Set it explicitly so a user-lowered global config can't
    // undercut the proxy.
    env.npm_config_fetch_timeout = String(readTimeoutSeconds * 1000);
    if (options.manager === "yarn") {
      env.YARN_NETWORK_TIMEOUT = String(readTimeoutSeconds * 1000);
    }
    if (options.manager === "yarn") {
      // Yarn Berry (2+) ignores HTTP(S)_PROXY/npm_config_*; without its own
      // proxy + CA config it fetches straight from the registry, bypassing the
      // firewall. Classic Yarn ignores these YARN_ vars, so set them for both.
      env.YARN_HTTP_PROXY = proxyUrl;
      env.YARN_HTTPS_PROXY = proxyUrl;
      env.YARN_HTTPS_CA_FILE_PATH = options.caBundlePath;
    }
    if (options.cacheDir) {
      env.npm_config_cache = options.cacheDir;
      if (options.manager === "yarn") {
        // Both: YARN_CACHE_FOLDER is Berry's per-project cache, but Berry 2+
        // defaults to a shared global cache (~/.yarn/berry) that a warm install
        // serves from without ever fetching, so redirect that too.
        env.YARN_CACHE_FOLDER = options.cacheDir;
        env.YARN_GLOBAL_FOLDER = options.cacheDir;
      }
    }
    return env;
  }

  if (options.manager === "pip" || options.manager === "pipx") {
    env.http_proxy = proxyUrl;
    env.https_proxy = proxyUrl;
    env.REQUESTS_CA_BUNDLE = options.caBundlePath;
    env.PIP_CERT = options.caBundlePath;
    env.PIP_NO_CACHE_DIR = "1";
    env.PIP_DEFAULT_TIMEOUT = String(readTimeoutSeconds);
    return env;
  }

  if (options.manager === "uv" || options.manager === "uvx") {
    env.HTTP_PROXY = proxyUrl;
    env.HTTPS_PROXY = proxyUrl;
    env.ALL_PROXY = proxyUrl;
    env.SSL_CERT_FILE = options.caBundlePath;
    env.UV_NO_CACHE = "1";
    env.UV_HTTP_TIMEOUT = String(readTimeoutSeconds);
    return env;
  }

  env.HTTPS_PROXY = proxyUrl;
  env.https_proxy = proxyUrl;
  env.http_proxy = proxyUrl;
  env.CARGO_HTTP_CAINFO = options.caBundlePath;
  env.CARGO_HTTP_TIMEOUT = String(readTimeoutSeconds);
  if (options.cacheDir) {
    // cargo serves a cached crate from ~/.cargo with zero network, skipping the
    // firewall; pointing CARGO_HOME at the throwaway dir forces a re-fetch.
    env.CARGO_HOME = options.cacheDir;
  }
  return env;
}
