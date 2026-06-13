const DEFAULT_MITM_PATTERNS = [
  "registry.npmjs.org",
  "*.npmjs.org",
  "registry.yarnpkg.com",
  "pypi.org",
  "files.pythonhosted.org",
  "crates.io",
  "static.crates.io",
  "index.crates.io"
] as const;

export function shouldMitmHost(host: string, env: NodeJS.ProcessEnv): boolean {
  const normalized = normalizeHost(host);
  const configured = (env.DG_PROXY_MITM_HOSTS ?? "").split(",").map((entry) => entry.trim()).filter(Boolean);
  return [...DEFAULT_MITM_PATTERNS, ...configured].some((pattern) => hostMatchesPattern(normalized, pattern));
}

function hostMatchesPattern(host: string, pattern: string): boolean {
  const normalized = normalizeHost(pattern);
  if (normalized.startsWith("*.")) {
    const suffix = normalized.slice(1);
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return host === normalized;
}

function normalizeHost(host: string): string {
  return host.replace(/^\[/, "").replace(/\]$/, "").replace(/\.$/, "").toLowerCase();
}
