const MINIMUM_NODE = Object.freeze({
  major: 22,
  minor: 14,
  patch: 0
});

export type NodeVersion = {
  major: number;
  minor: number;
  patch: number;
};

export function parseNodeVersion(version: string): NodeVersion | null {
  const normalized = version.trim().replace(/^v/, "");
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-.+)?$/.exec(normalized);
  if (!match) {
    return null;
  }

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3])
  };
}

export function isSupportedNode(version: string): boolean {
  const parsed = parseNodeVersion(version);
  if (!parsed) {
    return false;
  }

  if (parsed.major > MINIMUM_NODE.major) {
    return true;
  }
  if (parsed.major < MINIMUM_NODE.major) {
    return false;
  }
  if (parsed.minor > MINIMUM_NODE.minor) {
    return true;
  }
  if (parsed.minor < MINIMUM_NODE.minor) {
    return false;
  }
  return parsed.patch >= MINIMUM_NODE.patch;
}

export function assertSupportedNode(version: string): void {
  if (isSupportedNode(version)) {
    return;
  }

  throw new Error(
    `dg requires Node.js >=22.14.0. Current runtime is ${version}. Upgrade Node before running dg.`
  );
}

export function currentNodeVersion(): string {
  if (process.env.NODE_ENV === "test" && process.env.DG_TEST_NODE_VERSION) {
    return process.env.DG_TEST_NODE_VERSION;
  }
  return process.version;
}

export interface ShimFallback {
  readonly binary: string;
  readonly args: readonly string[];
  readonly warning: string;
}

// The shims exec dg unconditionally; a hard exit on old Node would brick every shimmed manager.
export async function resolveShimFallback(
  env: NodeJS.ProcessEnv = process.env,
  argv: readonly string[] = process.argv
): Promise<ShimFallback | null> {
  if (!env.DG_SHIM_ACTIVE) {
    return null;
  }
  const manager = argv[2];
  if (!manager) {
    return null;
  }
  try {
    const { resolveRealBinary } = await import("../launcher/resolve-real-binary.js");
    const binary = resolveRealBinary({ name: manager, env }).path;
    if (!binary) {
      return null;
    }
    return {
      binary,
      args: argv.slice(3),
      warning: `dg: protection inactive — dg requires Node.js >=22.14.0 but found ${currentNodeVersion()}; running ${manager} unprotected\n`
    };
  } catch {
    return null;
  }
}

export async function assertCurrentNode(): Promise<void> {
  const version = currentNodeVersion();
  if (isSupportedNode(version)) {
    return;
  }
  const fallback = await resolveShimFallback();
  if (fallback) {
    process.stderr.write(fallback.warning);
    const [{ spawnSync }, { resolveSpawnInvocation }] = await Promise.all([
      import("node:child_process"),
      import("../launcher/spawn-invocation.js")
    ]);
    const invocation = resolveSpawnInvocation(fallback.binary, fallback.args);
    const result = spawnSync(invocation.command, [...invocation.args], {
      stdio: "inherit",
      windowsVerbatimArguments: invocation.windowsVerbatimArguments
    });
    process.exit(result.status ?? 1);
  }
  process.stderr.write(`dg requires Node.js >=22.14.0. Current runtime is ${version}. Upgrade Node before running dg.\n`);
  process.exit(1);
}
