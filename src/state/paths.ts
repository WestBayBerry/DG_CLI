import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";

export interface DgPathEnvironment {
  readonly [key: string]: string | undefined;
  readonly HOME?: string;
  readonly XDG_CONFIG_HOME?: string;
  readonly XDG_STATE_HOME?: string;
  readonly XDG_CACHE_HOME?: string;
}

export interface DgPaths {
  readonly homeDir: string;
  readonly configDir: string;
  readonly stateDir: string;
  readonly cacheDir: string;
  readonly sessionsDir: string;
  readonly cleanupRegistryPath: string;
  readonly locksDir: string;
}

export function resolveDgPaths(env: DgPathEnvironment = process.env): DgPaths {
  const homeDir = env.HOME && isAbsolute(env.HOME) ? env.HOME : homedir();
  const fallbackRoot = join(homeDir, ".dg");
  const configDir = xdgPath(env.XDG_CONFIG_HOME, fallbackRoot);
  const stateDir = xdgPath(env.XDG_STATE_HOME, join(fallbackRoot, "state"));
  const cacheDir = xdgPath(env.XDG_CACHE_HOME, join(fallbackRoot, "cache"));

  return {
    homeDir,
    configDir,
    stateDir,
    cacheDir,
    sessionsDir: join(stateDir, "sessions"),
    cleanupRegistryPath: join(stateDir, "cleanup-registry.json"),
    locksDir: join(stateDir, "locks")
  };
}

function xdgPath(value: string | undefined, fallback: string): string {
  if (!value || !isAbsolute(value)) {
    return fallback;
  }
  return join(value, "dg");
}
