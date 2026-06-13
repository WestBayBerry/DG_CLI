import { resolveRealBinary } from "../launcher/resolve-real-binary.js";
import { resolveSpawnInvocation, type SpawnInvocation } from "../launcher/spawn-invocation.js";

const toolPathCache = new Map<string, string | null>();

// Windows resolves bare command names against the child cwd before PATH,
// and dg routinely runs with cwd inside untrusted trees; external tools
// must always spawn from an absolute PATH-resolved location. Callers may
// pass a minimal child env; resolution then falls back to the parent PATH.
export function resolveToolPath(name: string, env: NodeJS.ProcessEnv = process.env): string | null {
  const searchEnv = env.PATH ? env : { ...env, PATH: process.env.PATH };
  const key = `${name} ${searchEnv.PATH ?? ""}`;
  const cached = toolPathCache.get(key);
  if (cached !== undefined) {
    return cached;
  }
  const path = resolveRealBinary({ name, env: searchEnv }).path;
  toolPathCache.set(key, path);
  return path;
}

export function toolInvocation(
  name: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv = process.env
): SpawnInvocation | null {
  const path = resolveToolPath(name, env);
  if (!path) {
    return null;
  }
  return resolveSpawnInvocation(path, args);
}
