import { existsSync, lstatSync, mkdirSync, symlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const PRESERVED_ENTRIES = ["config.toml", "config", "credentials.toml", "credentials"] as const;

export function userCargoHome(env: NodeJS.ProcessEnv): string {
  const explicit = env.CARGO_HOME?.trim();
  return explicit ? explicit : join(homedir(), ".cargo");
}

// Cargo keeps registry config and auth tokens (config.toml / credentials.toml)
// inside CARGO_HOME, next to the crate cache. dg redirects CARGO_HOME to an empty
// per-session dir so cached crates re-fetch through the firewall, which would also
// hide a private-registry user's config and tokens — so link those back in.
export function prepareCargoHome(cacheDir: string, source: string): readonly string[] {
  mkdirSync(cacheDir, { recursive: true });
  const linked: string[] = [];
  for (const name of PRESERVED_ENTRIES) {
    const target = join(source, name);
    const link = join(cacheDir, name);
    if (!existsSync(target) || pathPresent(link)) {
      continue;
    }
    try {
      symlinkSync(target, link);
      linked.push(name);
    } catch {
      continue;
    }
  }
  return linked;
}

function pathPresent(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}
