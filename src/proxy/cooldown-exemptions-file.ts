import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseCooldownExemption, type CooldownExemption } from "../project/dgfile.js";

export const COOLDOWN_EXEMPTIONS_FILE = "cooldown-exemptions.json";
export const COOLDOWN_EXEMPTIONS_ENV = "DG_PROXY_COOLDOWN_EXEMPTIONS_FILE";

export function writeCooldownExemptionsFile(
  sessionDir: string,
  exemptions: readonly CooldownExemption[]
): Record<string, string> {
  if (exemptions.length === 0) {
    return {};
  }
  try {
    const path = join(sessionDir, COOLDOWN_EXEMPTIONS_FILE);
    writeFileSync(path, JSON.stringify(exemptions), { encoding: "utf8", mode: 0o600 });
    return { [COOLDOWN_EXEMPTIONS_ENV]: path };
  } catch {
    return {};
  }
}

export function loadCooldownExemptionsFile(path: string | undefined): readonly CooldownExemption[] {
  if (!path) {
    return [];
  }
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.map((entry) => parseCooldownExemption(entry)).filter((entry): entry is CooldownExemption => entry !== null);
  } catch {
    return [];
  }
}
