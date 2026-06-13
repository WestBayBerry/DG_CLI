import { accessSync, constants, readFileSync } from "node:fs";
import { delimiter, join, resolve, sep } from "node:path";
import { resolveDgPaths } from "../state/index.js";

export interface ResolveRealBinaryOptions {
  readonly name: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly extraSkipDirs?: readonly string[];
}

export interface ResolveRealBinaryResult {
  readonly path: string | null;
  readonly skipped: readonly string[];
  readonly searched: readonly string[];
}

// Many systems (homebrew/macOS, some Linux) ship only the version-suffixed
// pip3/python3, not a bare pip/python. Fall back to those instead of reporting
// "real pip binary was not found".
const BINARY_FALLBACKS: Record<string, readonly string[]> = {
  pip: ["pip3"],
  python: ["python3"]
};

export function resolveRealBinary(options: ResolveRealBinaryOptions): ResolveRealBinaryResult {
  const env = options.env ?? process.env;
  const shimDir = join(resolveDgPaths(env).homeDir, ".dg", "shims");
  const skipDirs = new Set([resolve(shimDir), ...(options.extraSkipDirs ?? []).map((dir) => resolve(dir))]);
  const searched: string[] = [];
  const skipped: string[] = [];
  const extensions = process.platform === "win32" ? ["", ".cmd", ".exe", ".bat"] : [""];
  const pathDirs = (env.PATH ?? "").split(delimiter).filter(Boolean);
  const candidateNames = [options.name, ...(BINARY_FALLBACKS[options.name] ?? [])].filter(
    (name, index, all) => all.indexOf(name) === index
  );

  for (const name of candidateNames) {
    for (const rawDir of pathDirs) {
      const dir = resolve(rawDir);
      if (isSkippedDir(dir, skipDirs)) {
        skipped.push(rawDir);
        continue;
      }
      for (const extension of extensions) {
        const candidate = join(rawDir, `${name}${extension}`);
        searched.push(candidate);
        if (isExecutable(candidate) && !isDgShim(candidate)) {
          return {
            path: candidate,
            skipped,
            searched
          };
        }
        if (isDgShim(candidate)) {
          skipped.push(candidate);
        }
      }
    }
  }

  return {
    path: null,
    skipped,
    searched
  };
}

function isSkippedDir(dir: string, skipDirs: ReadonlySet<string>): boolean {
  for (const skipped of skipDirs) {
    if (dir === skipped || dir.startsWith(`${skipped}${sep}`)) {
      return true;
    }
  }
  return false;
}

function isExecutable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function isDgShim(path: string): boolean {
  try {
    return readFileSync(path, "utf8").slice(0, 160).includes("dg-shim-v1");
  } catch {
    return false;
  }
}
