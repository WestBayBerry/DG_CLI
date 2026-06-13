import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { toDisplay } from "./collect.js";
import type { PublishSet } from "./npm.js";

const EXCLUDED_DIRS = new Set([
  ".git",
  ".svn",
  ".hg",
  ".venv",
  "venv",
  "__pycache__",
  "build",
  "dist",
  ".tox",
  ".mypy_cache",
  ".pytest_cache",
  ".eggs"
]);

export function pypiPublishSet(root: string): PublishSet {
  const hasAllowlist = pypiHasAllowlist(root);
  const out: string[] = [];
  walk(root, "", 0, out);
  return { relPaths: out.sort((left, right) => left.localeCompare(right)), source: "fallback", hasAllowlist };

  function walk(absolute: string, rel: string, depth: number, acc: string[]): void {
    if (depth > 24) {
      return;
    }
    let entries;
    try {
      entries = readdirSync(absolute, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const childRel = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.has(entry.name) && !entry.name.endsWith(".egg-info")) {
          walk(join(absolute, entry.name), childRel, depth + 1, acc);
        }
        continue;
      }
      if (entry.isFile() || entry.isSymbolicLink()) {
        acc.push(toDisplay(childRel));
      }
    }
  }
}

function pypiHasAllowlist(root: string): boolean {
  if (existsSync(join(root, "MANIFEST.in"))) {
    return true;
  }
  try {
    const pyproject = readFileSync(join(root, "pyproject.toml"), "utf8");
    return /\[tool\.(setuptools|hatch|flit|poetry)[^\]]*\]/u.test(pyproject) && /include|packages|sdist/u.test(pyproject);
  } catch {
    return false;
  }
}
