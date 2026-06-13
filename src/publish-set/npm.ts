import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { toolInvocation } from "../util/external-tool.js";
import { toDisplay } from "./collect.js";
import { noExecPackEnv } from "./no-exec-shell.js";

export interface PublishSet {
  readonly relPaths: string[];
  readonly source: "npm-pack" | "fallback";
  readonly hasAllowlist: boolean;
}

const DEFAULT_EXCLUDED_DIRS = new Set([
  "node_modules",
  ".git",
  ".svn",
  ".hg",
  "CVS",
  ".venv",
  "venv",
  "__pycache__"
]);

const DEFAULT_EXCLUDED_NAMES = new Set([
  ".npmignore",
  ".gitignore",
  ".DS_Store",
  ".npmrc",
  ".lock-wscript",
  "npm-debug.log",
  "package-lock.json"
]);

export function npmPublishSet(root: string, env: NodeJS.ProcessEnv = process.env): PublishSet {
  const hasAllowlist = npmHasAllowlist(root);
  const packed = npmPackList(root, env);
  if (packed) {
    return { relPaths: packed, source: "npm-pack", hasAllowlist };
  }
  return { relPaths: fallbackWalk(root), source: "fallback", hasAllowlist };
}

function npmHasAllowlist(root: string): boolean {
  if (existsSync(join(root, ".npmignore"))) {
    return true;
  }
  try {
    const parsed = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { files?: unknown };
    return Array.isArray(parsed.files) && parsed.files.length > 0;
  } catch {
    return false;
  }
}

function npmPackList(root: string, env: NodeJS.ProcessEnv): string[] | null {
  const invocation = toolInvocation("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], env);
  if (!invocation) {
    return null;
  }
  const shell = noExecPackEnv(env);
  let result;
  try {
    result = spawnSync(invocation.command, [...invocation.args], {
      cwd: root,
      env: shell.env,
      encoding: "utf8",
      timeout: 60_000,
      maxBuffer: 64 * 1024 * 1024,
      windowsVerbatimArguments: invocation.windowsVerbatimArguments
    });
  } finally {
    shell.cleanup();
  }
  if (result.status !== 0 || !result.stdout) {
    return null;
  }
  try {
    const parsed = JSON.parse(result.stdout) as Array<{ files?: Array<{ path?: string }> }>;
    const entry = parsed[0];
    if (!entry || !Array.isArray(entry.files)) {
      return null;
    }
    const paths = entry.files.map((file) => file.path).filter((path): path is string => typeof path === "string");
    return paths.length > 0 ? paths.map(toDisplay) : null;
  } catch {
    return null;
  }
}

function fallbackWalk(root: string): string[] {
  const out: string[] = [];
  walk(root, "", 0, out);
  return out.sort((left, right) => left.localeCompare(right));

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
        if (!DEFAULT_EXCLUDED_DIRS.has(entry.name)) {
          walk(join(absolute, entry.name), childRel, depth + 1, acc);
        }
        continue;
      }
      if (entry.isFile() || entry.isSymbolicLink()) {
        if (!DEFAULT_EXCLUDED_NAMES.has(entry.name)) {
          acc.push(toDisplay(childRel));
        }
      }
    }
  }
}
