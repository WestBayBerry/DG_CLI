import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import type { ScriptHook } from "../project/dgfile.js";

export interface ScriptWanter {
  readonly name: string;
  readonly version: string;
  readonly hooks: readonly ScriptHook[];
  readonly scriptsHash: string;
}

const LIFECYCLE_HOOKS = ["preinstall", "install", "postinstall"] as const;

export function computeScriptsHash(scripts: Readonly<Record<string, unknown>>, hasGyp: boolean): string {
  const canonical = JSON.stringify({
    preinstall: lifecycleCommand(scripts, "preinstall"),
    install: lifecycleCommand(scripts, "install"),
    postinstall: lifecycleCommand(scripts, "postinstall"),
    gyp: hasGyp
  });
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

export function detectScriptWanters(projectDir: string): readonly ScriptWanter[] {
  const nodeModules = join(projectDir, "node_modules");
  const fromLockfile = wantersFromHiddenLockfile(projectDir, nodeModules);
  const wanters = fromLockfile ?? wantersFromWalk(nodeModules);
  const byName = new Map<string, ScriptWanter>();
  for (const wanter of wanters) {
    if (!byName.has(wanter.name)) {
      byName.set(wanter.name, wanter);
    }
  }
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function detectPnpmIgnoredBuilds(projectDir: string): readonly string[] {
  const modulesYamlPath = join(projectDir, "node_modules", ".modules.yaml");
  let content: string;
  try {
    content = readFileSync(modulesYamlPath, "utf8");
  } catch {
    return [];
  }
  const lines = content.split("\n");
  const startIndex = lines.findIndex((line) => /^ignoredBuilds:/.test(line));
  if (startIndex === -1) {
    return [];
  }
  const startLine = lines[startIndex] ?? "";
  if (/\[\s*\]\s*$/.test(startLine)) {
    return [];
  }
  const names: string[] = [];
  for (const line of lines.slice(startIndex + 1)) {
    const match = /^\s+-\s+(.+?)\s*$/.exec(line);
    if (!match || !match[1]) {
      break;
    }
    names.push(stripYamlQuotes(match[1]));
  }
  return names;
}

function stripYamlQuotes(value: string): string {
  if (value.length >= 2 && ((value.startsWith("'") && value.endsWith("'")) || (value.startsWith('"') && value.endsWith('"')))) {
    return value.slice(1, -1);
  }
  return value;
}

function wantersFromHiddenLockfile(projectDir: string, nodeModules: string): readonly ScriptWanter[] | null {
  const lockfilePath = join(nodeModules, ".package-lock.json");
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(lockfilePath, "utf8"));
  } catch {
    return null;
  }
  if (!isPlainObject(parsed) || !isPlainObject(parsed.packages)) {
    return null;
  }
  const wanters: ScriptWanter[] = [];
  for (const [packagePath, entry] of Object.entries(parsed.packages)) {
    if (!isPlainObject(entry) || entry.hasInstallScript !== true || !packagePath.startsWith("node_modules/")) {
      continue;
    }
    const manifestDir = resolve(projectDir, packagePath);
    const containment = relative(resolve(nodeModules), manifestDir);
    if (containment === "" || containment.startsWith("..") || isAbsolute(containment)) {
      continue;
    }
    const wanter = wanterFromManifestDir(manifestDir);
    if (wanter) {
      wanters.push(wanter);
    }
  }
  return wanters;
}

function wantersFromWalk(nodeModules: string): readonly ScriptWanter[] {
  const wanters: ScriptWanter[] = [];
  for (const dir of packageDirs(nodeModules)) {
    const wanter = wanterFromManifestDir(dir);
    if (wanter) {
      wanters.push(wanter);
    }
  }
  return wanters;
}

function packageDirs(nodeModules: string): readonly string[] {
  const dirs: string[] = [];
  for (const entry of safeReaddir(nodeModules)) {
    if (entry.startsWith(".")) {
      continue;
    }
    if (entry.startsWith("@")) {
      for (const scoped of safeReaddir(join(nodeModules, entry))) {
        if (!scoped.startsWith(".")) {
          dirs.push(join(nodeModules, entry, scoped));
        }
      }
      continue;
    }
    dirs.push(join(nodeModules, entry));
  }
  return dirs;
}

function wanterFromManifestDir(dir: string): ScriptWanter | null {
  let manifest: unknown;
  try {
    manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  } catch {
    return null;
  }
  if (!isPlainObject(manifest) || typeof manifest.name !== "string" || manifest.name.length === 0) {
    return null;
  }
  const scripts = isPlainObject(manifest.scripts) ? manifest.scripts : {};
  const hasGyp = existsSync(join(dir, "binding.gyp"));
  const hooks: ScriptHook[] = LIFECYCLE_HOOKS.filter((hook) => typeof lifecycleCommand(scripts, hook) === "string");
  if (hasGyp) {
    hooks.push("gyp");
  }
  if (hooks.length === 0) {
    return null;
  }
  return {
    name: manifest.name,
    version: typeof manifest.version === "string" ? manifest.version : "",
    hooks,
    scriptsHash: computeScriptsHash(scripts, hasGyp)
  };
}

function lifecycleCommand(scripts: Readonly<Record<string, unknown>>, hook: string): string | null {
  const command = scripts[hook];
  return typeof command === "string" && command.length > 0 ? command : null;
}

function safeReaddir(dir: string): readonly string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
