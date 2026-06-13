import { lstatSync, readFileSync, readlinkSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { AuditFile } from "../audit/detectors.js";

export function buildAuditFile(root: string, relPath: string): AuditFile | null {
  const absolute = resolve(root, relPath);
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch {
    return null;
  }
  const isSymlink = stat.isSymbolicLink();
  let symlinkEscapes = false;
  if (isSymlink) {
    try {
      const target = readlinkSync(absolute);
      const resolved = isAbsolute(target) ? target : resolve(root, relPath, "..", target);
      const real = realpathSync(resolved);
      const rootReal = realpathSync(root);
      symlinkEscapes = real !== rootReal && !real.startsWith(rootReal + sep);
    } catch {
      symlinkEscapes = true;
    }
  }
  if (!isSymlink && !stat.isFile()) {
    return null;
  }
  return {
    path: toDisplay(relPath),
    size: stat.size,
    isSymlink,
    symlinkEscapes,
    mode: stat.mode,
    read: () => {
      try {
        return readFileSync(absolute);
      } catch {
        return null;
      }
    }
  };
}

export function toDisplay(relPath: string): string {
  const normalized = relative(".", relPath) || relPath;
  return normalized.split(sep).join("/");
}
