import { mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname } from "node:path";

export function writeJsonAtomic(
  path: string,
  value: unknown,
  options: { readonly fileMode?: number; readonly dirMode?: number } = {}
): void {
  mkdirSync(dirname(path), {
    recursive: true,
    mode: options.dirMode ?? 0o700
  });
  const tempPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    writeFileSync(tempPath, `${JSON.stringify(value, null, 2)}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: options.fileMode ?? 0o600
    });
    renameSync(tempPath, path);
  } catch (error) {
    rmSync(tempPath, {
      force: true
    });
    throw error;
  }
}
