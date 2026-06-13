import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { CommandResult } from "./types.js";

function readPackageVersion(): string {
  const packageJsonPath = fileURLToPath(new URL("../../package.json", import.meta.url));
  const parsed = JSON.parse(readFileSync(packageJsonPath, "utf8")) as { version?: string };
  if (!parsed.version) {
    throw new Error("package.json is missing a version field — reinstall @westbayberry/dg");
  }
  return parsed.version;
}

let cachedVersion: string | undefined;

export function dgVersion(): string {
  cachedVersion ??= readPackageVersion();
  return cachedVersion;
}

export function versionResult(): CommandResult {
  return {
    exitCode: 0,
    stdout: `dg ${dgVersion()}\n`,
    stderr: ""
  };
}
