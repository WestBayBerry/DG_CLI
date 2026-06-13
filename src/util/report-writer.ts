import { randomUUID } from "node:crypto";
import { mkdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";

export interface ExportDestination {
  readonly label: string;
  readonly dir: string;
}

export function writeReportAtomic(outputPath: string, contents: string): void {
  const directory = dirname(outputPath);
  mkdirSync(directory, { recursive: true });
  const temporaryPath = `${outputPath}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporaryPath, contents, { encoding: "utf8", flag: "wx" });
    renameSync(temporaryPath, outputPath);
  } catch (error) {
    rmSync(temporaryPath, { force: true });
    throw error;
  }
}

export function resolveExportPath(input: string, cwd: string): string {
  const trimmed = input.trim();
  if (trimmed === "~" || trimmed.startsWith("~/")) {
    return resolve(homedir(), trimmed.slice(2));
  }
  return resolve(cwd, trimmed);
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path, { throwIfNoEntry: false })?.isDirectory() ?? false;
  } catch {
    return false;
  }
}

export function userHomeDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.HOME && isAbsolute(env.HOME) ? env.HOME : homedir();
}

export function exportDestinations(cwd: string, env: NodeJS.ProcessEnv = process.env): readonly ExportDestination[] {
  const home = userHomeDir(env);
  const candidates: ExportDestination[] = [{ label: "This folder", dir: cwd }];
  for (const name of ["Downloads", "Desktop"]) {
    const dir = join(home, name);
    if (isDirectory(dir)) {
      candidates.push({ label: name, dir });
    }
  }
  candidates.push({ label: "Home", dir: home });

  const seen = new Set<string>();
  const out: ExportDestination[] = [];
  for (const candidate of candidates) {
    const key = resolve(candidate.dir);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(candidate);
  }
  return out;
}
