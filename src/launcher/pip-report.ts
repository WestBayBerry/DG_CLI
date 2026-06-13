export interface PipReportPackage {
  readonly name: string;
  readonly version: string;
}

function parseInstallArray(stdout: string): unknown[] | undefined {
  const trimmed = stdout.trim();
  if (!trimmed) return undefined;
  const candidates = [trimmed];
  const brace = trimmed.indexOf("{");
  if (brace > 0) candidates.push(trimmed.slice(brace));
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate) as { install?: unknown };
      if (Array.isArray(parsed.install)) {
        return parsed.install;
      }
    } catch {
      continue;
    }
  }
  return undefined;
}

export function parsePipReportInstallCount(stdout: string): number | undefined {
  return parseInstallArray(stdout)?.length;
}

export function parsePipReportInstallSet(stdout: string): PipReportPackage[] | undefined {
  const install = parseInstallArray(stdout);
  if (!install) return undefined;
  const set: PipReportPackage[] = [];
  for (const entry of install) {
    const metadata = (entry as { metadata?: { name?: unknown; version?: unknown } }).metadata;
    if (metadata && typeof metadata.name === "string" && typeof metadata.version === "string") {
      set.push({ name: metadata.name, version: metadata.version });
    }
  }
  return set;
}
