import { AnalyzeError, analyzePackages, type AnalyzeEcosystem, type AnalyzeErrorCode } from "../api/analyze.js";
import type { DgPathEnvironment } from "../state/index.js";
import { mergeVerdicts } from "./inventory.js";
import type { SbomStore } from "./store.js";

const SCAN_ECOSYSTEMS: readonly AnalyzeEcosystem[] = ["npm", "pypi"];

export async function runSbomScan(store: SbomStore, env: DgPathEnvironment, signal?: AbortSignal): Promise<void> {
  const scannable = store.get().rows.filter((row) => row.scannable);
  if (scannable.length === 0) {
    store.update({ phase: "done" });
    return;
  }
  store.update({ phase: "scanning", scannable: scannable.length, scanProgress: 0 });

  let completed = 0;
  try {
    for (const ecosystem of SCAN_ECOSYSTEMS) {
      const inputs = scannable.filter((row) => row.ecosystem === ecosystem).map((row) => ({ name: row.name, version: row.version }));
      if (inputs.length === 0) {
        continue;
      }
      const base = completed;
      const response = await analyzePackages(inputs, {
        ecosystem,
        env,
        ...(signal ? { signal } : {}),
        onProgress: (progress) => store.update({ scanProgress: base + progress.done })
      });
      completed += inputs.length;
      store.update({
        rows: mergeVerdicts(store.get().rows, ecosystem, response.packages),
        scanProgress: completed,
        ...(response.usage ? { usage: response.usage } : {})
      });
    }
    store.update({ phase: "done" });
  } catch (error) {
    store.update({
      phase: "done",
      scanError: error instanceof AnalyzeError ? failOpenReason(error.code) : error instanceof Error ? error.message : "verdict scan failed"
    });
  }
}

function failOpenReason(code: AnalyzeErrorCode): string {
  switch (code) {
    case "auth":
      return "sign in with dg login to see verdicts";
    case "quota_exceeded":
      return "scan quota reached — showing inventory only";
    case "rate_limited":
      return "rate limited — showing inventory only";
    case "network":
    case "timeout":
      return "offline — showing inventory only";
    default:
      return "scanner unavailable — showing inventory only";
  }
}
