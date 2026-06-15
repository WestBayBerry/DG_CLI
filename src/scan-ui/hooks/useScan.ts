import { randomUUID } from "node:crypto";
import { useReducer, useEffect, useRef, useCallback, useState } from "react";
import {
  analyzePackages,
  AnalyzeError,
  mergeAnalyzeResponses,
  type AnalyzeResponse
} from "../../api/analyze.js";
import { applyDecisions, packageKey, type AppliedDecisions } from "../../decisions/apply.js";
import { findProjectRoot, loadDgFile } from "../../project/dgfile.js";
import { collectScanPackages, discoverScanProjectsAsync } from "../../scan/collect.js";
import type { CLIConfig, FoundProject } from "../shims.js";

export type CapReason = "monthly_limit" | "prefix_cap";

export type ScanState =
  | { phase: "discovering"; path?: string; found?: number }
  | { phase: "selecting"; projects: FoundProject[] }
  | { phase: "scanning"; done: number; total: number; batchIndex: number; batchCount: number }
  | { phase: "results"; result: AnalyzeResponse; durationMs: number; skippedCount: number; discoveredTotal?: number; decisions?: AppliedDecisions }
  | { phase: "error"; error: Error }
  | { phase: "empty"; message: string }
  | { phase: "free_cap_reached"; scansUsed: number; maxScans: number; capReason: CapReason; resetsAt?: string };

type ScanAction =
  | { type: "PROJECTS_FOUND"; projects: FoundProject[] }
  | { type: "RESTART_SELECTION"; projects: FoundProject[] }
  | { type: "DISCOVERY_PROGRESS"; path: string; found: number }
  | { type: "DISCOVERY_COMPLETE"; total: number }
  | { type: "DISCOVERY_EMPTY"; message: string }
  | { type: "SCAN_PROGRESS"; done: number; total: number; batchIndex: number; batchCount: number }
  | { type: "SCAN_COMPLETE"; result: AnalyzeResponse; durationMs: number; skippedCount: number; discoveredTotal?: number; decisions?: AppliedDecisions }
  | { type: "ERROR"; error: Error }
  | { type: "FREE_CAP_REACHED"; scansUsed: number; maxScans: number; capReason: CapReason; resetsAt?: string };

function reducer(_state: ScanState, action: ScanAction): ScanState {
  switch (action.type) {
    case "PROJECTS_FOUND":
    case "RESTART_SELECTION":
      return { phase: "selecting", projects: action.projects };
    case "DISCOVERY_PROGRESS":
      return { phase: "discovering", path: action.path, found: action.found };
    case "DISCOVERY_COMPLETE":
      return { phase: "scanning", done: 0, total: action.total, batchIndex: 0, batchCount: 1 };
    case "DISCOVERY_EMPTY":
      return { phase: "empty", message: action.message };
    case "SCAN_PROGRESS":
      return { phase: "scanning", done: action.done, total: action.total, batchIndex: action.batchIndex, batchCount: action.batchCount };
    case "SCAN_COMPLETE":
      return {
        phase: "results",
        result: action.result,
        durationMs: action.durationMs,
        skippedCount: action.skippedCount,
        ...(action.discoveredTotal !== undefined ? { discoveredTotal: action.discoveredTotal } : {}),
        ...(action.decisions !== undefined ? { decisions: action.decisions } : {})
      };
    case "ERROR":
      return { phase: "error", error: action.error };
    case "FREE_CAP_REACHED":
      return {
        phase: "free_cap_reached",
        scansUsed: action.scansUsed,
        maxScans: action.maxScans,
        capReason: action.capReason,
        ...(action.resetsAt ? { resetsAt: action.resetsAt } : {})
      };
  }
}

export function useScan(config: CLIConfig): {
  state: ScanState;
  scanSelectedProjects: (projects: FoundProject[]) => void;
  restartSelection: (() => void) | null;
} {
  const [state, dispatch] = useReducer(reducer, { phase: "discovering" });
  const started = useRef(false);
  const abortRef = useRef<AbortController | null>(null);
  if (abortRef.current === null) {
    abortRef.current = new AbortController();
  }
  const [multiProjects, setMultiProjects] = useState<FoundProject[] | null>(null);

  useEffect(() => () => abortRef.current?.abort(), []);

  useEffect(() => {
    if (started.current) {
      return;
    }
    started.current = true;

    void (async () => {
      const discovered = await discoverScanProjectsAsync(process.cwd(), (progress) => {
        dispatch({ type: "DISCOVERY_PROGRESS", path: progress.path, found: progress.found });
      });
      const projects = discovered.filter((project): project is FoundProject => project.ecosystem === "npm" || project.ecosystem === "pypi");
      if (projects.length === 0) {
        dispatch({ type: "DISCOVERY_EMPTY", message: "No dependency lockfiles found." });
        return;
      }
      if (projects.length > 1) {
        setMultiProjects(projects);
        dispatch({ type: "PROJECTS_FOUND", projects });
        return;
      }
      await scanProjects(projects, dispatch, abortRef.current?.signal);
    })();
  }, [config]);

  const scanSelectedProjects = useCallback((projects: FoundProject[]) => {
    void scanProjects(projects, dispatch, abortRef.current?.signal);
  }, []);

  const restartSelection = useCallback(() => {
    if (multiProjects) {
      dispatch({ type: "RESTART_SELECTION", projects: multiProjects });
    }
  }, [multiProjects]);

  return {
    state,
    scanSelectedProjects,
    restartSelection: multiProjects ? restartSelection : null
  };
}

type EcosystemOutcome = { response: AnalyzeResponse } | { error: unknown };

function computeProjectDecisions(
  result: AnalyzeResponse,
  entries: ReadonlyArray<readonly [("npm" | "pypi"), ReadonlyArray<{ name: string; version: string }>]>
): AppliedDecisions | undefined {
  try {
    const root = findProjectRoot(process.cwd());
    if (!root) {
      return undefined;
    }
    const file = loadDgFile(root);
    if (!file.readable) {
      return undefined;
    }
    const ecosystems = new Map<string, "npm" | "pypi">();
    for (const [ecosystem, packages] of entries) {
      for (const pkg of packages) {
        ecosystems.set(packageKey(pkg.name, pkg.version), ecosystem);
      }
    }
    return applyDecisions(result.packages, (pkg) => ecosystems.get(packageKey(pkg.name, pkg.version)), file, result.action);
  } catch {
    return undefined;
  }
}

async function scanProjects(
  projects: readonly FoundProject[],
  dispatch: React.Dispatch<ScanAction>,
  signal?: AbortSignal
): Promise<void> {
  const startMs = Date.now();
  let skipped = 0;
  let total = 0;
  try {
    const collected = collectScanPackages(projects);
    skipped = collected.skipped;
    const entries = [...collected.byEcosystem.entries()];
    total = entries.reduce((sum, [, list]) => sum + list.length, 0);
    if (total === 0) {
      dispatch({ type: "DISCOVERY_EMPTY", message: "No packages to scan." });
      return;
    }
    dispatch({ type: "DISCOVERY_COMPLETE", total });

    const scanId = randomUUID();
    const progressByEcosystem = new Map(
      entries.map(([ecosystem]) => [ecosystem, { done: 0, batchIndex: 0, batchCount: 1 }])
    );
    const reportProgress = (): void => {
      let done = 0;
      let batchIndex = 0;
      let batchCount = 0;
      for (const progress of progressByEcosystem.values()) {
        done += progress.done;
        batchIndex += progress.batchIndex;
        batchCount += progress.batchCount;
      }
      dispatch({ type: "SCAN_PROGRESS", done, total, batchIndex, batchCount });
    };

    const outcomes = await Promise.all(
      entries.map(async ([ecosystem, packages]): Promise<EcosystemOutcome> => {
        try {
          const response = await analyzePackages(packages, {
            ecosystem,
            scanId,
            ...(signal ? { signal } : {}),
            onProgress: (progress) => {
              progressByEcosystem.set(ecosystem, {
                done: progress.done,
                batchIndex: progress.batchIndex,
                batchCount: progress.batchCount
              });
              reportProgress();
            }
          });
          return { response };
        } catch (error) {
          return { error };
        }
      })
    );

    if (signal?.aborted) {
      return;
    }

    const responses = outcomes.flatMap((outcome) => ("response" in outcome ? [outcome.response] : []));
    const firstFailure = outcomes.find((outcome): outcome is { error: unknown } => "error" in outcome);

    if (responses.length > 0) {
      const merged = mergeAnalyzeResponses(responses);
      // A failed ecosystem means its verdict is unknown; escalate anything short of
      // a confirmed block to analysis_incomplete so a warn from the succeeded
      // ecosystem does not present as the whole verdict while the other is unscanned.
      const base = firstFailure && merged.action !== "block" ? { ...merged, action: "analysis_incomplete" as const } : merged;
      const ecoByKey = new Map<string, "npm" | "pypi">();
      for (const [ecosystem, packages] of entries) {
        for (const pkg of packages) {
          ecoByKey.set(packageKey(pkg.name, pkg.version), ecosystem);
        }
      }
      const result = {
        ...base,
        packages: base.packages.map((pkg) => {
          const ecosystem = ecoByKey.get(packageKey(pkg.name, pkg.version));
          return ecosystem ? { ...pkg, ecosystem } : pkg;
        })
      };
      const decisions = computeProjectDecisions(result, entries);
      dispatch({
        type: "SCAN_COMPLETE",
        result,
        durationMs: Date.now() - startMs,
        skippedCount: skipped,
        discoveredTotal: total,
        ...(decisions ? { decisions } : {})
      });
      return;
    }
    if (firstFailure) {
      throw firstFailure.error;
    }
  } catch (error) {
    if (signal?.aborted) {
      return;
    }
    if (error instanceof AnalyzeError && error.code === "quota_exceeded") {
      const body = (error.body ?? {}) as { reason?: CapReason; resetsAt?: string };
      dispatch({
        type: "FREE_CAP_REACHED",
        scansUsed: error.scansUsed ?? 0,
        maxScans: error.scansLimit ?? 0,
        capReason: body.reason === "prefix_cap" ? "prefix_cap" : "monthly_limit",
        ...(typeof body.resetsAt === "string" ? { resetsAt: body.resetsAt } : {})
      });
      return;
    }
    dispatch({ type: "ERROR", error: error instanceof Error ? error : new Error(String(error)) });
  }
}
