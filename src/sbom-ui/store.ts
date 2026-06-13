import type { ScannerUsage } from "../api/analyze.js";
import type { SbomRow } from "./inventory.js";

export type SbomPhase = "inventory" | "scanning" | "done";

export interface SbomView {
  readonly phase: SbomPhase;
  readonly rows: readonly SbomRow[];
  readonly subject: string;
  readonly dropped: readonly string[];
  readonly scannable: number;
  readonly scanProgress: number;
  readonly scanError: string | null;
  readonly usage: ScannerUsage | null;
}

export interface SbomStore {
  get(): SbomView;
  set(next: SbomView): void;
  update(patch: Partial<SbomView>): void;
  subscribe(listener: () => void): () => void;
}

export function createSbomStore(initial: SbomView): SbomStore {
  let view = initial;
  const listeners = new Set<() => void>();
  const emit = (): void => {
    for (const listener of listeners) {
      listener();
    }
  };
  return {
    get: () => view,
    set: (next) => {
      view = next;
      emit();
    },
    update: (patch) => {
      view = { ...view, ...patch };
      emit();
    },
    subscribe: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    }
  };
}
