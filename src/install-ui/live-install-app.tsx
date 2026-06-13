import React from "react";
import { render, useApp } from "ink";
import { LiveInstall, type LiveInstallView } from "./LiveInstall.js";
import type { CommandResult } from "../commands/types.js";

interface ViewStore {
  readonly get: () => LiveInstallView;
  readonly set: (view: LiveInstallView) => void;
  readonly subscribe: (listener: () => void) => () => void;
}

function createViewStore(initial: LiveInstallView): ViewStore {
  let current = initial;
  const listeners = new Set<() => void>();
  return {
    get: () => current,
    set: (view) => {
      current = view;
      for (const listener of listeners) {
        listener();
      }
    },
    subscribe: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    }
  };
}

const App: React.FC<{ readonly store: ViewStore }> = ({ store }) => {
  const view = React.useSyncExternalStore(store.subscribe, store.get, store.get);
  const { exit } = useApp();
  React.useEffect(() => {
    if (view.phase !== "done") {
      return undefined;
    }
    const timer = setTimeout(() => exit(), 30);
    return () => clearTimeout(timer);
  }, [view.phase, exit]);
  return React.createElement(LiveInstall, { view });
};

export async function renderLiveInstall(
  run: (onView: (view: LiveInstallView) => void) => Promise<CommandResult>
): Promise<CommandResult> {
  const store = createViewStore({ phase: "scanning", total: 0, verified: 0, flagged: 0 });
  const restoreCursor = () => process.stdout.write(String.fromCharCode(27) + "[?25h");
  process.once("exit", restoreCursor);
  const instance = render(React.createElement(App, { store }));
  try {
    return await run((view) => store.set(view));
  } finally {
    store.set({ ...store.get(), phase: "done" });
    await instance.waitUntilExit().catch(() => undefined);
    process.off("exit", restoreCursor);
  }
}
