import React from "react";
import { render } from "ink-testing-library";
import { describe, expect, it, vi } from "vitest";
import { ProjectSelector } from "../../src/scan-ui/components/ProjectSelector.js";
import type { FoundProject } from "../../src/scan-ui/shims.js";

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function projects(count: number): FoundProject[] {
  return Array.from({ length: count }, (_, i) => ({
    path: `/tmp/app-${i}`,
    relativePath: `app-${i}`,
    ecosystem: "npm" as const,
    depFile: "package-lock.json",
    packageCount: i + 1
  }));
}

function renderSelector(overrides: { onConfirm?: (selected: FoundProject[]) => void; onCancel?: () => void } = {}) {
  return render(
    React.createElement(ProjectSelector, {
      projects: projects(3),
      onConfirm: overrides.onConfirm ?? (() => undefined),
      onCancel: overrides.onCancel ?? (() => undefined)
    })
  );
}

describe("ProjectSelector keybindings", () => {
  it("moves the cursor with j and k like the arrow keys", async () => {
    const view = renderSelector();
    await sleep(30);

    view.stdin.write("j");
    await sleep(30);
    view.stdin.write(" ");
    await sleep(30);
    expect(view.lastFrame()).toContain("2 of 3 selected");

    view.stdin.write("k");
    await sleep(30);
    view.stdin.write(" ");
    await sleep(30);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(frame).toContain("1 of 3 selected");
  });

  it("clamps j at the last row", async () => {
    const view = renderSelector();
    await sleep(30);

    for (let i = 0; i < 5; i += 1) {
      view.stdin.write("j");
      await sleep(10);
    }
    view.stdin.write(" ");
    await sleep(30);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(frame).toContain("2 of 3 selected");
    expect(frame).toContain("app-2");
  });

  it("cancels on Esc", async () => {
    const onCancel = vi.fn();
    const view = renderSelector({ onCancel });
    await sleep(30);

    view.stdin.write("\u001B");
    await sleep(30);
    view.unmount();

    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("still cancels on q and confirms on Enter", async () => {
    const onCancel = vi.fn();
    const onConfirm = vi.fn();
    const view = renderSelector({ onCancel, onConfirm });
    await sleep(30);

    view.stdin.write("q");
    await sleep(30);
    expect(onCancel).toHaveBeenCalledTimes(1);

    view.stdin.write("\r");
    await sleep(30);
    view.unmount();

    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onConfirm.mock.calls[0]?.[0]).toHaveLength(3);
  });
});
