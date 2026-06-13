import React from "react";
import { render } from "ink-testing-library";
import { describe, expect, it, vi } from "vitest";
import { Selector } from "../../src/setup-ui/selector.js";

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

const OPTIONS = [{ label: "Yes, use recommended settings" }, { label: "No, maybe later with dg setup" }];

function renderSelector(overrides: { onSelect?: (index: number) => void; onCancel?: () => void } = {}) {
  return render(
    React.createElement(Selector, {
      options: OPTIONS,
      onSelect: overrides.onSelect ?? (() => undefined),
      onCancel: overrides.onCancel ?? (() => undefined)
    })
  );
}

describe("Selector", () => {
  it("starts with the cursor on the first option", async () => {
    const view = renderSelector();
    await sleep(30);
    const frame = view.lastFrame() ?? "";
    view.unmount();
    expect(frame).toContain("❯ 1. Yes, use recommended settings");
    expect(frame).toContain("  2. No, maybe later with dg setup");
  });

  it("moves the cursor with arrows and j/k and confirms with Enter", async () => {
    const onSelect = vi.fn();
    const view = renderSelector({ onSelect });
    await sleep(30);

    view.stdin.write("\u001B[B");
    await sleep(30);
    expect(view.lastFrame()).toContain("❯ 2.");

    view.stdin.write("k");
    await sleep(30);
    expect(view.lastFrame()).toContain("❯ 1.");

    view.stdin.write("j");
    await sleep(30);
    view.stdin.write("\r");
    await sleep(30);
    view.unmount();

    expect(onSelect).toHaveBeenCalledWith(1);
  });

  it("confirms instantly on a number key", async () => {
    const onSelect = vi.fn();
    const view = renderSelector({ onSelect });
    await sleep(30);

    view.stdin.write("2");
    await sleep(30);
    view.unmount();

    expect(onSelect).toHaveBeenCalledWith(1);
  });

  it("ignores number keys beyond the option count", async () => {
    const onSelect = vi.fn();
    const view = renderSelector({ onSelect });
    await sleep(30);

    view.stdin.write("9");
    await sleep(30);
    view.unmount();

    expect(onSelect).not.toHaveBeenCalled();
  });

  it("cancels on Esc", async () => {
    const onCancel = vi.fn();
    const view = renderSelector({ onCancel });
    await sleep(30);

    view.stdin.write("\u001B");
    await sleep(30);
    view.unmount();

    expect(onCancel).toHaveBeenCalled();
  });
});
