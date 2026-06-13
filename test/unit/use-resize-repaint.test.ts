import React from "react";
import { Text } from "ink";
import { render } from "ink-testing-library";
import { describe, expect, it } from "vitest";
import { useResizeRepaint } from "../../src/scan-ui/hooks/useResizeRepaint.js";
import { CLEAR_HOME } from "../../src/scan-ui/alt-screen.js";

const Probe: React.FC = () => {
  useResizeRepaint();
  return React.createElement(Text, null, "frame");
};

const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 30));

function repaintWrites(frames: string[]): string[] {
  return frames.filter((chunk) => chunk.includes(CLEAR_HOME));
}

describe("useResizeRepaint", () => {
  it("does not repaint before any resize", async () => {
    const view = render(React.createElement(Probe));
    await settle();

    expect(repaintWrites(view.stdout.frames)).toEqual([]);
    view.unmount();
  });

  it("clears and repaints the frame on terminal resize", async () => {
    const view = render(React.createElement(Probe));
    await settle();

    view.stdout.emit("resize");
    await settle();

    expect(repaintWrites(view.stdout.frames).length).toBeGreaterThan(0);
    view.unmount();
  });

  it("repaints once more for every further resize", async () => {
    const view = render(React.createElement(Probe));
    await settle();

    view.stdout.emit("resize");
    await settle();
    const afterFirst = repaintWrites(view.stdout.frames).length;

    view.stdout.emit("resize");
    await settle();

    expect(repaintWrites(view.stdout.frames).length).toBe(afterFirst + 1);
    view.unmount();
  });

  it("stops repainting after unmount", async () => {
    const view = render(React.createElement(Probe));
    await settle();

    view.stdout.emit("resize");
    await settle();
    const beforeUnmount = repaintWrites(view.stdout.frames).length;

    view.unmount();
    view.stdout.emit("resize");
    await settle();

    expect(repaintWrites(view.stdout.frames).length).toBe(beforeUnmount);
  });
});
