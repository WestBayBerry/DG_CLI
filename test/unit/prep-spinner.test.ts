import { afterEach, describe, expect, it, vi } from "vitest";
import { startPrepSpinner } from "../../src/install-ui/prep-spinner.js";

function fakeStream(isTTY: boolean): { readonly stream: NodeJS.WriteStream; readonly chunks: string[] } {
  const chunks: string[] = [];
  const stream = {
    isTTY,
    write: (chunk: string): boolean => {
      chunks.push(chunk);
      return true;
    }
  } as unknown as NodeJS.WriteStream;
  return { stream, chunks };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("startPrepSpinner", () => {
  it("draws a frame immediately, animates, and clears the line on stop", () => {
    vi.useFakeTimers();
    const { stream, chunks } = fakeStream(true);
    const spinner = startPrepSpinner("DG preparing…", stream, {});

    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toContain("DG preparing…");
    expect(chunks[0]?.startsWith("\r")).toBe(true);

    vi.advanceTimersByTime(170);
    expect(chunks.length).toBeGreaterThan(1);

    spinner.stop();
    expect(chunks[chunks.length - 1]).toBe("\r\u001b[2K");

    const written = chunks.length;
    vi.advanceTimersByTime(500);
    spinner.stop();
    expect(chunks).toHaveLength(written);
  });

  it("writes nothing without a TTY", () => {
    const { stream, chunks } = fakeStream(false);
    startPrepSpinner("DG preparing…", stream, {}).stop();
    expect(chunks).toEqual([]);
  });

  it("writes nothing in CI even on a TTY", () => {
    const { stream, chunks } = fakeStream(true);
    startPrepSpinner("DG preparing…", stream, { CI: "1" }).stop();
    expect(chunks).toEqual([]);
  });
});
