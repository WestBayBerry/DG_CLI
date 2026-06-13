import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  __resetTuiStateForTests,
  enterTui,
  leaveTui,
  tuiIsActive
} from "../../src/scan-ui/alt-screen.js";

const ALT_SCREEN_ON = "\x1b[?1049h";
const ALT_SCREEN_OFF = "\x1b[?1049l";
const TITLE_PUSH = "\x1b[22;0t";
const TITLE_POP = "\x1b[23;0t";
const TITLE_OSC = "\x1b]0;Dependency Guardian\x07";
const TRACKED_SIGNALS = ["SIGHUP", "SIGINT", "SIGTERM"] as const;

type Counts = { exit: number; SIGHUP: number; SIGINT: number; SIGTERM: number };

function listenerCounts(): Counts {
  return {
    exit: process.listenerCount("exit"),
    SIGHUP: process.listenerCount("SIGHUP"),
    SIGINT: process.listenerCount("SIGINT"),
    SIGTERM: process.listenerCount("SIGTERM")
  };
}

describe("alt-screen TUI lifecycle (TTY)", () => {
  let isTtyDescriptor: PropertyDescriptor | undefined;
  let writeSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    __resetTuiStateForTests();
    isTtyDescriptor = Object.getOwnPropertyDescriptor(process.stdout, "isTTY");
    Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });
    writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    leaveTui();
    __resetTuiStateForTests();
    writeSpy.mockRestore();
    if (isTtyDescriptor) {
      Object.defineProperty(process.stdout, "isTTY", isTtyDescriptor);
    } else {
      delete (process.stdout as { isTTY?: boolean }).isTTY;
    }
  });

  it("enterTui writes the alt-screen-on sequence and registers exactly one listener for exit and each signal", () => {
    const before = listenerCounts();

    enterTui();

    expect(tuiIsActive()).toBe(true);
    const written = writeSpy.mock.calls.map((call) => String(call[0])).join("");
    expect(written).toContain(ALT_SCREEN_ON);

    const after = listenerCounts();
    expect(after.exit).toBe(before.exit + 1);
    for (const signal of TRACKED_SIGNALS) {
      expect(after[signal]).toBe(before[signal] + 1);
    }
  });

  it("leaveTui writes the alt-screen-off sequence and removes the listeners it added", () => {
    const before = listenerCounts();
    enterTui();
    writeSpy.mockClear();

    leaveTui();

    expect(tuiIsActive()).toBe(false);
    const written = writeSpy.mock.calls.map((call) => String(call[0])).join("");
    expect(written).toContain(ALT_SCREEN_OFF);
    expect(listenerCounts()).toEqual(before);
  });

  it("enterTui is idempotent while active: no second write, no extra listeners", () => {
    enterTui();
    const afterFirst = listenerCounts();
    writeSpy.mockClear();

    enterTui();

    expect(writeSpy).not.toHaveBeenCalled();
    expect(listenerCounts()).toEqual(afterFirst);
    expect(tuiIsActive()).toBe(true);
  });

  it("saves the terminal title before setting it and restores it on leave", () => {
    enterTui();
    const entered = writeSpy.mock.calls.map((call) => String(call[0])).join("");
    expect(entered).toContain(TITLE_OSC);
    expect(entered.indexOf(TITLE_PUSH)).toBeGreaterThanOrEqual(0);
    expect(entered.indexOf(TITLE_PUSH)).toBeLessThan(entered.indexOf(TITLE_OSC));
    writeSpy.mockClear();

    leaveTui();

    const left = writeSpy.mock.calls.map((call) => String(call[0])).join("");
    expect(left).toContain(TITLE_POP);
  });

  it("leaveTui without a prior enterTui is a no-op", () => {
    const before = listenerCounts();

    leaveTui();

    expect(writeSpy).not.toHaveBeenCalled();
    expect(listenerCounts()).toEqual(before);
    expect(tuiIsActive()).toBe(false);
  });

  it("__resetTuiStateForTests clears active state and removes the installed handlers", () => {
    const before = listenerCounts();
    enterTui();
    expect(listenerCounts()).not.toEqual(before);

    __resetTuiStateForTests();

    expect(tuiIsActive()).toBe(false);
    expect(listenerCounts()).toEqual(before);
  });
});

describe("alt-screen TUI lifecycle (non-TTY)", () => {
  let isTtyDescriptor: PropertyDescriptor | undefined;
  let writeSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    __resetTuiStateForTests();
    isTtyDescriptor = Object.getOwnPropertyDescriptor(process.stdout, "isTTY");
    Object.defineProperty(process.stdout, "isTTY", { value: false, configurable: true });
    writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    __resetTuiStateForTests();
    writeSpy.mockRestore();
    if (isTtyDescriptor) {
      Object.defineProperty(process.stdout, "isTTY", isTtyDescriptor);
    } else {
      delete (process.stdout as { isTTY?: boolean }).isTTY;
    }
  });

  it("enterTui is inert without a TTY: no write, no listeners, not active", () => {
    const before = listenerCounts();

    enterTui();

    expect(tuiIsActive()).toBe(false);
    expect(writeSpy).not.toHaveBeenCalled();
    expect(listenerCounts()).toEqual(before);
  });
});
