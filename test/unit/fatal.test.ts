import { describe, expect, it } from "vitest";
import { exitOnFatal, type FatalIo } from "../../src/runtime/fatal.js";

function fakeIo(tuiActive: boolean, leaveTui?: () => void): {
  io: FatalIo;
  calls: string[];
  stderr: () => string;
  exitCode: () => number | null;
} {
  const calls: string[] = [];
  let stderr = "";
  let exitCode: number | null = null;
  return {
    io: {
      writeStderr: (text) => {
        calls.push("stderr");
        stderr += text;
      },
      exit: (code) => {
        calls.push("exit");
        exitCode = code;
      },
      tuiIsActive: () => tuiActive,
      leaveTui:
        leaveTui ??
        (() => {
          calls.push("leaveTui");
        })
    },
    calls,
    stderr: () => stderr,
    exitCode: () => exitCode
  };
}

describe("exitOnFatal", () => {
  it("leaves the alt screen before writing the error when a TUI is active", () => {
    const t = fakeIo(true);
    exitOnFatal(new Error("boom"), t.io);
    expect(t.calls).toEqual(["leaveTui", "stderr", "exit"]);
    expect(t.stderr()).toContain("dg: unexpected error — boom");
    expect(t.stderr()).toContain("dg doctor");
    expect(t.exitCode()).toBe(70);
  });

  it("does not touch the screen when no TUI is active", () => {
    const t = fakeIo(false);
    exitOnFatal("plain failure", t.io);
    expect(t.calls).toEqual(["stderr", "exit"]);
    expect(t.stderr()).toContain("plain failure");
    expect(t.exitCode()).toBe(70);
  });

  it("still reports and exits when leaving the TUI throws", () => {
    const t = fakeIo(true, () => {
      throw new Error("tty gone");
    });
    exitOnFatal(new Error("boom"), t.io);
    expect(t.stderr()).toContain("dg: unexpected error — boom");
    expect(t.exitCode()).toBe(70);
  });
});
