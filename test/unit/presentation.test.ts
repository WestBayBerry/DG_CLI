import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { colorEnabled, isCiEnv, resolvePresentation } from "../../src/presentation/mode.js";
import { createTheme, severityBadge } from "../../src/presentation/theme.js";

const tty = { isTTY: true };
const notTty = { isTTY: false };

describe("presentation mode", () => {
  it("enables color on an interactive TTY with a clean env", () => {
    expect(colorEnabled({ stream: tty, env: {} })).toBe(true);
  });

  it("disables color when stdout is not a TTY", () => {
    expect(colorEnabled({ stream: notTty, env: {} })).toBe(false);
  });

  it("disables color when NO_COLOR is present and non-empty", () => {
    expect(colorEnabled({ stream: tty, env: { NO_COLOR: "1" } })).toBe(false);
  });

  it("ignores an empty NO_COLOR", () => {
    expect(colorEnabled({ stream: tty, env: { NO_COLOR: "" } })).toBe(true);
  });

  it("disables color for DG_NO_COLOR and TERM=dumb", () => {
    expect(colorEnabled({ stream: tty, env: { DG_NO_COLOR: "1" } })).toBe(false);
    expect(colorEnabled({ stream: tty, env: { TERM: "dumb" } })).toBe(false);
  });

  it("lets FORCE_COLOR and --color=always override NO_COLOR and non-TTY", () => {
    expect(colorEnabled({ stream: notTty, env: { FORCE_COLOR: "1", NO_COLOR: "1" } })).toBe(true);
    expect(colorEnabled({ stream: notTty, env: { NO_COLOR: "1" }, forceColorFlag: true })).toBe(true);
  });

  it("disables color for FORCE_COLOR=0/false, matching the chalk convention", () => {
    expect(colorEnabled({ stream: tty, env: { FORCE_COLOR: "0" } })).toBe(false);
    expect(colorEnabled({ stream: tty, env: { FORCE_COLOR: "false" } })).toBe(false);
  });

  it("forces color on for any other FORCE_COLOR value, including empty", () => {
    expect(colorEnabled({ stream: notTty, env: { FORCE_COLOR: "2" } })).toBe(true);
    expect(colorEnabled({ stream: notTty, env: { FORCE_COLOR: "" } })).toBe(true);
  });

  it("honors --no-color over an interactive TTY", () => {
    expect(colorEnabled({ stream: tty, env: {}, noColorFlag: true })).toBe(false);
  });

  it("detects CI from CI and common markers", () => {
    expect(isCiEnv({ CI: "true" })).toBe(true);
    expect(isCiEnv({ GITHUB_ACTIONS: "true" })).toBe(true);
    expect(isCiEnv({ CI: "" })).toBe(false);
    expect(isCiEnv({})).toBe(false);
  });

  it("resolves rich only on an interactive non-CI TTY", () => {
    expect(resolvePresentation({ stream: tty, env: {} }).mode).toBe("rich");
    expect(resolvePresentation({ stream: tty, env: { CI: "1" } }).mode).toBe("plain");
    expect(resolvePresentation({ stream: notTty, env: {} }).mode).toBe("plain");
  });
});

describe("theme", () => {
  it("maps the scanner action to the source-of-truth badge", () => {
    expect(severityBadge("block").word).toBe("BLOCK");
    expect(severityBadge("warn").word).toBe("WARN");
    expect(severityBadge("pass").word).toBe("PASS");
    expect(severityBadge("analysis_incomplete").word).toBe("UNKNOWN");
  });

  it("emits no escape codes when color is off", () => {
    const theme = createTheme(false);
    expect(theme.paint("block", "x")).toBe("x");
    expect(theme.badge("block")).toBe("✘ BLOCK");
    expect(theme.badge("block")).not.toContain("\x1b");
  });

  it("wraps text in ANSI when color is on", () => {
    const theme = createTheme(true);
    expect(theme.paint("warn", "x")).toBe("\x1b[33mx\x1b[0m");
    expect(theme.badge("pass")).toContain("\x1b[32m");
    expect(theme.badge("pass")).toContain("✓ PASS");
  });

  it("keeps the source free of raw ESC control bytes", () => {
    const source = readFileSync(fileURLToPath(new URL("../../src/presentation/theme.ts", import.meta.url)), "utf8");
    expect(source.includes("\u001b")).toBe(false);
  });
});
