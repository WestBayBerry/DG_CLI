import React from "react";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { render } from "ink-testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ExportDialog, type ExportOption } from "../../src/export-ui/ExportDialog.js";
import { createTheme } from "../../src/presentation/theme.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const stripAnsi = (s: string) => s.replace(/\[[0-9;]*m/g, "");
const theme = createTheme(false);
const DOWN = "[B";
const ESC = "";
const CTRL_E = "";
const BACKSPACE = "";
const ENTER = "\r";

function option(over: Partial<ExportOption> = {}): ExportOption {
  return { label: "JSON", defaultName: "report.json", render: () => '{"ok":true}\n', ...over };
}

describe("ExportDialog", () => {
  let home: string;
  let cwd: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-export-home-"));
    cwd = join(home, "project");
    mkdirSync(cwd);
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  function open(options: readonly ExportOption[], onDone: (r: unknown) => void = () => undefined) {
    return render(React.createElement(ExportDialog, { options, theme, cwd, onDone, env: { ...process.env, HOME: home } }));
  }

  it("opens a single-format export at the destinations list, not the editor", async () => {
    const view = open([option()]);
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("This folder");
    expect(frame).toContain("Home");
    expect(frame).toContain("Type a path");
    expect(frame).not.toContain("Save as");
  });

  it("plain Enter saves the default name into the current folder", async () => {
    const onDone = vi.fn();
    const view = open([option()], onDone);
    await sleep(30);
    view.stdin.write(ENTER);
    await sleep(40);
    view.unmount();

    expect(readFileSync(join(cwd, "report.json"), "utf8")).toBe('{"ok":true}\n');
    expect(onDone).toHaveBeenCalledWith({ path: resolve(cwd, "report.json") });
  });

  it("saving to Home writes into the home directory, not cwd", async () => {
    const onDone = vi.fn();
    const view = open([option()], onDone);
    await sleep(30);
    view.stdin.write(DOWN);
    await sleep(30);
    view.stdin.write(ENTER);
    await sleep(40);
    view.unmount();

    expect(readFileSync(join(home, "report.json"), "utf8")).toBe('{"ok":true}\n');
    expect(readdirSync(cwd)).toEqual([]);
    expect(onDone).toHaveBeenCalledWith({ path: resolve(home, "report.json") });
  });

  it("shows Downloads when it exists and saves into it", async () => {
    mkdirSync(join(home, "Downloads"));
    const onDone = vi.fn();
    const view = open([option()], onDone);
    await sleep(30);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("Downloads");
    view.stdin.write(DOWN);
    await sleep(30);
    view.stdin.write(ENTER);
    await sleep(40);
    view.unmount();

    expect(readFileSync(join(home, "Downloads", "report.json"), "utf8")).toBe('{"ok":true}\n');
    expect(onDone).toHaveBeenCalledWith({ path: resolve(home, "Downloads", "report.json") });
  });

  it("marks a destination that already holds a file of that name", async () => {
    writeFileSync(join(cwd, "report.json"), "old");
    const view = open([option()]);
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(frame).toContain("(replaces)");
  });

  it("'t' opens the path editor prefilled with the highlighted destination", async () => {
    const view = open([option()]);
    await sleep(30);
    view.stdin.write(DOWN);
    await sleep(30);
    view.stdin.write("t");
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(frame).toContain("Save as");
    expect(frame).toContain("~/report.json");
  });

  it("a typed name in the editor saves under the current folder", async () => {
    const onDone = vi.fn();
    const view = open([option()], onDone);
    await sleep(30);
    view.stdin.write("t");
    await sleep(30);
    view.stdin.write("X");
    await sleep(30);
    view.stdin.write(ENTER);
    await sleep(40);
    view.unmount();

    expect(readFileSync(join(cwd, "reportX.json"), "utf8")).toBe('{"ok":true}\n');
  });

  it("Tab completes the typed fragment to a real folder", async () => {
    mkdirSync(join(cwd, "reports"));
    const view = open([option({ defaultName: "rep" })]);
    await sleep(30);
    view.stdin.write("t");
    await sleep(30);
    view.stdin.write("\t");
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(frame).toContain("reports/");
  });

  it("Esc from the editor returns to the destinations list", async () => {
    const view = open([option()]);
    await sleep(30);
    view.stdin.write("t");
    await sleep(30);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("Save as");
    view.stdin.write(ESC);
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(frame).toContain("This folder");
    expect(frame).not.toContain("Save as");
  });

  it("Esc from a single-format destinations list cancels without writing", async () => {
    const onDone = vi.fn();
    const view = open([option()], onDone);
    await sleep(30);
    view.stdin.write(ESC);
    await sleep(30);
    view.unmount();
    expect(onDone).toHaveBeenCalledWith(null);
    expect(readdirSync(cwd)).toEqual([]);
  });

  it("renders the format chooser first when more than one format is offered", async () => {
    const view = open([option(), option({ label: "Markdown", defaultName: "report.md" }), option({ label: "Plain", defaultName: "report.txt" })]);
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();

    expect(frame).toContain("JSON");
    expect(frame).toContain("Markdown");
    expect(frame).toContain("Plain");
    expect(frame).not.toContain("This folder");
  });

  it("multi-format flows format -> destinations and Esc steps back to the format list", async () => {
    const view = open([option(), option({ label: "Markdown", defaultName: "report.md" })]);
    await sleep(30);
    view.stdin.write(ENTER);
    await sleep(30);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("Type a path");
    view.stdin.write(ESC);
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(frame).not.toContain("Type a path");
    expect(frame).toContain("Markdown");
  });
});
