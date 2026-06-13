import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { exportDestinations, resolveExportPath, writeReportAtomic } from "../../src/util/report-writer.js";

describe("exportDestinations", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-dest-home-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("always offers This folder and Home, plus Type-a-path is added by the dialog", () => {
    const cwd = join(home, "project");
    mkdirSync(cwd);
    const dests = exportDestinations(cwd, { HOME: home });
    expect(dests.map((d) => d.label)).toEqual(["This folder", "Home"]);
    expect(dests[0]).toEqual({ label: "This folder", dir: cwd });
    expect(dests.at(-1)).toEqual({ label: "Home", dir: home });
  });

  it("includes Downloads and Desktop only when they exist", () => {
    const cwd = join(home, "project");
    mkdirSync(cwd);
    mkdirSync(join(home, "Downloads"));
    const dests = exportDestinations(cwd, { HOME: home });
    expect(dests.map((d) => d.label)).toEqual(["This folder", "Downloads", "Home"]);
  });

  it("dedupes Home when cwd is the home directory", () => {
    const dests = exportDestinations(home, { HOME: home });
    expect(dests.map((d) => d.label)).toEqual(["This folder"]);
  });

  it("does not crash when a candidate is a broken symlink", () => {
    const cwd = join(home, "project");
    mkdirSync(cwd);
    symlinkSync(join(home, "nowhere"), join(home, "Downloads"));
    const dests = exportDestinations(cwd, { HOME: home });
    expect(dests.map((d) => d.label)).toEqual(["This folder", "Home"]);
  });
});

describe("resolveExportPath", () => {
  it("expands a leading ~/ to the home directory", () => {
    expect(resolveExportPath("~/reports/out.json", "/elsewhere")).toBe(resolve(homedir(), "reports/out.json"));
    expect(resolveExportPath("~", "/elsewhere")).toBe(resolve(homedir()));
  });

  it("resolves a relative path against the provided cwd, trimming whitespace", () => {
    expect(resolveExportPath("  out/report.csv ", "/base/dir")).toBe(resolve("/base/dir", "out/report.csv"));
  });

  it("keeps absolute paths untouched", () => {
    expect(resolveExportPath("/abs/file.txt", "/base")).toBe("/abs/file.txt");
  });
});

describe("writeReportAtomic", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "dg-report-writer-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("creates missing parent directories before writing", () => {
    const target = join(dir, "a", "b", "report.txt");
    writeReportAtomic(target, "hello\n");
    expect(readFileSync(target, "utf8")).toBe("hello\n");
  });

  it("removes the temp file when the final rename fails", () => {
    const target = join(dir, "occupied");
    mkdirSync(target);
    writeFileSync(join(target, "keep.txt"), "x");
    expect(() => writeReportAtomic(target, "body")).toThrow();
    expect(readdirSync(dir)).toEqual(["occupied"]);
    expect(readFileSync(join(target, "keep.txt"), "utf8")).toBe("x");
  });
});
