import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

const ALT_SCREEN_ON = "[?1049h";
const CLEAR_SCREEN = "[2J";
const SELECTOR_HEADER = "Found 2 projects";

const cliRoot = resolve(fileURLToPath(new URL(".", import.meta.url)), "..", "..");

// node-pty's exit callback aborts V8 inside vitest worker threads, so the pty session runs in a child process.
const PTY_HARNESS = [
  'const { createRequire } = require("node:module");',
  'const path = require("node:path");',
  'const req = createRequire(path.join(process.cwd(), "package.json"));',
  'const pty = req("node-pty");',
  "const [distPath, fixture, home, selectorHeader] = process.argv.slice(1);",
  "const child = pty.spawn(process.execPath, [distPath, \"scan\"], {",
  '  name: "xterm-256color", cols: 100, rows: 40, cwd: fixture,',
  '  env: { HOME: home, PATH: process.env.PATH, TERM: "xterm-256color", XDG_CONFIG_HOME: "", XDG_STATE_HOME: "", XDG_CACHE_HOME: "" }',
  "});",
  'let output = "";',
  "let wroteQuit = false;",
  "child.onData((chunk) => {",
  "  output += chunk;",
  "  if (!wroteQuit && output.includes(selectorHeader)) {",
  "    wroteQuit = true;",
  '    setTimeout(() => child.write("q"), 300);',
  "  }",
  "});",
  "const timeout = setTimeout(() => { try { child.kill(); } catch {} finish(-1); }, 20000);",
  "child.onExit(({ exitCode }) => finish(exitCode));",
  "function finish(exitCode) {",
  "  clearTimeout(timeout);",
  "  process.stdout.write(JSON.stringify({ output, exitCode }));",
  "  process.exit(0);",
  "}"
].join("\n");

async function writeNpmProject(root: string, name: string): Promise<void> {
  const dir = join(root, name);
  await mkdir(dir, { recursive: true });
  await writeFile(
    join(dir, "package-lock.json"),
    `${JSON.stringify({
      name,
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name, version: "1.0.0", dependencies: { "left-pad": "^1.3.0" } },
        "node_modules/left-pad": {
          version: "1.3.0",
          resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
        }
      }
    }, null, 2)}\n`,
    "utf8"
  );
}

describe("scan TUI first frame (pty)", () => {
  it("renders the project selector inside the alt screen without any keypress", async () => {
    const workdir = await mkdtemp(join(tmpdir(), "dg-pty-scan-"));
    const home = join(workdir, "home");
    const fixture = join(workdir, "repo");
    await mkdir(join(home, ".dg", "state"), { recursive: true });
    await writeFile(join(home, ".dg", "state", "first-run-shown"), `${new Date().toISOString()}\n`, "utf8");
    await mkdir(join(home, ".dg", "shims"), { recursive: true });
    await writeFile(join(home, ".dg", "shims", "npm"), "#!/bin/sh\n", "utf8");
    await writeNpmProject(fixture, "app-a");
    await writeNpmProject(fixture, "app-b");

    try {
      const { stdout } = await execFileAsync(
        process.execPath,
        ["-e", PTY_HARNESS, join(cliRoot, "dist", "bin", "dg.js"), fixture, home, SELECTOR_HEADER],
        { cwd: cliRoot, timeout: 30000, maxBuffer: 16 * 1024 * 1024 }
      );
      const { output, exitCode } = JSON.parse(stdout) as { output: string; exitCode: number };

      expect(output).toContain(SELECTOR_HEADER);
      const altIndex = output.indexOf(ALT_SCREEN_ON);
      expect(altIndex).toBeGreaterThanOrEqual(0);

      const beforeFlip = output.slice(0, altIndex);
      expect(beforeFlip).not.toContain("Scanning for projects");
      expect(beforeFlip).not.toContain("Found");
      expect(beforeFlip).not.toContain("Dependency Guardian");

      expect(output.indexOf(SELECTOR_HEADER)).toBeGreaterThan(output.lastIndexOf(ALT_SCREEN_ON));
      expect(output.indexOf(SELECTOR_HEADER, output.lastIndexOf(CLEAR_SCREEN))).toBeGreaterThan(-1);
      expect(output).toContain("app-a");
      expect(output).toContain("app-b");
      expect(exitCode).toBe(0);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  }, 60000);
});
