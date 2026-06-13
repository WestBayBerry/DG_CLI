import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { commitGuardOffer } from "../../src/setup/git-hook.js";
import { activateShell, activationOffer, type ShellSpawnRequest, type ShellSpawner } from "../../src/setup/activate-shell.js";

const made: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "dg-setup-surface-"));
  made.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of made.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("activationOffer", () => {
  const tty = { isTTY: true };
  const pipe = {};

  it("prompts when stdin and stdout are TTYs outside CI", () => {
    expect(activationOffer({ env: {}, stdin: tty, stdout: tty })).toBe("prompt");
  });

  it("skips the offer entirely inside an already-activated shell", () => {
    expect(activationOffer({ env: { DG_ACTIVATED_SHELL: "1" }, stdin: tty, stdout: tty })).toBe("none");
  });

  it("falls back to the hint when stdin or stdout is not a TTY", () => {
    expect(activationOffer({ env: {}, stdin: pipe, stdout: tty })).toBe("hint");
    expect(activationOffer({ env: {}, stdin: tty, stdout: pipe })).toBe("hint");
  });

  it("falls back to the hint in CI", () => {
    expect(activationOffer({ env: { CI: "1" }, stdin: tty, stdout: tty })).toBe("hint");
  });
});

describe("activateShell", () => {
  function capture(exitCode: number): { readonly requests: ShellSpawnRequest[]; readonly spawner: ShellSpawner } {
    const requests: ShellSpawnRequest[] = [];
    return {
      requests,
      spawner: (request) => {
        requests.push(request);
        return exitCode;
      }
    };
  }

  it("spawns $SHELL interactively with DG_ACTIVATED_SHELL=1 and returns its exit code", () => {
    const { requests, spawner } = capture(7);
    const code = activateShell({ env: { SHELL: "/bin/zsh", HOME: "/home/u" }, spawner });
    expect(code).toBe(7);
    expect(requests[0]?.binary).toBe("/bin/zsh");
    expect(requests[0]?.args).toEqual(["-i"]);
    expect(requests[0]?.args).not.toContain("-l");
    expect(requests[0]?.env.DG_ACTIVATED_SHELL).toBe("1");
    expect(requests[0]?.env.HOME).toBe("/home/u");
  });

  it("passes -i to bash", () => {
    const { requests, spawner } = capture(0);
    activateShell({ env: { SHELL: "/bin/bash" }, spawner });
    expect(requests[0]?.args).toEqual(["-i"]);
  });

  it("falls back to /bin/sh without flags when SHELL is unset", () => {
    const { requests, spawner } = capture(0);
    activateShell({ env: {}, spawner });
    expect(requests[0]?.binary).toBe("/bin/sh");
    expect(requests[0]?.args).toEqual([]);
  });
});

describe("commitGuardOffer", () => {
  it("offers inside a git repo with no commit guard", () => {
    const dir = tempDir();
    execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
    expect(commitGuardOffer({ cwd: dir, env: { HOME: dir } })).not.toBeNull();
  });

  it("does not offer outside a git repo", () => {
    const dir = tempDir();
    expect(commitGuardOffer({ cwd: dir, env: { HOME: dir } })).toBeNull();
  });
});
