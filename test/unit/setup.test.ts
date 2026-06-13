import { access, chmod, lstat, mkdir, readFile, stat, symlink, utimes, writeFile } from "node:fs/promises";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runCli } from "../../src/runtime/cli.js";
import {
  buildSetupPlan,
  doctorReport,
  isValidShimSource,
  SetupUnsupportedPlatformError,
  shimSource,
  uninstallSetup,
  SHIM_COMMANDS,
  SHIM_SENTINEL,
  RC_BEGIN,
  RC_END,
  RC_SENTINEL
} from "../../src/setup/plan.js";
import { dgVersion } from "../../src/commands/version.js";

const PYTHON_HOOK_BODY = '"""Dependency Guardian pip-install interceptor."""\n';
import { SERVICE_SENTINEL } from "../../src/service/state.js";
import { writeAuthState } from "../../src/auth/store.js";
import { acquireLockSync, createSession, resolveDgPaths } from "../../src/state/index.js";
import { OPTIONAL_SUPPORT_GATES, optionalPackageManagerNames } from "../../src/setup/optional-support.js";

function withPlatform<T>(platform: NodeJS.Platform, run: () => T): T {
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
  try {
    return run();
  } finally {
    if (descriptor) {
      Object.defineProperty(process, "platform", descriptor);
    }
  }
}

describe("setup command", () => {
  it("prints the exact write plan without mutating when --print is used", async () => {
    const home = await tempHome();
    const result = await withEnv(home, () => runCli(["setup", "--print", "--shell", "bash"]));

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Dependency Guardian setup write plan");
    expect(result.stdout).toContain(join(home, ".dg", "shims", "npm"));
    expect(result.stdout).toContain(join(home, ".bashrc"));
    expect(result.stderr).toBe("");
    await expect(access(join(home, ".dg", "shims", "npm"))).rejects.toThrow();
  });

  it("requires --yes before writing the non-interactive setup plan", async () => {
    const home = await tempHome();
    const result = await withEnv(home, () => runCli(["setup", "--shell=bash"]));

    expect(result.exitCode).toBe(2);
    expect(result.stdout).toContain("No files are changed until this plan is confirmed.");
    expect(result.stderr).toContain("requires --yes");
    await expect(access(join(home, ".bashrc"))).rejects.toThrow();
  });

  it("writes reversible shims, shell rc sentinel, and cleanup registry after --yes", async () => {
    const home = await tempHome();
    const result = await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Setup complete — active in new terminals");
    expect(result.stdout).toContain("Activate this shell now: source ");
    expect(result.stdout).toContain("&& hash -r");
    expect(result.stdout).toContain("details: dg doctor");
    expect(result.stdout).not.toContain("No files are changed until this plan is confirmed.");
    expect(result.stderr).toBe("");

    for (const command of SHIM_COMMANDS) {
      await expect(readFile(join(home, ".dg", "shims", command), "utf8")).resolves.toContain(`${SHIM_SENTINEL}`);
    }
    await expect(readFile(join(home, ".bashrc"), "utf8")).resolves.toContain(RC_SENTINEL);

    const registry = JSON.parse(await readFile(join(home, ".dg", "state", "cleanup-registry.json"), "utf8")) as {
      readonly entries: readonly { readonly kind: string; readonly owner: string }[];
    };
    expect(registry.entries.filter((entry) => entry.kind === "shim" && entry.owner === "dg")).toHaveLength(SHIM_COMMANDS.length);
    expect(registry.entries.filter((entry) => entry.kind === "rc" && entry.owner === "dg")).toHaveLength(1);
  });

  it("prints the activation hint as the final summary line, after the opted-in surface lines", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".claude"), { recursive: true });
    const result = await withEnv(home, () => runCli(["setup", "--yes", "--agents", "--shell", "bash"]));

    expect(result.exitCode).toBe(0);
    const surfaceIndex = result.stdout.indexOf("Claude Code installs now route through dg");
    const hintIndex = result.stdout.indexOf("Activate this shell now:");
    expect(surfaceIndex).toBeGreaterThan(-1);
    expect(hintIndex).toBeGreaterThan(surfaceIndex);
    expect(result.stdout.trimEnd().split("\n").at(-1)).toContain("Activate this shell now: source ");
  });

  it("enumerates every detected agent offer in --print", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".claude"), { recursive: true });
    const result = await withEnv(home, () => runCli(["setup", "--print", "--shell", "bash"]));

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("would offer: route Claude Code installs through dg (--agents)");
    await expect(access(join(home, ".claude", "settings.json"))).rejects.toThrow();
  });

  it("keeps --yes scoped to the shell: no agent config is written without --agents", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".claude"), { recursive: true });
    const result = await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));

    expect(result.exitCode).toBe(0);
    await expect(access(join(home, ".claude", "settings.json"))).rejects.toThrow();
  });

  it("refuses to mutate while the setup/uninstall lock is held", async () => {
    const home = await tempHome();
    const lock = acquireLockSync(
      resolveDgPaths({
        HOME: home
      }),
      "setup-uninstall"
    );
    try {
      const result = await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));

      expect(result.exitCode).toBe(1);
      expect(result.stdout).toContain("Dependency Guardian setup write plan");
      expect(result.stderr).toContain("another setup or uninstall is running");
      await expect(access(join(home, ".dg", "shims", "npm"))).rejects.toThrow();
    } finally {
      lock.release();
    }
  });

  it("repairs drift idempotently without duplicating the shell rc block", async () => {
    const home = await tempHome();
    await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));
    await writeFile(join(home, ".dg", "shims", "npm"), "drifted\n", "utf8");

    const result = await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));
    const rc = await readFile(join(home, ".bashrc"), "utf8");

    expect(result.exitCode).toBe(0);
    await expect(readFile(join(home, ".dg", "shims", "npm"), "utf8")).resolves.toContain(SHIM_SENTINEL);
    expect(rc.match(/dg-shell-rc-v1/g)).toHaveLength(1);
  });

  it("configures service mode only through explicit service setup", async () => {
    const home = await tempHome();
    const print = await withEnv(home, () => runCli(["setup", "--service", "--print"]));

    expect(print.exitCode).toBe(0);
    expect(print.stdout).toContain("Dependency Guardian service setup write plan");
    await expect(access(join(home, ".dg", "state", "service", "service.json"))).rejects.toThrow();

    const gated = await withEnv(home, () => runCli(["setup", "--service", "--yes"]));
    expect(gated.exitCode).toBe(69);
    expect(gated.stderr).toContain("Pro or Team");
    await expect(access(join(home, ".dg", "state", "service", "service.json"))).rejects.toThrow();

    await withEnv(home, () => writeAuthState({ token: "dg_test_token_abcdefghi" }));

    const withoutConsent = await withEnv(home, () => runCli(["setup", "--service"]));
    expect(withoutConsent.exitCode).toBe(2);
    expect(withoutConsent.stderr).toContain("requires --yes");
    await expect(access(join(home, ".dg", "state", "service", "service.json"))).rejects.toThrow();

    const service = await withEnv(home, () => runCli(["setup", "--service", "--yes"]));
    expect(service.exitCode).toBe(0);
    expect(service.stdout).toContain("Service mode configured");

    const state = JSON.parse(await readFile(join(home, ".dg", "state", "service", "service.json"), "utf8")) as {
      readonly configured: boolean;
    };
    expect(state.configured).toBe(true);
    const registry = JSON.parse(await readFile(join(home, ".dg", "state", "cleanup-registry.json"), "utf8")) as {
      readonly entries: readonly { readonly kind: string; readonly sentinel?: string; readonly mode: string }[];
    };
    expect(registry.entries).toEqual(
      expect.arrayContaining([expect.objectContaining({ kind: "service", sentinel: SERVICE_SENTINEL, mode: "mode2" })])
    );
  });

  it("does not claim Python hook or PowerShell setup support, and redirects --git-hooks to dg guard-commit", async () => {
    const home = await tempHome();
    const python = await withEnv(home, () => runCli(["setup", "--python-hook", "--yes"]));
    const git = await withEnv(home, () => runCli(["setup", "--git-hooks", "--yes"]));
    const powershell = await withEnv(home, () => runCli(["setup", "--shell", "powershell", "--yes"]));

    expect(python.exitCode).toBe(69);
    expect(python.stderr).toContain("Python .pth hook support is gated");
    expect(git.exitCode).toBe(2);
    expect(git.stderr).toContain("dg guard-commit");
    expect(powershell.exitCode).toBe(69);
    expect(powershell.stderr).toContain("Windows support is gated");
    await expect(access(join(home, ".dg", "shims", "npm"))).rejects.toThrow();
  });

  it("does not register optional hook, Windows, or gated package-manager writes during default setup", async () => {
    const home = await tempHome();
    const result = await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));

    expect(result.exitCode).toBe(0);
    const registry = JSON.parse(await readFile(join(home, ".dg", "state", "cleanup-registry.json"), "utf8")) as {
      readonly entries: readonly { readonly kind: string; readonly path: string }[];
    };

    expect(registry.entries.some((entry) => entry.kind === "python-hook" || entry.kind === "git-hook")).toBe(false);
    expect(registry.entries.some((entry) => /powershell|\.ps1|\.cmd|bun|conda|mamba/.test(entry.path))).toBe(false);
  });
});

describe("uninstall command", () => {
  it("removes registered dg-owned writes and can run twice", async () => {
    const home = await tempHome();
    await writeFile(join(home, ".bashrc"), "export USER_CONTENT=1\n", "utf8");
    await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));

    const first = await withEnv(home, () => runCli(["uninstall", "--yes"]));
    const second = await withEnv(home, () => runCli(["uninstall", "--yes"]));

    expect(first.exitCode).toBe(0);
    expect(first.stdout).toContain("removed:");
    await expect(access(join(home, ".dg", "shims", "npm"))).rejects.toThrow();
    await expect(readFile(join(home, ".bashrc"), "utf8")).resolves.toBe("export USER_CONTENT=1\n");
    expect(second.exitCode).toBe(0);
    expect(second.stdout).toContain("No dg-owned setup writes were present.");
  });

  it("sweeps stale sessions during soft uninstall without deleting active sessions", async () => {
    const home = await tempHome();
    const paths = resolveDgPaths({
      HOME: home
    });
    const stale = await createSession(paths, "stale-session");
    const active = await createSession(paths, "active-session");
    const oldDate = new Date("2026-01-01T00:00:00.000Z");
    await utimes(stale.dir, oldDate, oldDate);

    const result = await withEnv(home, () => runCli(["uninstall", "--yes", "--keep-config"]));

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("stale session removed: stale-session");
    await expect(access(stale.dir)).rejects.toThrow();
    await expect(access(active.dir)).resolves.toBeUndefined();
  });

  it("refuses to run while the setup/uninstall lock is held", async () => {
    const home = await tempHome();
    const lock = acquireLockSync(
      resolveDgPaths({
        HOME: home
      }),
      "setup-uninstall"
    );
    try {
      const result = await withEnv(home, () => runCli(["uninstall", "--yes"]));

      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain("another setup or uninstall is running");
    } finally {
      lock.release();
    }
  });

  it("tolerates malformed cleanup registry without deleting untrusted files", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".dg", "state"), {
      recursive: true
    });
    await mkdir(join(home, ".dg", "shims"), {
      recursive: true
    });
    await writeFile(join(home, ".dg", "state", "cleanup-registry.json"), "{bad", "utf8");
    await writeFile(join(home, ".dg", "shims", "npm"), "user file\n", "utf8");

    const result = await withEnv(home, () => runCli(["uninstall", "--yes"]));

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("cleanup registry was malformed");
    expect(result.stdout).toContain("preserved at");
    await expect(readFile(join(home, ".dg", "shims", "npm"), "utf8")).resolves.toBe("user file\n");
  });
});

describe("doctor command", () => {
  it("reports local setup health in text and JSON formats", async () => {
    const home = await tempHome();
    await writeOfflineApiConfig(home);
    await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));

    const text = await withEnv(home, () => runCli(["doctor"]));
    const verbose = await withEnv(home, () => runCli(["doctor", "--verbose"]));
    const json = await withEnv(home, () => runCli(["doctor", "--json"]));
    const parsed = JSON.parse(json.stdout) as {
      readonly checks: readonly { readonly name: string; readonly status: string }[];
    };

    expect(text.exitCode).toBe(0);
    expect(text.stdout).toContain("DG doctor");
    expect(text.stdout).toContain("Environment");
    expect(text.stdout).toContain("✓ Setup");
    expect(text.stdout).not.toContain("node");
    expect(text.stdout).not.toContain("shims");
    expect(text.stdout).not.toContain("service");
    expect(verbose.exitCode).toBe(0);
    expect(verbose.stdout).toContain("node");
    expect(verbose.stdout).toContain("shims");
    expect(verbose.stdout).toContain("service");
    expect(`${text.stdout}\n${text.stderr}`).not.toMatch(/\b(cli-m\d+[a-z0-9-]*|lands in|implemented later|Contract:|later enforcement slice)\b/i);
    expect(json.exitCode).toBe(0);
    expect(parsed.checks).toEqual(expect.arrayContaining([expect.objectContaining({ name: "path", status: "pass" })]));
    expect(json.stdout).not.toMatch(/\b(cli-m\d+[a-z0-9-]*|lands in|implemented later|Contract:|later enforcement slice)\b/i);
  });

  it("reports stale sessions and unavailable dependent surfaces without claiming support", async () => {
    const home = await tempHome();
    await writeOfflineApiConfig(home);
    const paths = resolveDgPaths({
      HOME: home
    });
    const stale = await createSession(paths, "stale-session");
    const oldDate = new Date("2026-01-01T00:00:00.000Z");
    await utimes(stale.dir, oldDate, oldDate);

    const result = await withEnv(home, () => runCli(["doctor", "--json"]));
    const parsed = JSON.parse(result.stdout) as {
      readonly checks: readonly { readonly name: string; readonly status: string; readonly message: string }[];
    };

    expect(result.exitCode).toBe(0);
    expect(parsed.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "stale-sessions",
          status: "warn",
          message: expect.stringContaining("stale-session")
        }),
        expect.objectContaining({
          name: "auth",
          status: "warn"
        }),
        expect.objectContaining({
          name: "policy",
          status: "pass"
        }),
        expect.objectContaining({
          name: "api",
          status: "warn",
          message: expect.stringContaining("http://127.0.0.1:1")
        }),
        expect.objectContaining({
          name: "update",
          status: "pass"
        }),
        expect.objectContaining({
          name: "real-binary-resolution",
          status: "pass"
        }),
        expect.objectContaining({
          name: "recursive-shim-guard",
          status: "pass"
        }),
        expect.objectContaining({
          name: "package-manager-discovery",
          status: "pass"
        }),
        expect.objectContaining({
          name: "proxy",
          status: "unavailable"
        }),
        expect.objectContaining({
          name: "dashboard",
          status: "unavailable"
        }),
        expect.objectContaining({
          name: "windows",
          status: "unavailable",
          message: expect.stringContaining("Windows support is gated")
        }),
        expect.objectContaining({
          name: "yarn-berry",
          status: "unavailable",
          message: expect.stringContaining("Yarn Berry support is gated")
        }),
        expect.objectContaining({
          name: "bun",
          status: "unavailable",
          message: expect.stringContaining("Bun support is gated")
        }),
        expect.objectContaining({
          name: "conda",
          status: "unavailable",
          message: expect.stringContaining("Conda support is gated")
        }),
        expect.objectContaining({
          name: "mamba",
          status: "unavailable",
          message: expect.stringContaining("Mamba support is gated")
        }),
        expect.objectContaining({
          name: "docs-api",
          status: "unavailable"
        })
      ])
    );
  });

  it("ignores DG_TEST_CURRENT_DG_PATH outside the test environment", async () => {
    const home = await tempHome();
    const report = doctorReport({
      env: { HOME: home, SHELL: "/bin/bash", PATH: `${join(home, "nowhere")}`, DG_TEST_CURRENT_DG_PATH: "/tmp/fake-current-dg" }
    });
    const check = report.checks.find((candidate) => candidate.name === "dg-binary-path");
    expect(check?.message).not.toContain("/tmp/fake-current-dg");
  });

  it("identifies an older dg executable earlier on PATH", async () => {
    const home = await tempHome();
    await writeOfflineApiConfig(home);
    const oldBin = join(home, "old-bin");
    const currentBin = join(home, "current-bin");
    const currentDg = join(currentBin, "dg");
    await mkdir(oldBin, {
      recursive: true
    });
    await mkdir(currentBin, {
      recursive: true
    });
    await writeFile(join(oldBin, "dg"), "#!/bin/sh\necho old-dg 0.0.0\n", "utf8");
    await writeFile(currentDg, "#!/bin/sh\necho new-dg 0.0.0\n", "utf8");
    await chmod(join(oldBin, "dg"), 0o755);
    await chmod(currentDg, 0o755);

    const result = await withEnv(home, () => runCli(["doctor", "--verbose"]), {
      DG_TEST_CURRENT_DG_PATH: currentDg,
      PATH: `${oldBin}:${currentBin}:/usr/bin:/bin`
    });

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("dg-binary-path");
    expect(result.stdout).toContain("Another dg executable is earlier on PATH");
    expect(result.stdout).toContain(join(oldBin, "dg"));
    expect(result.stdout).toContain("which -a dg");
  });
});

describe("setup Windows guard", () => {
  it("refuses dg setup --yes on win32 without writing POSIX shims", async () => {
    const home = await tempHome();
    const result = await withEnv(home, () => withPlatform("win32", () => runCli(["setup", "--yes", "--shell", "bash"])));

    expect(result.exitCode).toBe(69);
    expect(result.stderr).toContain("does not support Windows");
    expect(result.stdout).toBe("");
    await expect(access(join(home, ".dg", "shims", "npm"))).rejects.toThrow();
    await expect(access(join(home, ".bashrc"))).rejects.toThrow();
  });

  it("refuses dg setup --print on win32 and never claims a write plan succeeded", async () => {
    const home = await tempHome();
    const result = await withEnv(home, () => withPlatform("win32", () => runCli(["setup", "--print", "--shell", "bash"])));

    expect(result.exitCode).toBe(69);
    expect(result.stderr).toContain("does not support Windows");
  });

  it("buildSetupPlan throws SetupUnsupportedPlatformError on win32 as a defense layer", () => {
    withPlatform("win32", () => {
      expect(() => buildSetupPlan({ shell: "bash", env: { HOME: "/home/user", SHELL: "/bin/bash" } })).toThrow(
        SetupUnsupportedPlatformError
      );
    });
  });
});

describe("shim source escaping and validation", () => {
  it("round-trips: every generated shim is accepted by isValidShimSource", () => {
    for (const command of SHIM_COMMANDS) {
      expect(isValidShimSource(shimSource(command), command)).toBe(true);
    }
  });

  it("rejects a drifted shim that lost the dg exec structure", () => {
    expect(isValidShimSource(`#!/bin/sh\n# ${SHIM_SENTINEL}\nexec npm "$@"\n`, "npm")).toBe(false);
    expect(isValidShimSource("drifted\n", "npm")).toBe(false);
  });

  it("escapes special characters in the dg entrypoint path so the shim stays parseable", () => {
    const originalArgv1 = process.argv[1];
    process.argv[1] = '/opt/dg dir/"weird"/$HOME/`cmd`/dg.js';
    try {
      const source = shimSource("npm");
      expect(source).toContain('exec "/opt/dg dir/\\"weird\\"/\\$HOME/\\`cmd\\`/dg.js" npm "$@"');
      expect(isValidShimSource(source, "npm")).toBe(true);
    } finally {
      if (originalArgv1 === undefined) {
        delete (process.argv as string[])[1];
      } else {
        process.argv[1] = originalArgv1;
      }
    }
  });

  it("escapes special characters in the shim directory inside the shell rc block", async () => {
    const home = await tempHome();
    const weird = join(home, 'space dir', 'a"b$c');
    const plan = buildSetupPlan({ shell: "bash", env: { HOME: weird, SHELL: "/bin/bash" } });
    expect(plan.shimDir).toContain('a"b$c');
  });
});

describe("uninstall registry ordering", () => {
  it("prunes the registry before removing the state directory and leaves no orphan registry", async () => {
    const home = await tempHome();
    await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));

    const result = await withEnv(home, () =>
      uninstallSetup({ keepConfig: false, all: true, env: { HOME: home, SHELL: "/bin/bash" } })
    );

    expect(result.removed.some((path) => path.includes("shims"))).toBe(true);
    await expect(access(join(home, ".dg", "state", "cleanup-registry.json"))).rejects.toThrow();
    await expect(access(join(home, ".dg", "state"))).rejects.toThrow();
  });

  it("keeps user entries while pruning dg-owned entries under keep-config without losing the registry", async () => {
    const home = await tempHome();
    await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));

    await withEnv(home, () =>
      uninstallSetup({ keepConfig: true, all: false, env: { HOME: home, SHELL: "/bin/bash" } })
    );

    const registry = JSON.parse(await readFile(join(home, ".dg", "state", "cleanup-registry.json"), "utf8")) as {
      readonly entries: readonly { readonly owner: string }[];
    };
    expect(registry.entries.every((entry) => entry.owner !== "dg")).toBe(true);
  });
});

describe("uninstall legacy shell-rc sweep", () => {
  it("strips a legacy dg-managed PATH block left by an older CLI, preserving user content", async () => {
    const home = await tempHome();
    const zshrc = join(home, ".zshrc");
    const userBefore = 'export PATH="/usr/local/bin:$PATH"\nalias ll="ls -la"\n';
    const legacy = '# >>> dg-managed >>>\nexport PATH="$HOME/.dg/shims:$PATH"\n# <<< dg-managed <<<\n';
    const userAfter = "export EDITOR=vim\n";
    await writeFile(zshrc, userBefore + legacy + userAfter);

    const result = await withEnv(home, () =>
      uninstallSetup({ keepConfig: false, all: false, env: { HOME: home, SHELL: "/bin/zsh" } })
    );

    const contents = await readFile(zshrc, "utf8");
    expect(contents).not.toContain("dg-managed");
    expect(contents).not.toContain(".dg/shims");
    expect(contents).toContain('alias ll="ls -la"');
    expect(contents).toContain("export EDITOR=vim");
    expect(result.removed.some((path) => path.includes(".zshrc") && path.includes("legacy"))).toBe(true);
  });
});

describe("rc atomic rewrite", () => {
  it("rewrites a symlinked shell rc through the link instead of replacing the link", async () => {
    const home = await tempHome();
    const dotfiles = join(home, "dotfiles");
    await mkdir(dotfiles, { recursive: true });
    const realRc = join(dotfiles, "bashrc");
    await writeFile(realRc, "export USER_CONTENT=1\n", "utf8");
    await symlink(realRc, join(home, ".bashrc"));

    const result = await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));

    expect(result.exitCode).toBe(0);
    expect((await lstat(join(home, ".bashrc"))).isSymbolicLink()).toBe(true);
    const linked = await readFile(realRc, "utf8");
    expect(linked).toContain("export USER_CONTENT=1");
    expect(linked).toContain(RC_SENTINEL);
  });

  it("preserves the rc file mode across the rewrite", async () => {
    const home = await tempHome();
    const rcPath = join(home, ".bashrc");
    await writeFile(rcPath, "export A=1\n", "utf8");
    await chmod(rcPath, 0o600);

    const result = await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));

    expect(result.exitCode).toBe(0);
    expect((await stat(rcPath)).mode & 0o777).toBe(0o600);
    await expect(readFile(rcPath, "utf8")).resolves.toContain(RC_SENTINEL);
  });
});

describe("rc unterminated dg marker repair", () => {
  it("setup never deletes user content below a stale unterminated begin marker", async () => {
    const home = await tempHome();
    const rcPath = join(home, ".bashrc");
    const before = [
      "export A=1",
      RC_BEGIN,
      "# dg-shell-rc-v1",
      `export PATH="${join(home, ".dg", "shims")}:$PATH"`,
      'alias keepme="ls -la"',
      "export B=2",
      ""
    ].join("\n");
    await writeFile(rcPath, before);

    const result = await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));
    const after = await readFile(rcPath, "utf8");

    expect(result.exitCode).toBe(0);
    expect(after).toContain("export A=1");
    expect(after).toContain('alias keepme="ls -la"');
    expect(after).toContain("export B=2");
    expect(after.match(new RegExp(RC_BEGIN, "g"))).toHaveLength(1);
    expect(after.match(new RegExp(RC_END, "g"))).toHaveLength(1);
  });

  it("uninstall repairs an unterminated dg block, keeps user lines below it, and warns", async () => {
    const home = await tempHome();
    await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));
    const rcPath = join(home, ".bashrc");
    const installed = await readFile(rcPath, "utf8");
    await writeFile(rcPath, `${installed.replace(`${RC_END}\n`, "")}alias keepme="ls -la"\nexport B=2\n`);

    const result = await withEnv(home, () => runCli(["uninstall", "--yes"]));
    const after = await readFile(rcPath, "utf8");

    expect(result.exitCode).toBe(0);
    expect(after).toContain('alias keepme="ls -la"');
    expect(after).toContain("export B=2");
    expect(after).not.toContain(RC_BEGIN);
    expect(after).not.toContain("__dg_shim");
    expect(result.stdout).toContain("repaired an unterminated dg block");
  });

  it("a stale begin marker above the real block never swallows the user lines between them", async () => {
    const home = await tempHome();
    await withEnv(home, () => runCli(["setup", "--yes", "--shell", "bash"]));
    const rcPath = join(home, ".bashrc");
    const installed = await readFile(rcPath, "utf8");
    await writeFile(rcPath, `${RC_BEGIN}\nexport USER_KEEP=1\n${installed}`);

    const result = await withEnv(home, () => runCli(["uninstall", "--yes"]));
    const after = await readFile(rcPath, "utf8");

    expect(result.exitCode).toBe(0);
    expect(after).toContain("export USER_KEEP=1");
    expect(after).not.toContain(RC_BEGIN);
    expect(after).not.toContain(RC_SENTINEL);
  });
});

describe("setup shell-function interception", () => {
  it("writes per-command shell functions that delegate to the shims so a virtualenv cannot shadow them", async () => {
    const home = await tempHome();
    await writeFile(join(home, ".zshrc"), "# user content\n");
    await withEnv(home, () => runCli(["setup", "--yes", "--shell", "zsh"]));

    const rc = await readFile(join(home, ".zshrc"), "utf8");
    expect(rc).toContain("# dg-shim-functions-v1");
    expect(rc).toContain("__dg_shim()");
    for (const command of SHIM_COMMANDS) {
      expect(rc).toContain(`${command}() { __dg_shim ${command} "$@"; }`);
    }
    expect(rc.match(/dg-shell-rc-v1/g)).toHaveLength(1);
  });

  it("doctor path check passes inside a virtualenv because the shell functions intercept regardless of PATH order", async () => {
    const home = await tempHome();
    await writeFile(join(home, ".zshrc"), "# user content\n");
    await withEnv(home, () => runCli(["setup", "--yes", "--shell", "zsh"]));

    const venvBin = join(home, "venv", "bin");
    await mkdir(venvBin, { recursive: true });
    await writeFile(join(venvBin, "pip"), "#!/bin/sh\nexit 0\n");
    await chmod(join(venvBin, "pip"), 0o755);
    const shimDir = join(home, ".dg", "shims");
    const env = { HOME: home, SHELL: "/bin/zsh", PATH: `${venvBin}:${shimDir}:/usr/bin:/bin` };

    const path = doctorReport({ env }).checks.find((check) => check.name === "path");
    expect(path?.status).toBe("pass");
    expect(path?.message).toContain("virtualenv");
  });
});

describe("uninstall legacy python-hook sweep", () => {
  it("removes a macOS user-site dg_pip_hook.py + .pth left by an older CLI", async () => {
    const home = await tempHome();
    const site = join(home, "Library", "Python", "3.11", "lib", "python", "site-packages");
    await mkdir(site, { recursive: true });
    await writeFile(join(site, "dg_pip_hook.py"), PYTHON_HOOK_BODY);
    await writeFile(join(site, "dg_pip_hook.pth"), "import dg_pip_hook\n");

    const result = await withEnv(home, () =>
      uninstallSetup({ keepConfig: true, all: false, env: { HOME: home, SHELL: "/bin/zsh" } })
    );

    await expect(access(join(site, "dg_pip_hook.py"))).rejects.toThrow();
    await expect(access(join(site, "dg_pip_hook.pth"))).rejects.toThrow();
    expect(result.removed.filter((path) => path.includes("legacy dg pip hook"))).toHaveLength(2);
  });

  it("removes a Linux user-site hook regardless of host platform", async () => {
    const home = await tempHome();
    const site = join(home, ".local", "lib", "python3.10", "site-packages");
    await mkdir(site, { recursive: true });
    await writeFile(join(site, "dg_pip_hook.py"), PYTHON_HOOK_BODY);
    await writeFile(join(site, "dg_pip_hook.pth"), "import dg_pip_hook\n");

    await withEnv(home, () =>
      uninstallSetup({ keepConfig: true, all: false, env: { HOME: home, SHELL: "/bin/bash" } })
    );

    await expect(access(join(site, "dg_pip_hook.py"))).rejects.toThrow();
    await expect(access(join(site, "dg_pip_hook.pth"))).rejects.toThrow();
  });

  it("never deletes a same-named file that lacks the dg marker, and spares sibling user files", async () => {
    const home = await tempHome();
    const site = join(home, "Library", "Python", "3.12", "lib", "python", "site-packages");
    await mkdir(site, { recursive: true });
    await writeFile(join(site, "dg_pip_hook.py"), "print('not ours')\n");
    await writeFile(join(site, "local_fixups.py"), "x = 1\n");

    const result = await withEnv(home, () =>
      uninstallSetup({ keepConfig: true, all: false, env: { HOME: home, SHELL: "/bin/zsh" } })
    );

    await expect(access(join(site, "dg_pip_hook.py"))).resolves.toBeUndefined();
    await expect(access(join(site, "local_fixups.py"))).resolves.toBeUndefined();
    expect(result.removed.some((path) => path.includes("legacy dg pip hook"))).toBe(false);
  });

  it("never deletes a dg_pip_hook.pth whose content is not the dg import line", async () => {
    const home = await tempHome();
    const site = join(home, ".local", "lib", "python3.12", "site-packages");
    await mkdir(site, { recursive: true });
    await writeFile(join(site, "dg_pip_hook.pth"), "import somebody_elses_module\n");

    const result = await withEnv(home, () =>
      uninstallSetup({ keepConfig: true, all: false, env: { HOME: home, SHELL: "/bin/bash" } })
    );

    await expect(access(join(site, "dg_pip_hook.pth"))).resolves.toBeUndefined();
    expect(result.removed.some((path) => path.includes("legacy dg pip hook"))).toBe(false);

    const drift = doctorReport({ env: { HOME: home, SHELL: "/bin/bash" } }).checks.find(
      (check) => check.name === "python-hook-drift"
    );
    expect(drift?.status).toBe("pass");
  });

  it("doctor warns on python-hook-drift when a stale hook is present and passes when clean", async () => {
    const home = await tempHome();
    const site = join(home, "Library", "Python", "3.13", "lib", "python", "site-packages");
    await mkdir(site, { recursive: true });
    await writeFile(join(site, "dg_pip_hook.pth"), "import dg_pip_hook\n");

    const warned = doctorReport({ env: { HOME: home, SHELL: "/bin/zsh" } }).checks.find(
      (check) => check.name === "python-hook-drift"
    );
    expect(warned?.status).toBe("warn");

    await withEnv(home, () => uninstallSetup({ keepConfig: true, all: false, env: { HOME: home, SHELL: "/bin/zsh" } }));

    const cleared = doctorReport({ env: { HOME: home, SHELL: "/bin/zsh" } }).checks.find(
      (check) => check.name === "python-hook-drift"
    );
    expect(cleared?.status).toBe("pass");
  });
});

describe("optional package-manager derivation", () => {
  it("derives gated package-manager names from the gate table, excluding non-standalone variants", () => {
    const derived = optionalPackageManagerNames();
    const expected = OPTIONAL_SUPPORT_GATES.filter(
      (gate) => gate.kind === "package-manager" && gate.standaloneCommand === true
    ).map((gate) => gate.id);

    expect([...derived]).toEqual(expected);
    expect(derived).toContain("bun");
    expect(derived).toContain("conda");
    expect(derived).toContain("mamba");
    expect(derived).not.toContain("yarn-berry");
  });
});

async function tempHome(): Promise<string> {
  return mkdtemp(join(tmpdir(), "dg-setup-test-"));
}

async function writeOfflineApiConfig(home: string): Promise<void> {
  await mkdir(join(home, ".dg"), { recursive: true });
  await writeFile(
    join(home, ".dg", "config.json"),
    `${JSON.stringify({ version: 1, api: { baseUrl: "http://127.0.0.1:1" } })}\n`
  );
}

async function withEnv<T>(home: string, run: () => T | Promise<T>, extraEnv: Partial<NodeJS.ProcessEnv> = {}): Promise<T> {
  const previous = {
    HOME: process.env.HOME,
    PATH: process.env.PATH,
    SHELL: process.env.SHELL,
    DG_API_TOKEN: process.env.DG_API_TOKEN,
    DG_TEST_NODE_VERSION: process.env.DG_TEST_NODE_VERSION,
    DG_TEST_CURRENT_DG_PATH: process.env.DG_TEST_CURRENT_DG_PATH,
    DG_UPDATE_LATEST_VERSION: process.env.DG_UPDATE_LATEST_VERSION
  };
  process.env.HOME = home;
  process.env.PATH = extraEnv.PATH ?? `${join(home, ".dg", "shims")}:/usr/bin:/bin`;
  process.env.SHELL = extraEnv.SHELL ?? "/bin/bash";
  process.env.DG_TEST_NODE_VERSION = extraEnv.DG_TEST_NODE_VERSION ?? "v22.14.0";
  process.env.DG_UPDATE_LATEST_VERSION = extraEnv.DG_UPDATE_LATEST_VERSION ?? dgVersion();
  if (extraEnv.DG_TEST_CURRENT_DG_PATH) {
    process.env.DG_TEST_CURRENT_DG_PATH = extraEnv.DG_TEST_CURRENT_DG_PATH;
  } else {
    delete process.env.DG_TEST_CURRENT_DG_PATH;
  }
  delete process.env.DG_API_TOKEN;
  try {
    return await run();
  } finally {
    restoreEnv("HOME", previous.HOME);
    restoreEnv("PATH", previous.PATH);
    restoreEnv("SHELL", previous.SHELL);
    restoreEnv("DG_API_TOKEN", previous.DG_API_TOKEN);
    restoreEnv("DG_TEST_NODE_VERSION", previous.DG_TEST_NODE_VERSION);
    restoreEnv("DG_TEST_CURRENT_DG_PATH", previous.DG_TEST_CURRENT_DG_PATH);
    restoreEnv("DG_UPDATE_LATEST_VERSION", previous.DG_UPDATE_LATEST_VERSION);
  }
}

function restoreEnv(key: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[key];
  } else {
    process.env[key] = value;
  }
}
