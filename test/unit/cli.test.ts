import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../../src/runtime/cli.js";
import { commandCatalog } from "../../src/commands/router.js";
import { EXIT_USAGE, EXIT_USAGE_VERDICT } from "../../src/commands/types.js";
import { dgVersion } from "../../src/commands/version.js";

const originalLatest = process.env.DG_UPDATE_LATEST_VERSION;
const internalOutputPattern = /\b(cli-m\d+[a-z0-9-]*|slice|lands in|implemented later|Contract:|later enforcement slice)\b/i;

describe("cli command router", () => {
  afterEach(() => {
    if (originalLatest === undefined) {
      delete process.env.DG_UPDATE_LATEST_VERSION;
    } else {
      process.env.DG_UPDATE_LATEST_VERSION = originalLatest;
    }
  });

  it("prints a concise root help with common commands and a pointer to --help-all", async () => {
    const result = await runCli(["--help"]);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain(`dg ${dgVersion()}`);
    expect(result.stdout).toContain("dg <command> [options]");
    expect(result.stdout).toContain("scan");
    expect(result.stdout).toContain("verify");
    expect(result.stdout).toContain("--help-all");
    expect(result.stderr).toBe("");
  });

  it("lists every command, including service and wrappers, under --help-all", async () => {
    const result = await runCli(["--help-all"]);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("service");
    expect(result.stdout).toContain("npm");
    expect(result.stderr).toBe("");
  });

  it("prints the package version", async () => {
    expect(await runCli(["--version"])).toEqual({
      exitCode: 0,
      stdout: `dg ${dgVersion()}\n`,
      stderr: ""
    });
  });

  it("shows the friendly protection snapshot for dg status", async () => {
    const result = await runCli(["status"]);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Dependency Guardian status");
    expect(result.stdout).toContain("Account");
    expect(result.stdout).toContain("Policy");
    expect(result.stdout).toContain("dg doctor");
    expect(result.stderr).toBe("");
  });

  it("has one catalog entry per routed command name", () => {
    const names = commandCatalog.map((command) => command.name);

    expect(new Set(names).size).toBe(names.length);
    expect(names).toEqual(
      expect.arrayContaining([
        "scan",
        "verify",
        "setup",
        "uninstall",
        "doctor",
        "npm",
        "npx",
        "pnpm",
        "pnpx",
        "yarn",
        "pip",
        "pipx",
        "uv",
        "uvx",
        "cargo",
        "login",
        "logout",
        "config",
        "licenses",
        "audit",
        "update",
        "service"
      ])
    );
  });

  it("prints command-specific help without running the command", async () => {
    const result = await runCli(["setup", "--help"]);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("dg setup");
    expect(result.stdout).toContain("one consent screen");
    expect(result.stderr).toBe("");
  });

  it("keeps help output free of internal loop wording", async () => {
    const root = await runCli(["--help"]);
    expect(`${root.stdout}\n${root.stderr}`).not.toMatch(internalOutputPattern);

    for (const command of commandCatalog) {
      const result = await runCli([command.name, "--help"]);
      expect(result.exitCode).toBe(0);
      expect(`${result.stdout}\n${result.stderr}`).not.toMatch(internalOutputPattern);
    }

    const serviceTrust = await runCli(["service", "trust", "--help"]);
    expect(serviceTrust.exitCode).toBe(0);
    expect(`${serviceTrust.stdout}\n${serviceTrust.stderr}`).not.toMatch(internalOutputPattern);
  });

  it("prints optional ecosystem gates in command help", async () => {
    const yarn = await runCli(["yarn", "--help"]);
    const bun = await runCli(["bun", "--help"]);

    expect(yarn.exitCode).toBe(0);
    expect(yarn.stdout).toContain("Yarn classic routing only");
    expect(yarn.stdout).toContain("Yarn Berry remains gated and unclaimed");
    expect(bun.exitCode).toBe(0);
    expect(bun.stdout).toContain("Bun support is gated");
  });

  it("runs the implemented scan command through the router", async () => {
    const emptyTarget = await mkdtemp(join(tmpdir(), "dg-router-scan-"));
    try {
      const result = await runCli(["scan", emptyTarget]);

      expect(result.exitCode).toBe(10);
      expect(result.stdout).toContain("Dependency Guardian scan");
      expect(result.stderr).toBe("");
    } finally {
      await rm(emptyTarget, { force: true, recursive: true });
    }
  });

  it("routes package-manager prefixes without executing the package manager", async () => {
    const result = await runCli(["npm", "install", "left-pad"]);

    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("DG could not verify");
    expect(result.stderr).toContain("protection unavailable");
  });

  it("routes service subcommands and service trust subcommands", async () => {
    const status = await runCli(["service", "status"]);
    const trust = await runCli(["service", "trust", "install"]);

    expect(status.exitCode).toBe(0);
    expect(status.stdout).toContain("Dependency Guardian service");
    expect(trust.exitCode).toBe(EXIT_USAGE);
    expect(trust.stderr).toContain("requires --yes");
  });

  it("prints service group help and rejects unknown service actions", async () => {
    const help = await runCli(["service", "--help"]);
    const unknown = await runCli(["service", "enable"]);

    expect(help.exitCode).toBe(0);
    expect(help.stdout).toContain("dg service <start|stop|restart|status|doctor|uninstall|trust>");
    expect(unknown.exitCode).toBe(EXIT_USAGE);
    expect(unknown.stderr).toContain("unknown subcommand 'enable'");
  });

  it("keeps upgrade as an alias for update", async () => {
    process.env.DG_UPDATE_LATEST_VERSION = "999.0.0";

    const result = await runCli(["upgrade"]);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Dependency Guardian update");
    expect(result.stdout).toContain("npm install -g @westbayberry/dg@999.0.0");
    expect(result.stderr).toBe("");
  });

  it("rejects unknown commands as usage errors", async () => {
    const result = await runCli(["unknown-command"]);

    expect(result.exitCode).toBe(EXIT_USAGE);
    expect(result.stderr).toBe("dg: unknown command 'unknown-command'. Run 'dg --help'.\n");
  });

  it("dg --version prints 'dg ' plus the package.json version field", async () => {
    const packageJsonPath = fileURLToPath(new URL("../../package.json", import.meta.url));
    const version = (JSON.parse(readFileSync(packageJsonPath, "utf8")) as { version: string }).version;
    expect(typeof version).toBe("string");
    expect(version.length).toBeGreaterThan(0);

    const result = await runCli(["--version"]);
    expect(result).toEqual({
      exitCode: 0,
      stdout: `dg ${version}\n`,
      stderr: ""
    });
  });

  it("dg uninstall --all --keep-config exits 2 with a conflict message naming both flags", async () => {
    const result = await runCli(["uninstall", "--all", "--keep-config"]);

    expect(result.exitCode).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("--all");
    expect(result.stderr).toContain("--keep-config");
    expect(result.stderr).toContain("conflict");
  });

  it("dg audit --no-upload now errors as an unknown option (alias removed)", async () => {
    const result = await runCli(["audit", "--no-upload"]);

    expect(result.exitCode).toBe(EXIT_USAGE_VERDICT);
    expect(result.stderr).toContain("unknown option '--no-upload'");
  });
});
