import { describe, expect, it } from "vitest";
import { runCli } from "../../src/runtime/cli.js";
import { renderCommandHelp } from "../../src/commands/help.js";
import { commandCatalog } from "../../src/commands/router.js";

async function help(command: string): Promise<string> {
  return (await runCli([command, "--help"])).stdout;
}

describe("command help documents flags", () => {
  it("verify --help lists its real flags and examples", async () => {
    const text = await help("verify");
    expect(text).toContain("Flags:");
    expect(text).toContain("--verbose");
    expect(text).toContain("--output");
    expect(text).toContain("Examples:");
    expect(text).toContain("dg verify npm:react");
  });

  it("licenses --help documents --fail-on and --csv", async () => {
    const text = await help("licenses");
    expect(text).toContain("--fail-on");
    expect(text).toContain("--csv");
  });

  it("login --help documents --token", async () => {
    const text = await help("login");
    expect(text).toContain("--token");
  });

  it("scan --help documents --staged and --output", async () => {
    const text = await help("scan");
    expect(text).toContain("--staged");
    expect(text).toContain("--output");
  });

  it("guard-commit --help documents --check and an example", async () => {
    const text = await help("guard-commit");
    expect(text).toContain("--check");
    expect(text).toContain("dg guard-commit");
  });

  it("a package-manager wrapper documents --dg-force-install", async () => {
    expect(await help("npm")).toContain("--dg-force-install");
  });

  it("every command help ends with the global-flags footer", () => {
    for (const command of commandCatalog) {
      expect(renderCommandHelp(command)).toContain("Global:");
    }
  });

  it("root --help and --help-all point at per-command help and globals", async () => {
    const root = (await runCli(["--help"])).stdout;
    expect(root).toContain("Global:");
    expect(root).toContain("--help-all");
    expect((await runCli(["--help-all"])).stdout).toContain("Global:");
  });
});
