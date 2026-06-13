import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { consentSurfaces, renderConsentScreen, type ConsentSurface } from "../../src/commands/setup.js";
import { buildSetupPlan } from "../../src/setup/plan.js";
import { collectAgentOffers } from "../../src/agents/registry.js";
import { createTheme } from "../../src/presentation/theme.js";

describe("setup consent screen", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-consent-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("orders surfaces shell first, agents next, deferred commit line last", () => {
    const plan = buildSetupPlan({ shell: "zsh", env: { HOME: home } });
    mkdirSync(join(home, ".claude"), { recursive: true });
    const agents = collectAgentOffers({ home, env: { HOME: home } });
    const surfaces = consentSurfaces(plan, agents, true);
    expect(surfaces.map((surface) => surface.label)).toEqual([
      "shell installs",
      "Claude Code installs",
      "commits in this repo"
    ]);
    expect(surfaces[0]?.detail).toContain(".zshrc");
    expect(surfaces[1]?.detail).toContain("settings.json");
    expect(surfaces[2]).toMatchObject({ detail: "asked separately", deferred: true });
  });

  it("lists only the shell surface outside a repo with no agents", () => {
    const plan = buildSetupPlan({ shell: "zsh", env: { HOME: home } });
    const surfaces = consentSurfaces(plan, [], false);
    expect(surfaces).toHaveLength(1);
    expect(surfaces[0]?.label).toBe("shell installs");
  });

  it("renders aligned labels and every target path before consent", () => {
    const theme = createTheme(false);
    const surfaces: ConsentSurface[] = [
      { label: "shell installs", detail: "writes ~/.zshrc", deferred: false },
      { label: "Claude Code installs", detail: "writes ~/.claude/settings.json", deferred: false },
      { label: "Cursor installs", detail: "writes ~/.cursor/hooks.json", deferred: false },
      { label: "commits in this repo", detail: "asked separately", deferred: true }
    ];
    const screen = renderConsentScreen(surfaces, theme);
    expect(screen).toContain("Sets up:");
    expect(screen).toContain("shell installs        writes ~/.zshrc");
    expect(screen).toContain("Claude Code installs  writes ~/.claude/settings.json");
    expect(screen).toContain("Cursor installs       writes ~/.cursor/hooks.json");
    expect(screen).toContain("commits in this repo  asked separately");
    expect(screen).toContain("Reversible with dg uninstall");
    expect(screen).toContain("no dg prefix");
  });
});
