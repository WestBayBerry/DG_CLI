import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { maybeOfferSetupWizard, type WizardOfferOptions } from "../../src/setup-ui/offer.js";

const tty = { isTTY: true };
const noTty = { isTTY: false };

async function tempHome(): Promise<string> {
  return mkdtemp(join(tmpdir(), "dg-wizard-offer-"));
}

function options(home: string, overrides: Partial<WizardOfferOptions> = {}): WizardOfferOptions & { runWizard: ReturnType<typeof vi.fn> } {
  const runWizard = vi.fn(async () => ({ exitCode: 0, stdout: "", stderr: "" }));
  return {
    env: { HOME: home, SHELL: "/bin/zsh" },
    stdin: tty,
    stderr: tty,
    richMode: true,
    runWizard,
    ...overrides,
    ...(overrides.runWizard ? {} : { runWizard })
  };
}

describe("maybeOfferSetupWizard", () => {
  it("handles bare dg entirely once the wizard ran", async () => {
    const home = await tempHome();
    const opts = options(home);
    const outcome = await maybeOfferSetupWizard([], opts);
    expect(opts.runWizard).toHaveBeenCalledOnce();
    expect(outcome.handled).toBe(true);
  });

  it("runs the wizard first but lets a real command continue", async () => {
    const home = await tempHome();
    const opts = options(home);
    const outcome = await maybeOfferSetupWizard(["scan"], opts);
    expect(opts.runWizard).toHaveBeenCalledOnce();
    expect(outcome.handled).toBe(false);
  });

  it("never triggers for administrative commands", async () => {
    const home = await tempHome();
    for (const command of ["setup", "login", "logout", "uninstall", "update", "upgrade", "--help", "help", "--version", "version"]) {
      const opts = options(home);
      const outcome = await maybeOfferSetupWizard([command], opts);
      expect(opts.runWizard, command).not.toHaveBeenCalled();
      expect(outcome.handled).toBe(false);
    }
  });

  it("never triggers with machine-output flags", async () => {
    const home = await tempHome();
    const opts = options(home);
    await maybeOfferSetupWizard(["scan", "--json"], opts);
    expect(opts.runWizard).not.toHaveBeenCalled();
  });

  it("never triggers without a TTY or in plain mode", async () => {
    const home = await tempHome();
    const piped = options(home, { stdin: noTty });
    await maybeOfferSetupWizard(["scan"], piped);
    expect(piped.runWizard).not.toHaveBeenCalled();

    const plain = options(home, { richMode: false });
    await maybeOfferSetupWizard(["scan"], plain);
    expect(plain.runWizard).not.toHaveBeenCalled();
  });
});
