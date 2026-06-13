import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  markSecurityNotesShown,
  markWizardSkipped,
  securityNotesMarkerPath,
  securityNotesShown,
  setupApplied,
  shouldOfferSetupWizard,
  wizardSkippedMarkerPath
} from "../../src/setup-ui/gate.js";

const tty = { isTTY: true };
const noTty = { isTTY: false };

async function tempHome(): Promise<string> {
  return mkdtemp(join(tmpdir(), "dg-wizard-gate-"));
}

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

describe("shouldOfferSetupWizard", () => {
  it("offers the wizard on a fresh interactive machine", async () => {
    const home = await tempHome();
    expect(shouldOfferSetupWizard({ HOME: home }, tty, tty)).toBe(true);
  });

  it("declines without a TTY on stdin or stderr", async () => {
    const home = await tempHome();
    expect(shouldOfferSetupWizard({ HOME: home }, noTty, tty)).toBe(false);
    expect(shouldOfferSetupWizard({ HOME: home }, tty, noTty)).toBe(false);
  });

  it("declines in CI", async () => {
    const home = await tempHome();
    expect(shouldOfferSetupWizard({ HOME: home, CI: "1" }, tty, tty)).toBe(false);
  });

  it("declines on win32", async () => {
    const home = await tempHome();
    expect(withPlatform("win32", () => shouldOfferSetupWizard({ HOME: home }, tty, tty))).toBe(false);
  });

  it("declines once the npm shim exists", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".dg", "shims"), { recursive: true });
    await writeFile(join(home, ".dg", "shims", "npm"), "#!/bin/sh\n");
    expect(setupApplied({ HOME: home })).toBe(true);
    expect(shouldOfferSetupWizard({ HOME: home }, tty, tty)).toBe(false);
  });

  it("declines after the wizard was explicitly skipped", async () => {
    const home = await tempHome();
    markWizardSkipped({ HOME: home });
    expect(existsSync(wizardSkippedMarkerPath({ HOME: home }))).toBe(true);
    expect(shouldOfferSetupWizard({ HOME: home }, tty, tty)).toBe(false);
  });
});

describe("security notes marker", () => {
  it("records and reports the notes as shown", async () => {
    const home = await tempHome();
    expect(securityNotesShown({ HOME: home })).toBe(false);
    markSecurityNotesShown({ HOME: home });
    expect(securityNotesShown({ HOME: home })).toBe(true);
    expect(existsSync(securityNotesMarkerPath({ HOME: home }))).toBe(true);
  });
});
