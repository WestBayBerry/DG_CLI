import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const hoisted = vi.hoisted(() => ({
  calls: [] as string[],
  renderedProps: [] as Array<Record<string, unknown>>,
  policyMode: "warn" as string
}));

vi.mock("ink", () => ({
  render: (element: { props: Record<string, unknown> }) => {
    hoisted.calls.push("render");
    hoisted.renderedProps.push(element.props);
    return { waitUntilExit: () => Promise.resolve() };
  }
}));

vi.mock("../../src/scan-ui/alt-screen.js", () => ({
  enterTui: () => {
    hoisted.calls.push("enterTui");
  },
  leaveTui: () => {
    hoisted.calls.push("leaveTui");
  },
  showCursor: () => undefined,
  tuiIsActive: () => false
}));

vi.mock("../../src/config/settings.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/config/settings.js")>();
  return {
    ...actual,
    loadUserConfig: () => ({
      ...actual.DEFAULT_CONFIG,
      policy: { ...actual.DEFAULT_CONFIG.policy, mode: hoisted.policyMode as "off" | "warn" | "block" | "strict" }
    })
  };
});

import { launchScanTui, shouldLaunchScanTui } from "../../src/scan-ui/launch.js";
import { shouldLaunchSbomTui } from "../../src/sbom-ui/launch.js";
import { shouldLaunchAuditTui } from "../../src/audit-ui/launch.js";
import { dgVersion } from "../../src/commands/version.js";

const tempRoots: string[] = [];

async function tempHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-launch-"));
  tempRoots.push(root);
  return root;
}

async function writeNudgeState(home: string, state: Record<string, unknown>): Promise<void> {
  const stateDir = join(home, ".dg", "state");
  await mkdir(stateDir, { recursive: true });
  await writeFile(join(stateDir, "nudges.json"), `${JSON.stringify(state)}\n`, "utf8");
}

describe("launchScanTui", () => {
  let previousHome: string | undefined;

  beforeEach(async () => {
    hoisted.calls.length = 0;
    hoisted.renderedProps.length = 0;
    hoisted.policyMode = "warn";
    previousHome = process.env.HOME;
    process.env.HOME = await tempHome();
  });

  afterEach(async () => {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
  });

  it("enters the alt screen before the first ink render and leaves it after exit", async () => {
    await launchScanTui();

    expect(hoisted.calls).toEqual(["enterTui", "render", "leaveTui"]);
  });

  it("passes every policy mode through unchanged, including strict", async () => {
    for (const mode of ["off", "warn", "block", "strict"]) {
      hoisted.policyMode = mode;
      hoisted.renderedProps.length = 0;
      await launchScanTui();
      expect(hoisted.renderedProps[0]?.config).toEqual({ mode });
    }
  });

  it("passes the stored update as the updateAvailable prop without any lookup", async () => {
    await writeNudgeState(process.env.HOME as string, { updateLatest: "99.0.0" });

    await launchScanTui();

    expect(hoisted.renderedProps[0]?.updateAvailable).toBe(
      `Update available: ${dgVersion()} → 99.0.0 · run dg update`
    );
  });

  it("omits updateAvailable when the stored latest is not newer", async () => {
    await writeNudgeState(process.env.HOME as string, { updateLatest: dgVersion() });

    await launchScanTui();

    expect(hoisted.renderedProps[0]?.updateAvailable).toBeUndefined();
  });

  it("restores a falsy CI env var after the session instead of deleting it", async () => {
    const previousCi = process.env.CI;
    try {
      for (const value of ["", "0", "false"]) {
        process.env.CI = value;
        await launchScanTui();
        expect(process.env.CI).toBe(value);
      }
      delete process.env.CI;
      await launchScanTui();
      expect(process.env.CI).toBeUndefined();
    } finally {
      if (previousCi === undefined) delete process.env.CI;
      else process.env.CI = previousCi;
    }
  });
});

describe("TUI launch gates", () => {
  const ciVars = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "TRAVIS", "TEAMCITY_VERSION"];
  let stdoutTtyDescriptor: PropertyDescriptor | undefined;
  let stdinTtyDescriptor: PropertyDescriptor | undefined;
  let previousTerm: string | undefined;
  let previousCiVars: Record<string, string | undefined>;

  function setStdinTty(value: boolean): void {
    Object.defineProperty(process.stdin, "isTTY", { value, configurable: true });
  }

  beforeEach(() => {
    stdoutTtyDescriptor = Object.getOwnPropertyDescriptor(process.stdout, "isTTY");
    stdinTtyDescriptor = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
    Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });
    setStdinTty(true);
    previousTerm = process.env.TERM;
    previousCiVars = Object.fromEntries(ciVars.map((name) => [name, process.env[name]]));
    for (const name of ciVars) delete process.env[name];
    process.env.TERM = "xterm-256color";
  });

  afterEach(() => {
    if (stdoutTtyDescriptor) Object.defineProperty(process.stdout, "isTTY", stdoutTtyDescriptor);
    else delete (process.stdout as { isTTY?: boolean }).isTTY;
    if (stdinTtyDescriptor) Object.defineProperty(process.stdin, "isTTY", stdinTtyDescriptor);
    else delete (process.stdin as { isTTY?: boolean }).isTTY;
    if (previousTerm === undefined) delete process.env.TERM;
    else process.env.TERM = previousTerm;
    for (const name of ciVars) {
      if (previousCiVars[name] === undefined) delete process.env[name];
      else process.env[name] = previousCiVars[name];
    }
  });

  it("launches on a rich TTY", () => {
    expect(shouldLaunchScanTui({ targetPath: ".", format: "text" })).toBe(true);
    expect(shouldLaunchSbomTui({ json: false, outputPath: null })).toBe(true);
    expect(shouldLaunchAuditTui({ format: "text", outputPath: null })).toBe(true);
  });

  it("falls back to the plain renderer when TERM=dumb", () => {
    process.env.TERM = "dumb";
    expect(shouldLaunchScanTui({ targetPath: ".", format: "text" })).toBe(false);
    expect(shouldLaunchSbomTui({ json: false, outputPath: null })).toBe(false);
    expect(shouldLaunchAuditTui({ format: "text", outputPath: null })).toBe(false);
  });

  it("falls back to the plain renderer when stdin is not a TTY", () => {
    setStdinTty(false);
    expect(shouldLaunchScanTui({ targetPath: ".", format: "text" })).toBe(false);
    expect(shouldLaunchSbomTui({ json: false, outputPath: null })).toBe(false);
    expect(shouldLaunchAuditTui({ format: "text", outputPath: null })).toBe(false);
  });
});
