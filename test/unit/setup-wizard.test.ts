import React from "react";
import { Text, useInput } from "ink";
import { render } from "ink-testing-library";
import { describe, expect, it, vi } from "vitest";
import { protectsSentence, SetupWizardApp, type LoginFlowProps, type SetupWizardProps } from "../../src/setup-ui/wizard.js";
import type { WizardTask } from "../../src/setup-ui/tasks.js";

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

// Poll the rendered frame instead of asserting after a fixed sleep: an async
// task -> state update -> re-render can outlast a constant delay under CI load.
async function waitForFrame(view: { lastFrame: () => string | undefined }, needle: string, timeoutMs = 3000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  let frame = view.lastFrame() ?? "";
  while (!frame.includes(needle) && Date.now() < deadline) {
    await sleep(20);
    frame = view.lastFrame() ?? "";
  }
  return frame;
}

function fakeTask(label: string, result: { ok?: boolean; fatal?: boolean; detail?: string } = {}): WizardTask {
  return {
    label,
    run: vi.fn(async () => ({ ok: result.ok ?? true, fatal: result.fatal, detail: result.detail }))
  };
}

const FakeLoginFlow: React.FC<LoginFlowProps> = ({ onDone }) => {
  useInput((_input, key) => {
    if (key.return) {
      onDone("user@example.com");
    }
  });
  return React.createElement(Text, null, "Login successful. Press Enter to continue…");
};

function makeProps(overrides: Partial<SetupWizardProps> = {}): SetupWizardProps {
  return {
    version: "9.9.9",
    notesNeeded: true,
    loginNeeded: false,
    authedEmail: "",
    sentence: protectsSentence([]),
    guardsRepo: false,
    tasks: [],
    webBase: "https://example.test",
    env: {},
    activateHint: "source ~/.zshrc && rehash",
    skips: [],
    onNotesAgreed: vi.fn(),
    onLoginSkipped: vi.fn(),
    onOutcome: vi.fn(),
    ...overrides
  };
}

function renderWizard(props: SetupWizardProps) {
  return render(React.createElement(SetupWizardApp, props));
}

describe("protectsSentence", () => {
  it("adapts to detected agents without listing write paths", () => {
    expect(protectsSentence([])).toBe("Protects npm and pip installs in your shell.");
    expect(protectsSentence(["Claude Code"])).toBe("Protects npm and pip installs in your shell and in Claude Code.");
    expect(protectsSentence(["Claude Code", "Cursor"])).toBe("Protects npm and pip installs in your shell and in Claude Code and Cursor.");
  });
});

describe("SetupWizardApp", () => {
  it("shows the logo header with the version on every screen", async () => {
    const view = renderWizard(makeProps());
    await sleep(30);
    const frame = view.lastFrame() ?? "";
    view.unmount();
    expect(frame).toContain("Dependency Guardian v9.9.9");
  });

  it("starts at the login step when unauthenticated and skips it with one keypress", async () => {
    const props = makeProps({ loginNeeded: true });
    const view = renderWizard(props);
    await sleep(30);
    expect(view.lastFrame()).toContain("Connect your account");
    expect(view.lastFrame()).toContain("1. Connect in your browser");
    expect(view.lastFrame()).toContain("2. Skip for now");

    view.stdin.write("2");
    await sleep(30);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(props.onLoginSkipped).toHaveBeenCalled();
    expect(frame).toContain("Security notes");
  });

  it("runs the injected login flow and carries the email into the done summary", async () => {
    const props = makeProps({ loginNeeded: true, notesNeeded: false, LoginFlowComponent: FakeLoginFlow });
    const view = renderWizard(props);
    await sleep(30);

    view.stdin.write("1");
    await sleep(30);
    expect(view.lastFrame()).toContain("Login successful. Press Enter to continue…");

    view.stdin.write("\r");
    await sleep(30);
    expect(view.lastFrame()).toContain("Use recommended settings?");

    view.stdin.write("1");
    await sleep(80);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(frame).toContain("✓ Setup complete.");
    expect(frame).toContain("Logged in as user@example.com");
    expect(props.onLoginSkipped).not.toHaveBeenCalled();
  });

  it("skips the login step entirely when already authenticated", async () => {
    const view = renderWizard(makeProps({ loginNeeded: false }));
    await sleep(30);
    const frame = view.lastFrame() ?? "";
    view.unmount();
    expect(frame).not.toContain("Connect your account");
    expect(frame).toContain("Security notes");
  });

  it("shows the security notes with TOS links and advances on Enter", async () => {
    const props = makeProps();
    const view = renderWizard(props);
    await sleep(30);
    const notesFrame = view.lastFrame() ?? "";
    expect(notesFrame).toContain("dg can make mistakes.");
    expect(notesFrame).toContain("Terms of Service");
    expect(notesFrame).toContain("Privacy Policy");
    expect(notesFrame).toContain("]8;;https://example.test/terms");
    expect(notesFrame).toContain("]8;;https://example.test/privacy");
    expect(notesFrame).toContain("Press Enter to agree");

    view.stdin.write("\r");
    await sleep(30);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(props.onNotesAgreed).toHaveBeenCalled();
    expect(frame).toContain("Use recommended settings?");
    expect(frame).not.toContain("writes ~/");
  });

  it("shows the repo commit-guard line when run inside an unguarded repo", async () => {
    const withRepo = renderWizard(makeProps({ notesNeeded: false, guardsRepo: true }));
    await sleep(30);
    const repoFrame = withRepo.lastFrame() ?? "";
    withRepo.unmount();
    expect(repoFrame).toContain("Also scans this repo's commits before they land.");

    const withoutRepo = renderWizard(makeProps({ notesNeeded: false, guardsRepo: false }));
    await sleep(30);
    const bareFrame = withoutRepo.lastFrame() ?? "";
    withoutRepo.unmount();
    expect(bareFrame).not.toContain("Also scans this repo's commits");
  });

  it("lists detected agents that were skipped by their support probe", async () => {
    const view = renderWizard(
      makeProps({ notesNeeded: false, skips: [{ label: "Codex CLI", detail: "Codex CLI 0.118.0 is older than 0.124.0, which added the hook dg needs" }] })
    );
    await sleep(30);
    const frame = view.lastFrame() ?? "";
    view.unmount();
    expect(frame).toContain("Codex CLI found but skipped");
    expect(frame).toContain("older than 0.124.0");
  });

  it("skips the notes when already shown", async () => {
    const view = renderWizard(makeProps({ notesNeeded: false }));
    await sleep(30);
    const frame = view.lastFrame() ?? "";
    view.unmount();
    expect(frame).not.toContain("Security notes");
    expect(frame).toContain("Use recommended settings?");
  });

  it("declines with 'No, maybe later' without running any tasks", async () => {
    const task = fakeTask("shell installs route through dg");
    const props = makeProps({ notesNeeded: false, tasks: [task] });
    const view = renderWizard(props);
    await sleep(30);

    view.stdin.write("2");
    await sleep(30);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(props.onOutcome).toHaveBeenCalledWith({ kind: "declined" });
    expect(task.run).not.toHaveBeenCalled();
    expect(frame).toContain("Run dg setup any time to turn this on.");
  });

  it("applies tasks, streams results, and finishes with the activation hint", async () => {
    const shellTask = fakeTask("shell installs route through dg");
    const agentTask = fakeTask("Claude Code installs route through dg");
    const props = makeProps({ notesNeeded: false, tasks: [shellTask, agentTask] });
    const view = renderWizard(props);
    await sleep(30);

    view.stdin.write("1");
    await sleep(80);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(shellTask.run).toHaveBeenCalled();
    expect(agentTask.run).toHaveBeenCalled();
    expect(frame).toContain("✓ shell installs route through dg");
    expect(frame).toContain("✓ Claude Code installs route through dg");
    expect(frame).toContain("✓ Setup complete.");
    expect(frame).toContain("source ~/.zshrc && rehash");
    expect(frame).toContain("Press Enter to continue…");
    expect(props.onOutcome).toHaveBeenCalledWith(expect.objectContaining({ kind: "done", email: "" }));
    const outcome = (props.onOutcome as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as { results: { label: string; ok: boolean }[] };
    expect(outcome.results.map((line) => line.label)).toEqual(["shell installs route through dg", "Claude Code installs route through dg"]);
  });

  it("stops on a fatal task with exit code 1", async () => {
    const lockTask = fakeTask("shell installs route through dg", { ok: false, fatal: true, detail: "another setup is running" });
    const agentTask = fakeTask("Claude Code installs route through dg");
    const props = makeProps({ notesNeeded: false, tasks: [lockTask, agentTask] });
    const view = renderWizard(props);
    await sleep(30);

    view.stdin.write("1");
    const frame = await waitForFrame(view, "another setup is running");
    view.unmount();

    expect(props.onOutcome).toHaveBeenCalledWith({ kind: "fatal", detail: "another setup is running" });
    expect(agentTask.run).not.toHaveBeenCalled();
    expect(frame).toContain("another setup is running");
  });

  it("keeps going when an agent task fails non-fatally", async () => {
    const shellTask = fakeTask("shell installs route through dg");
    const agentTask = fakeTask("Cursor installs route through dg", { ok: false, detail: "settings file is read-only" });
    const props = makeProps({ notesNeeded: false, tasks: [shellTask, agentTask] });
    const view = renderWizard(props);
    await sleep(30);

    view.stdin.write("1");
    await sleep(80);
    const frame = view.lastFrame() ?? "";
    view.unmount();

    expect(frame).toContain("✗ Cursor installs route through dg — settings file is read-only");
    expect(frame).toContain("✓ Setup complete.");
    expect(props.onOutcome).toHaveBeenCalledWith(expect.objectContaining({ kind: "done", email: "" }));
  });
});
