import { describe, expect, it, vi } from "vitest";

let throwMode = false;
vi.mock("../../src/launcher/agent-check.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/launcher/agent-check.js")>();
  return {
    ...actual,
    agentCheckCommand: (): Promise<{ decision: string }> => {
      if (throwMode) {
        // Synchronous throw (no rejected promise) models a verdict-engine
        // failure such as an I/O error reading dg.json, and is what the
        // try/catch in runAgentHookExec must turn into a block.
        throw new Error("simulated verdict-engine failure");
      }
      return Promise.resolve({ decision: "allow" });
    },
  };
});

import { runAgentHookExec } from "../../src/launcher/agent-hook-io.js";

describe("runAgentHookExec fails closed when the verdict engine throws", () => {
  it("denies on claude-code rather than allowing the install", async () => {
    throwMode = true;
    const r = await runAgentHookExec("claude-code", JSON.stringify({ tool_input: { command: "npm install evil" } }));
    throwMode = false;
    expect(r.stdout).not.toBe("{}");
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
  });

  it("blocks in every agent's native shape on a verdict throw", async () => {
    throwMode = true;
    const codex = await runAgentHookExec("codex", JSON.stringify({ tool_input: { command: "npm install evil" } }));
    expect(JSON.parse(codex.stdout).decision).toBe("block");

    const windsurf = await runAgentHookExec("windsurf", JSON.stringify({ tool_info: { command_line: "npm install evil" } }));
    expect(windsurf.exitCode).toBe(2);

    const cursor = await runAgentHookExec("cursor", JSON.stringify({ command: "npm install evil" }));
    expect(JSON.parse(cursor.stdout).permission).toBe("deny");

    const gemini = await runAgentHookExec("gemini", JSON.stringify({ tool_args: { command: "npm install evil" } }));
    expect(JSON.parse(gemini.stdout).decision).toBe("block");

    const copilot = await runAgentHookExec("copilot-cli", JSON.stringify({ toolArgs: { command: "npm install evil" } }));
    expect(JSON.parse(copilot.stdout).permissionDecision).toBe("deny");
    throwMode = false;
  });

  it("allows a passthrough when the engine returns allow", async () => {
    const r = await runAgentHookExec("claude-code", JSON.stringify({ tool_input: { command: "npm ls" } }));
    expect(r.stdout).toBe("{}");
  });
});
