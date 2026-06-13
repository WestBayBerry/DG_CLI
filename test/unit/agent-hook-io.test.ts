import { describe, it, expect, vi, beforeEach } from "vitest";

const checkMock = vi.fn();
vi.mock("../../src/launcher/agent-check.js", () => ({
  agentCheckCommand: (...a: unknown[]) => checkMock(...a),
}));

import { runAgentHookExec } from "../../src/launcher/agent-hook-io.js";

beforeEach(() => checkMock.mockReset());

describe("runAgentHookExec (claude-code)", () => {
  it("emits a deny decision for a blocked install and surfaces the reason", async () => {
    checkMock.mockResolvedValue({ decision: "deny", reason: "DG blocked install — evil@1 (block: malware)" });
    const r = await runAgentHookExec(
      "claude-code",
      JSON.stringify({ tool_input: { command: "npm install evil@1" }, cwd: "/repo" }),
    );
    const out = JSON.parse(r.stdout);
    expect(out.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain("evil@1");
    expect(out.hookSpecificOutput.hookEventName).toBe("PreToolUse");
    expect(r.exitCode).toBe(0);
    expect(r.stderr).toContain("evil@1");
    expect(checkMock).toHaveBeenCalledWith(expect.objectContaining({ commandLine: "npm install evil@1", cwd: "/repo" }));
  });

  it("stays silent ({}) on allow so normal permissions apply", async () => {
    checkMock.mockResolvedValue({ decision: "allow" });
    const r = await runAgentHookExec("claude-code", JSON.stringify({ tool_input: { command: "npm ls" } }));
    expect(r.stdout).toBe("{}");
    expect(r.stderr).toBe("");
  });

  it("emits ask for a flagged warn", async () => {
    checkMock.mockResolvedValue({ decision: "ask", reason: "DG flagged for review" });
    const r = await runAgentHookExec("claude-code", JSON.stringify({ tool_input: { command: "npm install sketchy" } }));
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("ask");
  });

  it("fails CLOSED (deny) on malformed stdin without calling the checker", async () => {
    const r = await runAgentHookExec("claude-code", "not json");
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
    expect(checkMock).not.toHaveBeenCalled();
  });

  it("fails CLOSED when tool_input.command is missing", async () => {
    const r = await runAgentHookExec("claude-code", JSON.stringify({ tool_input: {} }));
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
    expect(checkMock).not.toHaveBeenCalled();
  });

});
