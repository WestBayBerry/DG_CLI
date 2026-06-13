import { describe, expect, it } from "vitest";
import { maybeAgentHookExec } from "../../src/launcher/agent-hook-exec.js";

describe("maybeAgentHookExec dispatch", () => {
  it("ignores non hook-exec invocations", async () => {
    const r = await maybeAgentHookExec(["scan"]);
    expect(r.handled).toBe(false);
  });

  it("fails CLOSED for an unknown agent: non-zero exit, no allow JSON", async () => {
    const r = await maybeAgentHookExec(["hook-exec", "made-up-agent"]);
    expect(r.handled).toBe(true);
    expect(r.result.exitCode).toBe(2);
    expect(r.result.stdout).toBe("");
    expect(r.result.stdout).not.toBe("{}");
    expect(r.result.stderr).toContain("unknown agent");
    expect(r.result.stderr).toContain("blocked");
  });

  it("fails CLOSED for a missing agent id", async () => {
    const r = await maybeAgentHookExec(["hook-exec"]);
    expect(r.handled).toBe(true);
    expect(r.result.exitCode).toBe(2);
    expect(r.result.stdout).toBe("");
  });

  it("fails CLOSED when stdin cannot be read: emits a deny decision, never empty stdout", async () => {
    const throwingStdin = {
      isTTY: false,
      [Symbol.asyncIterator]() {
        return { next: () => Promise.reject(new Error("pipe reset")) };
      },
    } as unknown as NodeJS.ReadStream;
    const r = await maybeAgentHookExec(["hook-exec", "claude-code"], { stdin: throwingStdin });
    expect(r.handled).toBe(true);
    expect(r.result.stdout).not.toBe("");
    expect(r.result.stderr).toContain("stdin");
  });
});
