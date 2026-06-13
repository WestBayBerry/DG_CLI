import { join } from "node:path";
import { runAgentHookExec } from "./agent-hook-io.js";
import { getAgent, isAgentId } from "../agents/registry.js";
import { resolveDgPaths } from "../state/index.js";
import { writeJsonAtomic } from "../util/json-file.js";
import type { CommandResult } from "../commands/types.js";

async function readStdin(stream: NodeJS.ReadStream = process.stdin): Promise<string> {
  if (stream.isTTY) {
    return "";
  }
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function recordFixture(agent: string, stdin: string): string {
  const path = join(resolveDgPaths().stateDir, "fixtures", `${agent}-${Date.now()}.json`);
  writeJsonAtomic(path, { agent, capturedAt: new Date().toISOString(), stdin });
  return path;
}

// Short-circuited before any banner/nudge so stdout carries only the decision
// JSON the agent parses.
export async function maybeAgentHookExec(
  args: readonly string[],
  opts: { readonly stdin?: NodeJS.ReadStream } = {},
): Promise<{ handled: boolean; result: CommandResult }> {
  const noop: CommandResult = { exitCode: 0, stdout: "", stderr: "" };
  if (args[0] !== "hook-exec") {
    return { handled: false, result: noop };
  }
  const agent = args[1];
  if (!agent || !isAgentId(agent)) {
    // Unknown agent (e.g. a hook written by a newer dg, run by an older one):
    // fail closed. We can't emit this agent's allow shape, and a non-zero exit
    // with no decision blocks across the agents we support, so an out-of-date
    // dg refuses the install with a clear message rather than waving it through.
    return {
      handled: true,
      result: {
        exitCode: 2,
        stdout: "",
        stderr: `dg hook-exec: unknown agent '${agent ?? ""}' — blocked under the firewall; update dg (npm i -g @westbayberry/dg) or run 'dg agents off'\n`
      }
    };
  }
  let stdin: string;
  try {
    stdin = await readStdin(opts.stdin);
  } catch {
    // A stdin stream error must not escape to the fatal handler (exit 70 with
    // empty stdout reads as allow to every agent). Emit this agent's deny shape.
    const emitted = getAgent(agent).emitDecision({
      decision: "deny",
      reason: "dg hook: could not read the tool payload from stdin; blocked under the firewall",
    });
    return {
      handled: true,
      result: { exitCode: emitted.exitCode || 2, stdout: emitted.stdout, stderr: "dg hook: stdin read error\n" },
    };
  }
  let fixtureNote = "";
  if (args[2] === "--record-fixture") {
    try {
      fixtureNote = `dg hook-exec: recorded fixture ${recordFixture(agent, stdin)}\n`;
    } catch {
      fixtureNote = "dg hook-exec: could not record the fixture\n";
    }
  }
  const result = await runAgentHookExec(agent, stdin);
  return { handled: true, result: { exitCode: result.exitCode, stdout: result.stdout, stderr: `${fixtureNote}${result.stderr}` } };
}
