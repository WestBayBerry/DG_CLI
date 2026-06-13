import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { toolInvocation } from "../util/external-tool.js";
import { noExecPackEnv } from "./no-exec-shell.js";

export interface PackedArtifact {
  readonly bytes: Buffer;
  readonly sha256: string;
}

export function packNpmArtifact(root: string, env: NodeJS.ProcessEnv = process.env): PackedArtifact | { error: string } {
  const dest = mkdtempSync(join(tmpdir(), "dg-audit-pack-"));
  const invocation = toolInvocation("npm", ["pack", "--ignore-scripts", "--pack-destination", dest], env);
  if (!invocation) {
    rmSync(dest, { recursive: true, force: true });
    return { error: "npm executable not found on PATH" };
  }
  const shell = noExecPackEnv(env);
  try {
    const result = spawnSync(invocation.command, [...invocation.args], {
      cwd: root,
      env: shell.env,
      encoding: "utf8",
      timeout: 120_000,
      maxBuffer: 8 * 1024 * 1024,
      windowsVerbatimArguments: invocation.windowsVerbatimArguments
    });
    if (result.status !== 0) {
      return { error: result.stderr ? result.stderr.trim().split("\n").pop() ?? "npm pack failed" : "npm pack failed" };
    }
    const tgz = readdirSync(dest).find((name) => name.endsWith(".tgz"));
    if (!tgz) {
      return { error: "npm pack produced no tarball" };
    }
    const bytes = readFileSync(join(dest, tgz));
    return { bytes, sha256: createHash("sha256").update(bytes).digest("hex") };
  } catch (error) {
    return { error: error instanceof Error ? error.message : "pack failed" };
  } finally {
    shell.cleanup();
    rmSync(dest, { recursive: true, force: true });
  }
}
