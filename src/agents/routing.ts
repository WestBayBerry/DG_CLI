import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { buildAgentRoutingEnv } from "../launcher/env.js";
import { readServiceState } from "../service/state.js";
import { resolveDgPaths, type DgPathEnvironment } from "../state/index.js";
import { readSettings, writeSettingsAtomic, type Json } from "./persistence.js";
import { getAgent } from "./registry.js";
import type { AgentId } from "./types.js";

// The agent's install hook screens statically; this routes the agent's ACTUAL
// fetches through dg's proxy so a wrapped/dynamic install (eval, $VAR, python -m
// pip, …) the static hook can't decode is still screened at fetch time. Only
// applied when `dg service` is running, so the proxy endpoint baked into the
// agent's env is always live — never a dead HTTPS_PROXY that breaks installs.

const CODEX_BEGIN = "# >>> dg routing >>>";
const CODEX_END = "# <<< dg routing <<<";

export interface RoutingResult {
  readonly applied: boolean;
  readonly detail: string;
}

function backupPath(agent: AgentId, env: DgPathEnvironment): string {
  return join(resolveDgPaths(env).stateDir, `routing-${agent}.json`);
}

export function resolveServiceRoutingEnv(
  env: DgPathEnvironment = process.env,
): { readonly env: Record<string, string>; readonly proxyUrl: string } | { readonly error: string } {
  const { state } = readServiceState(env as NodeJS.ProcessEnv);
  if (!state.running || !state.proxy) {
    return { error: "dg service is not running — run 'dg service start' so the proxy gate is live before routing agents through it" };
  }
  return { env: buildAgentRoutingEnv(state.proxy.proxyUrl, state.proxy.caPath), proxyUrl: state.proxy.proxyUrl };
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stripCodexBlock(content: string): string {
  const block = new RegExp(`\\n?${escapeRegex(CODEX_BEGIN)}[\\s\\S]*?${escapeRegex(CODEX_END)}\\n?`, "g");
  return content.replace(block, "\n").replace(/\n{3,}/g, "\n\n");
}

function applyClaudeRouting(settingsPath: string, routing: Record<string, string>, backup: string): void {
  const { settings } = readSettings(settingsPath);
  const envObj: Json = typeof settings.env === "object" && settings.env !== null ? { ...(settings.env as Json) } : {};
  const prior: Record<string, string | null> = {};
  for (const [k, v] of Object.entries(routing)) {
    prior[k] = k in envObj ? String(envObj[k]) : null;
    envObj[k] = v;
  }
  settings.env = envObj;
  writeSettingsAtomic(settingsPath, settings);
  mkdirSync(dirname(backup), { recursive: true, mode: 0o700 });
  writeFileSync(backup, `${JSON.stringify({ kind: "claude-env", path: settingsPath, prior }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

function removeClaudeRouting(settingsPath: string, backup: string): void {
  if (!existsSync(backup)) {
    return;
  }
  let prior: Record<string, string | null> = {};
  try {
    prior = (JSON.parse(readFileSync(backup, "utf8")) as { prior?: Record<string, string | null> }).prior ?? {};
  } catch {
    prior = {};
  }
  if (existsSync(settingsPath)) {
    const { settings } = readSettings(settingsPath);
    const envObj: Json = typeof settings.env === "object" && settings.env !== null ? { ...(settings.env as Json) } : {};
    for (const [k, v] of Object.entries(prior)) {
      if (v === null) {
        delete envObj[k];
      } else {
        envObj[k] = v;
      }
    }
    if (Object.keys(envObj).length === 0) {
      delete settings.env;
    } else {
      settings.env = envObj;
    }
    writeSettingsAtomic(settingsPath, settings);
  }
  rmSync(backup, { force: true });
}

function applyCodexRouting(configPath: string, routing: Record<string, string>): RoutingResult {
  const content = existsSync(configPath) ? stripCodexBlock(readFileSync(configPath, "utf8")) : "";
  if (/^\s*\[shell_environment_policy\]/m.test(content)) {
    return { applied: false, detail: "~/.codex/config.toml already defines [shell_environment_policy] — add dg's proxy vars (HTTPS_PROXY, NODE_EXTRA_CA_CERTS, …) to its `set` table manually" };
  }
  const set = Object.entries(routing).map(([k, v]) => `${k} = ${JSON.stringify(v)}`).join(", ");
  const block = `${CODEX_BEGIN}\n[shell_environment_policy]\nset = { ${set} }\n${CODEX_END}\n`;
  const next = content === "" || content.endsWith("\n") ? `${content}${block}` : `${content}\n${block}`;
  writeFileSync(configPath, next, { encoding: "utf8", mode: 0o600 });
  return { applied: true, detail: configPath };
}

function removeCodexRouting(configPath: string): void {
  if (!existsSync(configPath)) {
    return;
  }
  writeFileSync(configPath, stripCodexBlock(readFileSync(configPath, "utf8")), { encoding: "utf8" });
}

function codexConfigPath(home: string): string {
  return join(home, ".codex", "config.toml");
}

export function applyAgentRouting(agent: AgentId, routing: Record<string, string>, home: string, env: DgPathEnvironment = process.env): RoutingResult {
  if (agent === "codex") {
    return applyCodexRouting(codexConfigPath(home), routing);
  }
  // Every other supported agent reads a JSON settings file with an `env` block.
  applyClaudeRouting(getAgent(agent).configPath(home), routing, backupPath(agent, env));
  return { applied: true, detail: getAgent(agent).configPath(home) };
}

export function removeAgentRouting(agent: AgentId, home: string, env: DgPathEnvironment = process.env): void {
  if (agent === "codex") {
    removeCodexRouting(codexConfigPath(home));
    return;
  }
  removeClaudeRouting(getAgent(agent).configPath(home), backupPath(agent, env));
}

export function routingInstalled(agent: AgentId, home: string, env: DgPathEnvironment = process.env): boolean {
  if (agent === "codex") {
    const p = codexConfigPath(home);
    return existsSync(p) && readFileSync(p, "utf8").includes(CODEX_BEGIN);
  }
  return existsSync(backupPath(agent, env));
}
