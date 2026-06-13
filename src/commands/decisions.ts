import { recordDecisionEvents } from "../decisions/remember-prompt.js";
import { packageKey } from "../decisions/apply.js";
import {
  findProjectRoot,
  loadDgFile,
  mutateDgFile,
  removeDecisions,
  type DecisionEntry,
  type DgFile
} from "../project/dgfile.js";
import { EXIT_USAGE, type CommandContext, type CommandResult, type CommandSpec } from "./types.js";

export const decisionsCommand: CommandSpec = {
  name: "decisions",
  summary: "List or revoke remembered warn acceptances stored in dg.json.",
  usage: "dg decisions [list] [--json] | dg decisions revoke <id|name[@version]>",
  subcommands: [
    { name: "list", summary: "Show every remembered acceptance (default).", usage: "dg decisions list [--json]", details: [], handler: () => unreachable() },
    { name: "revoke", summary: "Remove an acceptance by id prefix, name, or name@version.", usage: "dg decisions revoke <id|name[@version]>", details: [], handler: () => unreachable() }
  ],
  flags: [{ flag: "--json", summary: "Machine-readable listing." }],
  examples: ["dg decisions", "dg decisions list --json", "dg decisions revoke left-pad@1.3.0"],
  details: [
    "Acceptances live in dg.json at the git root and only ever soften how an acknowledged warn is presented — a block verdict is never suppressible. Revoking makes the warn surface again on the next scan."
  ],
  handler: (context) => runDecisionsCommand(context)
};

function unreachable(): never {
  throw new Error("subcommand handled by the decisions router");
}

export function runDecisionsCommand(context: CommandContext, cwd: string = process.cwd(), env: NodeJS.ProcessEnv = process.env): CommandResult {
  const [first, ...rest] = context.args;

  if (first === undefined || first === "list" || first === "--json") {
    const json = first === "--json" || rest.includes("--json");
    const extras = rest.filter((arg) => arg !== "--json");
    if (extras.length > 0) {
      return usage(`unexpected argument '${extras[0]}'`);
    }
    return listDecisions(cwd, env, json);
  }

  if (first === "revoke") {
    const [selector, ...extra] = rest;
    if (!selector || extra.length > 0) {
      return usage("revoke takes exactly one <id|name[@version]>");
    }
    return revokeDecisions(selector, cwd, env);
  }

  return usage(`unknown subcommand '${first}'`);
}

function listDecisions(cwd: string, env: NodeJS.ProcessEnv, json: boolean): CommandResult {
  const located = locateDgFile(cwd, env);
  if ("error" in located) {
    return located.error;
  }
  if ("missing" in located) {
    if (json) {
      return { exitCode: 0, stdout: `${JSON.stringify({ schemaVersion: 1, path: null, decisions: [] }, null, 2)}\n`, stderr: "" };
    }
    return { exitCode: 0, stdout: `No dg.json at ${located.missing} — nothing remembered yet.\n`, stderr: "" };
  }
  const file = located.file;
  if (json) {
    return {
      exitCode: 0,
      stdout: `${JSON.stringify({ schemaVersion: 1, path: file.path, decisions: file.decisions.map((entry) => entryJson(entry)) }, null, 2)}\n`,
      stderr: ""
    };
  }
  if (file.decisions.length === 0) {
    return { exitCode: 0, stdout: `No remembered acceptances in ${file.path}.\n`, stderr: "" };
  }
  const rows = file.decisions.map((entry) => [
    entry.id.slice(0, 8),
    `${entry.ecosystem}:${entry.name}@${scopeLabel(entry)}`,
    findingsLabel(entry),
    entry.acceptedBy,
    entry.acceptedAt.slice(0, 10) || "-",
    entry.expiresAt ? entry.expiresAt.slice(0, 10) : "-",
    isExpired(entry) ? "expired" : "active"
  ]);
  const header = ["ID", "PACKAGE", "ACCEPTED FINDINGS", "BY", "WHEN", "EXPIRES", "STATUS"];
  const widths = header.map((label, column) => Math.max(label.length, ...rows.map((row) => row[column]?.length ?? 0)));
  const renderRow = (row: readonly string[]): string => row.map((cell, column) => cell.padEnd(widths[column] ?? 0)).join("  ").trimEnd();
  const lines = [
    `Remembered acceptances in ${file.path} (warns only — blocks are never suppressible):`,
    "",
    renderRow(header),
    ...rows.map(renderRow),
    "",
    `Revoke with: dg decisions revoke <id|name[@version]>`
  ];
  return { exitCode: 0, stdout: `${lines.join("\n")}\n`, stderr: "" };
}

function revokeDecisions(selector: string, cwd: string, env: NodeJS.ProcessEnv): CommandResult {
  const located = locateDgFile(cwd, env);
  if ("error" in located) {
    return located.error;
  }
  if ("missing" in located) {
    return { exitCode: 1, stdout: "", stderr: `dg decisions: nothing to revoke — no dg.json at ${located.missing} yet.\n` };
  }
  let matched: DecisionEntry[] = [];
  mutateDgFile(located.root, env, (file) => {
    matched = file.decisions.filter((entry) => matchesSelector(entry, selector));
    if (matched.length === 0) {
      return file;
    }
    return removeDecisions(file, new Set(matched.map((entry) => entry.id)));
  });
  if (matched.length === 0) {
    return { exitCode: 1, stdout: "", stderr: `dg decisions: nothing matches '${selector}' in ${located.file.path}.\n` };
  }
  recordDecisionEvents(
    "decision.revoked",
    matched.map((entry) => `${entry.ecosystem}:${packageKey(entry.name, scopeLabel(entry))}`),
    `revoked via dg decisions (${selector})`,
    env
  );
  const lines = matched.map((entry) => `Revoked ${entry.ecosystem}:${entry.name}@${scopeLabel(entry)} (${entry.id.slice(0, 8)}) — the warn will surface again.`);
  return { exitCode: 0, stdout: `${lines.join("\n")}\n`, stderr: "" };
}

function locateDgFile(cwd: string, env: NodeJS.ProcessEnv): { root: string; file: DgFile } | { missing: string } | { error: CommandResult } {
  const root = findProjectRoot(cwd, env);
  if (!root) {
    return { error: { exitCode: EXIT_USAGE, stdout: "", stderr: "dg decisions: not inside a git repository.\n" } };
  }
  const file = loadDgFile(root);
  if (!file.exists) {
    return { missing: root };
  }
  if (!file.readable) {
    return { error: { exitCode: 1, stdout: "", stderr: `dg decisions: cannot use ${file.path} — ${file.failure ?? "unreadable"}.\n` } };
  }
  return { root, file };
}

function matchesSelector(entry: DecisionEntry, selector: string): boolean {
  if (selector.length >= 4 && entry.id.startsWith(selector)) {
    return true;
  }
  const at = selector.lastIndexOf("@");
  if (at > 0) {
    const name = selector.slice(0, at);
    const version = selector.slice(at + 1);
    return entry.name === name && entry.scope.kind === "exact" && entry.scope.version === version;
  }
  return entry.name === selector;
}

function scopeLabel(entry: DecisionEntry): string {
  return entry.scope.kind === "exact" ? entry.scope.version : "*";
}

function findingsLabel(entry: DecisionEntry): string {
  const pairs = Object.entries(entry.findings).map(([category, severity]) => `${category}:${severity}`);
  return pairs.length > 0 ? pairs.sort().join(",") : "(action-only warn)";
}

function isExpired(entry: DecisionEntry): boolean {
  if (!entry.expiresAt) {
    return false;
  }
  const expiry = Date.parse(entry.expiresAt);
  return !Number.isFinite(expiry) || expiry <= Date.now();
}

function entryJson(entry: DecisionEntry): Record<string, unknown> {
  return {
    id: entry.id,
    ecosystem: entry.ecosystem,
    name: entry.name,
    scope: entry.scope,
    findings: entry.findings,
    reason: entry.reason,
    acceptedBy: entry.acceptedBy,
    acceptedAt: entry.acceptedAt,
    ...(entry.expiresAt ? { expiresAt: entry.expiresAt } : {}),
    status: isExpired(entry) ? "expired" : "active"
  };
}

function usage(message: string): CommandResult {
  return {
    exitCode: EXIT_USAGE,
    stdout: "",
    stderr: `dg decisions: ${message}. Usage: ${decisionsCommand.usage}\n`
  };
}
