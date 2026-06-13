import type { AgentVerdict } from "../launcher/agent-check.js";
import type { CleanupRegistryEntry, DgPaths } from "../state/index.js";

export type AgentId = "claude-code" | "codex" | "cursor" | "copilot-cli" | "gemini" | "windsurf";

export interface ParsedHookInput {
  readonly command: string;
  readonly cwd?: string;
}

export interface EmittedDecision {
  readonly stdout: string;
  readonly exitCode: number;
}

export interface ProbeResult {
  readonly supported: boolean;
  readonly detail: string;
}

export interface ProbeDeps {
  readonly execVersion?: (binary: string, args: readonly string[]) => string | null;
}

export interface AgentHookContext {
  readonly agent: AgentId;
  readonly settingsPath: string;
  readonly dgCommand: string;
  readonly paths: DgPaths;
}

export interface AgentHookApplyResult {
  readonly created: boolean;
}

export interface AgentHookCheck {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

export interface HookPersistence {
  apply(ctx: AgentHookContext): Promise<AgentHookApplyResult>;
  remove(ctx: AgentHookContext): Promise<{ removed: boolean }>;
  verify(ctx: AgentHookContext): AgentHookCheck[];
  isInstalledCheckName: string;
  reverseEntry(entry: CleanupRegistryEntry, removed: string[], missing: string[], warnings: string[]): void;
}

export interface AgentIntegration extends HookPersistence {
  readonly id: AgentId;
  readonly label: string;
  readonly kind: "merged-json" | "owned-json";
  readonly maturity: "verified" | "unverified";
  readonly minVersion: string | null;
  readonly postInstallNote?: string;
  configPath(home: string): string;
  detect(home: string): boolean;
  probeHookSupport(home: string, deps?: ProbeDeps): ProbeResult;
  parseInput(stdin: string): ParsedHookInput | null;
  emitDecision(verdict: AgentVerdict): EmittedDecision;
}
