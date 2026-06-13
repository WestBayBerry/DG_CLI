import { LockBusyError } from "../state/index.js";
import { applyGitHook, type GitRepoContext } from "../setup/git-hook.js";
import { applySetupPlanWithLock, type SetupPlan } from "../setup/plan.js";
import { applyAgentHook, type AgentOffer } from "../agents/registry.js";

export interface TaskResult {
  readonly ok: boolean;
  readonly detail?: string;
  readonly fatal?: boolean;
}

export interface WizardTask {
  readonly label: string;
  run(): Promise<TaskResult>;
}

export function buildWizardTasks(plan: SetupPlan, agents: readonly AgentOffer[]): WizardTask[] {
  const tasks: WizardTask[] = [
    {
      label: "shell installs route through dg",
      run: async () => {
        try {
          applySetupPlanWithLock(plan);
          return { ok: true };
        } catch (error) {
          if (error instanceof LockBusyError) {
            return {
              ok: false,
              fatal: true,
              detail: `dg setup cannot apply while another setup or uninstall is running: ${error.path}`
            };
          }
          throw error;
        }
      }
    }
  ];
  for (const offer of agents) {
    tasks.push({
      label: `${offer.label} installs route through dg`,
      run: async () => {
        try {
          await applyAgentHook(offer.ctx);
          return { ok: true };
        } catch (error) {
          return { ok: false, detail: error instanceof Error ? error.message : "unknown error" };
        }
      }
    });
  }
  return tasks;
}

export function buildCommitGuardTask(repo: GitRepoContext): WizardTask {
  return {
    label: "commits in this repo are scanned",
    run: async () => {
      try {
        applyGitHook(repo);
        return { ok: true };
      } catch (error) {
        return { ok: false, detail: error instanceof Error ? error.message : "unknown error" };
      }
    }
  };
}
