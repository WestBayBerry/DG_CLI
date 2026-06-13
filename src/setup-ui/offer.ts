import type { CommandResult } from "../commands/types.js";
import { resolvePresentation } from "../presentation/mode.js";
import { MACHINE_OUTPUT_FLAGS } from "../runtime/first-run.js";
import { buildSetupPlan, type SetupPlan } from "../setup/plan.js";
import type { DgPathEnvironment } from "../state/index.js";
import { shouldOfferSetupWizard } from "./gate.js";

const SKIP_COMMANDS = new Set([
  "help",
  "--help",
  "-h",
  "--help-all",
  "help-all",
  "version",
  "--version",
  "-v",
  "login",
  "logout",
  "setup",
  "update",
  "upgrade",
  "uninstall"
]);

export interface WizardOfferOptions {
  readonly env?: DgPathEnvironment;
  readonly stdin?: { isTTY?: boolean };
  readonly stderr?: { isTTY?: boolean };
  readonly richMode?: boolean;
  readonly runWizard?: (plan: SetupPlan, options: { readonly env: DgPathEnvironment; readonly autoActivate: boolean }) => Promise<CommandResult>;
}

export interface WizardOfferOutcome {
  readonly handled: boolean;
  readonly result: CommandResult;
}

const NOT_RUN: WizardOfferOutcome = { handled: false, result: { exitCode: 0, stdout: "", stderr: "" } };

export async function maybeOfferSetupWizard(args: readonly string[], options: WizardOfferOptions = {}): Promise<WizardOfferOutcome> {
  const env = options.env ?? process.env;
  const command = args[0] ?? "";
  if (command && SKIP_COMMANDS.has(command)) {
    return NOT_RUN;
  }
  if (args.some((arg) => MACHINE_OUTPUT_FLAGS.has(arg))) {
    return NOT_RUN;
  }
  if (!shouldOfferSetupWizard(env, options.stdin ?? process.stdin, options.stderr ?? process.stderr)) {
    return NOT_RUN;
  }
  const rich = options.richMode ?? resolvePresentation().mode === "rich";
  if (!rich) {
    return NOT_RUN;
  }
  const plan = buildSetupPlan({ shell: "auto" });
  const runWizard = options.runWizard ?? (await import("./wizard.js")).runSetupWizard;
  const result = await runWizard(plan, { env, autoActivate: args.length === 0 });
  return { handled: args.length === 0, result };
}
