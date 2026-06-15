import type { CommandSpec } from "./types.js";
import { EXIT_UNAVAILABLE, EXIT_USAGE, type CommandResult } from "./types.js";
import { LockBusyError } from "../state/index.js";
import { activationCommand as shellActivationCommand, applySetupPlanWithLock, buildSetupPlan, renderSetupPlan, tildifyPath as tildify, type SetupPlan, type SetupShell } from "../setup/plan.js";
import { activateShell, activationOffer } from "../setup/activate-shell.js";
import { buildServiceSetupPlan, configureService, renderServicePlan } from "../service/state.js";
import { optionalSupportGate } from "../setup/optional-support.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme, type Theme } from "../presentation/theme.js";
import { closeSync, openSync, readSync } from "node:fs";
import { authStatus } from "../auth/store.js";
import { resolveWebBase } from "../auth/device-login.js";
import { applyAgentHook, collectAgentOffers, type AgentOffer } from "../agents/registry.js";
import { applyGitHook, commitGuardOffer, type GitRepoContext } from "../setup/git-hook.js";
import { markSecurityNotesShown, securityNotesShown } from "../setup-ui/gate.js";

export const setupCommand: CommandSpec = {
  name: "setup",
  summary: "Protect this machine — shell installs, AI-agent installs, and a repo's commits.",
  usage: "dg setup [--print] [--yes] [--agents] [--guard-commit] [--shell <auto|zsh|bash|fish>] [--service]",
  flags: [
    { flag: "--print", summary: "Preview the exact write plan and change nothing." },
    { flag: "--yes", summary: "Apply the shell firewall only, without prompts (add --agents / --guard-commit to opt in the rest)." },
    { flag: "--agents", summary: "With --yes: also route every detected AI agent's installs through dg." },
    { flag: "--guard-commit", summary: "With --yes: also scan this repo's commits (per-repo)." },
    { flag: "--shell", value: "<auto|zsh|bash|fish>", summary: "Target shell rc to write (default: auto-detect)." },
    { flag: "--service", summary: "Set up service mode (Pro/Team; persistent proxy + managed CA)." }
  ],
  examples: ["dg setup", "dg setup --print", "dg setup --yes --agents", "dg setup --shell zsh --yes"],
  details: [
    "In a terminal it shows one consent screen listing everything it will protect — your shell's installs plus every detected AI agent, with the exact files it writes — and applies them on a single yes. Commits in the current repo are a separate per-repo question.",
    "Non-interactively, --yes applies just the shell firewall; add --agents and/or --guard-commit to opt those in. --print previews. Writes only dg-owned reversible files; undo it all with dg uninstall."
  ],
  handler: (context) => setupHandler(context.args)
};

const WINDOWS_UNSUPPORTED =
  "dg setup (automatic interception) does not support Windows yet.\n" +
  "You can still protect installs on Windows: prefix the command with dg,\n" +
  "for example `dg pip install <pkg>` or `dg npm install <pkg>`.\n";

async function setupHandler(args: readonly string[]): Promise<CommandResult> {
  const parsed = parseSetupArgs(args);
  if ("error" in parsed) {
    return {
      exitCode: parsed.exitCode,
      stdout: "",
      stderr: parsed.error
    };
  }

  if (process.platform === "win32") {
    return {
      exitCode: EXIT_UNAVAILABLE,
      stdout: "",
      stderr: WINDOWS_UNSUPPORTED
    };
  }

  if (parsed.service) {
    return serviceSetupHandler(parsed);
  }

  const plan = buildSetupPlan({
    shell: parsed.shell
  });
  const renderedPlan = renderSetupPlan(plan);

  if (parsed.printOnly) {
    return {
      exitCode: 0,
      stdout: `${renderedPlan}${printableSurfaceOffers()}`,
      stderr: ""
    };
  }

  if (!parsed.yes) {
    if (isInteractive()) {
      if (resolvePresentation().mode === "rich") {
        const { runSetupWizard } = await import("../setup-ui/wizard.js");
        return runSetupWizard(plan, { autoActivate: true });
      }
      return runInteractiveSetup(plan);
    }
    return {
      exitCode: EXIT_USAGE,
      stdout: renderedPlan,
      stderr: "dg setup requires --yes to apply this non-interactive write plan.\n"
    };
  }

  try {
    applySetupPlanWithLock(plan);
  } catch (error) {
    if (error instanceof LockBusyError) {
      return {
        exitCode: 1,
        stdout: renderedPlan,
        stderr: `dg setup cannot apply while another setup or uninstall is running: ${error.path}\n`
      };
    }
    throw error;
  }

  const extra = await applyRequestedSurfaces(parsed);
  const theme = createTheme(resolvePresentation().color);
  return {
    exitCode: 0,
    stdout: `${theme.paint("pass", "✓")} Setup complete — active in new terminals ${theme.paint("muted", `(wrote ${tildify(plan.shimDir)} and ${tildify(plan.rcPath)}; details: dg doctor)`)}\n${extra}Activate this shell now: ${theme.paint("accent", activationCommand(plan))}\n`,
    stderr: ""
  };
}

function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY && process.stderr.isTTY);
}

async function runInteractiveSetup(plan: SetupPlan): Promise<CommandResult> {
  const theme = createTheme(resolvePresentation().color);
  const accent = (text: string): string => theme.paint("accent", text);
  const muted = (text: string): string => theme.paint("muted", text);
  const err = process.stderr;

  const agents = collectAgentOffers();
  const repo = commitGuardOffer();
  if (!securityNotesShown()) {
    err.write(renderSecurityNotesText(theme));
    err.write(`  ${muted("Press Enter to agree")} `);
    if (readLineFromTty() !== null) {
      markSecurityNotesShown();
    }
    err.write("\n");
  }
  err.write(renderConsentScreen(consentSurfaces(plan, agents, repo !== null), theme));

  const answer = promptYesNoSync(`  ${accent("Protect installs on this machine?")}`, theme, true);
  if (answer === "no-tty") {
    return {
      exitCode: EXIT_USAGE,
      stdout: "",
      stderr: `  ${muted("no terminal to read consent — re-run with")} ${accent("dg setup --yes")} ${muted("to apply non-interactively")}\n`
    };
  }
  if (answer !== "yes") {
    return { exitCode: 0, stdout: "", stderr: `  ${muted("cancelled — nothing written")}\n` };
  }

  try {
    applySetupPlanWithLock(plan);
  } catch (error) {
    if (error instanceof LockBusyError) {
      return {
        exitCode: 1,
        stdout: "",
        stderr: `  dg setup cannot apply while another setup or uninstall is running: ${error.path}\n`
      };
    }
    throw error;
  }

  err.write(`\n  ${theme.paint("pass", "✓ shell installs protected — active in new terminals")}\n`);

  await applyAgentOffers(agents, theme, err);
  promptCommitSurface(repo, theme, err);
  return finishWithActivation(plan, theme, err);
}

export interface ConsentSurface {
  readonly label: string;
  readonly detail: string;
  readonly deferred: boolean;
}

export function consentSurfaces(plan: SetupPlan, agents: readonly AgentOffer[], repoOffered: boolean): ConsentSurface[] {
  const surfaces: ConsentSurface[] = [
    { label: "shell installs", detail: `writes ${tildify(plan.rcPath)}`, deferred: false }
  ];
  for (const offer of agents) {
    surfaces.push({ label: `${offer.label} installs`, detail: `writes ${tildify(offer.ctx.settingsPath)}`, deferred: false });
  }
  if (repoOffered) {
    surfaces.push({ label: "commits in this repo", detail: "asked separately", deferred: true });
  }
  return surfaces;
}

export function renderConsentScreen(surfaces: readonly ConsentSurface[], theme: Theme): string {
  const accent = (text: string): string => theme.paint("accent", text);
  const muted = (text: string): string => theme.paint("muted", text);
  const width = Math.max(...surfaces.map((surface) => surface.label.length));
  const lines = [
    "",
    `  Scans ${accent("npm")}/${accent("pip")}/${accent("yarn")}/${muted("…")} installs automatically — no ${accent("dg")} prefix.`,
    `  ${muted("Reversible with")} ${accent("dg uninstall")}${muted(".")}`,
    "",
    `  ${muted("Sets up:")}`
  ];
  for (const surface of surfaces) {
    const label = surface.label.padEnd(width);
    lines.push(surface.deferred ? `    ${muted(label)}  ${muted(surface.detail)}` : `    ${accent(label)}  ${muted(surface.detail)}`);
  }
  lines.push("", "");
  return lines.join("\n");
}

function finishWithActivation(plan: SetupPlan, theme: Theme, err: NodeJS.WriteStream): CommandResult {
  const offer = activationOffer();
  if (offer === "none") {
    return { exitCode: 0, stdout: "", stderr: "" };
  }
  const accent = (text: string): string => theme.paint("accent", text);
  const muted = (text: string): string => theme.paint("muted", text);
  if (offer === "prompt" && promptYesNoSync(`\n  ${accent("Activate in this terminal now?")}`, theme, true) === "yes") {
    err.write(`  ${muted("Starting a protected shell — type")} ${accent("exit")} ${muted("to return to your previous one.")}\n`);
    return { exitCode: activateShell(), stdout: "", stderr: "" };
  }
  err.write(`\n  ${muted("Activate this shell now:")}  ${accent(activationCommand(plan))}\n`);
  return { exitCode: 0, stdout: "", stderr: "" };
}

async function applyAgentOffers(offers: readonly AgentOffer[], theme: Theme, err: NodeJS.WriteStream): Promise<void> {
  const muted = (text: string): string => theme.paint("muted", text);
  for (const offer of offers) {
    try {
      await applyAgentHook(offer.ctx);
      err.write(`  ${theme.paint("pass", `✓ ${offer.label} installs route through dg`)} ${muted(`(${tildify(offer.ctx.settingsPath)})`)}\n`);
    } catch (error) {
      err.write(`  ${theme.paint("warn", `✗ ${offer.label}`)} ${muted(`— ${error instanceof Error ? error.message : "unknown error"}`)}\n`);
    }
  }
}

function promptCommitSurface(repo: GitRepoContext | null, theme: Theme, err: NodeJS.WriteStream): void {
  if (!repo) {
    return;
  }
  const accent = (text: string): string => theme.paint("accent", text);
  const muted = (text: string): string => theme.paint("muted", text);
  err.write(`\n  ${muted("This is a git repo. Scan its commits before they land?")}\n`);
  if (promptYesNoSync(`  ${accent("Guard commits in this repo?")}`, theme, false) !== "yes") {
    return;
  }
  try {
    applyGitHook(repo);
    err.write(`  ${theme.paint("pass", "✓ commits in this repo are now scanned")}\n`);
  } catch (error) {
    err.write(`  ${theme.paint("warn", `✗ commits in this repo`)} ${muted(`— ${error instanceof Error ? error.message : "unknown error"}`)}\n`);
  }
}

async function applyRequestedSurfaces(parsed: { readonly agents: boolean; readonly guardCommit: boolean }): Promise<string> {
  const lines: string[] = [];
  if (parsed.agents) {
    for (const offer of collectAgentOffers()) {
      try {
        await applyAgentHook(offer.ctx);
        lines.push(`${offer.label} installs now route through dg (${tildify(offer.ctx.settingsPath)}).`);
      } catch (error) {
        lines.push(`could not hook ${offer.label}: ${error instanceof Error ? error.message : "unknown error"}`);
      }
    }
  }
  if (parsed.guardCommit) {
    const repo = commitGuardOffer();
    if (repo) {
      try {
        applyGitHook(repo);
        lines.push("commits in this repo are now scanned.");
      } catch (error) {
        lines.push(`could not install the commit guard: ${error instanceof Error ? error.message : "unknown error"}`);
      }
    }
  }
  return lines.length > 0 ? `${lines.join("\n")}\n` : "";
}

function printableSurfaceOffers(): string {
  const lines: string[] = [];
  for (const offer of collectAgentOffers()) {
    lines.push(`would offer: route ${offer.label} installs through dg (--agents)`);
  }
  if (commitGuardOffer()) {
    lines.push("would offer: scan this repo's commits (--guard-commit)");
  }
  return lines.length > 0 ? `\n${lines.join("\n")}\n` : "";
}

function activationCommand(plan: SetupPlan): string {
  return shellActivationCommand(plan.shell, tildify(plan.rcPath));
}

type PromptAnswer = "yes" | "no" | "no-tty";

function renderSecurityNotesText(theme: Theme): string {
  const muted = (text: string): string => theme.paint("muted", text);
  const webBase = resolveWebBase(process.env);
  return [
    "",
    `  ${theme.paint("accent", "Security notes")}`,
    "",
    "  1. dg can make mistakes.",
    "     A PASS verdict does not guarantee a package is safe. You are",
    "     responsible for what you install.",
    "",
    "  2. By continuing you confirm you have read and understand the",
    "     Terms of Service and Privacy Policy.",
    `     ${muted(`${webBase}/terms`)}`,
    `     ${muted(`${webBase}/privacy`)}`,
    "",
    ""
  ].join("\n");
}

function readLineFromTty(): string | null {
  let tty: number;
  try {
    tty = openSync("/dev/tty", "rs");
  } catch {
    return null;
  }
  try {
    const byte = Buffer.alloc(1);
    let answer = "";
    for (;;) {
      let read = 0;
      try {
        read = readSync(tty, byte, 0, 1, null);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EAGAIN") {
          continue;
        }
        break;
      }
      if (read === 0) {
        break;
      }
      const char = byte.toString("utf8");
      if (char === "\n" || char === "\r") {
        break;
      }
      answer += char;
    }
    return answer;
  } finally {
    closeSync(tty);
  }
}

function promptYesNoSync(question: string, theme: ReturnType<typeof createTheme>, defaultYes = false): PromptAnswer {
  process.stderr.write(`${question} ${theme.paint("muted", defaultYes ? "[Y/n]" : "[y/N]")} `);
  const answer = readLineFromTty();
  if (answer === null) {
    return "no-tty";
  }
  const normalized = answer.trim().toLowerCase();
  if (normalized === "") {
    return defaultYes ? "yes" : "no";
  }
  return normalized === "y" || normalized === "yes" ? "yes" : "no";
}

type ParsedSetupArgs =
  | {
      readonly printOnly: boolean;
      readonly yes: boolean;
      readonly shell: SetupShell;
      readonly service: boolean;
      readonly agents: boolean;
      readonly guardCommit: boolean;
    }
  | {
      readonly error: string;
      readonly exitCode: number;
    };

function parseSetupArgs(args: readonly string[]): ParsedSetupArgs {
  let printOnly = false;
  let yes = false;
  let shell: SetupShell = "auto";
  let service = false;
  let agents = false;
  let guardCommit = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--print") {
      printOnly = true;
    } else if (arg === "--yes") {
      yes = true;
    } else if (arg === "--service") {
      service = true;
    } else if (arg === "--agents") {
      agents = true;
    } else if (arg === "--guard-commit") {
      guardCommit = true;
    } else if (arg === "--python-hook" || arg?.startsWith("--python-hook=")) {
      return {
        exitCode: EXIT_UNAVAILABLE,
        error: `dg setup --python-hook is gated and no files were changed. ${optionalSupportGate("python-hook").message}.\n`
      };
    } else if (arg === "--git-hooks") {
      return {
        exitCode: EXIT_USAGE,
        error: "dg setup --git-hooks moved — run 'dg guard-commit' inside the repo you want to protect.\n"
      };
    } else if (arg === "--shell") {
      const value = args[index + 1];
      if (!value) {
        return {
          exitCode: EXIT_USAGE,
          error: "dg setup --shell requires one of: auto, zsh, bash, fish.\n"
        };
      }
      const parsedShell = parseShell(value);
      if (!parsedShell) {
        if (value === "powershell") {
          return {
            exitCode: EXIT_UNAVAILABLE,
            error: `dg setup --shell powershell is gated and no files were changed. ${optionalSupportGate("windows").message}.\n`
          };
        }
        return {
          exitCode: EXIT_USAGE,
          error: `dg setup does not support shell '${value}' in this build. Supported shells: auto, zsh, bash, fish.\n`
        };
      }
      shell = parsedShell;
      index += 1;
    } else if (arg?.startsWith("--shell=")) {
      const value = arg.slice("--shell=".length);
      const parsedShell = parseShell(value);
      if (!parsedShell) {
        if (value === "powershell") {
          return {
            exitCode: EXIT_UNAVAILABLE,
            error: `dg setup --shell powershell is gated and no files were changed. ${optionalSupportGate("windows").message}.\n`
          };
        }
        return {
          exitCode: EXIT_USAGE,
          error: `dg setup does not support shell '${value}' in this build. Supported shells: auto, zsh, bash, fish.\n`
        };
      }
      shell = parsedShell;
    } else {
      return {
        exitCode: EXIT_USAGE,
        error: `dg setup: unknown option '${arg}'. Run 'dg setup --help'.\n`
      };
    }
  }

  return {
    printOnly,
    yes,
    shell,
    service,
    agents,
    guardCommit
  };
}

function parseShell(value: string): SetupShell | null {
  if (value === "auto" || value === "zsh" || value === "bash" || value === "fish") {
    return value;
  }
  return null;
}

function serviceSetupHandler(parsed: Extract<ParsedSetupArgs, { readonly service: boolean }>): CommandResult {
  const renderedPlan = renderServicePlan("Dependency Guardian service setup write plan", buildServiceSetupPlan());

  if (parsed.printOnly) {
    return {
      exitCode: 0,
      stdout: renderedPlan,
      stderr: ""
    };
  }

  if (!authStatus().authenticated) {
    const theme = createTheme(resolvePresentation().color);
    return {
      exitCode: EXIT_UNAVAILABLE,
      stdout: "",
      stderr: `${theme.paint("warn", "dg setup --service is a Pro or Team feature")} — ${theme.paint("accent", "dg login")} ${theme.paint("muted", "with a paid account, then re-run")} ${theme.paint("muted", "· westbayberry.com/pricing")}\n`
    };
  }

  if (!parsed.yes) {
    return {
      exitCode: EXIT_USAGE,
      stdout: renderedPlan,
      stderr: "dg setup --service requires --yes to apply this non-interactive write plan.\n"
    };
  }

  try {
    const result = configureService();
    return {
      exitCode: 0,
      stdout: `${renderedPlan}\nService mode ${result.changed ? "configured" : "already configured"}. Run 'dg service start' to start it.\n`,
      stderr: ""
    };
  } catch (error) {
    if (error instanceof LockBusyError) {
      return {
        exitCode: 1,
        stdout: renderedPlan,
        stderr: `dg setup --service cannot apply while service state is locked: ${error.path}\n`
      };
    }
    throw error;
  }
}
