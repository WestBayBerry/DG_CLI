import type { CommandContext, CommandResult, CommandSpec } from "./types.js";
import { EXIT_USAGE } from "./types.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme, type Theme } from "../presentation/theme.js";
import { promptYesNo } from "../util/tty-prompt.js";
import {
  applyGitHook,
  gitHookState,
  planGitHook,
  removeGitHookForRepo,
  resolveGitRepo,
  verifyGitHook,
  type GitRepoContext,
  type GuardCheck
} from "../setup/git-hook.js";

export const guardCommitCommand: CommandSpec = {
  name: "guard-commit",
  summary: "Scan staged dependencies before every commit in this repo.",
  usage: "dg guard-commit [off | --check | --print] [--yes]",
  args: [{ name: "[off]", summary: "Remove the hook and restore any hook it chained (alias remove/uninstall)." }],
  flags: [
    { flag: "--check", summary: "Verify the hook is installed and will actually fire." },
    { flag: "--print", summary: "Preview what it will write, change nothing." },
    { flag: "--yes", summary: "Install without the confirmation prompt (alias -y)." }
  ],
  examples: ["dg guard-commit", "dg guard-commit --check", "dg guard-commit off"],
  details: [
    "Installs a git pre-commit hook that scans staged lockfile changes and blocks a commit that would add a malicious dependency. Override a block with 'git commit --no-verify'.",
    "It resolves the real hooks directory (honouring core.hooksPath/husky and worktrees) and chains any existing pre-commit hook. Tune behaviour with the gitHook.onWarn / gitHook.onIncomplete config keys."
  ],
  handler: (context) => run(context)
};

type ParsedArgs = { off: boolean; check: boolean; print: boolean; yes: boolean } | { error: string };

function parse(args: readonly string[]): ParsedArgs {
  let off = false;
  let check = false;
  let print = false;
  let yes = false;
  for (const arg of args) {
    if (arg === "off" || arg === "remove" || arg === "uninstall") {
      off = true;
    } else if (arg === "install" || arg === "on") {
      off = false;
    } else if (arg === "--check") {
      check = true;
    } else if (arg === "--print") {
      print = true;
    } else if (arg === "--yes" || arg === "-y") {
      yes = true;
    } else {
      return { error: `unknown argument '${arg}'` };
    }
  }
  return { off, check, print, yes };
}

function run(context: CommandContext): CommandResult {
  const parsed = parse(context.args);
  if ("error" in parsed) {
    return {
      exitCode: EXIT_USAGE,
      stdout: "",
      stderr: `dg guard-commit: ${parsed.error}. Usage: ${guardCommitCommand.usage}\n`
    };
  }

  const theme = createTheme(resolvePresentation().color);
  const repo = resolveGitRepo();
  if ("error" in repo) {
    return { exitCode: EXIT_USAGE, stdout: "", stderr: `dg guard-commit: ${repo.error}.\n` };
  }

  if (parsed.off) {
    return remove(repo, theme);
  }
  if (parsed.check) {
    return check(repo, theme);
  }
  if (parsed.print) {
    return print(repo);
  }
  return install(repo, theme, parsed.yes);
}

function install(repo: GitRepoContext, theme: Theme, yes: boolean): CommandResult {
  const plan = planGitHook(repo);
  const err = process.stderr;
  const accent = (text: string): string => theme.paint("accent", text);
  const muted = (text: string): string => theme.paint("muted", text);

  if (resolvePresentation().mode === "rich" && !yes) {
    err.write(`\n  Scan staged dependencies before every commit in ${accent(repo.root)}${muted(".")}\n`);
    if (plan.willChain) {
      err.write(`  ${muted("Your existing pre-commit hook will be kept and run after dg.")}\n`);
    }
    err.write(`  ${muted("Reversible with")} ${accent("dg guard-commit off")}${muted(".")}\n\n`);
    const proceed = promptYesNo(`  ${accent("Proceed?")}`, true);
    if (proceed === false) {
      return { exitCode: 0, stdout: "", stderr: `  ${muted("cancelled — nothing written")}\n` };
    }
  }

  const result = applyGitHook(repo);
  if (result.active) {
    return {
      exitCode: 0,
      stdout: "",
      stderr: `\n  ${theme.paint("pass", "✓ commits in this repo are now scanned")}\n\n`
    };
  }
  return {
    exitCode: 1,
    stdout: "",
    stderr: `\n  ${theme.paint("warn", "⚠ installed, but it is not active yet:")}\n${renderChecks(result.checks, theme)}`
  };
}

function check(repo: GitRepoContext, theme: Theme): CommandResult {
  if (gitHookState(repo) !== "managed") {
    return {
      exitCode: 1,
      stdout: "",
      stderr: `  ${theme.paint("warn", "⚠")} not set up in this repo — run ${theme.paint("accent", "dg guard-commit")}\n`
    };
  }
  const checks = verifyGitHook(repo);
  const active = checks.every((entry) => entry.ok);
  const head = active
    ? `  ${theme.paint("pass", "✓ commit guard is active")}\n`
    : `  ${theme.paint("warn", "⚠ commit guard is installed but not firing:")}\n`;
  return { exitCode: active ? 0 : 1, stdout: "", stderr: `${head}${renderChecks(checks, theme)}` };
}

function print(repo: GitRepoContext): CommandResult {
  const plan = planGitHook(repo);
  const lines = [
    "dg guard-commit write plan",
    "",
    "No files are changed until you run dg guard-commit.",
    `- write pre-commit hook: ${plan.context.hookTarget}`
  ];
  if (plan.willChain) {
    lines.push("- back up + chain your existing hook so it still runs");
  } else if (plan.state === "managed") {
    lines.push("- (a dg hook is already installed; it will be refreshed)");
  }
  lines.push("- record it for 'dg guard-commit off' / 'dg uninstall'");
  return { exitCode: 0, stdout: `${lines.join("\n")}\n`, stderr: "" };
}

function remove(repo: GitRepoContext, theme: Theme): CommandResult {
  const result = removeGitHookForRepo(repo);
  if (result.found === 0) {
    return {
      exitCode: 0,
      stdout: "",
      stderr: `  ${theme.paint("muted", "no dg guard-commit hook in this repo")}\n`
    };
  }
  const restored = result.removed.some((path) => path.includes(".dg-chained-"));
  const note = restored ? ` ${theme.paint("muted", "(restored your previous hook)")}` : "";
  return {
    exitCode: 0,
    stdout: "",
    stderr: `  ${theme.paint("pass", "✓ removed dg commit guard")}${note}\n`
  };
}

function renderChecks(checks: readonly GuardCheck[], theme: Theme): string {
  return `${checks
    .map((entry) => `    ${entry.ok ? theme.paint("pass", "✓") : theme.paint("block", "✘")} ${theme.paint("muted", entry.detail)}`)
    .join("\n")}\n`;
}
