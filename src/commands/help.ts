import type { CommandSpec } from "./types.js";

const PRODUCT_DESCRIPTION = "Dependency Guardian";

const COMMON_COMMANDS = ["scan", "verify", "audit", "licenses", "setup", "guard-commit", "doctor", "login"];

const GLOBAL_FLAGS_FOOTER =
  "Global: --help/-h · --version/-v · --json (where supported) · --no-color / --force-color (also NO_COLOR, FORCE_COLOR).";

function isWrapper(command: CommandSpec): boolean {
  return command.summary.includes("prefix-mode routing");
}

export function renderRootHelp(
  version: string,
  commands: readonly CommandSpec[],
  options: { readonly all?: boolean } = {}
): string {
  const header = [
    `dg ${version}`,
    "",
    PRODUCT_DESCRIPTION,
    "",
    "Usage:",
    "  dg <command> [options]",
    ""
  ];

  if (!options.all) {
    const common = COMMON_COMMANDS
      .map((name) => commands.find((command) => command.name === name))
      .filter((command): command is CommandSpec => Boolean(command));
    const lines = [
      ...header,
      "Protect installs:  dg npm install <pkg>      (or run 'dg setup' once)",
      "Audit a project:   dg scan",
      "",
      "Common commands:"
    ];
    for (const command of common) {
      lines.push(`  ${command.name.padEnd(12)} ${command.summary}`);
    }
    lines.push(
      "",
      "Run 'dg <command> --help' for flags and examples, or 'dg --help-all' for every command.",
      GLOBAL_FLAGS_FOOTER
    );
    return `${lines.join("\n")}\n`;
  }

  const wrappers = commands.filter(isWrapper);
  const standalone = commands.filter((command) => !isWrapper(command));
  const lines = [...header, "Commands:"];
  for (const command of standalone) {
    lines.push(`  ${command.name.padEnd(14)} ${command.summary}`);
  }
  lines.push("", "Package-manager prefix mode (run any through dg):", `  ${wrappers.map((command) => command.name).join(", ")}`);
  lines.push(
    "",
    "Run 'dg <command> --help' for that command's flags and examples.",
    GLOBAL_FLAGS_FOOTER
  );
  return `${lines.join("\n")}\n`;
}

function column(rows: readonly { left: string; summary: string }[]): string[] {
  const width = Math.max(...rows.map((row) => row.left.length));
  return rows.map((row) => `  ${row.left.padEnd(width)}  ${row.summary}`);
}

export function renderCommandHelp(command: CommandSpec, path: readonly string[] = [command.name]): string {
  const lines = [
    `dg ${path.join(" ")}`,
    "",
    command.summary,
    "",
    "Usage:",
    `  ${command.usage}`
  ];

  if (command.args && command.args.length > 0) {
    lines.push("", "Arguments:", ...column(command.args.map((arg) => ({ left: arg.name, summary: arg.summary }))));
  }

  if (command.subcommands && command.subcommands.length > 0) {
    lines.push(
      "",
      "Subcommands:",
      ...column(command.subcommands.map((subcommand) => ({ left: subcommand.name, summary: subcommand.summary })))
    );
  }

  if (command.flags && command.flags.length > 0) {
    lines.push(
      "",
      "Flags:",
      ...column(command.flags.map((flag) => ({ left: flag.value ? `${flag.flag} ${flag.value}` : flag.flag, summary: flag.summary })))
    );
  }

  if (command.examples && command.examples.length > 0) {
    lines.push("", "Examples:", ...command.examples.map((example) => `  ${example}`));
  }

  if (command.details.length > 0) {
    lines.push("", ...command.details);
  }

  lines.push("", GLOBAL_FLAGS_FOOTER);

  return `${lines.join("\n")}\n`;
}
