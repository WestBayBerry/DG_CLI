export type CommandResult = {
  exitCode: number;
  stdout: string;
  stderr: string;
};

export type CommandContext = {
  commandPath: readonly string[];
  args: readonly string[];
};

export type CommandHandler = (context: CommandContext) => CommandResult | Promise<CommandResult>;

export type CommandArgument = {
  name: string;
  summary: string;
};

export type CommandFlag = {
  flag: string;
  value?: string;
  summary: string;
};

export type CommandSpec = {
  name: string;
  summary: string;
  usage: string;
  details: readonly string[];
  aliases?: readonly string[];
  subcommands?: readonly CommandSpec[];
  args?: readonly CommandArgument[];
  flags?: readonly CommandFlag[];
  examples?: readonly string[];
  handler: CommandHandler;
};

export const EXIT_USAGE = 2;
export const EXIT_USAGE_VERDICT = 64;
export const EXIT_ANALYSIS_INCOMPLETE = 4;
export const EXIT_NOTHING_TO_SCAN = 10;
export const EXIT_UNAVAILABLE = 69;
export const EXIT_TOOL_ERROR = 70;
