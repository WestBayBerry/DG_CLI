export interface SpawnInvocation {
  readonly command: string;
  readonly args: readonly string[];
  readonly windowsVerbatimArguments: boolean;
}

const CMD_SCRIPT_PATTERN = /\.(cmd|bat)$/i;
const CMD_META_CHARS = /([()\][%!^"`<>&|;, *?])/g;

export function resolveSpawnInvocation(
  binary: string,
  args: readonly string[],
  platform: NodeJS.Platform = process.platform
): SpawnInvocation {
  if (platform !== "win32" || !CMD_SCRIPT_PATTERN.test(binary)) {
    return { command: binary, args, windowsVerbatimArguments: false };
  }
  const commandLine = [escapeCmdCommand(binary), ...args.map(escapeCmdArgument)].join(" ");
  return {
    command: process.env.comspec ?? "cmd.exe",
    args: ["/d", "/s", "/c", `"${commandLine}"`],
    windowsVerbatimArguments: true
  };
}

function escapeCmdCommand(command: string): string {
  return command.replace(CMD_META_CHARS, "^$1");
}

// cmd shims parse their command line twice, hence the doubled meta-char escape (cross-spawn's algorithm)
function escapeCmdArgument(argument: string): string {
  const quoted = `"${argument.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, "$1$1")}"`;
  return quoted.replace(CMD_META_CHARS, "^$1").replace(CMD_META_CHARS, "^$1");
}
