import { EXIT_TOOL_ERROR } from "../commands/types.js";
import { leaveTui, tuiIsActive } from "../scan-ui/alt-screen.js";

export interface FatalIo {
  readonly writeStderr: (text: string) => void;
  readonly exit: (code: number) => void;
  readonly tuiIsActive: () => boolean;
  readonly leaveTui: () => void;
}

const defaultIo: FatalIo = {
  writeStderr: (text) => {
    process.stderr.write(text);
  },
  exit: (code) => {
    process.exit(code);
  },
  tuiIsActive,
  leaveTui
};

// Anything written while the alt screen is active is discarded when the exit handler restores the main screen.
export function exitOnFatal(error: unknown, io: FatalIo = defaultIo): void {
  const message = error instanceof Error ? error.message : String(error);
  try {
    if (io.tuiIsActive()) {
      io.leaveTui();
    }
  } catch {
    // screen restore must never mask the fatal report
  }
  try {
    io.writeStderr(
      `dg: unexpected error — ${message}\nRun 'dg doctor' to check your installation; remove ~/.dg/config.json if it is corrupted.\n`
    );
  } catch {
    // stderr is gone; nothing left to report to.
  }
  io.exit(EXIT_TOOL_ERROR);
}
