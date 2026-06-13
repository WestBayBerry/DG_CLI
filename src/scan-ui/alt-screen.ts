const ESC = "\x1b";
const ALT_SCREEN_ON = `${ESC}[?1049h`;
const ALT_SCREEN_OFF = `${ESC}[?1049l`;
const HIDE_CURSOR = `${ESC}[?25l`;
const SHOW_CURSOR = `${ESC}[?25h`;
const MOUSE_1000_OFF = `${ESC}[?1000l`;
const MOUSE_1003_OFF = `${ESC}[?1003l`;
export const CLEAR_HOME = `${ESC}[2J${ESC}[H`;
const CLEAR_LINE = `\r${ESC}[2K`;

const TITLE = "Dependency Guardian";
const TITLE_OSC = `${ESC}]0;${TITLE}\x07`;
const TITLE_PUSH = `${ESC}[22;0t`;
const TITLE_POP = `${ESC}[23;0t`;

let tuiActive = false;
let tuiHandle: ReturnType<typeof setInterval> | null = null;
let signalRegistrations: ReadonlyArray<{ readonly signal: NodeJS.Signals; readonly handler: () => void }> = [];
let exitHandler: (() => void) | null = null;

const SIGNAL_EXIT_CODES: Partial<Record<NodeJS.Signals, number>> = {
  SIGHUP: 129,
  SIGINT: 130,
  SIGTERM: 143
};

function installRestoreHandlers(): void {
  exitHandler = () => leaveTui();
  process.once("exit", exitHandler);
  signalRegistrations = (["SIGHUP", "SIGINT", "SIGTERM"] as const).map((signal) => {
    const handler = (): void => {
      leaveTui();
      process.exit(SIGNAL_EXIT_CODES[signal] ?? 1);
    };
    process.once(signal, handler);
    return { signal, handler };
  });
}

function removeRestoreHandlers(): void {
  if (exitHandler) {
    process.off("exit", exitHandler);
    exitHandler = null;
  }
  for (const registration of signalRegistrations) {
    process.off(registration.signal, registration.handler);
  }
  signalRegistrations = [];
}

export function enterTui(): void {
  if (!process.stdout.isTTY || tuiActive) return;
  process.stdout.write(
    CLEAR_LINE + ALT_SCREEN_ON + HIDE_CURSOR + MOUSE_1000_OFF + MOUSE_1003_OFF + CLEAR_HOME + TITLE_PUSH + TITLE_OSC,
  );
  tuiActive = true;
  installRestoreHandlers();
  if (!tuiHandle) tuiHandle = setInterval(() => { /* hold event loop */ }, 60000);
}

export function leaveTui(): void {
  if (!tuiActive) return;
  if (tuiHandle) { clearInterval(tuiHandle); tuiHandle = null; }
  process.stdout.write(
    MOUSE_1003_OFF + MOUSE_1000_OFF + SHOW_CURSOR + ALT_SCREEN_OFF + TITLE_POP,
  );
  tuiActive = false;
  removeRestoreHandlers();
}

export function clearScreen(): void {
  if (!process.stdout.isTTY) return;
  process.stdout.write(CLEAR_HOME);
}

export function showCursor(): void {
  if (!process.stdout.isTTY) return;
  process.stdout.write(SHOW_CURSOR);
}

export function tuiIsActive(): boolean {
  return tuiActive;
}

export function __resetTuiStateForTests(): void {
  tuiActive = false;
  removeRestoreHandlers();
}
