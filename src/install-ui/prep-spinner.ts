import { resolvePresentation } from "../presentation/mode.js";
import { createTheme } from "../presentation/theme.js";

export interface PrepSpinner {
  readonly stop: () => void;
}

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const FRAME_INTERVAL_MS = 80;
const CLEAR_LINE = "\r\u001b[2K";

const INACTIVE: PrepSpinner = { stop: () => undefined };

export function startPrepSpinner(
  label: string,
  stream: NodeJS.WriteStream = process.stderr,
  env: NodeJS.ProcessEnv = process.env
): PrepSpinner {
  const presentation = resolvePresentation({ stream, env });
  if (presentation.mode !== "rich") {
    return INACTIVE;
  }
  const theme = createTheme(presentation.color);
  let frame = 0;
  const draw = (): void => {
    stream.write(`\r ${theme.paint("unknown", FRAMES[frame % FRAMES.length] ?? "")} ${label}`);
    frame += 1;
  };
  draw();
  const timer = setInterval(draw, FRAME_INTERVAL_MS);
  timer.unref();
  let stopped = false;
  return {
    stop: (): void => {
      if (stopped) {
        return;
      }
      stopped = true;
      clearInterval(timer);
      stream.write(CLEAR_LINE);
    }
  };
}
