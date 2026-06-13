import { useEffect, useState } from "react";
import { useStdout } from "ink";
import { CLEAR_HOME } from "../alt-screen.js";

// Ink skips repainting when output matches its memoized last frame, so a bare
// screen clear on resize leaves the TUI blank until the next state change.
// useStdout().write is the only public path that erases and repaints the
// memoized frame unconditionally; CLEAR_HOME first wipes resize artifacts.
export function useResizeRepaint(): void {
  const { stdout, write } = useStdout();
  const [resizes, setResizes] = useState(0);

  useEffect(() => {
    const handle = (): void => setResizes((count) => count + 1);
    stdout.setMaxListeners(stdout.getMaxListeners() + 1);
    stdout.on("resize", handle);
    return () => {
      stdout.off("resize", handle);
      stdout.setMaxListeners(Math.max(0, stdout.getMaxListeners() - 1));
    };
  }, [stdout]);

  useEffect(() => {
    if (resizes === 0) return;
    write(CLEAR_HOME);
  }, [resizes, write]);
}
