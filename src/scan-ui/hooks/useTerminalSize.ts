import { useState, useEffect } from "react";
import { useStdout } from "ink";

export function useTerminalSize() {
  const { stdout } = useStdout();
  const [size, setSize] = useState({
    rows: stdout?.rows ?? process.stdout.rows ?? 24,
    cols: stdout?.columns ?? process.stdout.columns ?? 80,
  });

  useEffect(() => {
    const handle = () => {
      setSize({
        rows: process.stdout.rows ?? 24,
        cols: process.stdout.columns ?? 80,
      });
    };
    process.stdout.setMaxListeners(process.stdout.getMaxListeners() + 1);
    process.stdout.on("resize", handle);
    return () => {
      process.stdout.off("resize", handle);
      process.stdout.setMaxListeners(Math.max(0, process.stdout.getMaxListeners() - 1));
    };
  }, []);

  return size;
}
