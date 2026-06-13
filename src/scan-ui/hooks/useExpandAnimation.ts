import { useState, useEffect, useRef } from "react";

interface UseExpandAnimationResult {
  visibleLines: number;
  isAnimating: boolean;
}

export function useExpandAnimation(
  targetHeight: number,
  active: boolean,
  durationMs: number = 180
): UseExpandAnimationResult {
  const [visibleLines, setVisibleLines] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }

    if (!active || targetHeight <= 0) {
      setVisibleLines(0);
      return;
    }

    const intervalMs = Math.max(16, Math.floor(durationMs / targetHeight));
    let current = 1;
    setVisibleLines(1);

    timerRef.current = setInterval(() => {
      current++;
      if (current >= targetHeight) {
        setVisibleLines(targetHeight);
        if (timerRef.current) clearInterval(timerRef.current);
        timerRef.current = null;
      } else {
        setVisibleLines(current);
      }
    }, intervalMs);

    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [active, targetHeight, durationMs]);

  return {
    visibleLines: active ? visibleLines : 0,
    isAnimating: active && visibleLines > 0 && visibleLines < targetHeight,
  };
}
