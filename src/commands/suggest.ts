const MAX_SUGGESTION_DISTANCE = 3;

function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const width = n + 1;
  const dp = new Int32Array((m + 1) * width);
  for (let i = 0; i <= m; i += 1) {
    dp[i * width] = i;
  }
  for (let j = 0; j <= n; j += 1) {
    dp[j] = j;
  }
  for (let i = 1; i <= m; i += 1) {
    for (let j = 1; j <= n; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const up = dp[(i - 1) * width + j] ?? 0;
      const left = dp[i * width + (j - 1)] ?? 0;
      const diagonal = dp[(i - 1) * width + (j - 1)] ?? 0;
      dp[i * width + j] = Math.min(up + 1, left + 1, diagonal + cost);
    }
  }
  return dp[m * width + n] ?? 0;
}

export function closestCommand(input: string, commands: readonly string[]): string | null {
  let best: string | null = null;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (const command of commands) {
    const distance = editDistance(input, command);
    if (distance < bestDistance) {
      bestDistance = distance;
      best = command;
    }
  }
  return best !== null && bestDistance <= MAX_SUGGESTION_DISTANCE ? best : null;
}
