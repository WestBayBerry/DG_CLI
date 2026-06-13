import chalk from "chalk";

export type LogoAction = "block" | "warn" | "pass" | "analysis_incomplete";

function plot(grid: number[][], x: number, y: number, type: number) {
  const row = grid[y];
  if (!row || x < 0 || x >= row.length) return;
  row[x] = Math.max(row[x] ?? 0, type);
}

function bresenham(grid: number[][], x0: number, y0: number, x1: number, y1: number, type: number) {
  const dx = Math.abs(x1 - x0), dy = Math.abs(y1 - y0);
  const sx = x0 < x1 ? 1 : -1, sy = y0 < y1 ? 1 : -1;
  let err = dx - dy, x = x0, y = y0;
  while (true) {
    plot(grid, x, y, type);
    if (x === x1 && y === y1) break;
    const e2 = 2 * err;
    if (e2 > -dy) { err -= dy; x += sx; }
    if (e2 < dx) { err += dx; y += sy; }
  }
}

function fillCircle(grid: number[][], cx: number, cy: number, r: number, type: number) {
  for (let y = Math.floor(cy - r); y <= Math.ceil(cy + r); y++)
    for (let x = Math.floor(cx - r); x <= Math.ceil(cx + r); x++)
      if ((x - cx) ** 2 + (y - cy) ** 2 <= r * r) plot(grid, x, y, type);
}

const LOGO_DATA = (() => {
  const W = 22, H = 28;
  const grid: number[][] = Array.from({ length: H }, () => Array(W).fill(0));
  const cx = 11, cy = 14, R = 10;
  const angles = [270, 315, 0, 45, 90, 135, 180, 225];
  const nodes: [number, number][] = angles.map(a => {
    const rad = a * Math.PI / 180;
    return [Math.round(cx + R * Math.cos(rad)), Math.round(cy + R * Math.sin(rad))];
  });

  for (const [nx, ny] of nodes) bresenham(grid, cx, cy, nx, ny, 1);
  nodes.forEach(([nx, ny], i) => fillCircle(grid, nx, ny, 1.5, i === 1 ? 4 : 2));
  fillCircle(grid, cx, cy, 3, 3);

  const chars: string[] = [];
  const types: number[] = [];
  for (let row = 0; row < H; row += 4) {
    for (let col = 0; col < W; col += 2) {
      let bits = 0, maxType = 0;
      const offsets: [number, number, number][] = [
        [0, 0, 1], [1, 0, 2], [2, 0, 4], [3, 0, 64],
        [0, 1, 8], [1, 1, 16], [2, 1, 32], [3, 1, 128],
      ];
      for (const [dy, dx, bit] of offsets) {
        const py = row + dy, px = col + dx;
        const cell = grid[py]?.[px] ?? 0;
        if (py < H && px < W && cell > 0) {
          bits |= bit;
          maxType = Math.max(maxType, cell);
        }
      }
      chars.push(String.fromCharCode(0x2800 + bits));
      types.push(maxType);
    }
  }
  return { chars, types, cols: W / 2 };
})();

export function renderLogo(action: LogoAction): string[] {
  const colors: Record<number, (s: string) => string> = {
    1: chalk.dim,
    2: chalk.white,
    3: (s: string) => chalk.bold.white(s),
    4: action === "block" ? chalk.red
      : action === "warn" ? chalk.yellow
      : action === "analysis_incomplete" ? chalk.cyan
      : chalk.green,
  };
  const result: string[] = [];
  const { chars, types, cols } = LOGO_DATA;
  for (let i = 0; i < chars.length; i += cols) {
    let row = "";
    for (let j = 0; j < cols; j++) {
      const ch = chars[i + j] ?? "";
      const t = types[i + j] ?? 0;
      row += t > 0 ? (colors[t] ?? chalk.dim)(ch) : ch;
    }
    result.push(row);
  }
  return result;
}
