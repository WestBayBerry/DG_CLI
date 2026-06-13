export type Role = "block" | "warn" | "pass" | "unknown" | "muted" | "accent";

export type ScannerAction = "block" | "warn" | "pass" | "analysis_incomplete";

export type SeverityBadge = {
  word: "BLOCK" | "WARN" | "PASS" | "UNKNOWN";
  glyph: string;
  role: Role;
};

const ANSI: Record<Role, string> = {
  block: "\u001b[31m",
  warn: "\u001b[33m",
  pass: "\u001b[32m",
  unknown: "\u001b[36m",
  muted: "\u001b[2m",
  accent: "\u001b[1m"
};

const RESET = "\u001b[0m";

const BADGES: Record<ScannerAction, SeverityBadge> = {
  block: { word: "BLOCK", glyph: "✘", role: "block" },
  warn: { word: "WARN", glyph: "⚠", role: "warn" },
  pass: { word: "PASS", glyph: "✓", role: "pass" },
  analysis_incomplete: { word: "UNKNOWN", glyph: "?", role: "unknown" }
};

export function severityBadge(action: ScannerAction): SeverityBadge {
  return BADGES[action];
}

export type Theme = {
  readonly color: boolean;
  paint(role: Role, text: string): string;
  badge(action: ScannerAction): string;
};

export function createTheme(color: boolean): Theme {
  const paint = (role: Role, text: string): string =>
    color ? `${ANSI[role]}${text}${RESET}` : text;

  return {
    color,
    paint,
    badge(action: ScannerAction): string {
      const { word, glyph, role } = BADGES[action];
      return paint(role, `${glyph} ${word}`);
    }
  };
}
