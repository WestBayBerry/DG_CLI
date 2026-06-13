import chalk from "chalk";
import { sanitize } from "../security/sanitize.js";
import { APIPackageResult, UsageBlock } from "./api-aliases.js";

export const USAGE_NEAR_LIMIT_RATIO = 0.8;

export function formatUsage(usage: UsageBlock): { text: string; nearLimit: boolean } {
  const used = usage.used.toLocaleString();
  if (usage.limit === null) {
    return { text: `${used} packages this month`, nearLimit: false };
  }
  return {
    text: `${used} / ${usage.limit.toLocaleString()} packages this month`,
    nearLimit: usage.used / usage.limit >= USAGE_NEAR_LIMIT_RATIO,
  };
}

export function formatAccountStatus(tier: string, loggedIn: boolean, name?: string): string {
  const cleaned = sanitize(tier).trim().slice(0, 24).toLowerCase();
  const label = cleaned ? cleaned.charAt(0).toUpperCase() + cleaned.slice(1) : loggedIn ? "Account" : "Free";
  if (!loggedIn) {
    return `${chalk.dim(`${label} · `)}${chalk.cyan.bold("dg login")}`;
  }
  const plan = (cleaned === "free" ? chalk.yellow : chalk.green)(`${label} plan`);
  const who = name ? sanitize(name).trim().slice(0, 40) : "";
  return who ? `${chalk.dim(`${who} · `)}${plan}` : plan;
}

function isWideCodePoint(cp: number): boolean {
  return (
    cp >= 0x1100 &&
    (cp <= 0x115f ||
      cp === 0x2329 ||
      cp === 0x232a ||
      (cp >= 0x2e80 && cp <= 0xa4cf && cp !== 0x303f) ||
      (cp >= 0xac00 && cp <= 0xd7a3) ||
      (cp >= 0xf900 && cp <= 0xfaff) ||
      (cp >= 0xfe10 && cp <= 0xfe19) ||
      (cp >= 0xfe30 && cp <= 0xfe6b) ||
      (cp >= 0xff00 && cp <= 0xff60) ||
      (cp >= 0xffe0 && cp <= 0xffe6) ||
      (cp >= 0x1f300 && cp <= 0x1f64f) ||
      (cp >= 0x1f900 && cp <= 0x1f9ff) ||
      (cp >= 0x20000 && cp <= 0x3fffd))
  );
}

function isZeroWidthCodePoint(cp: number): boolean {
  return (
    (cp >= 0x0300 && cp <= 0x036f) ||
    (cp >= 0x1ab0 && cp <= 0x1aff) ||
    (cp >= 0x20d0 && cp <= 0x20ff) ||
    (cp >= 0xfe00 && cp <= 0xfe0f) ||
    (cp >= 0x200b && cp <= 0x200f) ||
    cp === 0xfeff
  );
}

function codePointWidth(cp: number): number {
  if (isZeroWidthCodePoint(cp)) return 0;
  return isWideCodePoint(cp) ? 2 : 1;
}

export function displayWidth(s: string): number {
  let width = 0;
  for (const ch of s) {
    width += codePointWidth(ch.codePointAt(0) ?? 0);
  }
  return width;
}

export function pad(s: string, len: number): string {
  return s + " ".repeat(Math.max(0, len - displayWidth(s)));
}

export function truncate(s: string, max: number): string {
  if (displayWidth(s) <= max) return s;
  let out = "";
  let width = 0;
  for (const ch of s) {
    const w = codePointWidth(ch.codePointAt(0) ?? 0);
    if (width + w > max - 1) break;
    out += ch;
    width += w;
  }
  return out + "…";
}

export interface PackageGroup {
  packages: APIPackageResult[];
  key: string;
}

export type GroupKeyStrategy = "name" | "fingerprint";

export function groupPackages(
  packages: APIPackageResult[],
  keyBy: GroupKeyStrategy = "name",
): PackageGroup[] {
  const map = new Map<string, APIPackageResult[]>();

  for (const pkg of packages) {
    const action = pkg.action ?? "pass";
    const fingerprint =
      pkg.findings.length === 0
        ? `${action}|${pkg.name}@${pkg.version ?? ""}|score:${pkg.score}`
        : `${action}|` + pkg.findings
            .map((f) => `${f.category ?? ""}:${f.severity}`)
            .sort()
            .join("|") + `|score:${pkg.score}`;

    const group = map.get(fingerprint) ?? [];
    group.push(pkg);
    map.set(fingerprint, group);
  }

  return [...map.entries()]
    .map(([fingerprint, pkgs]) => ({
      packages: pkgs,
      key: keyBy === "fingerprint" ? fingerprint : pkgs[0]?.name ?? "",
    }))
    .sort((a, b) => (b.packages[0]?.score ?? 0) - (a.packages[0]?.score ?? 0));
}
