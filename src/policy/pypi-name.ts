export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

// crates.io is case-insensitive and treats '-' and '_' as equivalent, so fold
// both to a single canonical form for exemption matching.
export function normalizeCargoName(name: string): string {
  return name.toLowerCase().replace(/_/g, "-");
}

export function canonicalCooldownName(ecosystem: "npm" | "pypi" | "cargo", name: string): string {
  if (ecosystem === "pypi") {
    return normalizePypiName(name);
  }
  if (ecosystem === "cargo") {
    return normalizeCargoName(name);
  }
  return name;
}
