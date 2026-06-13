import {
  BIDI_OVERRIDE_RE,
  CONTENT_RULES,
  DANGEROUS_SCRIPT_RE,
  FILENAME_RULES,
  INVISIBLE_UNICODE_RE,
  RISKY_SCRIPT_NAMES,
  type AuditCategory,
  type AuditSeverity
} from "./rules.js";

export interface AuditFile {
  readonly path: string;
  readonly size: number;
  readonly isSymlink: boolean;
  readonly symlinkEscapes: boolean;
  readonly mode: number;
  readonly read: () => Buffer | null;
}

export interface AuditContext {
  readonly packageJson: Record<string, unknown> | null;
  readonly ecosystem: "npm" | "pypi" | "cargo" | "unknown";
  readonly hasFilesAllowlist: boolean;
  readonly fileCount: number;
}

export interface AuditFinding {
  readonly id: string;
  readonly category: AuditCategory;
  readonly severity: AuditSeverity;
  readonly title: string;
  readonly recommendation: string;
  readonly location: string;
  readonly evidence: string;
  readonly line?: number;
}

export function findingLocation(finding: AuditFinding): string {
  return finding.line ? `${finding.location}:${finding.line}` : finding.location;
}

function lineAt(body: string, index: number): number {
  let line = 1;
  for (let cursor = 0; cursor < index && cursor < body.length; cursor += 1) {
    if (body.charCodeAt(cursor) === 10) {
      line += 1;
    }
  }
  return line;
}

const MAX_CONTENT_BYTES = 5 * 1024 * 1024;

export function detectFindings(files: readonly AuditFile[], context: AuditContext): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const seen = new Set<string>();
  const push = (finding: AuditFinding): void => {
    const key = `${finding.id}|${finding.location}`;
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    findings.push(finding);
  };

  for (const file of files) {
    structuralFileChecks(file, push);
    filenameChecks(file, push);
    contentChecks(file, push);
  }

  const manifest = files.find((file) => file.path === "package.json");
  structuralProjectChecks(context, push);
  lifecycleChecks(context, push, manifest ? readText(manifest) : null);

  return findings.sort((left, right) => right.severity - left.severity || left.location.localeCompare(right.location));
}

function structuralFileChecks(file: AuditFile, push: (finding: AuditFinding) => void): void {
  if (file.symlinkEscapes) {
    push({
      id: "symlink-escape",
      category: "structural",
      severity: 5,
      title: "Symlink points outside the package",
      recommendation: "Remove the symlink — it can leak host files or escape extraction.",
      location: file.path,
      evidence: `symlink: ${file.path}`
    });
  }
  if ((file.mode & 0o4000) !== 0 || (file.mode & 0o2000) !== 0) {
    push({
      id: "setuid-bit",
      category: "structural",
      severity: 5,
      title: "File has a setuid/setgid bit",
      recommendation: "Strip the setuid/setgid bit — it is a privilege-escalation vector.",
      location: file.path,
      evidence: `mode: ${file.mode.toString(8)}`
    });
  }
  if (INVISIBLE_UNICODE_RE.test(file.path)) {
    push({
      id: "trojan-source-filename",
      category: "structural",
      severity: 4,
      title: "Invisible/bidi unicode in a filename",
      recommendation: "Rename the file — hidden unicode can disguise a malicious filename.",
      location: file.path,
      evidence: "invisible unicode in path"
    });
  }
}

function filenameChecks(file: AuditFile, push: (finding: AuditFinding) => void): void {
  for (const rule of FILENAME_RULES) {
    if (!rule.re.test(file.path)) {
      continue;
    }
    if (rule.exempt && rule.exempt.test(file.path)) {
      continue;
    }
    if (rule.gateContent) {
      const body = readText(file);
      if (body === null || !rule.gateContent.test(body)) {
        continue;
      }
    }
    push({
      id: rule.id,
      category: rule.category,
      severity: rule.severity,
      title: rule.title,
      recommendation: rule.recommendation,
      location: file.path,
      evidence: `path: ${file.path}`
    });
  }
}

function contentChecks(file: AuditFile, push: (finding: AuditFinding) => void): void {
  const body = readText(file);
  if (body === null) {
    return;
  }
  const bidiIndex = body.search(BIDI_OVERRIDE_RE);
  if (bidiIndex !== -1) {
    push({
      id: "trojan-source-content",
      category: "structural",
      severity: 4,
      title: "Bidirectional-override unicode in source",
      recommendation: "Remove the bidi control characters — they hide code from human review.",
      location: file.path,
      evidence: "bidi override character in file",
      line: lineAt(body, bidiIndex)
    });
  }
  for (const rule of CONTENT_RULES) {
    const match = body.match(rule.re);
    if (!match) {
      continue;
    }
    if (rule.allow && rule.allow.test(match[0])) {
      continue;
    }
    push({
      id: rule.id,
      category: rule.category,
      severity: rule.severity,
      title: rule.title,
      recommendation: rule.recommendation,
      location: file.path,
      evidence: redact(match[0]),
      line: lineAt(body, body.indexOf(match[0]))
    });
  }
}

function structuralProjectChecks(context: AuditContext, push: (finding: AuditFinding) => void): void {
  if (context.ecosystem === "npm" && context.packageJson) {
    if (!context.hasFilesAllowlist) {
      push({
        id: "no-files-allowlist",
        category: "structural",
        severity: 3,
        title: "No publish allowlist — the whole directory may ship",
        recommendation: "Add a \"files\" array to package.json (or an .npmignore) so only intended files publish.",
        location: "package.json",
        evidence: "no \"files\" field and no .npmignore"
      });
    }
  }
  if (context.ecosystem === "pypi" && !context.hasFilesAllowlist) {
    push({
      id: "no-manifest-discipline",
      category: "structural",
      severity: 3,
      title: "No MANIFEST.in / packaging include discipline",
      recommendation: "Define an explicit include set (MANIFEST.in or pyproject include) so the sdist does not sweep the repo.",
      location: ".",
      evidence: "no MANIFEST.in / include config"
    });
  }
}

function lifecycleChecks(context: AuditContext, push: (finding: AuditFinding) => void, manifestText: string | null = null): void {
  const scripts = context.packageJson && isRecord(context.packageJson.scripts) ? context.packageJson.scripts : null;
  if (!scripts) {
    return;
  }
  const scriptLine = (name: string): number | undefined => {
    if (!manifestText) {
      return undefined;
    }
    const index = manifestText.indexOf(`"${name}"`);
    return index === -1 ? undefined : lineAt(manifestText, index);
  };
  for (const [name, value] of Object.entries(scripts)) {
    if (typeof value !== "string") {
      continue;
    }
    const risky = RISKY_SCRIPT_NAMES.includes(name);
    const line = scriptLine(name);
    if (DANGEROUS_SCRIPT_RE.test(value)) {
      push({
        id: "lifecycle-dangerous",
        category: "lifecycle-risk",
        severity: risky ? 4 : 3,
        title: `Dangerous shell pattern in the ${name} script`,
        recommendation: `Review the ${name} script — it fetches-and-runs, evals, or pipes to a shell.`,
        location: "package.json",
        evidence: redact(`${name}: ${value}`, 90),
        ...(line ? { line } : {})
      });
    } else if (risky) {
      push({
        id: "lifecycle-present",
        category: "lifecycle-risk",
        severity: 2,
        title: `Install-time ${name} script present`,
        recommendation: `The ${name} script runs on every consumer's install — confirm it is intentional and safe.`,
        location: "package.json",
        evidence: redact(`${name}: ${value}`, 90),
        ...(line ? { line } : {})
      });
    }
  }
}

function readText(file: AuditFile): string | null {
  if (file.size === 0 || file.size > MAX_CONTENT_BYTES) {
    return null;
  }
  const buffer = file.read();
  if (buffer === null || buffer.length === 0) {
    return null;
  }
  const sniffLength = Math.min(buffer.length, 8192);
  for (let index = 0; index < sniffLength; index += 1) {
    if (buffer[index] === 0) {
      return null;
    }
  }
  return buffer.toString("utf8");
}

export function redact(value: string, max = 64): string {
  const collapsed = value.replace(/[\r\n]+/gu, " ").trim();
  const masked = collapsed.replace(/[A-Za-z0-9_+/=-]{16,}/gu, (match) => `${match.slice(0, 4)}***`);
  return masked.length > max ? `${masked.slice(0, max - 1)}…` : masked;
}

export function actionForFindings(findings: readonly AuditFinding[]): "pass" | "warn" | "block" {
  if (findings.some((finding) => finding.severity >= 4)) {
    return "block";
  }
  if (findings.some((finding) => finding.severity >= 3)) {
    return "warn";
  }
  return "pass";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
