import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { analyzePackages, AnalyzeError, type AnalyzeEcosystem, type ScannerPackageResult } from "../api/analyze.js";
import { createTheme, type ScannerAction, type Theme } from "../presentation/theme.js";
import { provenanceLabel, provenanceDowngradeLine } from "../presentation/provenance.js";
import { packagePageUrl } from "../presentation/package-page.js";
import { resolvePresentation } from "../presentation/mode.js";
import { isRemotePackageSpec, isSupportedLockfilePath } from "./preflight.js";
import { authStatus } from "../auth/store.js";
import { EXIT_TOOL_ERROR, EXIT_UNAVAILABLE, EXIT_USAGE_VERDICT, type CommandResult } from "../commands/types.js";

const REGISTRIES: Record<string, AnalyzeEcosystem> = { npm: "npm", pypi: "pypi" };
const DEEP_VERIFY_HINT = "deep verify supports npm and pypi: dg verify npm:<package> or pypi:<package>";

type ParsedSpec = { ecosystem: AnalyzeEcosystem; name: string; version: string | null };

function parseSpec(target: string): ParsedSpec | { error: string } | null {
  const colon = target.indexOf(":");
  if (colon < 0) {
    return null;
  }
  const registry = target.slice(0, colon).toLowerCase();
  const ecosystem = REGISTRIES[registry];
  if (!ecosystem) {
    if (registry === "cargo") {
      return { error: `the cargo registry is not yet supported. ${DEEP_VERIFY_HINT}` };
    }
    return { error: `unknown registry '${registry}'. ${DEEP_VERIFY_HINT}` };
  }
  const rest = target.slice(colon + 1).trim();
  if (!rest) {
    return { error: `missing package name. ${DEEP_VERIFY_HINT}` };
  }
  const separator = ecosystem === "pypi" ? "==" : "@";
  const at = ecosystem === "npm" ? rest.lastIndexOf("@") : rest.indexOf("==");
  if (ecosystem === "npm" && (at <= 0)) {
    return { ecosystem, name: rest, version: null };
  }
  if (ecosystem === "pypi" && at < 0) {
    return { ecosystem, name: rest, version: null };
  }
  const name = rest.slice(0, at);
  const version = rest.slice(at + separator.length).trim() || null;
  return { ecosystem, name, version };
}

export async function resolveLatest(ecosystem: AnalyzeEcosystem, name: string, fetchImpl: typeof fetch): Promise<string | null> {
  try {
    if (ecosystem === "npm") {
      const response = await fetchImpl(`https://registry.npmjs.org/${encodeNpmPackagePath(name)}`);
      if (!response.ok) {
        return null;
      }
      const body = (await response.json()) as { "dist-tags"?: { latest?: string } };
      return body["dist-tags"]?.latest ?? null;
    }
    const response = await fetchImpl(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
    if (!response.ok) {
      return null;
    }
    const body = (await response.json()) as { info?: { version?: string } };
    return body.info?.version ?? null;
  } catch {
    return null;
  }
}

function provenanceLines(version: string, result: ScannerPackageResult, theme: Theme, withPredicate: boolean): string[] {
  if (!result.provenance) {
    return [];
  }
  const label = withPredicate && result.provenance.predicateType
    ? `provenance ${provenanceLabel(result.provenance)} · ${result.provenance.predicateType}`
    : `provenance ${provenanceLabel(result.provenance)}`;
  const lines = [`  ${theme.paint("muted", label)}`];
  const downgrade = provenanceDowngradeLine(version, result.provenance);
  if (downgrade) {
    lines.push(`  ${theme.paint("warn", `⚠ ${downgrade}`)}`);
  }
  return lines;
}

function reasonGlyph(action: ScannerAction, theme: Theme): string {
  return action === "block" ? theme.paint("block", "✘") : action === "warn" ? theme.paint("warn", "⚠") : theme.paint("muted", "·");
}

function renderResult(spec: ParsedSpec, version: string, result: ScannerPackageResult, theme: Theme, verbose: boolean): string {
  const action: ScannerAction = result.action ?? "pass";
  const badge = theme.badge(action);
  const lines = [`${badge}  ${result.name}@${version} (${spec.ecosystem})  ${theme.paint("muted", `score ${result.score}`)}`];
  lines.push(...provenanceLines(version, result, theme, verbose));
  const reasons = verbose ? result.reasons : result.reasons.slice(0, 6);
  for (const reason of reasons) {
    lines.push(`  ${reasonGlyph(action, theme)} ${reason}`);
  }
  if (!verbose && result.reasons.length > reasons.length) {
    lines.push(`  ${theme.paint("muted", `… ${result.reasons.length - reasons.length} more — rerun with --verbose`)}`);
  }
  if (verbose) {
    for (const finding of result.findings) {
      lines.push(`  ${theme.paint("muted", `finding: ${finding.title}`)}`);
    }
  }
  if (reasons.length === 0 && action === "pass") {
    lines.push(`  ${theme.paint("muted", "no risk signals")}`);
  }
  if (result.recommendation) {
    lines.push(`  ${theme.paint("muted", result.recommendation)}`);
  }
  const page = packagePageUrl(spec.ecosystem, result.name);
  if (page) {
    lines.push(`  ${theme.paint("muted", `→ ${page}`)}`);
  }
  return `${lines.join("\n")}\n`;
}

const FREE_REASON_CAP = 3;
const FREE_SCANS_FOOTER_THRESHOLD = 5_000;

function renderFreeResult(
  spec: ParsedSpec,
  version: string,
  result: ScannerPackageResult,
  theme: Theme,
  freeScansRemaining?: number
): string {
  const action: ScannerAction = result.action ?? "pass";
  const lines = [`${theme.badge(action)}  ${result.name}@${version} (${spec.ecosystem})`];
  lines.push(...provenanceLines(version, result, theme, false));
  if (action === "pass") {
    lines.push(`  ${theme.paint("muted", result.reasons[0] ?? "no risk signals")}`);
  } else {
    const reasons = result.reasons.slice(0, FREE_REASON_CAP);
    for (const reason of reasons) {
      lines.push(`  ${reasonGlyph(action, theme)} ${reason}`);
    }
    if (result.reasons.length > reasons.length) {
      lines.push(
        `  ${theme.paint("muted", `… ${result.reasons.length - reasons.length} more — sign in to see all:`)} ${theme.paint("accent", "dg login")}`
      );
    }
  }
  const page = packagePageUrl(spec.ecosystem, result.name);
  if (page) {
    lines.push(`  ${theme.paint("muted", `→ ${page}`)}`);
  }
  lines.push(`  ${theme.paint("muted", "full findings, license, JSON output:")} ${theme.paint("accent", "dg login")}`);
  if (freeScansRemaining !== undefined && freeScansRemaining < FREE_SCANS_FOOTER_THRESHOLD) {
    lines.push(`  ${theme.paint("muted", `${freeScansRemaining.toLocaleString()} free package checks left this month`)}`);
  }
  return `${lines.join("\n")}\n`;
}

function encodeNpmPackagePath(name: string): string {
  return name.split("/").map((segment) => encodeURIComponent(segment)).join("%2f");
}

function exitCodeFor(action: ScannerAction): number {
  if (action === "block") {
    return 2;
  }
  if (action === "warn") {
    return 1;
  }
  if (action === "analysis_incomplete") {
    return 4;
  }
  return 0;
}

export interface PackageCheckIo {
  readonly fetchImpl?: typeof fetch;
  readonly env?: NodeJS.ProcessEnv;
}

export interface PackageCheckOptions {
  readonly format?: "text" | "json";
  readonly verbose?: boolean;
  readonly outputPath?: string | null;
}

export async function runPackageCheck(target: string, io: PackageCheckIo = {}, options: PackageCheckOptions = {}): Promise<CommandResult> {
  const fetchImpl = io.fetchImpl ?? fetch;
  const theme = createTheme(resolvePresentation().color);

  const accent = (text: string): string => theme.paint("accent", text);
  const muted = (text: string): string => theme.paint("muted", text);
  const authenticated = authStatus(io.env).authenticated;

  if (!authenticated && (options.format === "json" || options.outputPath)) {
    return {
      exitCode: EXIT_UNAVAILABLE,
      stdout: "",
      stderr:
        `\n  ${theme.paint("warn", "⚠")} ${muted("--json and --output for registry checks require sign-in.")}\n` +
        `  ${accent("dg login")}${muted("  ·  see plans at")} ${accent("westbayberry.com/pricing")}\n\n`
    };
  }

  const parsed = parseSpec(target);
  if (parsed === null) {
    return {
      exitCode: EXIT_USAGE_VERDICT,
      stdout: "",
      stderr: `dg verify: add a registry, e.g. dg verify npm:${target} or dg verify pypi:${target}\n`
    };
  }
  if ("error" in parsed) {
    return { exitCode: EXIT_USAGE_VERDICT, stdout: "", stderr: `dg verify: ${parsed.error}\n` };
  }

  let version = parsed.version;
  if (!version) {
    version = await resolveLatest(parsed.ecosystem, parsed.name, fetchImpl);
    if (!version) {
      return {
        exitCode: exitCodeFor("analysis_incomplete"),
        stdout: "",
        stderr: `dg verify: could not resolve the latest version of ${parsed.name} on ${parsed.ecosystem}\n`
      };
    }
  }

  let result: ScannerPackageResult | undefined;
  let freeScansRemaining: number | undefined;
  try {
    const response = await analyzePackages([{ name: parsed.name, version }], {
      ecosystem: parsed.ecosystem,
      fetchImpl,
      ...(io.env ? { env: io.env } : {})
    });
    result = response.packages.find((entry) => entry.name === parsed.name) ?? response.packages[0];
    freeScansRemaining = response.freeScansRemaining;
  } catch (error) {
    if (error instanceof AnalyzeError && error.code === "quota_exceeded") {
      const loginLine = authenticated ? "" : `  ${muted("Run")} ${accent("dg login")} ${muted("to connect your account.")}\n`;
      return {
        exitCode: exitCodeFor("analysis_incomplete"),
        stdout: "",
        stderr: `dg verify: ${error.message}\n${loginLine}  ${muted("see plans at")} ${accent("westbayberry.com/pricing")}\n`
      };
    }
    const message = error instanceof AnalyzeError ? error.message : error instanceof Error ? error.message : "could not reach the scanner";
    return { exitCode: exitCodeFor("analysis_incomplete"), stdout: "", stderr: `dg verify: ${message}\n` };
  }

  if (!result) {
    return { exitCode: exitCodeFor("analysis_incomplete"), stdout: "", stderr: `dg verify: scanner returned no result for ${parsed.name}\n` };
  }

  // A missing per-package action means the scanner did not return a verdict;
  // treat that as incomplete, never as a clean pass.
  const action = result.action ?? "analysis_incomplete";
  const rendered =
    options.format === "json"
      ? `${JSON.stringify(
          {
            target,
            ecosystem: parsed.ecosystem,
            name: result.name,
            version,
            action,
            score: result.score,
            reasons: result.reasons,
            findings: result.findings,
            ...(result.provenance ? { provenance: result.provenance } : {}),
            ...(result.recommendation ? { recommendation: result.recommendation } : {})
          },
          null,
          2
        )}\n`
      : authenticated
        ? renderResult(parsed, version, result, theme, options.verbose ?? false)
        : renderFreeResult(parsed, version, result, theme, freeScansRemaining);
  if (options.outputPath) {
    try {
      writeFileSync(resolve(options.outputPath), rendered, "utf8");
    } catch (error) {
      return {
        exitCode: EXIT_TOOL_ERROR,
        stdout: "",
        stderr: `dg verify could not write ${options.outputPath}: ${error instanceof Error ? error.message : "write error"}\n`
      };
    }
    return { exitCode: exitCodeFor(action), stdout: `Wrote verify report to ${options.outputPath}\n`, stderr: "" };
  }
  return { exitCode: exitCodeFor(action), stdout: rendered, stderr: "" };
}

// Registry specs run the real scanner check here; local paths/lockfiles fall
// through to the advisory handler. --sarif errors rather than silently downgrading.
export async function maybeVerifyPackage(args: readonly string[]): Promise<{ handled: boolean; result: CommandResult }> {
  const noop: CommandResult = { exitCode: 0, stdout: "", stderr: "" };
  if (args[0] !== "verify") {
    return { handled: false, result: noop };
  }
  const rest = args.slice(1);
  if (rest.some((arg) => ["--help", "-h", "help"].includes(arg))) {
    return { handled: false, result: noop };
  }

  let format: "text" | "json" = "text";
  let verbose = false;
  let sarif = false;
  let outputPath: string | null = null;
  let outputFlagMissingPath: string | undefined;
  let target: string | undefined;
  let unknownFlag: string | undefined;
  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (!arg) {
      continue;
    }
    if (arg === "--json") {
      format = "json";
    } else if (arg === "--verbose" || arg === "-v") {
      verbose = true;
    } else if (arg === "--sarif") {
      sarif = true;
    } else if (arg === "--output" || arg === "-o") {
      const next = rest[index + 1];
      if (!next || next.startsWith("-")) {
        outputFlagMissingPath = outputFlagMissingPath ?? arg;
      } else {
        outputPath = next;
        index += 1;
      }
    } else if (arg.startsWith("-")) {
      unknownFlag = unknownFlag ?? arg;
    } else {
      target = target ?? arg;
    }
  }

  if (!target) {
    return { handled: false, result: noop };
  }
  if (isSupportedLockfilePath(target) || existsSync(resolve(target))) {
    return { handled: false, result: noop };
  }
  if (isRemotePackageSpec(target)) {
    return { handled: false, result: noop };
  }
  if (outputFlagMissingPath) {
    return {
      handled: true,
      result: { exitCode: EXIT_USAGE_VERDICT, stdout: "", stderr: `dg verify: ${outputFlagMissingPath} requires a path. Run 'dg verify --help'.\n` }
    };
  }
  if (unknownFlag) {
    return {
      handled: true,
      result: { exitCode: EXIT_USAGE_VERDICT, stdout: "", stderr: `dg verify: unknown option '${unknownFlag}'. Run 'dg verify --help'.\n` }
    };
  }
  if (sarif) {
    return {
      handled: true,
      result: {
        exitCode: EXIT_USAGE_VERDICT,
        stdout: "",
        stderr: "dg verify: --sarif applies to local artifacts and lockfiles; registry package checks support --json.\n"
      }
    };
  }
  return { handled: true, result: await runPackageCheck(target, {}, { format, verbose, outputPath }) };
}
