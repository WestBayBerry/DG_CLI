import { createHash, randomUUID } from "node:crypto";
import { basename, resolve } from "node:path";
import { writeReportAtomic } from "../util/report-writer.js";
import { discoverScanProjects, SBOM_LOCKFILE_ECOSYSTEMS } from "../scan/collect.js";
import { buildCycloneDxSbom, collectSbomComponents, readRootComponent, type CycloneDxBom } from "../sbom/cyclonedx.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme, type Theme } from "../presentation/theme.js";
import { buildSbomRows } from "../sbom-ui/inventory.js";
import { launchSbomTui, shouldLaunchSbomTui } from "../sbom-ui/launch.js";
import { dgVersion } from "./version.js";
import { EXIT_TOOL_ERROR, EXIT_USAGE, type CommandContext, type CommandResult, type CommandSpec } from "./types.js";

export const sbomCommand: CommandSpec = {
  name: "sbom",
  summary: "Inventory the project's dependencies as a CycloneDX 1.5 software bill of materials.",
  usage: "dg sbom [path] [--output <path>] [--reproducible]",
  args: [{ name: "[path]", summary: "Project directory to inventory (default: current directory)." }],
  flags: [
    { flag: "--output", value: "<path>", summary: "Write the document to a file without opening the interactive view (alias -o)." },
    { flag: "--json", summary: "Print the raw CycloneDX document to stdout instead of the interactive view." },
    { flag: "--reproducible", summary: "Byte-stable output: derive the serial number from the components and drop the timestamp (honors SOURCE_DATE_EPOCH)." }
  ],
  examples: ["dg sbom", "dg sbom -o sbom.cdx.json", "dg sbom --json | cyclonedx validate", "dg sbom --reproducible"],
  details: [
    "Reads the project's lockfiles and inventories every resolved dependency as a CycloneDX 1.5 component with its purl, license, and integrity hash.",
    "In a terminal it opens an interactive view: the inventory appears immediately, then dg's scanner runs over the npm and PyPI components and fills in a BLOCK/WARN/PASS verdict per package — malware, provenance downgrades, and cooldown — while cargo stays inventory only. Browse with the arrow keys, search with /, filter with f, and press w to write the document. Signing in unlocks verdicts; without it the view shows the inventory alone.",
    "Piped, with -o, or with --json it stays offline and prints the raw CycloneDX document so you can attach it to a release or feed any CycloneDX-aware tool — no scan, no account needed. Use --reproducible (or set SOURCE_DATE_EPOCH) for identical bytes across runs so a committed SBOM diffs cleanly."
  ],
  handler: (context) => runSbomCommand(context)
};

export function runSbomCommand(
  context: CommandContext,
  cwd: string = process.cwd(),
  now: Date = new Date(),
  env: NodeJS.ProcessEnv = process.env
): CommandResult {
  const parsed = parseArgs(context.args);
  if ("error" in parsed) {
    return { exitCode: EXIT_USAGE, stdout: "", stderr: `dg sbom: ${parsed.error}. Usage: ${sbomCommand.usage}\n` };
  }
  const root = resolve(cwd, parsed.targetPath ?? ".");
  const projects = discoverScanProjects(root, SBOM_LOCKFILE_ECOSYSTEMS);
  const { components, dropped } = collectSbomComponents(projects);
  const rootComponent = readRootComponent(root);
  const reproducible = parsed.reproducible || env.SOURCE_DATE_EPOCH !== undefined;

  const bom = buildCycloneDxSbom(components, {
    ...timestampOption(reproducible, now, env),
    serialNumber: "urn:uuid:00000000-0000-0000-0000-000000000000",
    toolVersion: dgVersion(),
    ...(rootComponent.component ? { rootComponent: rootComponent.component } : {})
  });
  const finalBom: CycloneDxBom = {
    ...bom,
    serialNumber: reproducible ? deterministicSerialNumber(bom) : `urn:uuid:${randomUUID()}`
  };
  const document = `${JSON.stringify(finalBom, null, 2)}\n`;

  const notes: string[] = [];
  if (components.length === 0) {
    notes.push(`dg sbom: no resolvable dependencies found under ${root} — emitting an empty SBOM.`);
  }
  if (dropped.length > 0) {
    notes.push(`dg sbom: omitted ${dropped.length} dependency(ies) without a pinned version (${formatDropped(dropped)}). Pin them (e.g. name==version) to include them.`);
  }
  if (rootComponent.malformed) {
    notes.push(`dg sbom: ${root}/package.json could not be parsed — the SBOM has no named subject component.`);
  }
  const stderr = notes.length > 0 ? `${notes.join("\n")}\n` : "";

  if (parsed.outputPath) {
    try {
      writeReportAtomic(resolve(cwd, parsed.outputPath), document);
    } catch (error) {
      return { exitCode: EXIT_TOOL_ERROR, stdout: "", stderr: `dg sbom: could not write ${parsed.outputPath}: ${error instanceof Error ? error.message : "unknown write error"}\n` };
    }
    return { exitCode: 0, stdout: `Wrote CycloneDX SBOM (${components.length} components) to ${parsed.outputPath}\n`, stderr };
  }

  const presentation = resolvePresentation();
  if (parsed.json || !presentation.isTTY) {
    return { exitCode: 0, stdout: document, stderr };
  }
  const subject = finalBom.metadata.component
    ? `${finalBom.metadata.component.name}${finalBom.metadata.component.version ? `@${finalBom.metadata.component.version}` : ""}`
    : basename(root) || ".";
  if (shouldLaunchSbomTui({ json: parsed.json, outputPath: parsed.outputPath })) {
    void launchSbomTui({ rows: buildSbomRows(components), dropped, subject, document, env, cwd }).then(
      () => process.exit(typeof process.exitCode === "number" ? process.exitCode : 0),
      (error: unknown) => {
        process.stderr.write(`dg sbom view failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
        process.exit(1);
      }
    );
    return { exitCode: 0, stdout: "", stderr: "" };
  }
  return { exitCode: 0, stdout: renderSbomSummary(finalBom, dropped, subject, createTheme(presentation.color)), stderr };
}

const ANSI_PATTERN = /\x1b\[[0-9;]*m/gu;

function visibleWidth(text: string): number {
  return text.replace(ANSI_PATTERN, "").length;
}

export function renderSbomSummary(
  bom: CycloneDxBom,
  dropped: readonly string[],
  subject: string,
  theme: Theme,
  terminalWidth: number = process.stdout.columns ?? 100
): string {
  const components = bom.components;
  const total = components.length;
  const count = (prefix: string): number => components.filter((c) => c["bom-ref"].startsWith(prefix)).length;
  const ecosystems = ([["npm", count("pkg:npm/")], ["pypi", count("pkg:pypi/")], ["cargo", count("pkg:cargo/")]] as const)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);
  const withLicense = components.filter((c) => c.licenses && c.licenses.length > 0).length;
  const withHash = components.filter((c) => c.hashes && c.hashes.length > 0).length;

  const accent = (text: string): string => theme.paint("accent", text);
  const muted = (text: string): string => theme.paint("muted", text);
  const warn = (text: string): string => theme.paint("warn", text);
  const denomWidth = String(total).length;

  const license = { label: "License", covered: withLicense, deficit: total - withLicense, gap: "unknown" };
  const integrity = { label: "Integrity", covered: withHash, deficit: total - withHash, gap: "no checksum" };
  const gapWidth = Math.max(1, String(license.deficit).length, String(integrity.deficit).length);
  const gapClause = (q: typeof license): string => (q.deficit > 0 ? `${String(q.deficit).padStart(gapWidth)} ${q.gap}` : "");
  const clauseWidth = Math.max(gapClause(license).length, gapClause(integrity).length);
  const qualityRow = (q: typeof license): string => {
    const clause = gapClause(q);
    const painted = clause ? warn(clause) : "";
    const fraction = muted(`${String(q.covered).padStart(denomWidth)} / ${total} covered`);
    return `${muted(q.label.padEnd(10))}${painted}${" ".repeat(clauseWidth - clause.length)}   ${fraction}`;
  };

  const breakdown = ecosystems.map(([name, n]) => `${n} ${name}`).join(muted(" · "));
  const rows = [
    `${accent(String(total))} ${total === 1 ? "component" : "components"}${breakdown ? `   ${muted(breakdown)}` : ""}`,
    "",
    qualityRow(license),
    qualityRow(integrity),
    ...(dropped.length > 0
      ? [`${muted("Omitted".padEnd(10))}${warn(`${String(dropped.length).padStart(gapWidth)} unpinned`)}${muted(", left out of the document")}`]
      : []),
    "",
    muted(`CycloneDX 1.5 · ${subject} · inventory only`)
  ];

  const inner = Math.min(Math.max(0, ...rows.map(visibleWidth)), Math.max(24, terminalWidth - 4));
  const bar = muted("─".repeat(inner + 2));
  const side = muted("│");
  const boxed = [
    `${muted("╭")}${bar}${muted("╮")}`,
    ...rows.map((row) => `${side} ${row}${" ".repeat(Math.max(0, inner - visibleWidth(row)))} ${side}`),
    `${muted("╰")}${bar}${muted("╯")}`
  ];

  const footer = [
    `  ${muted("→ write it:")} dg sbom -o sbom.cdx.json  ${muted("· --json prints it")}`,
    `  ${accent("dg scan")} ${muted("for BLOCK / WARN / PASS verdicts")}`
  ];
  return `${[...boxed, ...footer].join("\n")}\n`;
}

function timestampOption(reproducible: boolean, now: Date, env: NodeJS.ProcessEnv): { timestamp?: string } {
  if (!reproducible) {
    return { timestamp: now.toISOString() };
  }
  const epoch = env.SOURCE_DATE_EPOCH;
  if (epoch !== undefined && /^\d+$/.test(epoch.trim())) {
    const date = new Date(Number.parseInt(epoch.trim(), 10) * 1000);
    const iso = Number.isFinite(date.getTime()) ? date.toISOString() : "";
    if (/^\d{4}-/u.test(iso)) {
      return { timestamp: iso };
    }
  }
  return {};
}

function deterministicSerialNumber(bom: CycloneDxBom): string {
  const hex = createHash("sha256").update(JSON.stringify(bom.components)).digest("hex");
  const version = `4${hex.slice(13, 16)}`;
  const variantNibble = ((Number.parseInt(hex.slice(16, 17) || "0", 16) & 0x3) | 0x8).toString(16);
  const variant = `${variantNibble}${hex.slice(17, 20)}`;
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${version}-${variant}-${hex.slice(20, 32)}`;
}

function formatDropped(dropped: readonly string[]): string {
  const shown = dropped.slice(0, 5).join(", ");
  return dropped.length > 5 ? `${shown}, +${dropped.length - 5} more` : shown;
}

type ParsedArgs = { targetPath: string | null; outputPath: string | null; reproducible: boolean; json: boolean };

function parseArgs(args: readonly string[]): ParsedArgs | { error: string } {
  let targetPath: string | null = null;
  let outputPath: string | null = null;
  let reproducible = false;
  let json = false;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === undefined) {
      continue;
    }
    if (arg === "--output" || arg === "-o") {
      const value = args[i + 1];
      if (value === undefined || value.startsWith("-")) {
        return { error: `${arg} needs a path` };
      }
      outputPath = value;
      i += 1;
      continue;
    }
    if (arg.startsWith("--output=")) {
      outputPath = arg.slice("--output=".length);
      continue;
    }
    if (arg === "--reproducible") {
      reproducible = true;
      continue;
    }
    if (arg === "--json") {
      json = true;
      continue;
    }
    if (arg.startsWith("-")) {
      return { error: `unknown flag '${arg}'` };
    }
    if (targetPath !== null) {
      return { error: `unexpected argument '${arg}'` };
    }
    targetPath = arg;
  }
  return { targetPath, outputPath, reproducible, json };
}
