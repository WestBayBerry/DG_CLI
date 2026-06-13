import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, relative, resolve, sep } from "node:path";
import { gunzipSync, inflateRawSync } from "node:zlib";
import { scanProject } from "../scan/discovery.js";
import type { ScanFinding } from "../scan/types.js";
import type { VerifyArchiveSummary, VerifyFinding, VerifyInputKind, VerifyReport, VerifyStatus } from "./types.js";

const MAX_ARTIFACT_BYTES = 100 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 250 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES = 20000;
const MAX_ARCHIVE_PATH_LENGTH = 240;
const TAR_BLOCK_SIZE = 512;
const GNU_LONGNAME_TYPE = 0x4c;
const GNU_LONGLINK_TYPE = 0x4b;
const PAX_EXTENDED_TYPE = 0x78;
const PAX_GLOBAL_TYPE = 0x67;

type ArchiveScan = {
  summary: VerifyArchiveSummary;
  findings: VerifyFinding[];
  errors: string[];
};

type TarEntry = {
  name: string;
  body: Buffer;
};

export function verifyLocalTarget(targetPath: string, cwd = process.cwd()): VerifyReport {
  const absoluteTarget = resolve(cwd, targetPath);
  if (!existsSync(absoluteTarget)) {
    throw new Error(`path does not exist: ${targetPath}`);
  }

  const targetInfo = statSync(absoluteTarget);
  if (targetInfo.isDirectory()) {
    return verifyPackageProjectTarget(absoluteTarget, cwd);
  }
  if (!targetInfo.isFile()) {
    throw new Error(`path is neither a file nor a directory: ${targetPath}`);
  }
  if (basename(absoluteTarget) === "package.json") {
    return verifyPackageProjectTarget(absoluteTarget, cwd);
  }

  const inputKind = archiveInputKind(absoluteTarget);
  if (!inputKind) {
    throw new Error(`unsupported local verify input: ${targetPath}`);
  }
  if (targetInfo.size > MAX_ARTIFACT_BYTES) {
    return archiveReport({
      absoluteTarget,
      archive: {
        errors: [`artifact is ${targetInfo.size} bytes, above the ${MAX_ARTIFACT_BYTES} byte local verification limit`],
        findings: [],
        summary: {
          entryCount: 0,
          packageManifestCount: 0,
          unpackedSizeBytes: null
        }
      },
      cwd,
      inputKind,
      sha256: sha256File(absoluteTarget),
      sizeBytes: targetInfo.size
    });
  }

  const bytes = readFileSync(absoluteTarget);
  const archive = inputKind === "tarball"
    ? scanTarball(bytes, absoluteTarget)
    : scanZipLike(bytes, absoluteTarget);

  return archiveReport({
    absoluteTarget,
    archive,
    cwd,
    inputKind,
    sha256: sha256Buffer(bytes),
    sizeBytes: targetInfo.size
  });
}

function verifyPackageProjectTarget(absoluteTarget: string, cwd: string): VerifyReport {
  const workspaceScan = scanProject({
    cwd,
    targetPath: absoluteTarget
  });
  const findings = workspaceScan.findings.map(scanFindingToVerifyFinding);
  const errors = workspaceScan.errors.map((error) => `${error.location}: ${error.message}`);
  const inputKind = workspaceScan.summary.projectCount > 1 ? "workspace" : "package-directory";

  return {
    target: displayPath(cwd, absoluteTarget),
    inputKind,
    status: workspaceScan.status,
    sha256: null,
    sizeBytes: null,
    archive: null,
    workspaceScan,
    preflight: null,
    packages: [],
    findings,
    errors,
    summary: summarize(findings, errors)
  };
}

function archiveReport(options: {
  absoluteTarget: string;
  archive: ArchiveScan;
  cwd: string;
  inputKind: VerifyInputKind;
  sha256: string;
  sizeBytes: number;
}): VerifyReport {
  return {
    target: displayPath(options.cwd, options.absoluteTarget),
    inputKind: options.inputKind,
    status: statusFor(options.archive.findings, options.archive.errors),
    sha256: options.sha256,
    sizeBytes: options.sizeBytes,
    archive: options.archive.summary,
    workspaceScan: null,
    preflight: null,
    packages: [],
    findings: options.archive.findings,
    errors: options.archive.errors,
    summary: summarize(options.archive.findings, options.archive.errors)
  };
}

function scanTarball(bytes: Buffer, path: string): ArchiveScan {
  let tarBytes = bytes;
  if (path.endsWith(".tgz") || path.endsWith(".tar.gz")) {
    try {
      tarBytes = gunzipSync(bytes);
    } catch (error) {
      return archiveError(`could not decompress tarball: ${error instanceof Error ? error.message : "unknown gzip error"}`);
    }
  }
  if (tarBytes.length > MAX_UNPACKED_BYTES) {
    return archiveError(`unpacked tarball is above the ${MAX_UNPACKED_BYTES} byte local verification limit`);
  }

  const findings: VerifyFinding[] = [];
  const errors: string[] = [];
  const entries: TarEntry[] = [];
  let offset = 0;
  let unpackedSizeBytes = 0;
  let pendingLongName: string | null = null;
  let pendingPax: Map<string, string> | null = null;
  let globalPax: Map<string, string> | null = null;

  while (offset + TAR_BLOCK_SIZE <= tarBytes.length) {
    const header = tarBytes.subarray(offset, offset + TAR_BLOCK_SIZE);
    if (header.every((byte) => byte === 0)) {
      break;
    }

    const rawName = tarEntryName(header);
    const size = tarEntrySize(header);
    if (size === null) {
      errors.push("tar archive has an unparseable entry size");
      break;
    }
    const bodyOffset = offset + TAR_BLOCK_SIZE;
    const nextOffset = bodyOffset + Math.ceil(size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
    if (rawName.length === 0 || nextOffset > tarBytes.length) {
      errors.push("tar archive has a malformed entry header");
      break;
    }
    const body = tarBytes.subarray(bodyOffset, bodyOffset + size);
    const typeflag = header.readUInt8(156);

    if (typeflag === GNU_LONGNAME_TYPE) {
      pendingLongName = readNullTerminated(body, 0, body.length);
      if (pendingLongName.length === 0) {
        errors.push("tar archive has an empty long-name header");
        break;
      }
      offset = nextOffset;
      continue;
    }
    if (typeflag === GNU_LONGLINK_TYPE) {
      offset = nextOffset;
      continue;
    }
    if (typeflag === PAX_EXTENDED_TYPE || typeflag === PAX_GLOBAL_TYPE) {
      const records = parsePaxRecords(body);
      if (records === null) {
        errors.push("tar archive has an unparseable PAX extended header");
        break;
      }
      if (typeflag === PAX_EXTENDED_TYPE) {
        pendingPax = mergePaxRecords(pendingPax, records);
      } else {
        globalPax = mergePaxRecords(globalPax, records);
      }
      offset = nextOffset;
      continue;
    }

    const paxPath = pendingPax?.get("path") ?? globalPax?.get("path") ?? null;
    if (paxPath !== null && pendingLongName !== null && paxPath !== pendingLongName) {
      errors.push("tar entry name metadata is contradictory");
      break;
    }
    const paxSize = pendingPax?.get("size") ?? null;
    if (paxSize !== null && Number.parseInt(paxSize, 10) !== size) {
      errors.push("tar entry size metadata is contradictory");
      break;
    }
    const name = paxPath ?? pendingLongName ?? rawName;
    pendingLongName = null;
    pendingPax = null;

    unpackedSizeBytes += size;
    entries.push({
      name,
      body
    });
    findings.push(...pathSafetyFindings(name));

    if (entries.length > MAX_ARCHIVE_ENTRIES) {
      findings.push(limitFinding("archive has too many entries"));
      break;
    }
    if (unpackedSizeBytes > MAX_UNPACKED_BYTES) {
      findings.push(limitFinding("archive expands beyond the local verification limit"));
      break;
    }
    offset = nextOffset;
  }

  if (errors.length === 0 && (pendingLongName !== null || pendingPax !== null)) {
    errors.push("tar archive ends with an unapplied extended header");
  }

  findings.push(...packageManifestFindings(entries));

  return {
    findings,
    errors,
    summary: {
      entryCount: entries.length,
      packageManifestCount: packageManifestCount(entries.map((entry) => entry.name)),
      unpackedSizeBytes
    }
  };
}

const ZIP_LOCAL_HEADER_SIG = 0x04034b50;
const ZIP_CENTRAL_HEADER_SIG = 0x02014b50;
const ZIP_EOCD_SIG = 0x06054b50;
const ZIP_DATA_DESCRIPTOR_SIG = 0x08074b50;
const ZIP_EOCD_MIN_BYTES = 22;
const ZIP_EOCD_SEARCH_BYTES = ZIP_EOCD_MIN_BYTES + 0xffff;

type ZipCentralEntry = {
  name: string;
  flags: number;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
};

type ZipCentralDirectory = {
  entries: ZipCentralEntry[];
  centralDirectoryOffset: number;
};

function scanZipLike(bytes: Buffer, path: string): ArchiveScan {
  const central = readZipCentralDirectory(bytes);
  if ("error" in central) {
    return archiveError(`${basename(path)}: ${central.error}`);
  }
  const mismatch = zipLocalHeaderMismatch(bytes, central);
  if (mismatch) {
    return archiveError(`${basename(path)}: ${mismatch}`);
  }

  const findings: VerifyFinding[] = [];
  const errors: string[] = [];
  const entries: TarEntry[] = [];
  let unpackedSizeBytes = 0;

  for (const entry of central.entries) {
    findings.push(...pathSafetyFindings(entry.name));
    if ((entry.flags & 0x1) !== 0) {
      findings.push({
        id: "encrypted-archive-entry",
        severity: "block",
        title: "Encrypted archive entry",
        message: "encrypted archive entries cannot be inspected locally",
        location: entry.name
      });
    }

    unpackedSizeBytes += entry.uncompressedSize;
    entries.push({
      name: entry.name,
      body: readZipEntryBody(bytes, entry, errors)
    });

    if (entries.length > MAX_ARCHIVE_ENTRIES) {
      findings.push(limitFinding("archive has too many entries"));
      break;
    }
    if (unpackedSizeBytes > MAX_UNPACKED_BYTES) {
      findings.push(limitFinding("archive expands beyond the local verification limit"));
      break;
    }
  }

  findings.push(...packageManifestFindings(entries));

  return {
    findings,
    errors,
    summary: {
      entryCount: entries.length,
      packageManifestCount: packageManifestCount(entries.map((entry) => entry.name)),
      unpackedSizeBytes
    }
  };
}

function readZipCentralDirectory(bytes: Buffer): ZipCentralDirectory | { error: string } {
  const eocdOffset = findZipEndOfCentralDirectory(bytes);
  if (eocdOffset === null) {
    return { error: "zip end of central directory record not found" };
  }
  const entryCount = bytes.readUInt16LE(eocdOffset + 10);
  const centralDirectorySize = bytes.readUInt32LE(eocdOffset + 12);
  const centralDirectoryOffset = bytes.readUInt32LE(eocdOffset + 16);
  if (entryCount === 0xffff || centralDirectorySize === 0xffffffff || centralDirectoryOffset === 0xffffffff) {
    return { error: "zip64 archives are not supported by local verification" };
  }
  if (centralDirectoryOffset + centralDirectorySize > eocdOffset) {
    return { error: "zip central directory extends past its end record" };
  }

  const entries: ZipCentralEntry[] = [];
  let offset = centralDirectoryOffset;
  for (let index = 0; index < entryCount; index += 1) {
    if (offset + 46 > eocdOffset || bytes.readUInt32LE(offset) !== ZIP_CENTRAL_HEADER_SIG) {
      return { error: "zip central directory is truncated or malformed" };
    }
    const nameLength = bytes.readUInt16LE(offset + 28);
    const extraLength = bytes.readUInt16LE(offset + 30);
    const commentLength = bytes.readUInt16LE(offset + 32);
    if (offset + 46 + nameLength + extraLength + commentLength > eocdOffset) {
      return { error: "zip central directory is truncated or malformed" };
    }
    entries.push({
      name: bytes.subarray(offset + 46, offset + 46 + nameLength).toString("utf8"),
      flags: bytes.readUInt16LE(offset + 8),
      method: bytes.readUInt16LE(offset + 10),
      compressedSize: bytes.readUInt32LE(offset + 20),
      uncompressedSize: bytes.readUInt32LE(offset + 24),
      localHeaderOffset: bytes.readUInt32LE(offset + 42)
    });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  if (offset !== centralDirectoryOffset + centralDirectorySize) {
    return { error: "zip central directory size disagrees with its entries" };
  }
  return { entries, centralDirectoryOffset };
}

function findZipEndOfCentralDirectory(bytes: Buffer): number | null {
  const searchStart = Math.max(0, bytes.length - ZIP_EOCD_SEARCH_BYTES);
  for (let offset = bytes.length - ZIP_EOCD_MIN_BYTES; offset >= searchStart; offset -= 1) {
    if (bytes.readUInt32LE(offset) === ZIP_EOCD_SIG) {
      const commentLength = bytes.readUInt16LE(offset + 20);
      if (offset + ZIP_EOCD_MIN_BYTES + commentLength === bytes.length) {
        return offset;
      }
    }
  }
  return null;
}

function zipLocalHeaderMismatch(bytes: Buffer, central: ZipCentralDirectory): string | null {
  const { entries, centralDirectoryOffset } = central;
  const claimed = new Map<number, ZipCentralEntry>();
  for (const entry of entries) {
    if (claimed.has(entry.localHeaderOffset)) {
      return "zip central directory lists overlapping local entries";
    }
    claimed.set(entry.localHeaderOffset, entry);
  }

  for (const entry of entries) {
    const offset = entry.localHeaderOffset;
    if (offset + 30 > centralDirectoryOffset || bytes.readUInt32LE(offset) !== ZIP_LOCAL_HEADER_SIG) {
      return "zip central directory points at a missing local file header";
    }
    const flags = bytes.readUInt16LE(offset + 6);
    const compressedSize = bytes.readUInt32LE(offset + 18);
    const nameLength = bytes.readUInt16LE(offset + 26);
    const name = bytes.subarray(offset + 30, offset + 30 + nameLength).toString("utf8");
    if (name !== entry.name) {
      return "zip local file header name disagrees with the central directory";
    }
    if ((flags & 0x8) === 0 && compressedSize !== entry.compressedSize) {
      return "zip local file header size disagrees with the central directory";
    }
  }

  let offset = bytes.length >= 4 && bytes.readUInt32LE(0) === ZIP_LOCAL_HEADER_SIG
    ? 0
    : entries.length > 0
      ? Math.min(...entries.map((entry) => entry.localHeaderOffset))
      : centralDirectoryOffset;
  while (offset + 4 <= centralDirectoryOffset && bytes.readUInt32LE(offset) === ZIP_LOCAL_HEADER_SIG) {
    const entry = claimed.get(offset);
    if (!entry) {
      return "zip has a local file entry the central directory does not list";
    }
    const nameLength = bytes.readUInt16LE(offset + 26);
    const extraLength = bytes.readUInt16LE(offset + 28);
    let next = offset + 30 + nameLength + extraLength + entry.compressedSize;
    if ((entry.flags & 0x8) !== 0) {
      next += next + 4 <= centralDirectoryOffset && bytes.readUInt32LE(next) === ZIP_DATA_DESCRIPTOR_SIG ? 16 : 12;
    }
    if (next > centralDirectoryOffset) {
      return "zip local entry data extends into the central directory";
    }
    offset = next;
  }
  return null;
}

function readZipEntryBody(bytes: Buffer, entry: ZipCentralEntry, errors: string[]): Buffer {
  if ((entry.flags & 0x1) !== 0) {
    return Buffer.alloc(0);
  }
  const headerOffset = entry.localHeaderOffset;
  const nameLength = bytes.readUInt16LE(headerOffset + 26);
  const extraLength = bytes.readUInt16LE(headerOffset + 28);
  const dataStart = headerOffset + 30 + nameLength + extraLength;
  if (dataStart + entry.compressedSize > bytes.length) {
    errors.push(`${entry.name}: zip entry data is truncated`);
    return Buffer.alloc(0);
  }
  return readZipBody(bytes.subarray(dataStart, dataStart + entry.compressedSize), entry.method, entry.name, errors);
}

function readZipBody(data: Buffer, method: number, name: string, errors: string[]): Buffer {
  if (method === 0) {
    return data;
  }
  if (method === 8) {
    try {
      return inflateRawSync(data);
    } catch (error) {
      errors.push(`${name}: could not inflate zip entry: ${error instanceof Error ? error.message : "unknown inflate error"}`);
      return Buffer.alloc(0);
    }
  }
  errors.push(`${name}: unsupported zip compression method ${method}`);
  return Buffer.alloc(0);
}

function packageManifestFindings(entries: readonly TarEntry[]): VerifyFinding[] {
  const findings: VerifyFinding[] = [];
  for (const entry of entries) {
    if (!entry.name.endsWith("package.json")) {
      continue;
    }
    try {
      const parsed = JSON.parse(entry.body.toString("utf8")) as unknown;
      if (isRecord(parsed) && isRecord(parsed.scripts)) {
        for (const scriptName of Object.keys(parsed.scripts).sort()) {
          if (["preinstall", "install", "postinstall", "prepare"].includes(scriptName)) {
            findings.push({
              id: "npm-lifecycle-script",
              severity: "warn",
              title: "Install lifecycle script present",
              message: `script '${scriptName}' can execute during package manager installs`,
              location: `${entry.name}:scripts.${scriptName}`
            });
          }
        }
      }
    } catch (error) {
      findings.push({
        id: "malformed-package-manifest",
        severity: "block",
        title: "Malformed package manifest",
        message: error instanceof Error ? error.message : "package.json could not be parsed",
        location: entry.name
      });
    }
  }
  return findings;
}

function pathSafetyFindings(entryPath: string): VerifyFinding[] {
  const findings: VerifyFinding[] = [];
  if (!isSafeArchivePath(entryPath)) {
    findings.push({
      id: "archive-path-traversal",
      severity: "block",
      title: "Unsafe archive path",
      message: "archive entry escapes the extraction root or uses an unsafe absolute path",
      location: entryPath
    });
  }
  if (entryPath.length > MAX_ARCHIVE_PATH_LENGTH) {
    findings.push({
      id: "archive-path-too-long",
      severity: "block",
      title: "Archive path too long",
      message: `archive entry path is longer than ${MAX_ARCHIVE_PATH_LENGTH} characters`,
      location: entryPath
    });
  }
  return findings;
}

function isSafeArchivePath(entryPath: string): boolean {
  if (entryPath.length === 0 || entryPath.includes("\\") || entryPath.startsWith("/") || /^[a-zA-Z]:/.test(entryPath)) {
    return false;
  }
  const parts = entryPath.split("/");
  return !parts.some((part) => part === "..");
}

function archiveInputKind(path: string): VerifyInputKind | null {
  if (path.endsWith(".whl")) {
    return "wheel";
  }
  if (path.endsWith(".zip")) {
    return "zip";
  }
  if (path.endsWith(".tgz") || path.endsWith(".tar.gz") || path.endsWith(".tar")) {
    return "tarball";
  }
  return null;
}

function archiveError(message: string): ArchiveScan {
  return {
    findings: [],
    errors: [message],
    summary: {
      entryCount: 0,
      packageManifestCount: 0,
      unpackedSizeBytes: null
    }
  };
}

function scanFindingToVerifyFinding(finding: ScanFinding): VerifyFinding {
  return {
    id: finding.id,
    severity: finding.severity,
    title: finding.title,
    message: finding.message,
    location: finding.location
  };
}

function packageManifestCount(paths: readonly string[]): number {
  return paths.filter((path) => path.endsWith("package.json")).length;
}

function limitFinding(message: string): VerifyFinding {
  return {
    id: "archive-size-limit",
    severity: "block",
    title: "Archive safety limit exceeded",
    message,
    location: "archive"
  };
}

function statusFor(findings: readonly VerifyFinding[], errors: readonly string[]): VerifyStatus {
  if (errors.length > 0) {
    return "error";
  }
  if (findings.some((finding) => finding.severity === "block")) {
    return "block";
  }
  if (findings.some((finding) => finding.severity === "warn")) {
    return "warn";
  }
  return "pass";
}

function summarize(findings: readonly VerifyFinding[], errors: readonly string[]) {
  return {
    findingCount: findings.length,
    warnCount: findings.filter((finding) => finding.severity === "warn").length,
    blockCount: findings.filter((finding) => finding.severity === "block").length,
    errorCount: errors.length
  };
}

function tarEntryName(header: Buffer): string {
  const name = readNullTerminated(header, 0, 100);
  const prefix = readNullTerminated(header, 345, 155);
  return prefix.length > 0 ? `${prefix}/${name}` : name;
}

function tarEntrySize(header: Buffer): number | null {
  if ((header.readUInt8(124) & 0x80) !== 0) {
    return null;
  }
  const value = readNullTerminated(header, 124, 12).trim();
  if (value.length === 0) {
    return 0;
  }
  if (!/^[0-7]+$/u.test(value)) {
    return null;
  }
  return Number.parseInt(value, 8);
}

function parsePaxRecords(body: Buffer): Map<string, string> | null {
  const records = new Map<string, string>();
  let offset = 0;
  while (offset < body.length) {
    const space = body.indexOf(0x20, offset);
    if (space === -1 || space === offset) {
      return null;
    }
    const lengthText = body.subarray(offset, space).toString("ascii");
    if (!/^\d+$/u.test(lengthText)) {
      return null;
    }
    const length = Number.parseInt(lengthText, 10);
    const recordEnd = offset + length;
    if (length <= space - offset + 1 || recordEnd > body.length || body.readUInt8(recordEnd - 1) !== 0x0a) {
      return null;
    }
    const text = body.subarray(space + 1, recordEnd - 1).toString("utf8");
    const equals = text.indexOf("=");
    if (equals <= 0) {
      return null;
    }
    records.set(text.slice(0, equals), text.slice(equals + 1));
    offset = recordEnd;
  }
  return records;
}

function mergePaxRecords(existing: Map<string, string> | null, incoming: Map<string, string>): Map<string, string> {
  const merged = new Map(existing ?? []);
  for (const [key, value] of incoming) {
    merged.set(key, value);
  }
  return merged;
}

function readNullTerminated(buffer: Buffer, start: number, length: number): string {
  const slice = buffer.subarray(start, start + length);
  const end = slice.indexOf(0);
  return slice.subarray(0, end === -1 ? slice.length : end).toString("utf8");
}

function sha256File(path: string): string {
  return sha256Buffer(readFileSync(path));
}

function sha256Buffer(buffer: Buffer): string {
  return createHash("sha256").update(buffer).digest("hex");
}

function displayPath(root: string, path: string): string {
  const relativePath = relative(resolve(root), resolve(path));
  const display = relativePath.length === 0 ? "." : relativePath;
  return display.split(sep).join("/");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
