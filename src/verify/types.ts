import type { ScanReport } from "../scan/types.js";

export type VerifyStatus = "pass" | "warn" | "block" | "unknown" | "error";

export type VerifyFormat = "text" | "json" | "sarif";

export type VerifyInputKind =
  | "package-directory"
  | "workspace"
  | "tarball"
  | "zip"
  | "wheel"
  | "package-spec"
  | "lockfile";

export type VerifyPackageIdentity = {
  ecosystem: "npm" | "pypi" | "cargo" | "unknown";
  name: string;
  version: string | null;
  requested: string;
  sourceKind: "package-spec" | "lockfile" | "lockfile-url-fallback";
  resolvedUrl: string | null;
  integrity: string | null;
  license: string | null;
};

export type VerifyFinding = {
  id: string;
  severity: "warn" | "block";
  title: string;
  message: string;
  location: string;
};

export type VerifyArchiveSummary = {
  entryCount: number;
  packageManifestCount: number;
  unpackedSizeBytes: number | null;
};

export type VerifySummary = {
  findingCount: number;
  warnCount: number;
  blockCount: number;
  errorCount: number;
};

export type VerifyPreflightSummary = {
  advisory: true;
  packageCount: number;
  identitySource: "package-spec" | "lockfile";
  message: string;
};

export type VerifyReport = {
  target: string;
  inputKind: VerifyInputKind;
  status: VerifyStatus;
  sha256: string | null;
  sizeBytes: number | null;
  archive: VerifyArchiveSummary | null;
  workspaceScan: ScanReport | null;
  preflight: VerifyPreflightSummary | null;
  packages: readonly VerifyPackageIdentity[];
  findings: readonly VerifyFinding[];
  errors: readonly string[];
  summary: VerifySummary;
};
