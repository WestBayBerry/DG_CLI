import type { AnalyzeResponse } from "../api/analyze.js";
import type { AppliedDecisions } from "../decisions/apply.js";

export type ScanStatus = "pass" | "warn" | "block" | "unknown" | "error";

export type ScannerErrorKind =
  | "quota_exceeded"
  | "rate_limited"
  | "auth"
  | "server"
  | "network"
  | "timeout"
  | "invalid_response"
  | "lockfile_unparsed"
  | "worker";

export type ScannerError = {
  kind: ScannerErrorKind;
  message: string;
  statusCode?: number;
  scansUsed?: number;
  scansLimit?: number;
};

export type FindingSeverity = "warn" | "block";

export type ScanFormat = "text" | "json" | "sarif";

export type ScanAcknowledgement = {
  decisionId: string;
  by: string;
  at: string;
  reason: string;
};

export type ScanFinding = {
  id: string;
  severity: FindingSeverity;
  title: string;
  message: string;
  project: string;
  location: string;
  acknowledged?: ScanAcknowledgement;
};

export type ScanProject = {
  name: string;
  version: string | null;
  license: string | null;
  manifestPath: string;
  dependencyCount: number;
  findings: readonly ScanFinding[];
};

export type ScanError = {
  message: string;
  location: string;
};

export type ScanSummary = {
  projectCount: number;
  dependencyCount: number;
  findingCount: number;
  warnCount: number;
  blockCount: number;
  errorCount: number;
  acknowledgedCount?: number;
};

export type ScanDecisions = AppliedDecisions;

export type ScanReport = {
  target: string;
  status: ScanStatus;
  projects: readonly ScanProject[];
  findings: readonly ScanFinding[];
  errors: readonly ScanError[];
  summary: ScanSummary;
  scanner?: AnalyzeResponse;
  scannerError?: ScannerError;
  decisions?: ScanDecisions;
};

export type LockfileSkipReason = "workspace" | "local" | "git" | "direct-url";

export type LockfileSkippedPackage = {
  name: string;
  reason: LockfileSkipReason;
  location: string;
};

export type LockfileParseError = {
  file: string;
  reason: string;
};
