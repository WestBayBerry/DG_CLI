import React from "react";
import { render } from "ink-testing-library";
import { describe, expect, it } from "vitest";
import { AuditHeader } from "../../src/audit-ui/components/AuditHeader.js";
import { DeepStatusRow } from "../../src/audit-ui/components/DeepStatusRow.js";
import { buildExport, type AuditExportInput } from "../../src/audit-ui/export.js";
import { countSummary } from "../../src/audit-ui/format.js";
import type { AuditFinding } from "../../src/audit/detectors.js";

function stripAnsi(text: string): string {
  return text.replace(/\[[0-9;]*m/g, "");
}

const blockFinding: AuditFinding = {
  id: "pem-private-key",
  category: "secret",
  severity: 5,
  title: "Private key committed to the publish set",
  recommendation: "Remove deploy-key.pem from the package",
  location: "deploy-key.pem",
  evidence: "-----BEGIN RSA***"
};

const warnFinding: AuditFinding = {
  id: "no-files-allowlist",
  category: "publishing",
  severity: 3,
  title: "No files allowlist",
  recommendation: "Add a files array to package.json",
  location: "package.json",
  evidence: "path: package.json"
};

const noteFinding: AuditFinding = {
  id: "source-map",
  category: "publishing",
  severity: 2,
  title: "Source map shipped",
  recommendation: "Exclude .map files",
  location: "dist/index.js.map",
  evidence: "path: dist/index.js.map"
};

describe("AuditHeader", () => {
  it("renders the block verdict, artifact, ecosystem, counts and file count", () => {
    const { lastFrame, unmount } = render(
      React.createElement(AuditHeader, {
        action: "block",
        artifact: "demo@1.0.0",
        ecosystem: "npm",
        countSummary: countSummary([blockFinding, warnFinding, noteFinding]),
        fileCount: 7,
        fallback: false
      })
    );
    const frame = stripAnsi(lastFrame() ?? "");
    unmount();
    expect(frame).toContain("BLOCK");
    expect(frame).toContain("demo@1.0.0");
    expect(frame).toContain("npm");
    expect(frame).toContain("1 blocking · 1 warning · 1 note");
    expect(frame).toContain("7 files");
  });

  it("renders the pass verdict with no-issues count and no fallback note", () => {
    const { lastFrame, unmount } = render(
      React.createElement(AuditHeader, {
        action: "pass",
        artifact: "clean@1.0.0",
        ecosystem: "npm",
        countSummary: countSummary([]),
        fileCount: 1,
        fallback: false
      })
    );
    const frame = stripAnsi(lastFrame() ?? "");
    unmount();
    expect(frame).toContain("PASS");
    expect(frame).toContain("no issues in 1 file");
    expect(frame).not.toContain("approximated");
  });

  it("shows the publish-set-approximated note when fallback is set", () => {
    const { lastFrame, unmount } = render(
      React.createElement(AuditHeader, {
        action: "warn",
        artifact: "x@1.0.0",
        ecosystem: "npm",
        countSummary: countSummary([warnFinding]),
        fileCount: 3,
        fallback: true
      })
    );
    const frame = stripAnsi(lastFrame() ?? "");
    unmount();
    expect(frame).toContain("WARN");
    expect(frame).toContain("approximated");
  });
});

describe("DeepStatusRow", () => {
  it("shows the spinner label while the deep result is pending", () => {
    const { lastFrame, unmount } = render(React.createElement(DeepStatusRow, { deep: null }));
    const frame = stripAnsi(lastFrame() ?? "");
    unmount();
    expect(frame).toContain("uploading to behavioral scanner");
  });

  it("shows the deep summary reason once resolved", () => {
    const { lastFrame, unmount } = render(
      React.createElement(DeepStatusRow, { deep: { ran: false, reason: "not signed in — run dg login to enable" } })
    );
    const frame = stripAnsi(lastFrame() ?? "");
    unmount();
    expect(frame).toContain("Deep behavioral scan ·");
    expect(frame).toContain("not signed in");
  });
});

describe("audit export payloads", () => {
  const input: AuditExportInput = {
    target: ".",
    artifact: "demo@1.0.0",
    ecosystem: "npm",
    action: "block",
    fileCount: 7,
    publishSetSource: "files",
    findings: [blockFinding, warnFinding, noteFinding],
    deep: { ran: true, action: "block", reason: "malware" }
  };

  it("builds json carrying the report shape and findings", () => {
    const { body, ext } = buildExport(input, "json");
    expect(ext).toBe("json");
    const parsed = JSON.parse(body) as { action: string; findings: unknown[]; deep: { action: string } };
    expect(parsed.action).toBe("block");
    expect(parsed.findings).toHaveLength(3);
    expect(parsed.deep.action).toBe("block");
  });

  it("builds a markdown table with the verdict header and finding rows", () => {
    const { body, ext } = buildExport(input, "md");
    expect(ext).toBe("md");
    expect(body).toContain("# Dependency Guardian — audit of demo@1.0.0");
    expect(body).toContain("**Verdict:** BLOCK");
    expect(body).toContain("| Severity | Location | Title | Evidence | Recommendation |");
    expect(body).toContain("deploy-key.pem");
    expect(body).toContain("malware");
  });

  it("separates the findings table from the header paragraph so GitHub renders it", () => {
    const { body } = buildExport(input, "md");
    expect(body).toContain("\n\n| Severity | Location | Title | Evidence | Recommendation |\n");
    const noFindings = buildExport({ ...input, action: "pass", findings: [] }, "md");
    expect(noFindings.body).toContain("\n\n> No findings — the publish set is clean.");
  });

  it("builds a plain-text report without ANSI escapes", () => {
    const { body, ext } = buildExport(input, "txt");
    expect(ext).toBe("txt");
    expect(body).not.toMatch(/\[/);
    expect(body).toContain("✘ BLOCK");
    expect(body).toContain("deploy-key.pem");
    expect(body).toContain("→ ");
    expect(body).toContain("Deep behavioral scan · block — malware");
  });
});
