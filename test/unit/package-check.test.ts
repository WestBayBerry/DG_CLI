import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runPackageCheck, maybeVerifyPackage, resolveLatest } from "../../src/verify/package-check.js";
import { writeAuthState } from "../../src/auth/store.js";

function jsonResponse(body: unknown, ok = true, status?: number): Response {
  return { ok, status: status ?? (ok ? 200 : 500), json: async () => body } as unknown as Response;
}

describe("dg verify package check", () => {
  let home: string;
  let savedHome: string | undefined;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "dg-pkgcheck-"));
    savedHome = process.env.HOME;
    process.env.HOME = home;
  });

  afterEach(async () => {
    if (savedHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = savedHome;
    }
    await rm(home, { recursive: true, force: true });
  });

  function anonymousAnalyzeFetch(pkg: Record<string, unknown>, extra: Record<string, unknown> = {}): typeof fetch {
    return (async () =>
      jsonResponse({
        score: pkg.score ?? 0,
        action: pkg.action ?? "pass",
        packages: [{ findings: [], reasons: [], cached: false, ...pkg }],
        safeVersions: {},
        durationMs: 1,
        ...extra
      })) as typeof fetch;
  }

  it("renders a free warn verdict signed out: top reasons, no score, login footer", async () => {
    const fetchImpl = anonymousAnalyzeFetch({
      name: "chalk", version: "5.6.1", score: 64, action: "warn",
      reasons: ["install lifecycle script", "network access in install path"],
      recommendation: "review before installing"
    });
    const result = await runPackageCheck("npm:chalk@5.6.1", { env: { HOME: home }, fetchImpl });
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain("chalk@5.6.1 (npm)");
    expect(result.stdout).toContain("install lifecycle script");
    expect(result.stdout).not.toContain("score");
    expect(result.stdout).not.toContain("review before installing");
    expect(result.stdout).toContain("dg login");
  });

  it("caps a free block at three reasons and points the rest at sign-in", async () => {
    const fetchImpl = anonymousAnalyzeFetch({
      name: "evil", version: "1.0.0", score: 95, action: "block",
      reasons: ["credential exfiltration", "obfuscated payload", "spawns shell at install", "reads ssh keys", "posts to unknown host"]
    });
    const result = await runPackageCheck("npm:evil@1.0.0", { env: { HOME: home }, fetchImpl });
    expect(result.exitCode).toBe(2);
    expect(result.stdout).toContain("credential exfiltration");
    expect(result.stdout).toContain("spawns shell at install");
    expect(result.stdout).not.toContain("reads ssh keys");
    expect(result.stdout).toContain("… 2 more");
    expect(result.stdout).toContain("dg login");
  });

  it("keeps the free reason cap when --verbose is passed signed out", async () => {
    const fetchImpl = anonymousAnalyzeFetch({
      name: "evil", version: "1.0.0", score: 95, action: "block",
      reasons: ["r1", "r2", "r3", "r4"]
    });
    const result = await runPackageCheck("npm:evil@1.0.0", { env: { HOME: home }, fetchImpl }, { verbose: true });
    expect(result.stdout).not.toContain("r4");
    expect(result.stdout).toContain("… 1 more");
  });

  it("renders a free pass minimally: single reason line, no reason list, page link", async () => {
    const fetchImpl = anonymousAnalyzeFetch({
      name: "react", version: "19.0.0", action: "pass", reasons: ["no risky behavior found"]
    });
    const result = await runPackageCheck("npm:react@19.0.0", { env: { HOME: home }, fetchImpl });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("no risky behavior found");
    expect(result.stdout).not.toContain("✘");
    expect(result.stdout).not.toContain("⚠");
    expect(result.stdout).toContain("westbayberry.com/npm/react");
  });

  it("falls back to the no-risk-signals line on a free pass with no reasons", async () => {
    const fetchImpl = anonymousAnalyzeFetch({ name: "react", version: "19.0.0", action: "pass" });
    const result = await runPackageCheck("npm:react@19.0.0", { env: { HOME: home }, fetchImpl });
    expect(result.stdout).toContain("no risk signals");
  });

  it("gates --json and --output behind sign-in without touching the network", async () => {
    let called = 0;
    const fetchImpl = (async () => {
      called += 1;
      return jsonResponse({});
    }) as typeof fetch;
    const json = await runPackageCheck("npm:react@18.2.0", { env: { HOME: home }, fetchImpl }, { format: "json" });
    expect(json.exitCode).toBe(69);
    expect(json.stderr).toContain("sign-in");
    const output = await runPackageCheck("npm:react@18.2.0", { env: { HOME: home }, fetchImpl }, { outputPath: join(home, "out.txt") });
    expect(output.exitCode).toBe(69);
    expect(called).toBe(0);
  });

  it("reports a quota-exceeded analyze as exit 4 with the limit message and pricing pointer", async () => {
    const fetchImpl = (async () =>
      jsonResponse({ code: "quota_exceeded", scansUsed: 50000, scansLimit: 50000 }, false, 403)) as typeof fetch;
    const result = await runPackageCheck("npm:react@18.2.0", { env: { HOME: home }, fetchImpl });
    expect(result.exitCode).toBe(4);
    expect(result.stderr).toContain("scan limit reached");
    expect(result.stderr).toContain("pricing");
    expect(result.stderr).toContain("dg login");
  });

  it("shows the remaining free checks only when the balance runs low", async () => {
    const low = await runPackageCheck("npm:react@19.0.0", {
      env: { HOME: home },
      fetchImpl: anonymousAnalyzeFetch({ name: "react", version: "19.0.0", action: "pass" }, { freeScansRemaining: 120 })
    });
    expect(low.stdout).toContain("120 free package checks left this month");

    const plenty = await runPackageCheck("npm:react@19.0.0", {
      env: { HOME: home },
      fetchImpl: anonymousAnalyzeFetch({ name: "react", version: "19.0.0", action: "pass" }, { freeScansRemaining: 49_000 })
    });
    expect(plenty.stdout).not.toContain("free package checks left");
  });

  it("sends the device id and no bearer token when signed out", async () => {
    let headers: Record<string, string> = {};
    const fetchImpl = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      headers = (init?.headers ?? {}) as Record<string, string>;
      return jsonResponse({
        score: 0, action: "pass",
        packages: [{ name: "react", version: "19.0.0", score: 0, action: "pass", findings: [], reasons: [], cached: false }],
        safeVersions: {}, durationMs: 1
      });
    }) as typeof fetch;
    await runPackageCheck("npm:react@19.0.0", { env: { HOME: home }, fetchImpl });
    expect(headers["X-Device-Id"]).toBeTruthy();
    expect(headers["Authorization"]).toBeUndefined();
  });

  it("keeps the full authenticated render: score shown, no login footer", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const fetchImpl = anonymousAnalyzeFetch({
      name: "chalk", version: "5.6.1", score: 64, action: "warn", reasons: ["install lifecycle script"]
    });
    const result = await runPackageCheck("npm:chalk@5.6.1", { env: { HOME: home }, fetchImpl });
    expect(result.stdout).toContain("score 64");
    expect(result.stdout).not.toContain("dg login");
  });

  it("requires an explicit registry for a bare name", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const result = await runPackageCheck("react", { env: { HOME: home } });
    expect(result.exitCode).toBe(64);
    expect(result.stderr).toContain("add a registry");
  });

  it("rejects an unknown registry", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const result = await runPackageCheck("deno:oak", { env: { HOME: home } });
    expect(result.exitCode).toBe(64);
    expect(result.stderr).toContain("unknown registry");
  });

  it("names cargo as recognized but not yet supported", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const result = await runPackageCheck("cargo:serde", { env: { HOME: home } });
    expect(result.exitCode).toBe(64);
    expect(result.stderr).toContain("cargo registry is not yet supported");
    expect(result.stderr).toContain("deep verify supports npm and pypi");
    expect(result.stderr).not.toContain("unknown registry");
  });

  it("resolves the latest version and renders the real verdict", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const fetchImpl = (async (url: string | URL) => {
      const target = String(url);
      if (target.startsWith("https://registry.npmjs.org/")) {
        return jsonResponse({ "dist-tags": { latest: "5.3.0" } });
      }
      // analyze endpoint
      return jsonResponse({
        score: 64,
        action: "warn",
        packages: [{ name: "chalk", version: "5.3.0", score: 64, action: "warn", findings: [], reasons: ["install lifecycle script"], cached: false }],
        safeVersions: {},
        durationMs: 1
      });
    }) as typeof fetch;

    const result = await runPackageCheck("npm:chalk", { env: { HOME: home }, fetchImpl });
    expect(result.exitCode).toBe(1); // warn → 1
    expect(result.stdout).toContain("chalk@5.3.0 (npm)");
    expect(result.stdout).toContain("install lifecycle script");
  });

  it("returns exit 2 and a block glyph on a blocked package", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const fetchImpl = (async () =>
      jsonResponse({
        score: 95,
        action: "block",
        packages: [{ name: "evil", version: "1.0.0", score: 95, action: "block", findings: [], reasons: ["credential exfiltration"], cached: false }],
        safeVersions: {},
        durationMs: 1
      })) as typeof fetch;
    const result = await runPackageCheck("npm:evil@1.0.0", { env: { HOME: home }, fetchImpl });
    expect(result.exitCode).toBe(2);
    expect(result.stdout).toContain("credential exfiltration");
  });

  it("returns exit 4 when analysis is incomplete", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const fetchImpl = (async () =>
      jsonResponse({
        score: 0,
        action: "analysis_incomplete",
        packages: [{ name: "weird", version: "1.0.0", score: 0, action: "analysis_incomplete", findings: [], reasons: [], cached: false }],
        safeVersions: {},
        durationMs: 1
      })) as typeof fetch;
    const result = await runPackageCheck("npm:weird@1.0.0", { env: { HOME: home }, fetchImpl });
    expect(result.exitCode).toBe(4);
  });

  it("surfaces a scanner failure as exit 4 with a clear message", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const fetchImpl = (async () => {
      throw new TypeError("fetch failed");
    }) as typeof fetch;
    const result = await runPackageCheck("npm:react@18.2.0", { env: { HOME: home }, fetchImpl });
    expect(result.exitCode).toBe(4);
    expect(result.stderr).toContain("could not reach the scanner");
  });

  it("returns exit 4 when the latest version cannot be resolved", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const fetchImpl = (async (url: string | URL) =>
      String(url).startsWith("https://registry.npmjs.org/") ? jsonResponse({}, false) : jsonResponse({})) as typeof fetch;
    const result = await runPackageCheck("npm:ghostpkg", { env: { HOME: home }, fetchImpl });
    expect(result.exitCode).toBe(4);
    expect(result.stderr).toContain("could not resolve the latest version");
  });

  it("resolves a pypi package's latest version from the json endpoint", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    let analyzedVersion = "";
    const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
      const target = String(url);
      if (target.startsWith("https://pypi.org/pypi/")) {
        return jsonResponse({ info: { version: "2.31.0" } });
      }
      analyzedVersion = JSON.parse(String(init?.body)).packages[0].version;
      return jsonResponse({
        score: 0,
        action: "pass",
        packages: [{ name: "requests", version: "2.31.0", score: 0, action: "pass", findings: [], reasons: [], cached: false }],
        safeVersions: {},
        durationMs: 1
      });
    }) as typeof fetch;
    const result = await runPackageCheck("pypi:requests", { env: { HOME: home }, fetchImpl });
    expect(result.exitCode).toBe(0);
    expect(analyzedVersion).toBe("2.31.0");
    expect(result.stdout).toContain("requests@2.31.0 (pypi)");
  });

  it("percent-encodes every npm name segment when building the registry URL", async () => {
    const requested: string[] = [];
    const fetchImpl = (async (url: string | URL) => {
      requested.push(String(url));
      return jsonResponse({}, false);
    }) as typeof fetch;

    await resolveLatest("npm", "@scope/pkg", fetchImpl);
    await resolveLatest("npm", "a/b/c", fetchImpl);
    await resolveLatest("npm", "../weird name", fetchImpl);

    expect(requested).toEqual([
      "https://registry.npmjs.org/%40scope%2fpkg",
      "https://registry.npmjs.org/a%2fb%2fc",
      "https://registry.npmjs.org/..%2fweird%20name"
    ]);
  });

  it("maybeVerifyPackage owns registry specs with machine formats and defers local paths", async () => {
    expect((await maybeVerifyPackage(["verify", "."])).handled).toBe(false);
    expect((await maybeVerifyPackage(["scan"])).handled).toBe(false);
    expect((await maybeVerifyPackage(["verify", "npm:react", "--help"])).handled).toBe(false);

    const sarif = await maybeVerifyPackage(["verify", "npm:react", "--sarif"]);
    expect(sarif.handled).toBe(true);
    expect(sarif.result.exitCode).toBe(64);
    expect(sarif.result.stderr).toContain("--sarif applies to local artifacts");

    const unknown = await maybeVerifyPackage(["verify", "npm:react", "--wat"]);
    expect(unknown.handled).toBe(true);
    expect(unknown.result.exitCode).toBe(64);
    expect(unknown.result.stderr).toContain("unknown option '--wat'");
  });

  it("defers remote url, git, and file specs to the advisory verify path", async () => {
    expect((await maybeVerifyPackage(["verify", "https://registry.example.test/pkg.tgz"])).handled).toBe(false);
    expect((await maybeVerifyPackage(["verify", "git+https://github.com/user/repo.git"])).handled).toBe(false);
    expect((await maybeVerifyPackage(["verify", "github:user/repo"])).handled).toBe(false);
    expect((await maybeVerifyPackage(["verify", "ssh://git@github.com/user/repo.git"])).handled).toBe(false);
    expect((await maybeVerifyPackage(["verify", "file:./missing-local.tgz"])).handled).toBe(false);
  });

  it("rejects --output without a path on registry specs", async () => {
    const bare = await maybeVerifyPackage(["verify", "npm:react", "-o"]);
    expect(bare.handled).toBe(true);
    expect(bare.result.exitCode).toBe(64);
    expect(bare.result.stderr).toContain("-o requires a path");

    const flagAsValue = await maybeVerifyPackage(["verify", "npm:react", "--output", "--json"]);
    expect(flagAsValue.handled).toBe(true);
    expect(flagAsValue.result.exitCode).toBe(64);
    expect(flagAsValue.result.stderr).toContain("--output requires a path");
  });

  it("runs the real scanner check for registry specs with --json and renders machine output", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const fetchImpl = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.startsWith("https://registry.npmjs.org/")) {
        return jsonResponse({ "dist-tags": { latest: "19.0.0" } });
      }
      return jsonResponse({
        score: 0,
        action: "pass",
        packages: [{ name: "react", version: "19.0.0", score: 0, action: "pass", findings: [], reasons: [], cached: false }],
        safeVersions: {},
        durationMs: 1
      });
    }) as typeof fetch;
    const result = await runPackageCheck("npm:react", { env: { HOME: home }, fetchImpl }, { format: "json" });
    expect(result.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout) as { action: string; name: string; version: string; score: number };
    expect(parsed.action).toBe("pass");
    expect(parsed.name).toBe("react");
    expect(parsed.version).toBe("19.0.0");
  });

  function analyzeFetch(provenance: unknown): typeof fetch {
    return (async () =>
      jsonResponse({
        score: 0,
        action: "pass",
        packages: [
          { name: "sigstore", version: "5.0.0", score: 0, action: "pass", findings: [], reasons: [], cached: false, provenance }
        ],
        safeVersions: {},
        durationMs: 1
      })) as typeof fetch;
  }

  it("renders the provenance line for an attested package (says attested, never verified)", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const result = await runPackageCheck("npm:sigstore@5.0.0", {
      env: { HOME: home },
      fetchImpl: analyzeFetch({ status: "attested", predicateType: "https://slsa.dev/provenance/v1" })
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("provenance attested (slsa v1)");
    expect(result.stdout).not.toContain("verified");
  });

  it("renders the downgrade alarm when the prior version was attested", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const result = await runPackageCheck("npm:sigstore@5.0.0", {
      env: { HOME: home },
      fetchImpl: analyzeFetch({ status: "none", downgrade: { fromVersion: "4.9.0" } })
    });
    expect(result.stdout).toContain("provenance none");
    expect(result.stdout).toContain("provenance downgraded — 4.9.0 was attested, 5.0.0 is not");
  });

  it("omits the provenance line when the server sent none and includes it in --json when present", async () => {
    writeAuthState({ token: "dg_test_token_abcdefghi" });
    const withoutField = await runPackageCheck("npm:sigstore@5.0.0", {
      env: { HOME: home },
      fetchImpl: analyzeFetch(undefined)
    });
    expect(withoutField.stdout).not.toContain("provenance");

    const json = await runPackageCheck("npm:sigstore@5.0.0", {
      env: { HOME: home },
      fetchImpl: analyzeFetch({ status: "unknown" })
    }, { format: "json" });
    const parsed = JSON.parse(json.stdout) as { provenance?: { status: string } };
    expect(parsed.provenance).toEqual({ status: "unknown" });
  });
});
