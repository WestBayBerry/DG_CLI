import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { auditLogPath } from "../../src/audit/events.js";
import { renderInstallDecision } from "../../src/install-ui/block-render.js";
import { classifyPackageManagerInvocation, type PackageManager } from "../../src/launcher/classify.js";
import { buildAgentRoutingEnv, buildProxyChildEnv } from "../../src/launcher/env.js";
import { redactSecrets } from "../../src/launcher/output-redaction.js";
import {
  createLaunchPlan,
  dgFileExemptionsNotice,
  resolveSpawnInvocation,
  rootUnprotectedNotice,
  runPackageManager,
  shimDepth,
  inheritedDgProxyActive,
  type PackageManagerSpawner
} from "../../src/launcher/run.js";
import type { CooldownExemption } from "../../src/project/dgfile.js";
import { derivePackageName, enforceProtectedInstall, type EnforcementCause } from "../../src/proxy/enforcement.js";
import { resolveDgPaths } from "../../src/state/index.js";

describe("package manager classification", () => {
  const protectedCases: readonly [PackageManager, readonly string[]][] = [
    ["npm", ["install", "left-pad"]],
    ["npx", ["cowsay"]],
    ["pnpm", ["dlx", "create-vite"]],
    ["pnpx", ["create-vite"]],
    ["yarn", ["add", "vite"]],
    ["pip", ["install", "requests"]],
    ["pipx", ["run", "black"]],
    ["uv", ["pip", "install", "flask"]],
    ["uvx", ["ruff"]],
    ["cargo", ["add", "serde"]],
    ["cargo", ["build"]],
    ["npm", ["create", "vite"]],
    ["npm", ["init", "esbuild"]],
    ["yarn", ["create", "react-app"]],
    ["pnpm", ["create", "react-app"]],
    ["uv", ["tool", "install", "ruff"]],
    ["uv", ["tool", "upgrade", "ruff"]]
  ];

  for (const [manager, args] of protectedCases) {
    it(`classifies ${manager} ${args.join(" ")} as protected`, () => {
      const classification = classifyPackageManagerInvocation(manager, args);

      expect(classification.kind).toBe("protected");
    });
  }

  const passthroughCases: readonly [PackageManager, readonly string[]][] = [
    ["npm", ["run", "build"]],
    ["pnpm", ["list"]],
    ["yarn", ["version"]],
    ["pip", ["freeze"]],
    ["pipx", ["list"]],
    ["uv", ["tree"]],
    ["cargo", ["metadata"]],
    ["npm", ["init"]],
    ["npm", ["init", "-y"]],
    ["cargo", ["init"]],
    ["cargo", ["new", "my-app"]]
  ];

  for (const [manager, args] of passthroughCases) {
    it(`classifies ${manager} ${args.join(" ")} as passthrough`, () => {
      const classification = classifyPackageManagerInvocation(manager, args);

      expect(classification.kind).toBe("passthrough");
    });
  }

  it("normalizes version-suffixed pip/python to the base manager (pip3 ⇒ pip)", () => {
    const pip3 = classifyPackageManagerInvocation("pip3" as PackageManager, ["install", "requests"]);
    expect(pip3.kind).toBe("protected");
    expect(pip3.manager).toBe("pip");
    expect(pip3.ecosystem).toBe("python");
    expect(classifyPackageManagerInvocation("pip3.12" as PackageManager, ["install", "requests"]).kind).toBe("protected");
    // pipx must NOT collapse to pip.
    expect(classifyPackageManagerInvocation("pipx", ["install", "black"]).manager).toBe("pipx");
  });

  it("classifies uv run --with as a fetch path but leaves a bare uv run alone", () => {
    expect(classifyPackageManagerInvocation("uv", ["run", "--with", "evil", "python"]).kind).toBe("protected");
    expect(classifyPackageManagerInvocation("uv", ["run", "python", "script.py"]).kind).toBe("passthrough");
  });

  it("leaves gated ecosystems unclaimed", () => {
    expect(classifyPackageManagerInvocation("bun", ["add", "left-pad"]).kind).toBe("unsupported");
    expect(classifyPackageManagerInvocation("bun", ["add", "left-pad"]).reason).toContain("Bun support is gated");
    expect(classifyPackageManagerInvocation("conda", ["install", "numpy"]).reason).toContain("Conda support is gated");
    expect(classifyPackageManagerInvocation("mamba", ["install", "numpy"]).reason).toContain("Mamba support is gated");
  });
});

describe("derivePackageName", () => {
  const cases: readonly [PackageManager, readonly string[], string][] = [
    ["npm", ["install", "left-pad"], "left-pad"],
    ["npm", ["install", "--registry", "https://registry.evil.test", "evil-pkg"], "evil-pkg"],
    ["npm", ["install", "--registry=https://registry.evil.test", "evil-pkg"], "evil-pkg"],
    ["npm", ["install", "-g", "left-pad"], "left-pad"],
    ["npm", ["install", "--save-dev", "chalk"], "chalk"],
    ["npm", ["install", "--tag", "next", "react"], "react"],
    ["yarn", ["add", "--registry", "https://registry.evil.test", "vite"], "vite"],
    ["pip", ["install", "--index-url", "https://mirror.test/simple", "requests"], "requests"],
    ["pip", ["install", "-i", "https://mirror.test/simple", "requests"], "requests"],
    ["pip", ["install", "--upgrade", "requests"], "requests"],
    ["pip", ["install", "--proxy", "http://proxy.test:8080", "flask"], "flask"],
    ["cargo", ["add", "--registry", "alt-registry", "serde"], "serde"],
    ["cargo", ["install", "--git", "https://github.com/user/tool", "tool-pkg"], "tool-pkg"],
    ["npm", ["install", "--registry", "https://registry.evil.test"], "npm:install"],
    ["pip", ["install", "-r", "requirements.txt"], "pip:install"],
    ["npm", ["install"], "npm:install"]
  ];

  for (const [manager, args, expected] of cases) {
    it(`names ${expected} for ${manager} ${args.join(" ")}`, () => {
      expect(derivePackageName(classifyPackageManagerInvocation(manager, args))).toBe(expected);
    });
  }
});

describe("launcher planning", () => {
  it("skips dg shims when resolving the real binary", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-"));
    const shimDir = join(temp, ".dg", "shims");
    const binDir = join(temp, "bin");
    await mkdir(shimDir, {
      recursive: true
    });
    await mkdir(binDir);
    await writeExecutable(join(shimDir, "npm"), "#!/bin/sh\n# dg-shim-v1\n");
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf real-npm\n");

    try {
      const plan = createLaunchPlan("npm", ["run", "build"], {
        HOME: temp,
        PATH: [shimDir, binDir].join(delimiter)
      });

      expect(plan.classification.kind).toBe("passthrough");
      expect(plan.startsProxy).toBe(false);
      expect(plan.realBinary.path).toBe(join(binDir, "npm"));
      expect(plan.realBinary.skipped).toContain(shimDir);
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("fails protected commands closed when the production proxy is unavailable", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-protected-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf should-not-run\n");

    try {
      const result = await runPackageManager("npm", ["install", "https://user:secret@registry.example/pkg.tgz"], {
        env: {
          HOME: temp,
          PATH: binDir
        }
      });

      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain("DG could not verify");
      expect(result.stderr).toContain("protection unavailable");
      expect(result.stderr).toContain("https://<redacted>@registry.example/pkg.tgz");
      expect(result.stderr).not.toContain("secret");
      await expect(readFile(auditLogPath(resolveDgPaths({ HOME: temp })), "utf8")).resolves.toContain("install.blocked");
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("passes through non-fetch commands without proxy startup", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-passthrough-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf 'token=secret-token\\n'\n");

    try {
      const result = await runPackageManager("npm", ["run", "local"], {
        env: {
          HOME: temp,
          PATH: binDir
        }
      });

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toBe("token=<redacted>\n");
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  it("rejects gated package-manager prefixes before resolving or spawning binaries", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-gated-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "bun"), "#!/bin/sh\nprintf should-not-run\n");

    try {
      const result = await runPackageManager("bun", ["add", "left-pad"], {
        env: {
          HOME: temp,
          PATH: binDir
        }
      });

      expect(result.exitCode).toBe(69);
      expect(result.stderr).toContain("Bun support is gated");
      expect(result.stdout).toBe("");
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("spawns protected commands only after an enforcement pass or warning", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-enforced-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf should-not-run\n");

    try {
      const pass = await runPackageManager("npm", ["install", "left-pad"], {
        env: {
          HOME: temp,
          PATH: binDir
        },
        proxyVerdict: {
          verdict: "pass",
          packageName: "left-pad",
          cause: "pass",
          reason: "proxy verdict pass"
        },
        spawner: fakeSpawner("installed\n", "")
      });
      const warn = await runPackageManager("npm", ["install", "left-pad"], {
        env: {
          HOME: temp,
          PATH: binDir
        },
        proxyVerdict: {
          verdict: "warn",
          packageName: "left-pad",
          cause: "warn",
          reason: "proxy verdict warn"
        },
        spawner: fakeSpawner("", "npm warning\n")
      });

      const ciPass = await runPackageManager("npm", ["install", "left-pad"], {
        env: {
          HOME: temp,
          PATH: binDir,
          CI: "1"
        },
        proxyVerdict: {
          verdict: "pass",
          packageName: "left-pad",
          cause: "pass",
          reason: "proxy verdict pass"
        },
        spawner: fakeSpawner("installed\n", "")
      });

      expect(pass.exitCode).toBe(0);
      expect(pass.stdout).toBe("installed\n");
      expect(pass.stderr).toContain("DG verified");
      expect(ciPass.exitCode).toBe(0);
      expect(ciPass.stderr).not.toContain("DG verified");
      expect(warn.exitCode).toBe(0);
      expect(warn.stderr).toContain("DG flagged");
      expect(warn.stderr).toContain("npm warning");
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("nudges toward dg setup once after a successful protected install on a TTY", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-nudge-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf should-not-run\n");
    const ttyDescriptor = Object.getOwnPropertyDescriptor(process.stderr, "isTTY");
    Object.defineProperty(process.stderr, "isTTY", { value: true, configurable: true });

    const run = (env: NodeJS.ProcessEnv = {}) =>
      runPackageManager("npm", ["install", "left-pad"], {
        env: { HOME: temp, PATH: binDir, ...env },
        proxyVerdict: { verdict: "pass", packageName: "left-pad", cause: "pass", reason: "proxy verdict pass" },
        spawner: fakeSpawner("installed\n", "")
      });

    try {
      const first = await run();
      expect(first.stderr).toContain("Make this automatic");
      expect(first.stderr.indexOf("dg setup")).toBeGreaterThan(first.stderr.indexOf("DG verified"));

      const second = await run();
      expect(second.stderr).not.toContain("Make this automatic");

      const shimHome = await mkdtemp(join(tmpdir(), "dg-launcher-nudge-shim-"));
      await mkdir(join(shimHome, ".dg", "shims"), { recursive: true });
      await writeExecutable(join(shimHome, ".dg", "shims", "npm"), "#!/bin/sh\n");
      const withShim = await runPackageManager("npm", ["install", "left-pad"], {
        env: { HOME: shimHome, PATH: binDir },
        proxyVerdict: { verdict: "pass", packageName: "left-pad", cause: "pass", reason: "proxy verdict pass" },
        spawner: fakeSpawner("installed\n", "")
      });
      expect(withShim.stderr).not.toContain("Make this automatic");
      await rm(shimHome, { force: true, recursive: true });
    } finally {
      if (ttyDescriptor) {
        Object.defineProperty(process.stderr, "isTTY", ttyDescriptor);
      } else {
        delete (process.stderr as { isTTY?: boolean }).isTTY;
      }
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("distinguishes block causes in install UI copy", () => {
    const causes: readonly EnforcementCause[] = [
      "malware",
      "policy",
      "license",
      "hash-mismatch",
      "private-upload-disabled",
      "api-timeout",
      "registry-timeout",
      "analysis-incomplete",
      "unsupported-manager",
      "proxy-setup-failure"
    ];

    for (const cause of causes) {
      const rendered = renderInstallDecision({
        action: "block",
        cause,
        packageName: "left-pad",
        policyMode: "block",
        reason: `reason for ${cause}`
      });

      expect(rendered).toContain(`reason for ${cause}`);
      expect(rendered).toContain("--dg-force-install");
      expect(rendered).not.toContain("undefined");
    }
  });

  it("allows a policy-controlled force install", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-force-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf should-not-run\n");

    try {
      const result = await runPackageManager("npm", ["install", "left-pad"], {
        env: {
          HOME: temp,
          PATH: binDir
        },
        proxyVerdict: {
          verdict: "block",
          packageName: "left-pad",
          cause: "malware",
          reason: "known malicious package"
        },
        forceOverride: {
          force: true
        },
        spawner: fakeSpawner("installed with override\n", "")
      });

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toBe("installed with override\n");
      expect(result.stderr).toContain("--dg-force-install");
      await expect(readFile(auditLogPath(resolveDgPaths({ HOME: temp })), "utf8")).resolves.toContain("install.force_override");
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("keeps project-local policy out of enforcement decisions by default", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-policy-"));
    const classification = classifyPackageManagerInvocation("npm", ["install", "left-pad"]);

    try {
      const decision = enforceProtectedInstall({
        classification,
        env: {
          HOME: temp
        },
        userConfig: {
          version: 1,
          api: {
            baseUrl: "https://api.example.test"
          },
          org: {
            id: ""
          },
          policy: {
            mode: "block",
            trustProjectAllowlists: false,
            allowForceOverride: true,
            scriptHardening: false
          }
        },
        proxyVerdict: {
          verdict: "block",
          packageName: "left-pad",
          cause: "policy",
          reason: "project-local allowlist ignored"
        }
      });

      expect(decision.action).toBe("block");
      expect(decision.reason).toBe("project-local allowlist ignored");
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("lets an over-quota install through as a warning when quotaBehavior is pass", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-quota-pass-"));
    const classification = classifyPackageManagerInvocation("npm", ["install", "left-pad"]);
    try {
      const decision = enforceProtectedInstall({
        classification,
        env: { HOME: temp },
        proxyVerdict: {
          verdict: "block",
          packageName: "left-pad",
          cause: "quota-exceeded",
          reason: "monthly scan limit reached",
          resetsAt: "2026-07-01T00:00:00.000Z",
          quotaBehavior: "pass"
        }
      });
      expect(decision.action).toBe("warn");
      expect(decision.cause).toBe("quota-exceeded");
      expect(decision.resetsAt).toBe("2026-07-01T00:00:00.000Z");
    } finally {
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("fails closed on an over-quota install when quotaBehavior is block", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-quota-block-"));
    const classification = classifyPackageManagerInvocation("npm", ["install", "left-pad"]);
    try {
      const decision = enforceProtectedInstall({
        classification,
        env: { HOME: temp },
        userConfig: {
          version: 1,
          api: { baseUrl: "https://api.example.test" },
          org: { id: "" },
          policy: {
            mode: "block",
            trustProjectAllowlists: false,
            allowForceOverride: true,
            scriptHardening: false
          }
        },
        proxyVerdict: {
          verdict: "block",
          packageName: "left-pad",
          cause: "quota-exceeded",
          reason: "monthly scan limit reached",
          resetsAt: "2026-07-01T00:00:00.000Z",
          quotaBehavior: "block"
        }
      });
      expect(decision.action).toBe("block");
      expect(decision.cause).toBe("quota-exceeded");
      expect(decision.resetsAt).toBe("2026-07-01T00:00:00.000Z");
    } finally {
      await rm(temp, { force: true, recursive: true });
    }
  });
});

describe("buildAgentRoutingEnv", () => {
  it("sets every manager's proxy + CA var (literal values, no shell expansion) plus DG_PROXY_ACTIVE", () => {
    const env = buildAgentRoutingEnv("http://127.0.0.1:19000", "/tmp/dg-ca.pem");
    expect(env.DG_PROXY_ACTIVE).toBe("1");
    // node/npm, pip, uv, cargo CA vars all present so any tool the agent runs trusts the proxy CA.
    for (const k of ["NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "PIP_CERT", "SSL_CERT_FILE", "CARGO_HTTP_CAINFO"]) {
      expect(env[k]).toBe("/tmp/dg-ca.pem");
    }
    for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "npm_config_proxy", "npm_config_https_proxy"]) {
      expect(env[k]).toBe("http://127.0.0.1:19000");
    }
    expect(env.NO_PROXY).toBe("127.0.0.1,localhost");
    // No value contains a shell metachar — safe to drop into a settings `env` block verbatim.
    for (const v of Object.values(env)) {
      expect(v).not.toMatch(/[$`]/);
    }
  });
});

describe("child env injection and redaction", () => {
  it("controls NO_PROXY to loopback only, dropping an inherited registry-disabling value", () => {
    // An inherited NO_PROXY naming the registry (or a `*`/`.org` glob) would route
    // the manager straight past the firewall, so dg overrides it (both cases).
    const env = buildProxyChildEnv({
      manager: "npm",
      baseEnv: {
        NO_PROXY: "registry.npmjs.org",
        no_proxy: "*"
      },
      proxyUrl: "http://127.0.0.1:19000",
      caBundlePath: "/tmp/dg-ca-bundle.pem"
    });

    expect(env.HTTP_PROXY).toBe("http://127.0.0.1:19000");
    expect(env.HTTPS_PROXY).toBe("http://127.0.0.1:19000");
    expect(env.NODE_EXTRA_CA_CERTS).toBe("/tmp/dg-ca-bundle.pem");
    expect(env.NO_PROXY).toBe("127.0.0.1,localhost");
    expect(env.no_proxy).toBe("127.0.0.1,localhost");
    expect(env.NO_PROXY).not.toContain("registry.npmjs.org");
    expect(env.no_proxy).not.toContain("*");
  });

  it("busts the per-manager cache (incl. Yarn Berry global cache and cargo CARGO_HOME) so installs re-fetch through the proxy", () => {
    const mk = (manager: Parameters<typeof buildProxyChildEnv>[0]["manager"]): NodeJS.ProcessEnv =>
      buildProxyChildEnv({ manager, baseEnv: {}, proxyUrl: "http://127.0.0.1:19000", caBundlePath: "/tmp/ca.pem", cacheDir: "/tmp/dg-pm-cache" });
    const yarn = mk("yarn");
    expect(yarn.YARN_CACHE_FOLDER).toBe("/tmp/dg-pm-cache");
    expect(yarn.YARN_GLOBAL_FOLDER).toBe("/tmp/dg-pm-cache");
    const cargo = mk("cargo");
    expect(cargo.CARGO_HOME).toBe("/tmp/dg-pm-cache");
    expect(mk("npm").npm_config_cache).toBe("/tmp/dg-pm-cache");
  });

  it("injects Python and Cargo-specific proxy env", () => {
    const pip = buildProxyChildEnv({
      manager: "pip",
      baseEnv: {},
      proxyUrl: "http://127.0.0.1:19000",
      caBundlePath: "/tmp/dg-ca-bundle.pem"
    });
    const cargo = buildProxyChildEnv({
      manager: "cargo",
      baseEnv: {},
      proxyUrl: "http://127.0.0.1:19000",
      caBundlePath: "/tmp/dg-ca-bundle.pem"
    });

    expect(pip.https_proxy).toBe("http://127.0.0.1:19000");
    expect(pip.REQUESTS_CA_BUNDLE).toBe("/tmp/dg-ca-bundle.pem");
    expect(cargo.HTTPS_PROXY).toBe("http://127.0.0.1:19000");
    expect(cargo.CARGO_HTTP_CAINFO).toBe("/tmp/dg-ca-bundle.pem");
  });

  it("sets a generous client read timeout above the proxy verdict ceiling so a slow verify never aborts the install", () => {
    const mk = (manager: Parameters<typeof buildProxyChildEnv>[0]["manager"], baseEnv: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv =>
      buildProxyChildEnv({ manager, baseEnv, proxyUrl: "http://127.0.0.1:19000", caBundlePath: "/tmp/ca.pem" });

    expect(mk("pip").PIP_DEFAULT_TIMEOUT).toBe("300");
    expect(mk("uv").UV_HTTP_TIMEOUT).toBe("300");
    expect(mk("cargo").CARGO_HTTP_TIMEOUT).toBe("300");
    expect(mk("npm").npm_config_fetch_timeout).toBe("300000");
    expect(mk("yarn").YARN_NETWORK_TIMEOUT).toBe("300000");

    expect(mk("pip", { DG_INSTALL_VERDICT_TIMEOUT_MS: "300000" }).PIP_DEFAULT_TIMEOUT).toBe("360");
    expect(mk("pip", { DG_CLIENT_READ_TIMEOUT_S: "90" }).PIP_DEFAULT_TIMEOUT).toBe("90");
  });

  it("routes Yarn Berry through the firewall via YARN_-prefixed proxy + CA (Berry ignores the classic vars)", () => {
    const yarn = buildProxyChildEnv({
      manager: "yarn",
      baseEnv: {},
      proxyUrl: "http://127.0.0.1:19000",
      caBundlePath: "/tmp/dg-ca-bundle.pem"
    });
    expect(yarn.YARN_HTTP_PROXY).toBe("http://127.0.0.1:19000");
    expect(yarn.YARN_HTTPS_PROXY).toBe("http://127.0.0.1:19000");
    expect(yarn.YARN_HTTPS_CA_FILE_PATH).toBe("/tmp/dg-ca-bundle.pem");
    expect(yarn.NODE_EXTRA_CA_CERTS).toBe("/tmp/dg-ca-bundle.pem");
    const npm = buildProxyChildEnv({ manager: "npm", baseEnv: {}, proxyUrl: "http://127.0.0.1:19000", caBundlePath: "/tmp/ca.pem" });
    expect(npm.YARN_HTTPS_PROXY).toBeUndefined();
  });

  it("never forwards the dg account credential into the untrusted package-manager child", () => {
    const baseEnv = { DG_API_KEY: "dg_live_secret", DG_API_TOKEN: "dg_live_secret2", PATH: "/usr/bin" };
    for (const manager of ["npm", "pip", "uv", "cargo", "yarn"] as const) {
      const env = buildProxyChildEnv({ manager, baseEnv, proxyUrl: "http://127.0.0.1:19000", caBundlePath: "/tmp/ca.pem" });
      expect(env.DG_API_KEY).toBeUndefined();
      expect(env.DG_API_TOKEN).toBeUndefined();
      expect(env.PATH).toBe("/usr/bin");
    }
  });

  it("forces a cache bypass so every install re-fetches through the firewall", () => {
    const pip = buildProxyChildEnv({
      manager: "pip",
      baseEnv: {},
      proxyUrl: "http://127.0.0.1:19000",
      caBundlePath: "/tmp/ca.pem"
    });
    const uv = buildProxyChildEnv({
      manager: "uv",
      baseEnv: {},
      proxyUrl: "http://127.0.0.1:19000",
      caBundlePath: "/tmp/ca.pem"
    });
    const npm = buildProxyChildEnv({
      manager: "npm",
      baseEnv: {},
      proxyUrl: "http://127.0.0.1:19000",
      caBundlePath: "/tmp/ca.pem",
      cacheDir: "/tmp/sess/pm-cache"
    });
    const yarn = buildProxyChildEnv({
      manager: "yarn",
      baseEnv: {},
      proxyUrl: "http://127.0.0.1:19000",
      caBundlePath: "/tmp/ca.pem",
      cacheDir: "/tmp/sess/pm-cache"
    });

    expect(pip.PIP_NO_CACHE_DIR).toBe("1");
    expect(uv.UV_NO_CACHE).toBe("1");
    expect(npm.npm_config_cache).toBe("/tmp/sess/pm-cache");
    expect(yarn.npm_config_cache).toBe("/tmp/sess/pm-cache");
    expect(yarn.YARN_CACHE_FOLDER).toBe("/tmp/sess/pm-cache");
  });

  it("leaves the npm cache untouched when no throwaway cacheDir is provided", () => {
    const npm = buildProxyChildEnv({
      manager: "npm",
      baseEnv: {},
      proxyUrl: "http://127.0.0.1:19000",
      caBundlePath: "/tmp/ca.pem"
    });
    expect(npm.npm_config_cache).toBeUndefined();
  });

  it("redacts authorization headers, token assignments, and credential URLs", () => {
    expect(
      redactSecrets("Proxy-Authorization: Basic abc\nhttps://user:pass@example.test/pkg.tgz token=abc123 dg_token=xyz")
    ).toBe("Proxy-Authorization: <redacted>\nhttps://<redacted>@example.test/pkg.tgz token=<redacted> dg_token=<redacted>");
  });
});

describe("streaming sinks and real spawner", () => {
  it("does not duplicate streamed child output in the result for a passthrough command", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-sink-pass-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf should-not-run\n");

    const sinkOut: string[] = [];
    const sinkErr: string[] = [];

    try {
      const result = await runPackageManager("npm", ["run", "local"], {
        env: {
          HOME: temp,
          PATH: binDir
        },
        spawner: sinkEchoSpawner("streamed-stdout\n", "streamed-stderr\n"),
        onStdout: (chunk) => sinkOut.push(chunk),
        onStderr: (chunk) => sinkErr.push(chunk)
      });

      expect(sinkOut.join("")).toBe("streamed-stdout\n");
      expect(sinkErr.join("")).toBe("streamed-stderr\n");
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe("");
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("streams child output to sinks while keeping the decision text in stderr on a proxy pass", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-sink-verdict-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf should-not-run\n");

    const sinkOut: string[] = [];
    const sinkErr: string[] = [];

    try {
      const result = await runPackageManager("npm", ["install", "left-pad"], {
        env: {
          HOME: temp,
          PATH: binDir
        },
        proxyVerdict: {
          verdict: "pass",
          packageName: "left-pad",
          cause: "pass",
          reason: "proxy verdict pass"
        },
        spawner: sinkEchoSpawner("added 1 package\n", "npm notice\n"),
        onStdout: (chunk) => sinkOut.push(chunk),
        onStderr: (chunk) => sinkErr.push(chunk)
      });

      expect(sinkOut.join("")).toBe("added 1 package\n");
      expect(sinkErr.join("")).toBe("npm notice\n");
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("DG verified left-pad");
      expect(result.stderr).not.toContain("npm notice");
      expect(result.stderr).not.toContain("added 1 package");
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  });

  it("captures multi-megabyte stdout without truncation and exits zero", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-big-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    const bigBytes = 2 * 1024 * 1024 + 4096;
    await writeExecutable(
      join(binDir, "npm"),
      `#!/bin/sh\nyes A | head -c ${bigBytes}\nexit 0\n`
    );

    try {
      const result = await runPackageManager("npm", ["run", "local"], {
        env: {
          HOME: temp,
          PATH: [binDir, "/bin", "/usr/bin"].join(delimiter)
        }
      });

      expect(result.exitCode).toBe(0);
      expect(result.stdout.length).toBe(bigBytes);
      expect(/^[A\n]+$/.test(result.stdout)).toBe(true);
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 30_000);

  it("maps SIGTERM and SIGKILL self-signals to 128+n exit codes", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-signal-"));
    const termDir = join(temp, "term-bin");
    const killDir = join(temp, "kill-bin");
    await mkdir(termDir);
    await mkdir(killDir);
    await writeExecutable(join(termDir, "npm"), "#!/bin/sh\nkill -TERM $$\n");
    await writeExecutable(join(killDir, "npm"), "#!/bin/sh\nkill -KILL $$\n");

    try {
      const term = await runPackageManager("npm", ["run", "local"], {
        env: {
          HOME: temp,
          PATH: termDir
        }
      });
      const kill = await runPackageManager("npm", ["run", "local"], {
        env: {
          HOME: temp,
          PATH: killDir
        }
      });

      expect(term.exitCode).toBe(143);
      expect(kill.exitCode).toBe(137);
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);

  it("redacts secrets in live streamed output and the captured result", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-redact-stream-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    const token = "npm_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII";
    await writeExecutable(
      join(binDir, "npm"),
      `#!/bin/sh\nprintf '//registry.npmjs.org/:_authToken=${token}\\n'\n`
    );

    const sinkOut: string[] = [];

    try {
      const result = await runPackageManager("npm", ["run", "local"], {
        env: {
          HOME: temp,
          PATH: binDir
        },
        onStdout: (chunk) => sinkOut.push(chunk)
      });

      const streamed = sinkOut.join("");
      expect(result.exitCode).toBe(0);
      expect(streamed).toContain("<redacted>");
      expect(streamed).not.toContain(token);
      expect(result.stdout).not.toContain(token);
    } finally {
      await rm(temp, {
        force: true,
        recursive: true
      });
    }
  }, 20_000);
});

describe("shim re-entry guard", () => {
  it("parses DG_SHIM_DEPTH defensively", () => {
    expect(shimDepth({})).toBe(0);
    expect(shimDepth({ DG_SHIM_DEPTH: "garbage" })).toBe(0);
    expect(shimDepth({ DG_SHIM_DEPTH: "-3" })).toBe(0);
    expect(shimDepth({ DG_SHIM_DEPTH: "1" })).toBe(1);
    expect(shimDepth({ DG_SHIM_DEPTH: "2" })).toBe(2);
  });

  it("only treats a re-entry as proxied when a live loopback dg proxy is present (B1-H1)", async () => {
    // Isolated HOME so readServiceState deterministically finds no service.
    const home = await mkdtemp(join(tmpdir(), "dg-reentry-"));
    const e = (extra: NodeJS.ProcessEnv): NodeJS.ProcessEnv => ({ HOME: home, ...extra });
    try {
      // forged/stale env vars must NOT count as a live proxy
      expect(inheritedDgProxyActive(e({ DG_SHIM_DEPTH: "1" }))).toBe(false);
      expect(inheritedDgProxyActive(e({ DG_PROXY_ACTIVE: "1" }))).toBe(false);
      expect(inheritedDgProxyActive(e({ DG_PROXY_ACTIVE: "1", HTTP_PROXY: "" }))).toBe(false);
      expect(inheritedDgProxyActive(e({ DG_PROXY_ACTIVE: "1", HTTP_PROXY: "http://evil.example:8080" }))).toBe(false);
      // a bare loopback proxy with NO dg auth token is forgeable — reject it
      expect(inheritedDgProxyActive(e({ DG_PROXY_ACTIVE: "1", HTTP_PROXY: "http://127.0.0.1:54321" }))).toBe(false);
      expect(inheritedDgProxyActive(e({ DG_PROXY_ACTIVE: "1", HTTPS_PROXY: "http://127.0.0.1:1" }))).toBe(false);
      // genuine nesting (no persistent service): parent dg proxy set DG_PROXY_ACTIVE
      // + a loopback proxy URL carrying the proxy's auth token
      expect(inheritedDgProxyActive(e({ DG_PROXY_ACTIVE: "1", HTTP_PROXY: "http://dg:tok@127.0.0.1:54321" }))).toBe(true);
      expect(inheritedDgProxyActive(e({ DG_PROXY_ACTIVE: "1", HTTPS_PROXY: "http://dg:tok@localhost:54321" }))).toBe(true);
    } finally {
      await rm(home, { force: true, recursive: true });
    }
  });

  it("threads an incremented DG_SHIM_DEPTH into the child env", () => {
    expect(createLaunchPlan("npm", ["run", "build"], { PATH: "" }).childEnv.DG_SHIM_DEPTH).toBe("1");
    expect(createLaunchPlan("npm", ["run", "build"], { PATH: "", DG_SHIM_DEPTH: "1" }).childEnv.DG_SHIM_DEPTH).toBe("2");
  });

  it("scrubs the dg account credential from the non-proxy child env (B1-M4)", () => {
    const plan = createLaunchPlan("npm", ["run", "build"], { PATH: "", DG_API_KEY: "dg_live_x", DG_API_TOKEN: "dg_live_y" });
    expect(plan.childEnv.DG_API_KEY).toBeUndefined();
    expect(plan.childEnv.DG_API_TOKEN).toBeUndefined();
  });

  it("runs the real binary directly when re-entered under a live dg proxy", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-depth1-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf should-not-run\n");
    const spawned: string[] = [];

    try {
      const result = await runPackageManager("npm", ["install", "left-pad"], {
        env: {
          HOME: temp,
          PATH: binDir,
          DG_SHIM_DEPTH: "1",
          DG_PROXY_ACTIVE: "1",
          HTTP_PROXY: "http://dg:tok@127.0.0.1:54321"
        },
        spawner: (request) => {
          spawned.push(request.binary);
          return Promise.resolve({ exitCode: 0, stdout: "installed\n", stderr: "" });
        }
      });

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toBe("installed\n");
      expect(result.stderr).toContain("re-entered through its own shim");
      expect(spawned).toEqual([join(binDir, "npm")]);
    } finally {
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("refuses to re-enter at depth 2 with exit 69", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-depth2-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf should-not-run\n");
    const spawned: string[] = [];

    try {
      const result = await runPackageManager("npm", ["install", "left-pad"], {
        env: {
          HOME: temp,
          PATH: binDir,
          DG_SHIM_DEPTH: "2"
        },
        spawner: (request) => {
          spawned.push(request.binary);
          return Promise.resolve({ exitCode: 0, stdout: "", stderr: "" });
        }
      });

      expect(result.exitCode).toBe(69);
      expect(result.stderr).toContain("shim exec loop detected");
      expect(spawned).toEqual([]);
    } finally {
      await rm(temp, { force: true, recursive: true });
    }
  });
});

describe("root unprotected notice", () => {
  it("fires only for root without dg state", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-root-"));
    try {
      expect(rootUnprotectedNotice({ HOME: temp }, 501)).toBe("");
      expect(rootUnprotectedNotice({ HOME: temp }, undefined)).toBe("");
      expect(rootUnprotectedNotice({ HOME: temp }, 0)).toContain("running as root without dg state");
      await mkdir(join(temp, ".dg", "state"), { recursive: true });
      expect(rootUnprotectedNotice({ HOME: temp }, 0)).toBe("");
    } finally {
      await rm(temp, { force: true, recursive: true });
    }
  });
});

describe("project dg.json exemption notice", () => {
  const exemption: CooldownExemption = {
    ecosystem: "npm",
    name: "left-pad",
    reason: "team-approved",
    acceptedBy: "test",
    acceptedAt: "2026-06-11T00:00:00.000Z"
  };

  it("names dg.json as the source and counts the exemptions", () => {
    expect(dgFileExemptionsNotice([exemption])).toBe("dg: applying 1 cooldown exemption from this project's dg.json\n");
    expect(dgFileExemptionsNotice([exemption, { ...exemption, name: "lodash" }])).toContain("2 cooldown exemptions");
  });

  it("stays silent when the project supplies no exemptions", () => {
    expect(dgFileExemptionsNotice([])).toBe("");
  });
});

describe("cmd/bat spawn invocation", () => {
  it("passes non-script binaries through untouched", () => {
    expect(resolveSpawnInvocation("/usr/bin/npm", ["install"], "linux")).toEqual({
      command: "/usr/bin/npm",
      args: ["install"],
      windowsVerbatimArguments: false
    });
    expect(resolveSpawnInvocation("C:\\nodejs\\node.exe", ["script.js"], "win32")).toEqual({
      command: "C:\\nodejs\\node.exe",
      args: ["script.js"],
      windowsVerbatimArguments: false
    });
  });

  it("only rewrites cmd/bat targets on win32", () => {
    const onLinux = resolveSpawnInvocation("/opt/fake/npm.cmd", ["install"], "linux");
    expect(onLinux.command).toBe("/opt/fake/npm.cmd");
    expect(onLinux.windowsVerbatimArguments).toBe(false);
  });

  it("wraps npm.cmd in cmd.exe /d /s /c with verbatim arguments", () => {
    const invocation = resolveSpawnInvocation("C:\\Program Files\\nodejs\\npm.cmd", ["install", "left-pad@1.3.0"], "win32");
    expect(invocation.command.toLowerCase()).toContain("cmd");
    expect(invocation.args.slice(0, 3)).toEqual(["/d", "/s", "/c"]);
    expect(invocation.windowsVerbatimArguments).toBe(true);
    const commandLine = invocation.args[3] ?? "";
    expect(commandLine.startsWith('"')).toBe(true);
    expect(commandLine.endsWith('"')).toBe(true);
    expect(commandLine).toContain("npm.cmd");
    expect(commandLine).toContain('^^^"install^^^"');
  });

  it("escapes quotes and shell metacharacters in arguments", () => {
    const invocation = resolveSpawnInvocation("C:\\t\\npm.bat", ['say "hi" & del C:\\'], "win32");
    const commandLine = invocation.args[3] ?? "";
    expect(commandLine).toContain('\\^^^"hi\\^^^"');
    expect(commandLine).toContain("^^^&");
    expect(commandLine).not.toContain(' & ');
  });
});

async function writeExecutable(path: string, text: string): Promise<void> {
  await writeFile(path, text, "utf8");
  await chmod(path, 0o755);
}

function fakeSpawner(stdout: string, stderr: string): PackageManagerSpawner {
  return () => Promise.resolve({
    exitCode: 0,
    stdout,
    stderr
  });
}

function sinkEchoSpawner(stdout: string, stderr: string): PackageManagerSpawner {
  return (request) => {
    request.onStdout?.(stdout);
    request.onStderr?.(stderr);
    return Promise.resolve({
      exitCode: 0,
      stdout,
      stderr
    });
  };
}

describe("script-gate observe wiring", () => {
  async function fixtureProject(temp: string): Promise<string> {
    const project = join(temp, "project");
    await mkdir(join(project, "node_modules", "esbuild"), { recursive: true });
    await writeFile(
      join(project, "node_modules", "esbuild", "package.json"),
      JSON.stringify({ name: "esbuild", version: "0.25.5", scripts: { postinstall: "node install.js" } }),
      "utf8"
    );
    await writeFile(
      join(project, "node_modules", ".package-lock.json"),
      JSON.stringify({ packages: { "node_modules/esbuild": { version: "0.25.5", hasInstallScript: true } } }),
      "utf8"
    );
    return project;
  }

  it("appends the observe report line after a successful protected npm install", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-script-gate-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf should-not-run\n");
    const project = await fixtureProject(temp);

    try {
      const result = await runPackageManager("npm", ["install", "esbuild"], {
        env: { HOME: temp, PATH: binDir },
        proxyVerdict: { verdict: "pass", packageName: "esbuild", cause: "pass", reason: "proxy verdict pass" },
        spawner: fakeSpawner("added 1 package\n", ""),
        projectDir: project
      });

      expect(result.exitCode).toBe(0);
      expect(result.stderr).toContain("dg scripts: 1 package ran install scripts (esbuild@0.25.5)");
      expect(result.stderr).toContain("observed, not blocked");
    } finally {
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("enforce mode injects --ignore-scripts and npm_config_ignore_scripts into the npm spawn", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-script-enforce-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf should-not-run\n");
    const project = await fixtureProject(temp);
    const paths = resolveDgPaths({ HOME: temp });
    await mkdir(paths.configDir, { recursive: true });
    await writeFile(join(paths.configDir, "config.json"), JSON.stringify({ version: 1, scriptGate: { mode: "enforce", observe: false } }), "utf8");

    let captured: { args: readonly string[]; env: NodeJS.ProcessEnv } | undefined;
    const capturingSpawner: PackageManagerSpawner = (req) => {
      captured = { args: req.args, env: req.env };
      return Promise.resolve({ exitCode: 0, stdout: "added 1 package\n", stderr: "" });
    };

    try {
      const result = await runPackageManager("npm", ["install", "esbuild"], {
        env: { HOME: temp, PATH: binDir },
        proxyVerdict: { verdict: "pass", packageName: "esbuild", cause: "pass", reason: "proxy verdict pass" },
        spawner: capturingSpawner,
        projectDir: project
      });
      expect(result.exitCode).toBe(0);
      expect(captured?.args).toContain("--ignore-scripts");
      expect(captured?.env.npm_config_ignore_scripts).toBe("true");
    } finally {
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("observe mode does NOT inject --ignore-scripts", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-script-observe-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf should-not-run\n");
    const project = await fixtureProject(temp);

    let captured: readonly string[] | undefined;
    const capturingSpawner: PackageManagerSpawner = (req) => {
      captured = req.args;
      return Promise.resolve({ exitCode: 0, stdout: "added 1 package\n", stderr: "" });
    };

    try {
      await runPackageManager("npm", ["install", "esbuild"], {
        env: { HOME: temp, PATH: binDir },
        proxyVerdict: { verdict: "pass", packageName: "esbuild", cause: "pass", reason: "proxy verdict pass" },
        spawner: capturingSpawner,
        projectDir: project
      });
      expect(captured).not.toContain("--ignore-scripts");
    } finally {
      await rm(temp, { force: true, recursive: true });
    }
  });

  it("emits no report line for python installs or when detection finds nothing", async () => {
    const temp = await mkdtemp(join(tmpdir(), "dg-launcher-script-gate-"));
    const binDir = join(temp, "bin");
    await mkdir(binDir);
    await writeExecutable(join(binDir, "pip"), "#!/bin/sh\nprintf should-not-run\n");
    await writeExecutable(join(binDir, "npm"), "#!/bin/sh\nprintf should-not-run\n");

    try {
      const pip = await runPackageManager("pip", ["install", "requests"], {
        env: { HOME: temp, PATH: binDir },
        proxyVerdict: { verdict: "pass", packageName: "requests", cause: "pass", reason: "proxy verdict pass" },
        spawner: fakeSpawner("Successfully installed requests\n", "")
      });
      const emptyProject = await runPackageManager("npm", ["install", "left-pad"], {
        env: { HOME: temp, PATH: binDir },
        proxyVerdict: { verdict: "pass", packageName: "left-pad", cause: "pass", reason: "proxy verdict pass" },
        spawner: fakeSpawner("added 1 package\n", ""),
        projectDir: join(temp, "no-such-project")
      });

      expect(pip.exitCode).toBe(0);
      expect(pip.stderr).not.toContain("dg scripts:");
      expect(emptyProject.exitCode).toBe(0);
      expect(emptyProject.stderr).not.toContain("dg scripts:");
    } finally {
      await rm(temp, { force: true, recursive: true });
    }
  });
});
