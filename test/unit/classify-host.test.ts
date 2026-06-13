import { describe, expect, it } from "vitest";
import { shouldMitmHost } from "../../src/proxy/classify-host.js";

const emptyEnv: NodeJS.ProcessEnv = {};

describe("shouldMitmHost default registries", () => {
  it("MITMs the npm registry", () => {
    expect(shouldMitmHost("registry.npmjs.org", emptyEnv)).toBe(true);
  });

  it("MITMs an npmjs.org subdomain via the wildcard pattern", () => {
    expect(shouldMitmHost("sub.npmjs.org", emptyEnv)).toBe(true);
  });

  it("does not MITM the bare npmjs.org apex (wildcard requires a label)", () => {
    expect(shouldMitmHost("npmjs.org", emptyEnv)).toBe(false);
  });

  it("MITMs the yarn registry", () => {
    expect(shouldMitmHost("registry.yarnpkg.com", emptyEnv)).toBe(true);
  });

  it("MITMs pypi.org and files.pythonhosted.org", () => {
    expect(shouldMitmHost("pypi.org", emptyEnv)).toBe(true);
    expect(shouldMitmHost("files.pythonhosted.org", emptyEnv)).toBe(true);
  });

  it("MITMs crates.io and its static/index hosts", () => {
    expect(shouldMitmHost("crates.io", emptyEnv)).toBe(true);
    expect(shouldMitmHost("static.crates.io", emptyEnv)).toBe(true);
    expect(shouldMitmHost("index.crates.io", emptyEnv)).toBe(true);
  });

  it("does not MITM unknown hosts", () => {
    expect(shouldMitmHost("evil.example.com", emptyEnv)).toBe(false);
    expect(shouldMitmHost("npmjs.org.attacker.test", emptyEnv)).toBe(false);
    expect(shouldMitmHost("registry.yarnpkg.com.evil.test", emptyEnv)).toBe(false);
  });
});

describe("shouldMitmHost normalization", () => {
  it("strips a trailing dot before matching", () => {
    expect(shouldMitmHost("registry.npmjs.org.", emptyEnv)).toBe(true);
  });

  it("lowercases the host before matching", () => {
    expect(shouldMitmHost("Registry.NPMJS.org", emptyEnv)).toBe(true);
  });

  it("strips IPv6 brackets before matching", () => {
    expect(shouldMitmHost("[pypi.org]", emptyEnv)).toBe(true);
  });

  it("applies normalization to the wildcard subdomain too", () => {
    expect(shouldMitmHost("SUB.NPMJS.ORG.", emptyEnv)).toBe(true);
  });
});

describe("shouldMitmHost DG_PROXY_MITM_HOSTS extension", () => {
  it("MITMs an exact host added via the env override", () => {
    const env: NodeJS.ProcessEnv = { DG_PROXY_MITM_HOSTS: "mirror.internal.test" };
    expect(shouldMitmHost("mirror.internal.test", env)).toBe(true);
    expect(shouldMitmHost("other.internal.test", env)).toBe(false);
  });

  it("MITMs subdomains of a *.suffix pattern from the env override", () => {
    const env: NodeJS.ProcessEnv = { DG_PROXY_MITM_HOSTS: "*.corp.test" };
    expect(shouldMitmHost("registry.corp.test", env)).toBe(true);
    expect(shouldMitmHost("a.b.corp.test", env)).toBe(true);
    expect(shouldMitmHost("corp.test", env)).toBe(false);
  });

  it("supports multiple comma-separated env entries with surrounding whitespace", () => {
    const env: NodeJS.ProcessEnv = { DG_PROXY_MITM_HOSTS: " one.test , *.two.test " };
    expect(shouldMitmHost("one.test", env)).toBe(true);
    expect(shouldMitmHost("api.two.test", env)).toBe(true);
    expect(shouldMitmHost("three.test", env)).toBe(false);
  });

  it("ignores empty entries from trailing or doubled commas", () => {
    const env: NodeJS.ProcessEnv = { DG_PROXY_MITM_HOSTS: ",, ,one.test,," };
    expect(shouldMitmHost("one.test", env)).toBe(true);
    expect(shouldMitmHost("", env)).toBe(false);
  });

  it("normalizes env patterns (case and trailing dot) before matching", () => {
    const env: NodeJS.ProcessEnv = { DG_PROXY_MITM_HOSTS: "Mirror.Internal.Test." };
    expect(shouldMitmHost("mirror.internal.test", env)).toBe(true);
  });

  it("still MITMs the defaults when the env override is present", () => {
    const env: NodeJS.ProcessEnv = { DG_PROXY_MITM_HOSTS: "mirror.internal.test" };
    expect(shouldMitmHost("registry.npmjs.org", env)).toBe(true);
  });
});
