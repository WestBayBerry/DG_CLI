import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  applyAgentRouting,
  removeAgentRouting,
  resolveServiceRoutingEnv,
  routingInstalled,
} from "../../src/agents/routing.js";

const ROUTING = {
  DG_PROXY_ACTIVE: "1",
  HTTPS_PROXY: "http://127.0.0.1:9000",
  NODE_EXTRA_CA_CERTS: "/tmp/dg-ca.pem",
};

describe("agent routing injection", () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "dg-routing-"));
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("Claude: injects the env block, preserving the user's other env, and is fully reversible", () => {
    mkdirSync(join(home, ".claude"), { recursive: true });
    const settingsPath = join(home, ".claude", "settings.json");
    // The user already has a corporate HTTPS_PROXY and an unrelated key.
    writeFileSync(settingsPath, JSON.stringify({ env: { EXISTING: "keep", HTTPS_PROXY: "http://corp:8080" } }));

    const r = applyAgentRouting("claude-code", ROUTING, home, { HOME: home });
    expect(r.applied).toBe(true);
    let s = JSON.parse(readFileSync(settingsPath, "utf8")) as { env: Record<string, string> };
    expect(s.env.DG_PROXY_ACTIVE).toBe("1");
    expect(s.env.HTTPS_PROXY).toBe("http://127.0.0.1:9000");
    expect(s.env.EXISTING).toBe("keep");
    expect(routingInstalled("claude-code", home, { HOME: home })).toBe(true);

    removeAgentRouting("claude-code", home, { HOME: home });
    s = JSON.parse(readFileSync(settingsPath, "utf8")) as { env: Record<string, string> };
    expect(s.env.DG_PROXY_ACTIVE).toBeUndefined();
    expect(s.env.NODE_EXTRA_CA_CERTS).toBeUndefined();
    // The user's prior corporate proxy is RESTORED, not clobbered.
    expect(s.env.HTTPS_PROXY).toBe("http://corp:8080");
    expect(s.env.EXISTING).toBe("keep");
    expect(routingInstalled("claude-code", home, { HOME: home })).toBe(false);
  });

  it("Codex: appends a delimited [shell_environment_policy] block and strips it cleanly", () => {
    mkdirSync(join(home, ".codex"), { recursive: true });
    const configPath = join(home, ".codex", "config.toml");
    writeFileSync(configPath, '[projects]\nfoo = "bar"\n');

    const r = applyAgentRouting("codex", ROUTING, home, { HOME: home });
    expect(r.applied).toBe(true);
    let toml = readFileSync(configPath, "utf8");
    expect(toml).toContain("# >>> dg routing >>>");
    expect(toml).toContain("[shell_environment_policy]");
    expect(toml).toContain('DG_PROXY_ACTIVE = "1"');
    expect(toml).toContain('HTTPS_PROXY = "http://127.0.0.1:9000"');
    expect(routingInstalled("codex", home, { HOME: home })).toBe(true);

    removeAgentRouting("codex", home, { HOME: home });
    toml = readFileSync(configPath, "utf8");
    expect(toml).not.toContain("shell_environment_policy");
    expect(toml).not.toContain("dg routing");
    expect(toml).toContain('foo = "bar"');
    expect(routingInstalled("codex", home, { HOME: home })).toBe(false);
  });

  it("Codex: refuses (no clobber) when the user already defines [shell_environment_policy]", () => {
    mkdirSync(join(home, ".codex"), { recursive: true });
    const configPath = join(home, ".codex", "config.toml");
    writeFileSync(configPath, '[shell_environment_policy]\ninherit = "all"\n');

    const r = applyAgentRouting("codex", ROUTING, home, { HOME: home });
    expect(r.applied).toBe(false);
    expect(r.detail).toContain("already defines");
    expect(readFileSync(configPath, "utf8")).toContain('inherit = "all"');
  });

  it("refuses to resolve routing env when the dg service is not running", () => {
    const r = resolveServiceRoutingEnv({ HOME: home });
    expect("error" in r).toBe(true);
  });
});
