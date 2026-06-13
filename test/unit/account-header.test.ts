import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { stripVTControlCharacters } from "node:util";
import { writeAuthState } from "../../src/auth/store.js";
import { accountHeaderLine } from "../../src/scan-ui/shims.js";

describe("accountHeaderLine", () => {
  let home: string;
  let env: { HOME: string };

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "dg-account-header-test-"));
    env = { HOME: home };
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("uses the stored name and tier when the scan response has no usage block", () => {
    writeAuthState({ token: "dg_live_header_token_value", email: "dev@example.com", tier: "pro", name: "Ada" }, env);
    expect(stripVTControlCharacters(accountHeaderLine(undefined, env))).toBe("Ada · Pro plan");
  });

  it("prefers the usage tier from the scan response over the stored tier", () => {
    writeAuthState({ token: "dg_live_header_token_value", email: "dev@example.com", tier: "pro", name: "Ada" }, env);
    expect(stripVTControlCharacters(accountHeaderLine("team", env))).toBe("Ada · Team plan");
  });

  it("falls back to the stored email when no name was cached at login", () => {
    writeAuthState({ token: "dg_live_header_token_value", email: "dev@example.com", tier: "free" }, env);
    expect(stripVTControlCharacters(accountHeaderLine(undefined, env))).toBe("dev@example.com · Free plan");
  });

  it("nudges login when signed out", () => {
    expect(stripVTControlCharacters(accountHeaderLine(undefined, env))).toBe("Free · dg login");
  });
});
