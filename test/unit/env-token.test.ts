import { describe, expect, it } from "vitest";
import { envAuthToken } from "../../src/auth/env-token.js";

describe("envAuthToken (CI auth env)", () => {
  it("reads DG_API_KEY (the documented CI name)", () => {
    expect(envAuthToken({ DG_API_KEY: "dg_live_key" })).toBe("dg_live_key");
  });

  it("reads DG_API_TOKEN (historical alias)", () => {
    expect(envAuthToken({ DG_API_TOKEN: "dg_live_tok" })).toBe("dg_live_tok");
  });

  it("prefers DG_API_KEY when both are set", () => {
    expect(envAuthToken({ DG_API_KEY: "key", DG_API_TOKEN: "tok" })).toBe("key");
  });

  it("returns undefined when neither is set or values are empty", () => {
    expect(envAuthToken({})).toBeUndefined();
    expect(envAuthToken({ DG_API_KEY: "", DG_API_TOKEN: "" })).toBeUndefined();
  });
});
