import { describe, expect, it } from "vitest";
import { stripVTControlCharacters } from "node:util";
import { displayWidth, pad, truncate, formatAccountStatus } from "../../src/scan-ui/format-helpers.js";

const plain = (tier: string, loggedIn: boolean, name?: string): string =>
  stripVTControlCharacters(formatAccountStatus(tier, loggedIn, name));

describe("formatAccountStatus", () => {
  it("shows the plan when signed in", () => {
    expect(plain("pro", true)).toBe("Pro plan");
    expect(plain("team", true)).toBe("Team plan");
  });

  it("nudges login when signed out", () => {
    expect(plain("free", false)).toBe("Free \u00b7 dg login");
  });

  it("falls back when the tier is empty", () => {
    expect(plain("", false)).toBe("Free \u00b7 dg login");
    expect(plain("", true)).toBe("Account plan");
  });

  it("strips a hostile escape sequence smuggled in the tier", () => {
    expect(formatAccountStatus("pro\u001b[31m", true)).not.toContain("\u001b[31m");
  });

  it("shows the account name next to the plan when known", () => {
    expect(plain("pro", true, "Ada")).toBe("Ada \u00b7 Pro plan");
    expect(plain("team", true, "dev@example.com")).toBe("dev@example.com \u00b7 Team plan");
  });

  it("ignores the name when signed out", () => {
    expect(plain("free", false, "Ada")).toBe("Free \u00b7 dg login");
  });

  it("strips a hostile escape sequence smuggled in the name and caps its length", () => {
    expect(formatAccountStatus("pro", true, "Mc\u001b[31mkeane")).not.toContain("\u001b[31m");
    expect(plain("pro", true, "x".repeat(100))).toBe(`${"x".repeat(40)} \u00b7 Pro plan`);
  });
});

describe("displayWidth", () => {
  it("counts ASCII as one column per character", () => {
    expect(displayWidth("left-pad")).toBe(8);
    expect(displayWidth("")).toBe(0);
  });

  it("counts CJK and fullwidth characters as two columns", () => {
    expect(displayWidth("漢字")).toBe(4);
    expect(displayWidth("ライブラリ")).toBe(10);
    expect(displayWidth("ＡＢ")).toBe(4);
  });

  it("counts emoji as two columns without splitting surrogate pairs", () => {
    expect(displayWidth("🦀")).toBe(2);
    expect(displayWidth("pkg-🦀")).toBe(6);
  });

  it("counts combining marks and variation selectors as zero columns", () => {
    expect(displayWidth("é")).toBe(1);
    expect(displayWidth("⚠️")).toBe(1);
  });
});

describe("truncate", () => {
  it("keeps strings at or under the budget unchanged", () => {
    expect(truncate("abc", 3)).toBe("abc");
    expect(truncate("abc", 10)).toBe("abc");
  });

  it("cuts ASCII to width minus one plus the ellipsis", () => {
    expect(truncate("abcdef", 5)).toBe("abcd…");
  });

  it("never splits a surrogate pair", () => {
    expect(truncate("🦀🦀🦀", 4)).toBe("🦀…");
    expect(truncate("🦀🦀🦀", 5)).toBe("🦀🦀…");
  });

  it("budgets CJK characters at their rendered width", () => {
    expect(truncate("漢字漢字", 5)).toBe("漢字…");
    expect(displayWidth(truncate("漢字漢字", 5))).toBe(5);
  });
});

describe("pad", () => {
  it("pads by display width so wide characters stay column-aligned", () => {
    expect(pad("漢字", 6)).toBe("漢字  ");
    expect(pad("🦀", 4)).toBe("🦀  ");
    expect(pad("ab", 4)).toBe("ab  ");
  });

  it("leaves strings at or over the width unchanged", () => {
    expect(pad("abcd", 4)).toBe("abcd");
    expect(pad("abcdef", 4)).toBe("abcdef");
  });
});
