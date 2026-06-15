import { describe, expect, it } from "vitest";
import { sanitize, sanitizeLine, sanitizeDeep } from "../../src/security/sanitize.js";

describe("sanitize", () => {
  it("strips ANSI/VT escape sequences", () => {
    expect(sanitize("\x1b[31mred\x1b[0m")).toBe("red");
  });

  it("strips C0 controls (CR, BS) that survive VT-only stripping", () => {
    expect(sanitize("safe\rOVERWRITE\bX")).toBe("safeOVERWRITEX");
  });

  it("strips C1 controls (0x80-0x9F) that some terminals treat as escapes", () => {
    expect(sanitize("a\x9bb\x84c")).toBe("abc");
  });

  it("preserves newlines for multi-line reason text", () => {
    expect(sanitize("line1\nline2")).toBe("line1\nline2");
  });
});

describe("sanitizeLine", () => {
  it("collapses newlines to a space so a value cannot inject extra TUI rows", () => {
    expect(sanitizeLine("name\nINJECTED ROW")).toBe("name INJECTED ROW");
  });

  it("strips all control chars including tab", () => {
    expect(sanitizeLine("a\tb\rc")).toBe("ab c");
    expect(sanitizeLine("a\tb")).toBe("ab");
  });
});

describe("sanitizeDeep", () => {
  it("recursively strips control chars from nested findings/evidence", () => {
    const cleaned = sanitizeDeep({
      packages: [{ name: "evil\x1b[2J", findings: [{ title: "x\ry", evidence: ["snip\bpet"] }] }]
    });
    expect(cleaned.packages[0].name).toBe("evil");
    expect(cleaned.packages[0].findings[0].title).toBe("xy");
    expect(cleaned.packages[0].findings[0].evidence[0]).toBe("snippet");
  });

  it("neutralizes control chars in object keys (line mode)", () => {
    const cleaned = sanitizeDeep({ "k\rey": 1 }) as Record<string, number>;
    expect(Object.keys(cleaned)).toEqual(["k ey"]);
  });
});
