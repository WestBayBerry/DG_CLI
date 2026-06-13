import { describe, expect, it } from "vitest";
import { closestCommand } from "../../src/commands/suggest.js";
import { runCli } from "../../src/runtime/cli.js";

const commands = ["scan", "verify", "setup", "doctor", "licenses", "login"];

describe("closestCommand", () => {
  it("suggests the nearest command within the distance threshold", () => {
    expect(closestCommand("scna", commands)).toBe("scan");
    expect(closestCommand("verfy", commands)).toBe("verify");
    expect(closestCommand("licneses", commands)).toBe("licenses");
  });

  it("returns null when nothing is close enough", () => {
    expect(closestCommand("xylophone", commands)).toBeNull();
  });

  it("returns the command unchanged on an exact match", () => {
    expect(closestCommand("scan", commands)).toBe("scan");
    expect(closestCommand("licenses", commands)).toBe("licenses");
  });

  it("returns null when the edit distance exceeds the threshold", () => {
    expect(closestCommand("zzzzzzz", commands)).toBeNull();
  });

  it("picks the first-seen candidate on a distance tie", () => {
    expect(closestCommand("aaa", ["bbb", "ccc"])).toBe("bbb");
    expect(closestCommand("aaa", ["ccc", "bbb"])).toBe("ccc");
  });

  it("treats case as a substitution cost (not case-insensitive)", () => {
    expect(closestCommand("Scan", commands)).toBe("scan");
    expect(closestCommand("SCAN", commands)).toBeNull();
  });

  it("returns null for an empty candidate list", () => {
    expect(closestCommand("scan", [])).toBeNull();
  });

  it("suggests across a single-character transposition", () => {
    expect(closestCommand("sacn", commands)).toBe("scan");
  });
});

describe("router unknown command", () => {
  it("includes a did-you-mean hint for a near miss", async () => {
    const result = await runCli(["scna"]);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("unknown command 'scna'");
    expect(result.stderr).toContain("Did you mean 'scan'?");
  });

  it("omits the hint when there is no close match", async () => {
    const result = await runCli(["xylophone"]);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("unknown command 'xylophone'");
    expect(result.stderr).not.toContain("Did you mean");
  });
});
