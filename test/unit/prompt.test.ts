import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { promptYesNo, type PromptIo } from "../../src/install-ui/prompt.js";

function io(answer: string | null): PromptIo {
  const input = new PassThrough();
  const output = new PassThrough();
  if (answer !== null) {
    queueMicrotask(() => input.write(answer));
  }
  return { input, output, isTTY: answer !== null };
}

describe("promptYesNo", () => {
  it("returns true only for y or yes", async () => {
    await expect(promptYesNo("Proceed?", io("y\n"))).resolves.toBe(true);
    await expect(promptYesNo("Proceed?", io("yes\n"))).resolves.toBe(true);
    await expect(promptYesNo("Proceed?", io("Y\n"))).resolves.toBe(true);
  });

  it("defaults to No on Enter or any other input", async () => {
    await expect(promptYesNo("Proceed?", io("\n"))).resolves.toBe(false);
    await expect(promptYesNo("Proceed?", io("n\n"))).resolves.toBe(false);
    await expect(promptYesNo("Proceed?", io("maybe\n"))).resolves.toBe(false);
  });

  it("never prompts and returns false when not a TTY", async () => {
    await expect(promptYesNo("Proceed?", io(null))).resolves.toBe(false);
  });
});
