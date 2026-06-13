import { createInterface } from "node:readline";

export type PromptIo = {
  readonly input: NodeJS.ReadableStream;
  readonly output: NodeJS.WritableStream;
  readonly isTTY: boolean;
};

export function defaultPromptIo(): PromptIo {
  return {
    input: process.stdin,
    output: process.stderr,
    isTTY: Boolean(process.stdin.isTTY && process.stderr.isTTY)
  };
}

export async function promptText(question: string, io: PromptIo): Promise<string> {
  if (!io.isTTY) {
    return "";
  }
  const rl = createInterface({ input: io.input, output: io.output });
  try {
    return await new Promise<string>((resolve) => {
      rl.question(question, resolve);
    });
  } finally {
    rl.close();
  }
}

export async function promptYesNo(question: string, io: PromptIo, defaultYes = false): Promise<boolean> {
  if (!io.isTTY) {
    return false;
  }
  const rl = createInterface({ input: io.input, output: io.output });
  try {
    const answer = await new Promise<string>((resolve) => {
      rl.question(`${question} ${defaultYes ? "[Y/n]" : "[y/N]"} `, resolve);
    });
    const normalized = answer.trim().toLowerCase();
    if (normalized === "") {
      return defaultYes;
    }
    return normalized === "y" || normalized === "yes";
  } finally {
    rl.close();
  }
}
