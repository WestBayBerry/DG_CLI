import { closeSync, openSync, readSync } from "node:fs";

export function promptYesNo(
  question: string,
  defaultYes: boolean,
  out: { write(text: string): unknown } = process.stderr
): boolean | null {
  const answer = promptLine(`${question} ${defaultYes ? "[Y/n]" : "[y/N]"} `, out);
  if (answer === null) {
    return null;
  }
  const normalized = answer.trim().toLowerCase();
  if (normalized === "") {
    return defaultYes;
  }
  return normalized === "y" || normalized === "yes";
}

export function promptLine(
  question: string,
  out: { write(text: string): unknown } = process.stderr
): string | null {
  let tty: number;
  try {
    tty = openSync("/dev/tty", "rs");
  } catch {
    return null;
  }
  try {
    out.write(question);
    const byte = Buffer.alloc(1);
    let answer = "";
    for (;;) {
      let read = 0;
      try {
        read = readSync(tty, byte, 0, 1, null);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EAGAIN") {
          continue;
        }
        break;
      }
      if (read === 0) {
        break;
      }
      const char = byte.toString("utf8");
      if (char === "\n" || char === "\r") {
        break;
      }
      answer += char;
    }
    return answer;
  } finally {
    closeSync(tty);
  }
}
