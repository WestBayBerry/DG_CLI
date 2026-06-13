import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";

export class JsonStoreError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "JsonStoreError";
  }
}

export async function readJsonFile<T>(path: string, fallback: T): Promise<T> {
  try {
    const content = await readFile(path, "utf8");
    return JSON.parse(content) as T;
  } catch (error) {
    if (isNotFound(error)) {
      return fallback;
    }
    if (error instanceof SyntaxError) {
      throw new JsonStoreError(`Malformed JSON store at ${path}`, error);
    }
    throw error;
  }
}

export async function writeJsonFileAtomic(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), {
    recursive: true,
    mode: 0o700
  });

  const tempPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const payload = `${JSON.stringify(value, null, 2)}\n`;

  try {
    await writeFile(tempPath, payload, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600
    });
    await rename(tempPath, path);
  } catch (error) {
    await rm(tempPath, {
      force: true
    });
    throw error;
  }
}

function isNotFound(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
