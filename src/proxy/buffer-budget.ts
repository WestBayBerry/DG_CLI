import type { Readable } from "node:stream";

export class BufferBudgetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BufferBudgetError";
  }
}

const DEFAULT_MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BUFFERED_BYTES = 2 * 1024 * 1024 * 1024;

let totalBufferedBytes = 0;

export function maxArtifactBytes(env: NodeJS.ProcessEnv = process.env): number {
  return parseLimit(env.DG_PROXY_MAX_ARTIFACT_BYTES, DEFAULT_MAX_ARTIFACT_BYTES);
}

export function maxTotalBufferedBytes(env: NodeJS.ProcessEnv = process.env): number {
  return parseLimit(env.DG_PROXY_MAX_BUFFERED_BYTES, DEFAULT_MAX_TOTAL_BUFFERED_BYTES);
}

export function currentBufferedBytes(): number {
  return totalBufferedBytes;
}

export function collectBounded(
  stream: Readable,
  options: {
    readonly label: string;
    readonly env?: NodeJS.ProcessEnv;
    readonly limitBytes?: number;
  }
): Promise<Buffer> {
  const env = options.env ?? process.env;
  const limit = options.limitBytes ?? maxArtifactBytes(env);
  const totalLimit = maxTotalBufferedBytes(env);

  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;

    const settle = (finish: () => void): void => {
      if (settled) {
        return;
      }
      settled = true;
      totalBufferedBytes -= size;
      finish();
    };

    stream.on("data", (chunk: Buffer) => {
      if (settled) {
        return;
      }
      size += chunk.length;
      totalBufferedBytes += chunk.length;
      if (size > limit) {
        settle(() => reject(new BufferBudgetError(`${options.label} exceeded the ${limit}-byte artifact buffer limit`)));
        stream.destroy();
        return;
      }
      if (totalBufferedBytes > totalLimit) {
        settle(() => reject(new BufferBudgetError(`proxy buffered-bytes budget exhausted while fetching ${options.label}`)));
        stream.destroy();
        return;
      }
      chunks.push(chunk);
    });
    stream.once("end", () => settle(() => resolve(Buffer.concat(chunks))));
    stream.once("error", (error: Error) => settle(() => reject(error)));
    stream.once("close", () => settle(() => reject(new BufferBudgetError(`${options.label} connection closed before the response completed`))));
  });
}

function parseLimit(raw: string | undefined, fallback: number): number {
  if (!raw) {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
