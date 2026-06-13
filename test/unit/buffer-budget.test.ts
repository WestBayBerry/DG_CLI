import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { BufferBudgetError, collectBounded, currentBufferedBytes } from "../../src/proxy/buffer-budget.js";

describe("collectBounded", () => {
  it("collects a stream and releases the global accounting", async () => {
    const stream = new PassThrough();
    const pending = collectBounded(stream, { label: "test", env: {} });
    stream.write(Buffer.alloc(1024, 1));
    stream.write(Buffer.alloc(1024, 2));
    stream.end();

    const body = await pending;
    expect(body.length).toBe(2048);
    expect(currentBufferedBytes()).toBe(0);
  });

  it("rejects and destroys the stream past the per-artifact limit, never accumulating", async () => {
    const stream = new PassThrough();
    const pending = collectBounded(stream, { label: "big artifact", env: { DG_PROXY_MAX_ARTIFACT_BYTES: "1000" } });
    stream.write(Buffer.alloc(600));
    stream.write(Buffer.alloc(600));

    await expect(pending).rejects.toBeInstanceOf(BufferBudgetError);
    expect(stream.destroyed).toBe(true);
    expect(currentBufferedBytes()).toBe(0);
  });

  it("rejects when the global in-flight budget is exhausted across streams", async () => {
    const env = { DG_PROXY_MAX_BUFFERED_BYTES: "4000" };
    const first = new PassThrough();
    const second = new PassThrough();
    const firstPending = collectBounded(first, { label: "first", env });
    const secondPending = collectBounded(second, { label: "second", env });

    first.write(Buffer.alloc(3000));
    second.write(Buffer.alloc(3000));

    await expect(secondPending).rejects.toBeInstanceOf(BufferBudgetError);
    first.end();
    await expect(firstPending).resolves.toHaveLength(3000);
    expect(currentBufferedBytes()).toBe(0);
  });

  it("releases the accounting when a stream errors or closes before completing", async () => {
    const errored = new PassThrough();
    const erroredPending = collectBounded(errored, { label: "errored", env: {} });
    errored.write(Buffer.alloc(500));
    errored.destroy(new Error("connection reset"));
    await expect(erroredPending).rejects.toThrow("connection reset");

    const closed = new PassThrough();
    const closedPending = collectBounded(closed, { label: "closed", env: {} });
    closed.write(Buffer.alloc(500));
    closed.destroy();
    await expect(closedPending).rejects.toBeInstanceOf(BufferBudgetError);

    expect(currentBufferedBytes()).toBe(0);
  });
});
