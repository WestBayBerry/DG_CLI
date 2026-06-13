import type { Socket } from "node:net";
import { connect } from "node:net";
import { redactSecrets } from "../launcher/output-redaction.js";

export interface UpstreamProxyConfig {
  readonly url: URL;
  readonly authorizationHeader?: string;
  readonly redactedUrl: string;
}

export function selectUpstreamProxy(target: URL, env: NodeJS.ProcessEnv): UpstreamProxyConfig | null {
  const explicit = env.DG_UPSTREAM_PROXY;
  const inherited = target.protocol === "https:"
    ? env.HTTPS_PROXY ?? env.https_proxy ?? env.ALL_PROXY ?? env.all_proxy
    : env.HTTP_PROXY ?? env.http_proxy ?? env.ALL_PROXY ?? env.all_proxy;
  const raw = explicit ?? inherited;
  if (!raw || (!explicit && matchesNoProxy(target.hostname, target.port, env.NO_PROXY ?? env.no_proxy))) {
    return null;
  }
  const url = new URL(raw);
  if (url.protocol !== "http:") {
    throw new Error("only HTTP upstream proxies are supported for per-invocation proxy chaining");
  }
  const authorizationHeader = url.username || url.password
    ? `Basic ${Buffer.from(`${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`).toString("base64")}`
    : undefined;
  return {
    url,
    ...(authorizationHeader ? { authorizationHeader } : {}),
    redactedUrl: redactSecrets(url.toString())
  };
}

export function connectViaUpstreamProxy(
  target: URL,
  upstream: UpstreamProxyConfig,
  extraHeaders: readonly string[] = []
): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect(Number(upstream.url.port || "80"), upstream.url.hostname);
    const chunks: Buffer[] = [];
    const fail = (error: unknown) => {
      socket.destroy();
      reject(error);
    };
    socket.once("error", fail);
    socket.once("connect", () => {
      const authority = authorityFor(target);
      const headers = [
        `CONNECT ${authority} HTTP/1.1`,
        `Host: ${authority}`,
        "Proxy-Connection: keep-alive",
        ...(upstream.authorizationHeader ? [`Proxy-Authorization: ${upstream.authorizationHeader}`] : []),
        ...extraHeaders,
        "",
        ""
      ];
      socket.write(headers.join("\r\n"));
    });
    socket.on("data", function onData(chunk: Buffer) {
      chunks.push(chunk);
      const buffered = Buffer.concat(chunks);
      if (buffered.length > 64 * 1024) {
        socket.off("data", onData);
        socket.destroy();
        reject(new Error("upstream proxy CONNECT response exceeded the 64KiB header limit"));
        return;
      }
      const headerEnd = buffered.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        return;
      }
      socket.off("data", onData);
      socket.off("error", fail);
      const head = buffered.subarray(headerEnd + 4);
      const statusLine = buffered.subarray(0, headerEnd).toString("latin1").split("\r\n")[0] ?? "";
      if (!/^HTTP\/1\.[01] 2\d\d\b/.test(statusLine)) {
        socket.destroy();
        reject(new Error(`upstream proxy CONNECT failed: ${statusLine}`));
        return;
      }
      if (head.length > 0) {
        socket.unshift(head);
      }
      resolve(socket);
    });
  });
}

export function authorityFor(target: URL): string {
  const port = target.port || (target.protocol === "https:" ? "443" : "80");
  return `${target.hostname}:${port}`;
}

function matchesNoProxy(host: string, port: string, rawNoProxy: string | undefined): boolean {
  if (!rawNoProxy) {
    return false;
  }
  const normalizedHost = host.toLowerCase();
  const hostPort = `${normalizedHost}:${port}`;
  for (const rawEntry of rawNoProxy.split(",")) {
    const entry = rawEntry.trim().toLowerCase();
    if (!entry) {
      continue;
    }
    if (entry === "*") {
      return true;
    }
    if (entry === normalizedHost || entry === hostPort) {
      return true;
    }
    if (entry.startsWith(".") && normalizedHost.endsWith(entry)) {
      return true;
    }
  }
  return false;
}
