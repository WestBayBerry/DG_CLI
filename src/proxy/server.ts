import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { BufferBudgetError, collectBounded, maxArtifactBytes } from "./buffer-budget.js";
import { readFileSync } from "node:fs";
import {
  Agent as HttpAgent,
  createServer,
  request as httpRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type OutgoingHttpHeaders,
  type Server,
  type ServerResponse
} from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { connect, type Socket } from "node:net";
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { createSecureContext, createServer as createTlsServer, connect as tlsConnect, rootCertificates, type TLSSocket } from "node:tls";
import { createEphemeralCertificateAuthority, type CertificateAuthority } from "./ca.js";
import { shouldMitmHost } from "./classify-host.js";
import { generateProxyAuthToken, proxyAuthorizationValue, verifyProxyAuthorization, writeProxyAuthToken } from "./auth.js";
import { enforceProtectedInstall, noteEnforcementSideEffectFailure, type CooldownInfo, type EnforcementDecision, type ForceOverrideRequest, type ProxyVerdict } from "./enforcement.js";
import { cooldownRequestParam, isCooldownExemptByDgFile, type CooldownRequestParam } from "../policy/cooldown.js";
import type { CooldownExemption } from "../project/dgfile.js";
import { loadUserConfig } from "../config/settings.js";
import {
  artifactDisplayName,
  artifactUrlHash,
  extractRegistryMetadataIdentities,
  isRegistryIndexRequest,
  resolveArtifactIdentity,
  type ArtifactIdentity
} from "./metadata-map.js";
import { loadPreverifiedMap, preverifiedKey } from "./preverified.js";
import { authorityFor, connectViaUpstreamProxy, selectUpstreamProxy } from "./upstream-proxy.js";
import type { PackageManagerClassification } from "../launcher/classify.js";
import { redactSecrets } from "../launcher/output-redaction.js";
import { sanitize } from "../security/sanitize.js";
import { envAuthToken } from "../auth/env-token.js";
import { identityHeaders } from "../api/analyze.js";
import { dgVersion } from "../commands/version.js";
import { recordHeldPackage, type SessionHandle } from "../state/index.js";

export interface ProductionProxyOptions {
  readonly session: SessionHandle;
  readonly apiBaseUrl: string;
  readonly classification: PackageManagerClassification;
  readonly env: NodeJS.ProcessEnv;
  readonly listenHost?: string;
  readonly listenPort?: number;
  readonly verdictTimeoutMs?: number;
  readonly forceOverride?: ForceOverrideRequest;
  readonly cooldownExemptions?: readonly CooldownExemption[];
  readonly onCaRotate?: (caCertPem: string) => void;
}

export interface ProductionProxyHandle {
  readonly port: number;
  readonly proxyAuthorization: string;
  readonly close: () => Promise<void>;
}

export interface ProxySessionState {
  ready: boolean;
  port: number;
  decisions: EnforcementDecision[];
  inflight: string[];
  hashes: {
    readonly url: string;
    readonly sha256: string;
    readonly identity?: ArtifactIdentity;
  }[];
  identities: ArtifactIdentity[];
  events: string[];
}

export async function startProductionHttpProxy(options: ProductionProxyOptions): Promise<ProductionProxyHandle> {
  const onCaRotate = options.onCaRotate;
  const ca = createEphemeralCertificateAuthority(
    options.session.files.ca,
    onCaRotate ? { onRotate: (caCertPem) => safeCaRotateCallback(onCaRotate, caCertPem) } : {}
  );
  const authToken = generateProxyAuthToken();
  writeProxyAuthToken(options.session.dir, authToken);
  const state: ProxySessionState = {
    ready: false,
    port: 0,
    decisions: [],
    inflight: [],
    hashes: [],
    identities: [],
    events: []
  };
  const activeSockets = new Set<Socket>();
  const server = createServer((request, response) => {
    if (!verifyProxyAuthorization(headerValue(request.headers["proxy-authorization"]), authToken)) {
      sendProxyAuthRequired(response);
      return;
    }
    handleProxyRequest(request, response, options, state).catch((error: unknown) => {
      const decision = recordDecision(options, state, {
        verdict: "block",
        packageName: options.classification.manager,
        cause: "proxy-setup-failure",
        reason: error instanceof Error ? error.message : "proxy request failed"
      });
      sendBlocked(response, decision);
    });
  });
  server.on("connection", (socket) => trackSocket(activeSockets, socket));
  server.on("connect", (request, socket, head) => {
    const clientSocket = socket as Socket;
    if (!verifyProxyAuthorization(headerValue(request.headers["proxy-authorization"]), authToken)) {
      clientSocket.end("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"dg\"\r\nConnection: close\r\n\r\n");
      return;
    }
    handleConnectRequest(request, clientSocket, head, options, state, ca, activeSockets).catch((error: unknown) => {
      const decision = recordDecision(options, state, {
        verdict: "block",
        packageName: request.url ?? options.classification.manager,
        cause: "proxy-setup-failure",
        reason: error instanceof Error ? error.message : "TLS CONNECT proxying failed"
      });
      clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nDependency Guardian blocked ${redactSecrets(decision.packageName)}: ${redactSecrets(decision.reason)}\n`);
    });
  });

  await listen(server, options.listenHost ?? "127.0.0.1", options.listenPort ?? 0);
  const address = server.address();
  if (typeof address !== "object" || address === null) {
    throw new Error("production proxy did not bind a TCP port");
  }

  state.ready = true;
  state.port = address.port;
  writeProxyState(options.session, state);

  return {
    port: address.port,
    proxyAuthorization: proxyAuthorizationValue(authToken),
    close: () => closeServer(server, activeSockets)
  };
}

function safeCaRotateCallback(onCaRotate: (caCertPem: string) => void, caCertPem: string): void {
  try {
    onCaRotate(caCertPem);
  } catch (error) {
    noteEnforcementSideEffectFailure(error);
  }
}

function sendProxyAuthRequired(response: ServerResponse): void {
  const body = "Dependency Guardian proxy requires the per-session credential issued to the wrapped package manager.\n";
  response.writeHead(407, {
    "Proxy-Authenticate": "Basic realm=\"dg\"",
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": Buffer.byteLength(body)
  });
  response.end(body);
}

export function readProxySessionState(session: SessionHandle): ProxySessionState {
  try {
    const parsed = JSON.parse(readFileSync(session.files.proxy, "utf8")) as Partial<ProxySessionState>;
    return {
      ready: parsed.ready === true,
      port: typeof parsed.port === "number" ? parsed.port : 0,
      decisions: Array.isArray(parsed.decisions) ? parsed.decisions as EnforcementDecision[] : [],
      inflight: Array.isArray(parsed.inflight) ? parsed.inflight.filter((name): name is string => typeof name === "string") : [],
      hashes: Array.isArray(parsed.hashes) ? parsed.hashes as ProxySessionState["hashes"] : [],
      identities: Array.isArray(parsed.identities) ? parsed.identities as ArtifactIdentity[] : [],
      events: Array.isArray(parsed.events) ? parsed.events.filter((event): event is string => typeof event === "string") : []
    };
  } catch {
    return {
      ready: false,
      port: 0,
      decisions: [],
      inflight: [],
      hashes: [],
      identities: [],
      events: []
    };
  }
}

function listen(server: Server, host: string, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function closeServer(server: Server, activeSockets: Set<Socket>): Promise<void> {
  for (const socket of activeSockets) {
    socket.destroy();
  }
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}

function trackSocket(activeSockets: Set<Socket>, socket: Socket): void {
  activeSockets.add(socket);
  socket.once("close", () => {
    activeSockets.delete(socket);
  });
}

async function handleProxyRequest(
  request: IncomingMessage,
  response: ServerResponse,
  options: ProductionProxyOptions,
  state: ProxySessionState
): Promise<void> {
  const target = parseProxyTarget(request);
  if (!target || (target.protocol !== "http:" && target.protocol !== "https:")) {
    const decision = recordDecision(options, state, {
      verdict: "block",
      packageName: target?.hostname ?? "unknown-artifact",
      cause: "proxy-setup-failure",
      reason: "proxy request did not include a supported HTTP(S) artifact URL"
    });
    sendBlocked(response, decision);
    return;
  }

  await handleArtifactRequest(request, response, target, options, state);
}

async function handleConnectRequest(
  request: IncomingMessage,
  clientSocket: Socket,
  head: Buffer,
  options: ProductionProxyOptions,
  state: ProxySessionState,
  ca: CertificateAuthority,
  activeSockets: Set<Socket>
): Promise<void> {
  const target = parseConnectTarget(request.url);
  if (!target) {
    clientSocket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    return;
  }

  if (isLinkLocalHost(target)) {
    recordDecision(options, state, {
      verdict: "block",
      packageName: target.hostname,
      cause: "policy",
      reason: `refusing CONNECT to link-local/metadata address ${target.hostname}`
    });
    clientSocket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    return;
  }

  if (!shouldMitmHost(target.hostname, options.env)) {
    if (strictEgressEnabled(options.env)) {
      recordDecision(options, state, {
        verdict: "block",
        packageName: target.hostname,
        cause: "policy",
        reason: `strict egress: refusing to tunnel to un-screened host ${target.hostname} (add it to DG_PROXY_MITM_HOSTS to screen it, or disable policy.strictEgress)`
      });
      clientSocket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      return;
    }
    state.events = [...state.events, `tunnel:${redactSecrets(authorityFor(target))}`];
    writeProxyState(options.session, state);
    await blindTunnel(clientSocket, head, target, options, activeSockets);
    return;
  }

  state.events = [...state.events, `mitm:${redactSecrets(target.hostname)}`];
  writeProxyState(options.session, state);
  await mitmTunnel(clientSocket, head, target, options, state, ca, activeSockets);
}

const REDIRECT_LIMIT = 5;

// Streaming tail-hold: an OPT-IN fast path for artifacts so large their raw
// download alone would outlast the client read timeout. It streams bytes while
// hashing and withholds only the final TAIL bytes until the verdict arrives —
// so on a block the client receives most of the (unverified) artifact and is
// relied on to reject the truncated body via its own size/integrity checks.
// That is a weaker guarantee than the default buffered path, which delivers
// ZERO bytes until a pass verdict. It is therefore DISABLED by default; the
// preferred fix for a slow verify is a generous client read timeout (set in
// buildProxyChildEnv), which keeps the strong buffered guarantee. Enable only
// for genuinely huge artifacts via DG_STREAM_THRESHOLD_BYTES=<bytes>.
const STREAM_TAIL_BYTES = 64 * 1024;
const STREAMING_DISABLED = Number.POSITIVE_INFINITY;

// A package install fetches dozens-to-hundreds of artifacts from the same few
// registry hosts. Without connection reuse each is a fresh TCP+TLS handshake
// (~100-250ms to registry.npmjs.org); keep-alive agents pool sockets per host
// so an N-tarball install pays one handshake, not N. Reuse is keyed by the full
// connection option-set (host, port, TLS params), so this never crosses hosts
// or mixes TLS trust. Purely transport-level — no effect on what gets verified.
const upstreamHttpAgent = new HttpAgent({ keepAlive: true, maxSockets: 64, scheduling: "fifo" });
const upstreamHttpsAgent = new HttpsAgent({ keepAlive: true, maxSockets: 64, scheduling: "fifo" });

// Opt-in (policy.strictEgress, default off): a CONNECT to a host dg doesn't MITM
// is blind-tunnelled, so its artifacts arrive unscanned. Managed/CI environments
// can fail those closed instead. A corrupt config reads as off so a broken config
// never blocks installs that the default would have allowed.
function strictEgressEnabled(env: NodeJS.ProcessEnv): boolean {
  try {
    return loadUserConfig(env).policy.strictEgress;
  } catch {
    return false;
  }
}

function streamThresholdBytes(env: NodeJS.ProcessEnv): number {
  const raw = env.DG_STREAM_THRESHOLD_BYTES;
  if (raw === undefined || raw === "") {
    return STREAMING_DISABLED;
  }
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : STREAMING_DISABLED;
}

function canStreamTarget(target: URL, options: ProductionProxyOptions): boolean {
  if (selectUpstreamProxy(target, options.env)) {
    return false;
  }
  if (isRegistryIndexRequest(target)) {
    return false;
  }
  return !hostMatchesList(target.hostname, options.env.DG_PRIVATE_REGISTRY_HOSTS ?? "");
}

interface LiveUpstream {
  readonly statusCode: number;
  readonly headers: OutgoingHttpHeaders;
  readonly stream: IncomingMessage;
}

function shouldStreamArtifactResponse(live: LiveUpstream, env: NodeJS.ProcessEnv): boolean {
  if (live.statusCode < 200 || live.statusCode >= 300 || live.statusCode === 206) {
    return false;
  }
  const contentType = headerValue(live.headers["content-type"]) ?? "";
  if (/\bjson\b/i.test(contentType)) {
    return false;
  }
  const contentLength = Number(headerValue(live.headers["content-length"]) ?? "");
  return Number.isFinite(contentLength) && contentLength > streamThresholdBytes(env);
}

async function fetchUpstreamHeadersFollowingRedirects(
  request: IncomingMessage,
  target: URL,
  env: NodeJS.ProcessEnv
): Promise<LiveUpstream> {
  let current = target;
  let live = await fetchUpstreamHeaders(request, current, env);
  for (let hop = 0; isRedirectStatus(live.statusCode); hop += 1) {
    live.stream.resume();
    if (hop >= REDIRECT_LIMIT) {
      throw new Error(`registry redirect chain exceeded ${REDIRECT_LIMIT} hops for ${current.host}`);
    }
    const location = headerValue(live.headers.location);
    if (!location) {
      throw new Error(`registry returned a ${live.statusCode} redirect with no Location header for ${current.host}`);
    }
    const next = new URL(location, current);
    if (next.protocol !== "http:" && next.protocol !== "https:") {
      throw new Error(`registry redirected to unsupported protocol ${next.protocol}`);
    }
    if (isPrivateNetworkHost(next) && !isPrivateNetworkHost(target)) {
      throw new Error(`registry redirected a public artifact request into a private address (${next.hostname})`);
    }
    live = await fetchUpstreamHeaders(syntheticGetRequest(redirectHopHeaders(request, current, next)), next, env);
    current = next;
  }
  return live;
}

function fetchUpstreamHeaders(request: IncomingMessage, target: URL, env: NodeJS.ProcessEnv): Promise<LiveUpstream> {
  return new Promise((resolve, reject) => {
    const isHttps = target.protocol === "https:";
    const requester = isHttps ? httpsRequest : httpRequest;
    let liveStream: IncomingMessage | null = null;
    const upstream = requester({
      hostname: upstreamHostname(target, env),
      port: target.port ? Number(target.port) : isHttps ? 443 : 80,
      path: `${target.pathname}${target.search}`,
      method: request.method,
      agent: isHttps ? upstreamHttpsAgent : upstreamHttpAgent,
      headers: isHttps ? upstreamRequestHeaders(request, target) : stripProxyHopHeaders(request.headers),
      ...(isHttps ? upstreamTlsOptions(env) : {})
    }, (upstreamResponse) => {
      liveStream = upstreamResponse;
      resolve({
        statusCode: upstreamResponse.statusCode ?? 502,
        headers: responseHeaders(upstreamResponse),
        stream: upstreamResponse
      });
    });
    applyUpstreamTimeBudget(upstream, target, env, (error) => {
      liveStream?.destroy(error);
      reject(error);
    });
    upstream.on("error", reject);
    request.on("data", (chunk: Buffer) => upstream.write(chunk));
    request.on("end", () => upstream.end());
    request.on("error", reject);
    request.once("close", () => {
      if (!request.complete) {
        upstream.destroy();
      }
    });
  });
}

async function streamArtifactWithTailHold(
  response: ServerResponse,
  target: URL,
  options: ProductionProxyOptions,
  state: ProxySessionState,
  live: LiveUpstream
): Promise<void> {
  const identityResolution = resolveArtifactIdentity(target, state.identities, options.classification);
  if (identityResolution.kind === "ambiguous") {
    live.stream.destroy();
    const decision = recordDecision(options, state, {
      verdict: "block",
      packageName: identityResolution.packageName,
      cause: "policy",
      reason: identityResolution.reason
    });
    sendBlocked(response, decision);
    return;
  }
  const identity = identityResolution.identity;
  const inflightName = artifactDisplayName(identity);
  state.inflight = [...state.inflight, inflightName];
  writeProxyState(options.session, state);

  const limit = maxArtifactBytes(options.env);
  const hash = createHash("sha256");
  const tail: Buffer[] = [];
  let tailSize = 0;
  let total = 0;
  response.writeHead(live.statusCode, live.headers);
  response.once("close", () => {
    if (!response.writableEnded) {
      live.stream.destroy();
    }
  });

  const finishInflight = (): void => {
    state.inflight = removeFirst(state.inflight, inflightName);
  };

  try {
    await new Promise<void>((resolve, reject) => {
      live.stream.on("data", (chunk: Buffer) => {
        total += chunk.length;
        if (total > limit) {
          reject(new BufferBudgetError(`artifact exceeded the ${limit}-byte streaming budget for ${target.host}`));
          return;
        }
        hash.update(chunk);
        tail.push(chunk);
        tailSize += chunk.length;
        while (tail.length > 1 && tailSize - (tail[0]?.length ?? 0) >= STREAM_TAIL_BYTES) {
          const released = tail.shift();
          if (released) {
            tailSize -= released.length;
            response.write(released);
          }
        }
      });
      live.stream.once("end", () => resolve());
      live.stream.once("error", reject);
    });
  } catch (error) {
    finishInflight();
    live.stream.destroy();
    recordDecision(options, state, {
      verdict: "block",
      packageName: artifactDisplayName(identity),
      cause: error instanceof BufferBudgetError ? "proxy-setup-failure" : "registry-timeout",
      reason: error instanceof Error ? error.message : "registry stream failed"
    });
    response.destroy();
    return;
  }

  const sha256 = hash.digest("hex");
  state.hashes = [...state.hashes, {
    url: redactSecrets(target.toString()),
    sha256,
    identity
  }];
  writeProxyState(options.session, state);

  const verdict = await lookupVerdict(
    options,
    target,
    sha256,
    { statusCode: live.statusCode, headers: live.headers },
    identity
  ).catch((error: unknown): ProxyVerdict => ({
    verdict: "block",
    packageName: artifactDisplayName(identity),
    cause: "api-timeout",
    reason: error instanceof Error ? error.message : "Dependency Guardian API verdict lookup failed"
  }));
  finishInflight();
  const decision = recordDecision(options, state, verdict);

  if (decision.action === "block") {
    response.destroy();
    return;
  }
  for (const chunk of tail) {
    response.write(chunk);
  }
  response.end();
}


function isRedirectStatus(statusCode: number): boolean {
  return [301, 302, 303, 307, 308].includes(statusCode);
}

// Node's WHATWG URL parser canonicalizes an IPv4-mapped IPv6 literal to the hex
// hextet form ([::ffff:169.254.169.254] -> [::ffff:a9fe:a9fe]), so a guard that
// only string-matches the dotted-decimal form silently lets the cloud-metadata
// IP through as "public". Recover the embedded IPv4 (both forms) before
// classifying so the IPv4 ranges below cover the mapped address too.
function hextetsToIpv4(hi: string, lo: string): string {
  const h = parseInt(hi, 16);
  const l = parseInt(lo, 16);
  return `${(h >> 8) & 0xff}.${h & 0xff}.${(l >> 8) & 0xff}.${l & 0xff}`;
}

// Recover an IPv4 address embedded in an IPv6 literal so the IPv4 ranges below
// also cover it. Covers IPv4-mapped (::ffff:), IPv4-compatible (::), 6to4
// (2002::/16), and NAT64 (64:ff9b::/96) — each a way to smuggle 169.254.169.254
// past a guard that only string-matches the dotted-decimal form.
function recoverIpv4MappedHost(host: string): string {
  const mappedDotted = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(host);
  if (mappedDotted?.[1]) return mappedDotted[1];
  const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(host);
  if (mappedHex?.[1] && mappedHex[2]) return hextetsToIpv4(mappedHex[1], mappedHex[2]);
  const compatDotted = /^::(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(host);
  if (compatDotted?.[1]) return compatDotted[1];
  const compatHex = /^::([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(host);
  if (compatHex?.[1] && compatHex[2]) return hextetsToIpv4(compatHex[1], compatHex[2]);
  const sixToFour = /^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4}):/i.exec(host);
  if (sixToFour?.[1] && sixToFour[2]) return hextetsToIpv4(sixToFour[1], sixToFour[2]);
  const nat64Dotted = /^64:ff9b::(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(host);
  if (nat64Dotted?.[1]) return nat64Dotted[1];
  const nat64Hex = /^64:ff9b::([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(host);
  if (nat64Hex?.[1] && nat64Hex[2]) return hextetsToIpv4(nat64Hex[1], nat64Hex[2]);
  return host;
}

// Block a RESOLVED address (the actual connect target), so a public hostname
// whose A/AAAA record points at an internal/metadata IP — DNS-rebinding SSRF —
// is refused at connect time, not just literal-IP targets.
export function isBlockedResolvedIp(ip: string): boolean {
  const host = recoverIpv4MappedHost(ip.toLowerCase().replace(/^\[/, "").replace(/\]$/, ""));
  if (host === "0.0.0.0" || host === "::" || host === "::1") {
    return true;
  }
  if (isPrivateIpv4(host)) {
    return true;
  }
  return /^(fe80|f[cd][0-9a-f]{2}):/.test(host);
}

type GuardedLookupCb = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

function guardedLookup(hostname: string, options: unknown, callback: GuardedLookupCb): void {
  const opts = typeof options === "object" && options !== null ? (options as Record<string, unknown>) : {};
  dnsLookup(hostname, { ...opts, all: true }, (err, addresses) => {
    if (err) {
      callback(err, "", 0);
      return;
    }
    const list = addresses as LookupAddress[];
    const blocked = list.find((entry) => isBlockedResolvedIp(entry.address));
    if (blocked) {
      callback(new Error(`refusing to connect to ${hostname}: resolves to blocked address ${blocked.address}`), "", 0);
      return;
    }
    if (opts.all === true) {
      callback(null, list);
      return;
    }
    const first = list[0];
    if (!first) {
      callback(new Error(`no address found for ${hostname}`), "", 0);
      return;
    }
    callback(null, first.address, first.family);
  });
}

// The resolved-IP guard exists for DNS rebinding — a PUBLIC hostname whose A/AAAA
// record points at an internal IP. It must not fire for: an explicitly-configured
// private registry (DG_PRIVATE_REGISTRY_HOSTS) whose name legitimately resolves to
// a private IP; a test host-map target; or a target that is ALREADY a private/
// loopback literal (the user/test pointed there directly — not rebinding, and the
// link-local/metadata literal is still blocked at the artifact path).
function lookupForTarget(target: URL, env: NodeJS.ProcessEnv): typeof guardedLookup | undefined {
  const host = target.hostname.replace(/^\[(.*)\]$/, "$1");
  if (hostMatchesList(target.hostname, env.DG_PRIVATE_REGISTRY_HOSTS ?? "")) {
    return undefined;
  }
  if (testUpstreamHostMap(env).has(host)) {
    return undefined;
  }
  if (isPrivateNetworkHost(target)) {
    return undefined;
  }
  return guardedLookup;
}

function isPrivateIpv4(host: string): boolean {
  return (
    /^(127|10|0)\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^169\.254\./.test(host) ||
    /^172\.(1[6-9]|2[0-9]|3[01])\./.test(host) ||
    /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./.test(host)
  );
}

export function isPrivateNetworkHost(url: URL): boolean {
  const raw = url.hostname.toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
  const host = recoverIpv4MappedHost(raw);
  if (host === "localhost" || host.endsWith(".localhost") || host === "0.0.0.0" || host === "::" || host === "::1") {
    return true;
  }
  if (isPrivateIpv4(host)) {
    return true;
  }
  return /^(fe80|f[cd][0-9a-f]{2}):/.test(host);
}

export function isLinkLocalHost(url: URL): boolean {
  const raw = url.hostname.toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
  const host = recoverIpv4MappedHost(raw);
  return /^169\.254\./.test(host) || /^fe80:/.test(host);
}

function syntheticGetRequest(headers: IncomingHttpHeaders): IncomingMessage {
  const request = new EventEmitter() as IncomingMessage;
  request.method = "GET";
  request.headers = headers;
  request.complete = true;
  process.nextTick(() => request.emit("end"));
  return request;
}

function redirectHopHeaders(request: IncomingMessage, from: URL, next: URL): IncomingHttpHeaders {
  const headers: IncomingHttpHeaders = { ...request.headers };
  if (from.host !== next.host) {
    delete headers.authorization;
    delete headers.cookie;
  }
  return headers;
}

async function fetchUpstreamFollowingRedirects(
  request: IncomingMessage,
  target: URL,
  env: NodeJS.ProcessEnv
): Promise<{ readonly statusCode: number; readonly headers: OutgoingHttpHeaders; readonly body: Buffer }> {
  let current = target;
  let upstream = await fetchUpstream(request, current, env);
  for (let hop = 0; isRedirectStatus(upstream.statusCode); hop += 1) {
    if (hop >= REDIRECT_LIMIT) {
      throw new Error(`registry redirect chain exceeded ${REDIRECT_LIMIT} hops for ${current.host}`);
    }
    const location = headerValue(upstream.headers.location);
    if (!location) {
      throw new Error(`registry returned a ${upstream.statusCode} redirect with no Location header for ${current.host}`);
    }
    const next = new URL(location, current);
    if (next.protocol !== "http:" && next.protocol !== "https:") {
      throw new Error(`registry redirected to unsupported protocol ${next.protocol}`);
    }
    if (isPrivateNetworkHost(next) && !isPrivateNetworkHost(target)) {
      throw new Error(`registry redirected a public artifact request into a private address (${next.hostname})`);
    }
    upstream = await fetchUpstream(syntheticGetRequest(redirectHopHeaders(request, current, next)), next, env);
    current = next;
  }
  return upstream;
}

const ARTIFACT_CONDITIONAL_HEADERS = ["range", "if-range", "if-none-match", "if-modified-since"] as const;

async function handleArtifactRequest(
  request: IncomingMessage,
  response: ServerResponse,
  target: URL,
  options: ProductionProxyOptions,
  state: ProxySessionState
): Promise<void> {
  if (isLinkLocalHost(target)) {
    const decision = recordDecision(options, state, {
      verdict: "block",
      packageName: packageNameFromUrl(target),
      cause: "policy",
      reason: `refusing to fetch from link-local/metadata address ${target.hostname}`
    });
    sendBlocked(response, decision);
    return;
  }
  if (!isRegistryIndexRequest(target)) {
    for (const header of ARTIFACT_CONDITIONAL_HEADERS) {
      delete request.headers[header];
    }
  }
  let upstream: { readonly statusCode: number; readonly headers: OutgoingHttpHeaders; readonly body: Buffer } | null;
  try {
    if (canStreamTarget(target, options)) {
      const live = await fetchUpstreamHeadersFollowingRedirects(request, target, options.env);
      if (shouldStreamArtifactResponse(live, options.env)) {
        await streamArtifactWithTailHold(response, target, options, state, live);
        return;
      }
      upstream = {
        statusCode: live.statusCode,
        headers: live.headers,
        body: await collectBounded(live.stream, { label: target.toString() })
      };
    } else {
      upstream = await fetchUpstreamFollowingRedirects(request, target, options.env);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "registry request failed";
    const decision = recordDecision(options, state, {
      verdict: "block",
      packageName: packageNameFromUrl(target),
      cause: error instanceof BufferBudgetError ? "proxy-setup-failure" : "registry-timeout",
      reason: message
    });
    sendBlocked(response, decision);
    return;
  }
  if (!upstream) {
    return;
  }

  const metadataIdentities = extractRegistryMetadataIdentities(target, upstream);
  if (metadataIdentities.length > 0 || isRegistryIndexRequest(target)) {
    if (metadataIdentities.length > 0) {
      state.identities = mergeIdentities(state.identities, metadataIdentities);
      state.events = [...state.events, `metadata:${target.hostname}:${metadataIdentities.length}`];
    } else {
      state.events = [...state.events, `index:${target.hostname}`];
    }
    writeProxyState(options.session, state);
    response.writeHead(upstream.statusCode, upstream.headers);
    response.end(upstream.body);
    return;
  }

  if (upstream.statusCode === 206) {
    const decision = recordDecision(options, state, {
      verdict: "block",
      packageName: packageNameFromUrl(target),
      cause: "policy",
      reason: "registry returned partial content — a partial artifact cannot be verified"
    });
    sendBlocked(response, decision);
    return;
  }

  if (upstream.statusCode < 200 || upstream.statusCode >= 300) {
    // A non-success status is the registry's own error (e.g. 404 for a version
    // that does not exist) — not an installable artifact. Pass it through so the
    // package manager handles it (404s drive version resolution); scanning an
    // error body as if it were a package would mis-identify it.
    state.events = [...state.events, `passthrough:${upstream.statusCode}:${target.hostname}`];
    writeProxyState(options.session, state);
    response.writeHead(upstream.statusCode, upstream.headers);
    response.end(upstream.body);
    return;
  }

  const sha256 = createHash("sha256").update(upstream.body).digest("hex");
  const identity = resolveArtifactIdentity(target, state.identities, options.classification);
  if (identity.kind === "ambiguous") {
    state.hashes = [...state.hashes, {
      url: redactSecrets(target.toString()),
      sha256
    }];
    const decision = recordDecision(options, state, {
      verdict: "block",
      packageName: identity.packageName,
      cause: "policy",
      reason: identity.reason
    });
    sendBlocked(response, decision);
    return;
  }

  state.hashes = [...state.hashes, {
    url: redactSecrets(target.toString()),
    sha256,
    identity: identity.identity
  }];

  const inflightName = artifactDisplayName(identity.identity);
  state.inflight = [...state.inflight, inflightName];
  writeProxyState(options.session, state);
  const verdict = await lookupVerdict(options, target, sha256, upstream, identity.identity).catch((error: unknown): ProxyVerdict => ({
    verdict: "block",
    packageName: artifactDisplayName(identity.identity),
    cause: "api-timeout",
    reason: error instanceof Error ? error.message : "Dependency Guardian API verdict lookup failed"
  }));
  state.inflight = removeFirst(state.inflight, inflightName);
  const decision = recordDecision(options, state, verdict, identity.identity);

  if (decision.action === "block") {
    sendBlocked(response, decision);
    return;
  }

  response.writeHead(upstream.statusCode, upstream.headers);
  response.end(upstream.body);
}

async function blindTunnel(
  clientSocket: Socket,
  head: Buffer,
  target: URL,
  options: ProductionProxyOptions,
  activeSockets: Set<Socket>
): Promise<void> {
  const upstreamProxy = selectUpstreamProxy(target, options.env);
  const upstreamSocket = upstreamProxy
    ? await connectViaUpstreamProxy(target, upstreamProxy)
    : await connectDirect(target, options.env);
  trackSocket(activeSockets, upstreamSocket);
  clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
  if (head.length > 0) {
    upstreamSocket.write(head);
  }
  upstreamSocket.pipe(clientSocket);
  clientSocket.pipe(upstreamSocket);
}

async function mitmTunnel(
  clientSocket: Socket,
  head: Buffer,
  target: URL,
  options: ProductionProxyOptions,
  state: ProxySessionState,
  ca: CertificateAuthority,
  activeSockets: Set<Socket>
): Promise<void> {
  const leaf = ca.leafForHost(target.hostname);
  const secureContext = createSecureContext({
    cert: leaf.certPem,
    key: leaf.keyPem
  });
  const innerHttp = createServer((request, response) => {
    const artifactTarget = new URL(`${target.protocol}//${target.host}${request.url ?? "/"}`);
    handleArtifactRequest(request, response, artifactTarget, options, state).catch((error: unknown) => {
      const decision = recordDecision(options, state, {
        verdict: "block",
        packageName: artifactTarget.hostname,
        cause: "proxy-setup-failure",
        reason: error instanceof Error ? error.message : "MITM request failed"
      });
      sendBlocked(response, decision);
    });
  });
  const tlsServer = createTlsServer({
    SNICallback: (_servername, callback) => callback(null, secureContext),
    cert: leaf.certPem,
    key: leaf.keyPem,
    ALPNProtocols: ["http/1.1"]
  }, (tlsSocket) => {
    trackSocket(activeSockets, tlsSocket);
    innerHttp.emit("connection", tlsSocket);
  });
  tlsServer.once("tlsClientError", () => {
    clientSocket.destroy();
  });
  clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
  if (head.length > 0) {
    clientSocket.unshift(head);
  }
  tlsServer.emit("connection", clientSocket);
}

function parseProxyTarget(request: IncomingMessage): URL | null {
  const rawUrl = request.url ?? "";
  try {
    if (/^https?:\/\//.test(rawUrl)) {
      return new URL(rawUrl);
    }
    const host = request.headers.host;
    if (!host) {
      return null;
    }
    return new URL(`http://${host}${rawUrl.startsWith("/") ? rawUrl : `/${rawUrl}`}`);
  } catch {
    return null;
  }
}

function parseConnectTarget(authority: string | undefined): URL | null {
  if (!authority) {
    return null;
  }
  try {
    const normalized = authority.startsWith("[")
      ? authority
      : authority.replace(/^([^:]+)$/, "$1:443");
    return new URL(`https://${normalized}`);
  } catch {
    return null;
  }
}

function connectDirect(target: URL, env: NodeJS.ProcessEnv = process.env): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect({ port: Number(target.port || "443"), host: upstreamHostname(target, env), lookup: lookupForTarget(target, env) });
    socket.once("connect", () => resolve(socket));
    socket.once("error", reject);
  });
}

function upstreamHostname(target: URL, env: NodeJS.ProcessEnv = process.env): string {
  const hostname = target.hostname.replace(/^\[(.*)\]$/, "$1");
  return testUpstreamHostMap(env).get(hostname) ?? hostname;
}

function testUpstreamHostMap(env: NodeJS.ProcessEnv): ReadonlyMap<string, string> {
  if (env.NODE_ENV !== "test") {
    return new Map();
  }
  const entries = (env.DG_TEST_UPSTREAM_HOST_MAP ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry): readonly [string, string] | null => {
      const separator = entry.indexOf("=");
      if (separator <= 0) {
        return null;
      }
      return [entry.slice(0, separator), entry.slice(separator + 1)];
    })
    .filter((entry): entry is readonly [string, string] => entry !== null);
  return new Map(entries);
}

function fetchUpstream(request: IncomingMessage, target: URL, env: NodeJS.ProcessEnv): Promise<{
  readonly statusCode: number;
  readonly headers: OutgoingHttpHeaders;
  readonly body: Buffer;
}> {
  const upstreamProxy = selectUpstreamProxy(target, env);
  if (upstreamProxy && target.protocol === "http:") {
    return fetchHttpViaProxy(request, target, upstreamProxy, env);
  }
  if (upstreamProxy && target.protocol === "https:") {
    return fetchHttpsViaProxy(request, target, upstreamProxy, env);
  }
  if (target.protocol === "https:") {
    return fetchHttpsDirect(request, target, env);
  }
  return new Promise((resolve, reject) => {
    const upstream = httpRequest({
      hostname: upstreamHostname(target, env),
      port: target.port ? Number(target.port) : 80,
      path: `${target.pathname}${target.search}`,
      method: request.method,
      agent: upstreamHttpAgent,
      lookup: lookupForTarget(target, env),
      headers: stripProxyHopHeaders(request.headers)
    }, (upstreamResponse) => {
      collectBounded(upstreamResponse, { label: target.toString() })
        .then((body) => resolve({
          statusCode: upstreamResponse.statusCode ?? 502,
          headers: responseHeaders(upstreamResponse),
          body
        }))
        .catch(reject);
    });
    applyUpstreamTimeBudget(upstream, target, env, reject);
    upstream.on("error", reject);
    request.on("data", (chunk: Buffer) => upstream.write(chunk));
    request.on("end", () => upstream.end());
    request.on("error", reject);
    request.once("close", () => {
      if (!request.complete) {
        upstream.destroy();
      }
    });
  });
}

function fetchHttpViaProxy(
  request: IncomingMessage,
  target: URL,
  upstreamProxy: NonNullable<ReturnType<typeof selectUpstreamProxy>>,
  env: NodeJS.ProcessEnv
): Promise<{
  readonly statusCode: number;
  readonly headers: OutgoingHttpHeaders;
  readonly body: Buffer;
}> {
  return new Promise((resolve, reject) => {
    const headers = {
      ...stripProxyHopHeaders(request.headers),
      ...(upstreamProxy.authorizationHeader ? { "Proxy-Authorization": upstreamProxy.authorizationHeader } : {})
    };
    const upstream = httpRequest({
      hostname: upstreamProxy.url.hostname,
      port: upstreamProxy.url.port ? Number(upstreamProxy.url.port) : 80,
      path: target.toString(),
      method: request.method,
      headers
    }, (upstreamResponse) => {
      collectBounded(upstreamResponse, { label: target.toString() })
        .then((body) => resolve({
          statusCode: upstreamResponse.statusCode ?? 502,
          headers: responseHeaders(upstreamResponse),
          body
        }))
        .catch(reject);
    });
    applyUpstreamTimeBudget(upstream, target, env, reject);
    upstream.on("error", reject);
    request.on("data", (chunk: Buffer) => upstream.write(chunk));
    request.on("end", () => upstream.end());
    request.on("error", reject);
    request.once("close", () => {
      if (!request.complete) {
        upstream.destroy();
      }
    });
  });
}

function fetchHttpsDirect(request: IncomingMessage, target: URL, env: NodeJS.ProcessEnv): Promise<{
  readonly statusCode: number;
  readonly headers: OutgoingHttpHeaders;
  readonly body: Buffer;
}> {
  return new Promise((resolve, reject) => {
    const upstream = httpsRequest({
      hostname: upstreamHostname(target, env),
      port: target.port ? Number(target.port) : 443,
      path: `${target.pathname}${target.search}`,
      method: request.method,
      agent: upstreamHttpsAgent,
      lookup: lookupForTarget(target, env),
      headers: upstreamRequestHeaders(request, target),
      ...upstreamTlsOptions(env)
    }, (upstreamResponse) => {
      collectBounded(upstreamResponse, { label: target.toString() })
        .then((body) => resolve({
          statusCode: upstreamResponse.statusCode ?? 502,
          headers: responseHeaders(upstreamResponse),
          body
        }))
        .catch(reject);
    });
    applyUpstreamTimeBudget(upstream, target, env, reject);
    upstream.on("error", reject);
    request.on("data", (chunk: Buffer) => upstream.write(chunk));
    request.on("end", () => upstream.end());
    request.on("error", reject);
    request.once("close", () => {
      if (!request.complete) {
        upstream.destroy();
      }
    });
  });
}

async function fetchHttpsViaProxy(
  request: IncomingMessage,
  target: URL,
  upstreamProxy: NonNullable<ReturnType<typeof selectUpstreamProxy>>,
  env: NodeJS.ProcessEnv
): Promise<{
  readonly statusCode: number;
  readonly headers: OutgoingHttpHeaders;
  readonly body: Buffer;
}> {
  const tunnel = await connectViaUpstreamProxy(target, upstreamProxy);
  const tlsSocket = await connectTlsOverSocket(tunnel, target, env);
  const requestBody = await readRequestBody(request);
  const rawResponse = await writeRawHttpRequest(tlsSocket, request, target, requestBody);
  return parseRawHttpResponse(rawResponse);
}

function connectTlsOverSocket(socket: Socket, target: URL, env: NodeJS.ProcessEnv): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const tlsSocket = tlsConnect({
      socket,
      servername: target.hostname,
      ALPNProtocols: ["http/1.1"],
      ...upstreamTlsOptions(env)
    }, () => resolve(tlsSocket));
    applyUpstreamTimeBudget(tlsSocket, target, env);
    tlsSocket.once("error", reject);
  });
}

function upstreamIdleTimeoutMs(env: NodeJS.ProcessEnv): number {
  return parsePositiveInteger(env.DG_UPSTREAM_IDLE_TIMEOUT_MS, 30_000);
}

function upstreamTotalTimeoutMs(env: NodeJS.ProcessEnv): number {
  return parsePositiveInteger(env.DG_UPSTREAM_TOTAL_TIMEOUT_MS, 600_000);
}

function applyUpstreamTimeBudget(
  upstream: {
    setTimeout(ms: number, callback: () => void): unknown;
    destroy(error?: Error): unknown;
    once(event: "close", callback: () => void): unknown;
  },
  target: URL,
  env: NodeJS.ProcessEnv,
  onTimeout?: (error: Error) => void
): void {
  const idleMs = upstreamIdleTimeoutMs(env);
  const totalMs = upstreamTotalTimeoutMs(env);
  const expire = (detail: string): void => {
    const error = new Error(`upstream registry request for ${target.host} timed out: ${detail}`);
    onTimeout?.(error);
    upstream.destroy(error);
  };
  upstream.setTimeout(idleMs, () => expire(`no data for ${idleMs}ms`));
  const totalTimer = setTimeout(() => expire(`exceeded the ${totalMs}ms total budget`), totalMs);
  totalTimer.unref();
  upstream.once("close", () => clearTimeout(totalTimer));
}

function stripProxyHopHeaders(headers: IncomingHttpHeaders): IncomingHttpHeaders {
  const stripped: IncomingHttpHeaders = { ...headers };
  delete stripped["proxy-authorization"];
  delete stripped["proxy-connection"];
  return stripped;
}

function writeRawHttpRequest(tlsSocket: TLSSocket, request: IncomingMessage, target: URL, requestBody: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    collectBounded(tlsSocket, { label: target.toString() }).then(resolve).catch(reject);
    const headers = upstreamRequestHeaders(request, target);
    const lines = [
      `${request.method ?? "GET"} ${target.pathname}${target.search} HTTP/1.1`,
      ...Object.entries(headers).flatMap(([key, value]) => headerLines(key, value)),
      "Connection: close",
      "",
      ""
    ];
    tlsSocket.write(lines.join("\r\n"));
    if (requestBody.length > 0) {
      tlsSocket.write(requestBody);
    }
    tlsSocket.end();
  });
}

function parseRawHttpResponse(raw: Buffer): {
  readonly statusCode: number;
  readonly headers: OutgoingHttpHeaders;
  readonly body: Buffer;
} {
  const headerEnd = raw.indexOf("\r\n\r\n");
  if (headerEnd === -1) {
    throw new Error("upstream registry returned a malformed HTTP response");
  }
  const head = raw.subarray(0, headerEnd).toString("latin1");
  const body = raw.subarray(headerEnd + 4);
  const [statusLine = "", ...headerLinesRaw] = head.split("\r\n");
  const status = /^HTTP\/1\.[01] (\d{3})\b/.exec(statusLine)?.[1];
  const headers: OutgoingHttpHeaders = {};
  for (const line of headerLinesRaw) {
    const separator = line.indexOf(":");
    if (separator === -1) {
      continue;
    }
    const key = line.slice(0, separator).toLowerCase();
    const value = line.slice(separator + 1).trim();
    const existing = headers[key];
    headers[key] = existing === undefined ? value : `${headerValue(existing)},${value}`;
  }
  return {
    statusCode: status ? Number(status) : 502,
    headers,
    body: headerValue(headers["transfer-encoding"]).toLowerCase() === "chunked" ? decodeChunkedBody(body) : body
  };
}

function upstreamRequestHeaders(request: IncomingMessage, target: URL): OutgoingHttpHeaders {
  const headers: OutgoingHttpHeaders = {};
  for (const [key, value] of Object.entries(request.headers)) {
    const normalized = key.toLowerCase();
    if (["proxy-authorization", "proxy-connection", "connection", "host"].includes(normalized) || value === undefined) {
      continue;
    }
    headers[key] = Array.isArray(value) ? [...value] : value;
  }
  headers.Host = target.host;
  return headers;
}

function headerLines(key: string, value: string | number | readonly string[] | undefined): string[] {
  if (value === undefined) {
    return [];
  }
  if (Array.isArray(value)) {
    return value.map((entry) => `${key}: ${entry}`);
  }
  return [`${key}: ${value}`];
}

export function upstreamTlsOptions(env: NodeJS.ProcessEnv): {
  readonly ca?: string[];
} {
  // Trust an extra upstream CA only from DG_UPSTREAM_CA_CERT — an explicit,
  // dg-specific knob for corporate TLS-intercepting proxies / private mirrors.
  // The ambient NODE_EXTRA_CA_CERTS is deliberately NOT honored here: dg's own
  // agent routing sets that variable to dg's MITM CA for the CLIENT side, so
  // re-consuming it as an UPSTREAM trust anchor would let any process that can
  // set it MITM the real registry through dg's proxy.
  const caPath = env.DG_UPSTREAM_CA_CERT;
  if (!caPath) {
    return {};
  }
  try {
    return {
      ca: [...rootCertificates, readFileSync(caPath, "utf8")]
    };
  } catch {
    return {};
  }
}

function readRequestBody(request: IncomingMessage): Promise<Buffer> {
  return collectBounded(request, { label: "proxied request body" });
}

function decodeChunkedBody(body: Buffer): Buffer {
  const chunks: Buffer[] = [];
  let offset = 0;
  while (offset < body.length) {
    const lineEnd = body.indexOf("\r\n", offset);
    if (lineEnd === -1) {
      break;
    }
    const size = Number.parseInt(body.subarray(offset, lineEnd).toString("latin1"), 16);
    if (!Number.isFinite(size) || size < 0) {
      break;
    }
    if (size === 0) {
      return Buffer.concat(chunks);
    }
    const start = lineEnd + 2;
    const end = start + size;
    chunks.push(body.subarray(start, end));
    offset = end + 2;
  }
  return Buffer.concat(chunks);
}

async function lookupVerdict(
  options: ProductionProxyOptions,
  target: URL,
  sha256: string,
  upstream: { readonly statusCode: number; readonly headers: OutgoingHttpHeaders; readonly body?: Buffer },
  identity: ArtifactIdentity
): Promise<ProxyVerdict> {
  if (shouldUseScanTarball(options, target, identity)) {
    return lookupScanTarballVerdict(options, target, sha256, upstream, identity);
  }

  const preverified = preverifiedVerdict(options, target, sha256, identity);
  if (preverified) {
    return preverified;
  }

  const cooldown = resolveCooldownRequest(options, identity);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.verdictTimeoutMs ?? installVerdictTimeoutMs(options.env));
  try {
    const response = await fetch(`${options.apiBaseUrl}/v1/install-verdict`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Dg-Version": dgVersion(),
        ...identityHeaders(options.env)
      },
      body: JSON.stringify({
        manager: options.classification.manager,
        action: options.classification.action,
        url: redactSecrets(target.toString()),
        artifactUrlHash: artifactUrlHash(target),
        ecosystem: identity.ecosystem,
        name: identity.name,
        version: identity.version,
        registryHost: identity.registryHost,
        sourceKind: identity.sourceKind,
        sha256,
        statusCode: upstream.statusCode,
        contentType: headerValue(upstream.headers["content-type"]),
        ...(cooldown ? { cooldown } : {})
      }),
      signal: controller.signal
    });
    if (response.status === 402 || response.status === 429) {
      const body = (await response.json().catch(() => ({}))) as { resetsAt?: unknown; quotaBehavior?: unknown };
      return {
        verdict: "block",
        packageName: artifactDisplayName(identity),
        cause: "quota-exceeded",
        reason: "You've reached your monthly scan limit. Upgrade at westbayberry.com/pricing or wait for it to reset.",
        ...(typeof body.resetsAt === "string" ? { resetsAt: sanitize(body.resetsAt) } : {}),
        quotaBehavior: body.quotaBehavior === "pass" ? "pass" : "block"
      };
    }
    if (response.status === 401) {
      return {
        verdict: "block",
        packageName: artifactDisplayName(identity),
        cause: "needs-login",
        unauthenticated: true,
        reason: "Checking a package from the registry before it installs requires sign-in."
      };
    }
    if (!response.ok) {
      return {
        verdict: "block",
        packageName: artifactDisplayName(identity),
        cause: "api-unavailable",
        reason: `Dependency Guardian API returned ${response.status}. Run 'dg doctor' and 'dg login' to verify API access.`
      };
    }
    return normalizeVerdict(await response.json(), target, identity, sha256);
  } finally {
    clearTimeout(timeout);
  }
}

async function lookupScanTarballVerdict(
  options: ProductionProxyOptions,
  target: URL,
  sha256: string,
  upstream: { readonly statusCode: number; readonly headers: OutgoingHttpHeaders; readonly body?: Buffer },
  identity: ArtifactIdentity
): Promise<ProxyVerdict> {
  const body = upstream.body ?? Buffer.alloc(0);
  const uploadPolicy = scanTarballUploadPolicy(options.env);
  if (!uploadPolicy.enabled) {
    return {
      verdict: "block",
      packageName: artifactDisplayName(identity),
      cause: "private-upload-disabled",
      reason: `private artifact scan upload is disabled for ${target.hostname}`
    };
  }
  if (!uploadPolicy.token) {
    return {
      verdict: "block",
      packageName: artifactDisplayName(identity),
      cause: "private-upload-disabled",
      reason: "private artifact scan upload requires DG_API_TOKEN"
    };
  }
  if (body.length > uploadPolicy.maxBytes) {
    return {
      verdict: "block",
      packageName: artifactDisplayName(identity),
      cause: "private-upload-disabled",
      reason: `private artifact is ${body.length} bytes, above the ${uploadPolicy.maxBytes} byte scan-tarball upload limit`
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), uploadPolicy.timeoutMs);
  try {
    const response = await fetch(`${options.apiBaseUrl}/v1/scan-tarball`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${uploadPolicy.token}`,
        "Content-Type": "application/octet-stream",
        "X-DG-Action": options.classification.action,
        "X-DG-Artifact-SHA256": sha256,
        "X-DG-Artifact-URL-Hash": artifactUrlHash(target),
        "X-DG-Cache-Key": `sha256:${sha256}`,
        "X-DG-Ecosystem": identity.ecosystem,
        "X-DG-Manager": options.classification.manager,
        "X-DG-Package-Name": identity.name,
        "X-DG-Package-Version": identity.version,
        "X-DG-Privacy": "private-artifact",
        "X-DG-Registry-Host": identity.registryHost,
        "X-DG-Source-Kind": identity.sourceKind
      },
      body,
      signal: controller.signal
    });
    if (!response.ok) {
      throw new Error(`Dependency Guardian scan-tarball API returned ${response.status}`);
    }
    return normalizeScanTarballVerdict(await response.json(), target, identity, sha256);
  } finally {
    clearTimeout(timeout);
  }
}

// A preflight batch-analyze already verdicted this exact name@version (and the
// user accepted any warns), so a per-artifact API round-trip would re-answer
// the same question. Trust it only when the identity came from registry
// metadata and the preflight applied the same cooldown gate the proxy would;
// the synthesized verdict goes through normalizeVerdict so the scanned-SHA
// cross-check blocks tampered bytes exactly like a server response would.
function preverifiedVerdict(
  options: ProductionProxyOptions,
  target: URL,
  streamedSha256: string,
  identity: ArtifactIdentity
): ProxyVerdict | null {
  if (identity.sourceKind !== "registry-metadata") {
    return null;
  }
  const entry = loadPreverifiedMap(options.session.dir).get(
    preverifiedKey(identity.ecosystem, identity.name, identity.version)
  );
  if (!entry) {
    return null;
  }
  if (!entry.cooldownEvaluated && resolveCooldownRequest(options, identity) !== undefined) {
    return null;
  }
  if (!entry.scannedSha256) {
    // No byte-level fingerprint to cross-check against the streamed artifact, so
    // a preverified pass/warn can't prove the downloaded bytes match what was
    // screened (a metadata-only preflight, or a registry swap between preflight
    // and fetch). Fall through to a real scan of the streamed bytes — TOCTOU
    // defense — rather than honoring the verdict for whatever now arrives.
    return null;
  }
  return normalizeVerdict(
    {
      verdict: entry.action,
      cause: entry.action,
      packageName: `${identity.name}@${identity.version}`,
      reason: entry.reason ?? (entry.action === "pass" ? "verified before install" : "flagged for review"),
      ...(entry.scannedSha256 ? { scannedSha256: entry.scannedSha256 } : {})
    },
    target,
    identity,
    streamedSha256
  );
}

function normalizeVerdict(value: unknown, target: URL, identity: ArtifactIdentity, streamedSha256: string): ProxyVerdict {
  if (!isRecord(value)) {
    throw new Error("Dependency Guardian API returned a malformed verdict");
  }
  const verdict = value.verdict;
  if (verdict !== "pass" && verdict !== "warn" && verdict !== "block") {
    throw new Error("Dependency Guardian API returned a malformed verdict");
  }
  const scannedSha256 = typeof value.scannedSha256 === "string" ? value.scannedSha256.toLowerCase() : "";
  if (scannedSha256.length > 0 && scannedSha256 !== streamedSha256) {
    return {
      verdict: "block",
      packageName: artifactDisplayName(identity),
      cause: "hash-mismatch",
      reason: `server scanned SHA-256 ${scannedSha256} did not match streamed artifact SHA-256 ${streamedSha256}`
    };
  }
  const cause = typeof value.cause === "string" ? value.cause : undefined;
  const cooldown = parseCooldownInfo(value.cooldown);
  const dashboardUrl = safeDashboardUrl(value.dashboardUrl);
  return {
    verdict,
    packageName: typeof value.packageName === "string" ? sanitize(value.packageName) : artifactDisplayName(identity) || packageNameFromUrl(target),
    ...(isProxyCause(cause) ? { cause } : {}),
    reason: typeof value.reason === "string" ? sanitize(value.reason) : `API verdict ${verdict}`,
    ...(dashboardUrl ? { dashboardUrl } : {}),
    ...(value.unauthenticated === true ? { unauthenticated: true } : {}),
    ...(cooldown ? { cooldown } : {})
  };
}

function safeDashboardUrl(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  try {
    const url = new URL(sanitize(value));
    return url.protocol === "https:" ? url.toString() : undefined;
  } catch {
    return undefined;
  }
}

function resolveCooldownRequest(options: ProductionProxyOptions, identity: ArtifactIdentity): CooldownRequestParam | undefined {
  if (identity.ecosystem === "unknown" || identity.version === "unknown") {
    return undefined;
  }
  if (isCooldownExemptByDgFile(identity.name, identity.ecosystem, options.cooldownExemptions ?? [])) {
    return undefined;
  }
  try {
    return cooldownRequestParam(loadUserConfig(options.env), options.env, identity.ecosystem, identity.name);
  } catch {
    return undefined;
  }
}

function parseCooldownInfo(value: unknown): CooldownInfo | undefined {
  if (!isRecord(value) || typeof value.requiredDays !== "number" || !Number.isFinite(value.requiredDays)) {
    return undefined;
  }
  return {
    requiredDays: value.requiredDays,
    ...(typeof value.ageDays === "number" && Number.isFinite(value.ageDays) ? { ageDays: value.ageDays } : {}),
    ...(typeof value.publishedAt === "string" ? { publishedAt: sanitize(value.publishedAt) } : {}),
    ...(typeof value.eligibleAt === "string" ? { eligibleAt: sanitize(value.eligibleAt) } : {})
  };
}

function normalizeScanTarballVerdict(
  value: unknown,
  target: URL,
  identity: ArtifactIdentity,
  streamedSha256: string
): ProxyVerdict {
  if (!isRecord(value) || typeof value.scannedSha256 !== "string" || value.scannedSha256.length === 0) {
    throw new Error("Dependency Guardian scan-tarball API did not return scannedSha256");
  }
  return normalizeVerdict(value, target, identity, streamedSha256);
}

function shouldUseScanTarball(options: ProductionProxyOptions, target: URL, identity: ArtifactIdentity): boolean {
  if (identity.sourceKind !== "url-fallback") {
    return false;
  }
  return hostMatchesList(target.hostname, options.env.DG_PRIVATE_REGISTRY_HOSTS ?? "");
}

function scanTarballUploadPolicy(env: NodeJS.ProcessEnv): {
  readonly enabled: boolean;
  readonly maxBytes: number;
  readonly timeoutMs: number;
  readonly token: string;
} {
  return {
    enabled: env.DG_SCAN_TARBALL_UPLOAD === "1" || env.DG_SCAN_TARBALL_UPLOAD === "true",
    maxBytes: parsePositiveInteger(env.DG_SCAN_TARBALL_MAX_BYTES, 50 * 1024 * 1024),
    timeoutMs: parsePositiveInteger(env.DG_SCAN_TARBALL_TIMEOUT_MS, 5_000),
    token: envAuthToken(env) ?? ""
  };
}

function installVerdictTimeoutMs(env: NodeJS.ProcessEnv): number {
  return parsePositiveInteger(env.DG_INSTALL_VERDICT_TIMEOUT_MS, 240_000);
}

function parsePositiveInteger(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function hostMatchesList(host: string, rawList: string): boolean {
  const normalized = normalizeHost(host);
  return rawList.split(",").map((entry) => entry.trim()).filter(Boolean).some((pattern) => hostMatchesPattern(normalized, pattern));
}

function hostMatchesPattern(host: string, pattern: string): boolean {
  const normalized = normalizeHost(pattern);
  if (normalized.startsWith("*.")) {
    const suffix = normalized.slice(1);
    return host.endsWith(suffix) && host.length > suffix.length;
  }
  return host === normalized;
}

function normalizeHost(host: string): string {
  return host.replace(/^\[/, "").replace(/\]$/, "").replace(/\.$/, "").toLowerCase();
}

function mergeIdentities(existing: readonly ArtifactIdentity[], next: readonly ArtifactIdentity[]): ArtifactIdentity[] {
  const merged = [...existing];
  for (const identity of next) {
    if (!merged.some((candidate) => candidate.tarballUrl === identity.tarballUrl
      && candidate.ecosystem === identity.ecosystem
      && candidate.name === identity.name
      && candidate.version === identity.version
      && candidate.registryHost === identity.registryHost)) {
      merged.push(identity);
    }
  }
  return merged;
}

function recordDecision(
  options: ProductionProxyOptions,
  state: ProxySessionState,
  verdict: ProxyVerdict,
  identity?: ArtifactIdentity
): EnforcementDecision {
  const decision = enforceProtectedInstall({
    classification: options.classification,
    env: options.env,
    proxyVerdict: verdict,
    ...(options.forceOverride ? { forceOverride: options.forceOverride } : {})
  });
  state.decisions = [...state.decisions, decision];
  state.events = [...state.events, `${decision.action}:${decision.cause}:${redactSecrets(decision.packageName)}`];
  writeProxyState(options.session, state);
  if (identity && decision.action === "block" && decision.cause === "cooldown" && decision.cooldown) {
    try {
      recordHeldPackage({
        ecosystem: identity.ecosystem,
        name: identity.name,
        version: identity.version,
        requiredDays: decision.cooldown.requiredDays,
        ...(decision.cooldown.ageDays !== undefined ? { ageDays: decision.cooldown.ageDays } : {}),
        ...(decision.cooldown.publishedAt ? { publishedAt: decision.cooldown.publishedAt } : {}),
        ...(decision.cooldown.eligibleAt ? { eligibleAt: decision.cooldown.eligibleAt } : {}),
        manager: options.classification.manager
      }, options.env);
    } catch (error) {
      noteEnforcementSideEffectFailure(error);
    }
  }
  return decision;
}

function sendBlocked(response: ServerResponse, decision: EnforcementDecision): void {
  const breadcrumb = decision.cause === "cooldown" ? " · holds: dg cooldown" : "";
  const body = `Dependency Guardian blocked ${redactSecrets(decision.packageName)}: ${redactSecrets(decision.reason)}${breadcrumb}\n`;
  response.writeHead(403, {
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": Buffer.byteLength(body)
  });
  response.end(body);
}

function responseHeaders(response: IncomingMessage): OutgoingHttpHeaders {
  const headers: OutgoingHttpHeaders = {};
  for (const [key, value] of Object.entries(response.headers)) {
    if (value !== undefined) {
      headers[key] = Array.isArray(value) ? [...value] : value;
    }
  }
  return headers;
}

function headerValue(value: string | number | readonly string[] | undefined): string {
  if (Array.isArray(value)) {
    return value.join(",");
  }
  if (typeof value === "number") {
    return String(value);
  }
  if (typeof value === "string") {
    return value;
  }
  return "";
}

function packageNameFromUrl(url: URL): string {
  const name = url.pathname.split("/").filter(Boolean).pop();
  return name ? decodeURIComponent(name) : url.hostname;
}

function writeProxyState(session: SessionHandle, state: ProxySessionState): void {
  try {
    mkdirSync(dirname(session.files.proxy), {
      recursive: true,
      mode: 0o700
    });
    const tempPath = `${session.files.proxy}.${process.pid}.${process.hrtime.bigint().toString(36)}.tmp`;
    try {
      writeFileSync(tempPath, `${JSON.stringify(state, null, 2)}\n`, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600
      });
      renameSync(tempPath, session.files.proxy);
    } catch (error) {
      rmSync(tempPath, {
        force: true
      });
      throw error;
    }
  } catch (error) {
    noteEnforcementSideEffectFailure(error);
  }
}

function removeFirst(items: readonly string[], value: string): string[] {
  const index = items.indexOf(value);
  if (index === -1) {
    return [...items];
  }
  return [...items.slice(0, index), ...items.slice(index + 1)];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function isProxyCause(value: string | undefined): value is NonNullable<ProxyVerdict["cause"]> {
  return [
    "pass",
    "warn",
    "malware",
    "policy",
    "license",
    "hash-mismatch",
    "private-upload-disabled",
    "needs-login",
    "api-unavailable",
    "quota-exceeded",
    "api-timeout",
    "registry-timeout",
    "analysis-incomplete",
    "cooldown",
    "unsupported-manager",
    "proxy-setup-failure"
  ].includes(value ?? "");
}
