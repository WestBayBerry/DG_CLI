import { createServer, type Server } from "node:http";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { startProductionHttpProxy, type ProductionProxyHandle } from "../proxy/server.js";
import type { PackageManagerClassification } from "../launcher/classify.js";
import type { SessionHandle } from "../state/index.js";
import { resolveServicePaths, TRUST_SENTINEL } from "./state.js";
import { refreshServiceTrustAfterCaRotation } from "./trust-refresh.js";

const sessionPath = process.argv[2];
const apiBaseUrl = process.argv[3];
const runtimePath = process.argv[4];
const classificationJson = process.env.DG_SERVICE_CLASSIFICATION;

if (!sessionPath || !apiBaseUrl || !runtimePath || !classificationJson) {
  process.stderr.write("dg service worker missing startup arguments\n");
  process.exit(1);
}

const requiredSessionPath = sessionPath;
const requiredApiBaseUrl = apiBaseUrl;
const requiredRuntimePath = runtimePath;
const requiredClassificationJson = classificationJson;
const session = JSON.parse(readFileSync(requiredSessionPath, "utf8")) as SessionHandle;
const classification = JSON.parse(requiredClassificationJson) as PackageManagerClassification;

let proxy: ProductionProxyHandle | null = null;
let healthServer: Server | null = null;
let closed = false;

async function close(): Promise<void> {
  if (closed) {
    return;
  }
  closed = true;
  rmSync(requiredRuntimePath, {
    force: true
  });
  await Promise.all([proxy?.close(), closeHealthServer(healthServer)]);
}

process.stdin.on("end", () => {
  close().finally(() => process.exit(0));
});

process.on("SIGTERM", () => {
  close().finally(() => process.exit(0));
});
process.on("SIGINT", () => {
  close().finally(() => process.exit(0));
});

function exitOnFatal(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  try {
    process.stderr.write(`dg service worker: unexpected error — ${message}\n`);
  } catch {
    // stderr is gone; nothing left to report to.
  }
  close().finally(() => process.exit(1));
}

process.on("uncaughtException", exitOnFatal);
process.on("unhandledRejection", exitOnFatal);

const servicePaths = resolveServicePaths(process.env);

proxy = await startProductionHttpProxy({
  session,
  apiBaseUrl: requiredApiBaseUrl,
  classification,
  env: process.env,
  onCaRotate: () => refreshServiceTrustAfterCaRotation({
    serviceDir: servicePaths.serviceDir,
    trustRecordPath: servicePaths.trustRecordPath,
    sentinel: TRUST_SENTINEL,
    caPath: session.files.ca,
    env: process.env
  })
});
healthServer = await startHealthServer(proxy.port);

const healthAddress = healthServer.address();
if (typeof healthAddress !== "object" || healthAddress === null) {
  throw new Error("service health endpoint did not bind a TCP port");
}

writeFileSync(
  requiredRuntimePath,
  `${JSON.stringify(
    {
      pid: process.pid,
      proxyUrl: `http://127.0.0.1:${proxy.port}`,
      healthUrl: `http://127.0.0.1:${healthAddress.port}/health`,
      sessionDir: session.dir,
      caPath: session.files.ca,
      startedAt: new Date().toISOString()
    },
    null,
    2
  )}\n`,
  {
    encoding: "utf8",
    mode: 0o600
  }
);

function startHealthServer(proxyPort: number): Promise<Server> {
  const server = createServer((_request, response) => {
    response.writeHead(200, {
      "Content-Type": "application/json"
    });
    response.end(`${JSON.stringify({
      ok: true,
      pid: process.pid,
      proxyPort
    })}\n`);
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve(server);
    });
  });
}

function closeHealthServer(server: Server | null): Promise<void> {
  if (!server) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
}
