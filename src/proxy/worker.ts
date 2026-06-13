import { readFileSync, writeFileSync } from "node:fs";
import { startProductionHttpProxy, type ProductionProxyHandle } from "./server.js";
import { parseForceOverrideRequest } from "./enforcement.js";
import type { PackageManagerClassification } from "../launcher/classify.js";
import { cleanupSessionSync, type SessionHandle } from "../state/index.js";
import { COOLDOWN_EXEMPTIONS_ENV, loadCooldownExemptionsFile } from "./cooldown-exemptions-file.js";

const PARENT_POLL_MS = 500;

const sessionPath = process.argv[2];
const apiBaseUrl = process.argv[3];
const classificationJson = process.env.DG_PROXY_CLASSIFICATION;

if (!sessionPath || !apiBaseUrl || !classificationJson) {
  process.stderr.write("dg proxy worker missing startup arguments\n");
  process.exit(1);
}

const session = JSON.parse(readFileSync(sessionPath, "utf8")) as SessionHandle;
const classification = JSON.parse(classificationJson) as PackageManagerClassification;
const forceOverride = parseForceOverrideRequest(process.env.DG_FORCE_OVERRIDE_REQUEST);
const cooldownExemptions = loadCooldownExemptionsFile(process.env[COOLDOWN_EXEMPTIONS_ENV]);

writeFileSync(session.files.pid, `${process.pid}\n`, {
  encoding: "utf8",
  mode: 0o600
});

let handle: ProductionProxyHandle | null = null;
let closed = false;
async function close(): Promise<void> {
  if (closed) {
    return;
  }
  closed = true;
  await handle?.close();
  cleanupSessionSync(session);
}

function shutdown(): void {
  close().finally(() => process.exit(0));
}

function exitOnFatal(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  try {
    process.stderr.write(`dg proxy worker: unexpected error — ${message}\n`);
  } catch {
    // stderr is gone; nothing left to report to.
  }
  close().finally(() => process.exit(1));
}

process.on("uncaughtException", exitOnFatal);
process.on("unhandledRejection", exitOnFatal);

process.stdin.resume();
process.stdin.on("end", shutdown);
process.stdin.on("error", shutdown);

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

const parentWatch = setInterval(() => {
  if (process.ppid === 1) {
    shutdown();
  }
}, PARENT_POLL_MS);
parentWatch.unref();

handle = await startProductionHttpProxy({
  session,
  apiBaseUrl,
  classification,
  env: process.env,
  ...(forceOverride ? { forceOverride } : {}),
  ...(cooldownExemptions.length > 0 ? { cooldownExemptions } : {})
});

process.stdout.write(`ready ${handle.port}\n`);
