import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { constants as osConstants } from "node:os";
import { fileURLToPath } from "node:url";
import type { CommandResult } from "../commands/types.js";
import { EXIT_UNAVAILABLE } from "../commands/types.js";
import { loadUserConfig, trustsProjectOverrides } from "../config/settings.js";
import { findProjectRoot, loadDgFile, type CooldownExemption } from "../project/dgfile.js";
import { honoredOverrides } from "../project/override-trust.js";
import { writeCooldownExemptionsFile } from "../proxy/cooldown-exemptions-file.js";
import { writePreverifiedFile, type PreverifiedEntry } from "../proxy/preverified.js";
import { describeBlockedInstall, describeFlaggedWarn, renderInstallDecision } from "../install-ui/block-render.js";
import type { LiveInstallView } from "../install-ui/LiveInstall.js";
import { enforceProtectedInstall, type EnforcementDecision, type ForceOverrideRequest, type ProxyVerdict } from "../proxy/enforcement.js";
import { isCiEnv, resolvePresentation } from "../presentation/mode.js";
import { maybeSetupNudge } from "../runtime/nudges.js";
import { createTheme } from "../presentation/theme.js";
import { readProxySessionState } from "../proxy/server.js";
import { readServiceState } from "../service/state.js";
import { cleanupSessionSync, createSessionSync, resolveDgPaths, type SessionHandle } from "../state/index.js";
import {
  classifyPackageManagerInvocation,
  type PackageManager,
  type PackageManagerClassification,
  type SupportedPackageManager
} from "./classify.js";
import { buildProxyChildEnv, scrubChildSecrets } from "./env.js";
import { prepareCargoHome, userCargoHome } from "./cargo-cache.js";
import { cachedPipResolution } from "./install-preflight.js";
import { createStreamRedactor, redactSecrets } from "./output-redaction.js";
import { resolveSpawnInvocation } from "./spawn-invocation.js";
import { resolveRealBinary, type ResolveRealBinaryResult } from "./resolve-real-binary.js";
import { runScriptGateAfterInstall, scriptGateChildEnv, scriptGateInstallArgs } from "../scripts/gate.js";

export const EXIT_INSTALL_BLOCKED = 2;

export interface LaunchPlan {
  readonly classification: PackageManagerClassification;
  readonly realBinary: ResolveRealBinaryResult;
  readonly startsProxy: boolean;
  readonly childEnv: NodeJS.ProcessEnv;
}

export interface SpawnStreamRequest {
  readonly binary: string;
  readonly args: readonly string[];
  readonly env: NodeJS.ProcessEnv;
  readonly onStdout?: ((chunk: string) => void) | undefined;
  readonly onStderr?: ((chunk: string) => void) | undefined;
}

export interface SpawnStreamResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

export type PackageManagerSpawner = (request: SpawnStreamRequest) => Promise<SpawnStreamResult>;

export { resolveSpawnInvocation, type SpawnInvocation } from "./spawn-invocation.js";

export function shimDepth(env: NodeJS.ProcessEnv): number {
  const parsed = Number.parseInt(env.DG_SHIM_DEPTH ?? "", 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : 0;
}

// A genuine parent dg proxy sets DG_PROXY_ACTIVE=1 and routes the child through a
// loopback proxy URL that carries the proxy's auth token (buildProxyChildEnv ->
// proxyUrlWithAuth). All of these must hold for a nested invocation to safely run
// the real package manager directly (its traffic still flows through the live
// parent proxy). DG_PROXY_ACTIVE + a bare loopback URL are both forgeable, so:
//  - the URL must carry a dg auth token (a forged HTTPS_PROXY=http://127.0.0.1:1
//    with no credential is rejected), and
//  - when a persistent dg service is the parent (the agent-routing case), the URL
//    must match that live service's proxy, so a forged token cannot impersonate it.
// If neither matches, we start our own verifying proxy rather than trust the env.
export function inheritedDgProxyActive(env: NodeJS.ProcessEnv): boolean {
  if (env.DG_PROXY_ACTIVE !== "1") {
    return false;
  }
  const proxyUrl = env.HTTPS_PROXY ?? env.https_proxy ?? env.HTTP_PROXY ?? env.http_proxy;
  if (!proxyUrl) {
    return false;
  }
  let url: URL;
  try {
    url = new URL(proxyUrl);
  } catch {
    return false;
  }
  const host = url.hostname.replace(/^\[(.*)\]$/, "$1");
  if (host !== "127.0.0.1" && host !== "::1" && host !== "localhost") {
    return false;
  }
  if (!url.username && !url.password) {
    return false;
  }
  try {
    const { state } = readServiceState(env);
    if (state.running && state.proxy) {
      const live = new URL(state.proxy.proxyUrl);
      return live.hostname.replace(/^\[(.*)\]$/, "$1") === host && live.port === url.port;
    }
  } catch {
    // No readable service state — fall through to the session-proxy path below.
  }
  return true;
}

export function rootUnprotectedNotice(
  env: NodeJS.ProcessEnv,
  uid: number | undefined = process.getuid?.()
): string {
  if (uid !== 0) {
    return "";
  }
  if (existsSync(resolveDgPaths(env).stateDir)) {
    return "";
  }
  return "dg: running as root without dg state — bare package-manager installs by root are not protected\n";
}

let rootNoticeWritten = false;

function maybeWarnRootWithoutState(env: NodeJS.ProcessEnv): void {
  if (rootNoticeWritten) {
    return;
  }
  const notice = rootUnprotectedNotice(env);
  if (!notice) {
    return;
  }
  rootNoticeWritten = true;
  process.stderr.write(notice);
}

export interface RunPackageManagerOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly spawner?: PackageManagerSpawner;
  readonly proxyVerdict?: ProxyVerdict;
  readonly forceOverride?: ForceOverrideRequest;
  readonly preverified?: readonly PreverifiedEntry[];
  readonly now?: Date;
  readonly projectDir?: string;
  readonly onStdout?: (chunk: string) => void;
  readonly onStderr?: (chunk: string) => void;
}

export function createLaunchPlan(manager: PackageManager, args: readonly string[], env: NodeJS.ProcessEnv = process.env): LaunchPlan {
  const classification = classifyPackageManagerInvocation(manager, args);
  const realBinary = resolveRealBinary({
    name: classification.realBinaryName,
    env
  });

  return {
    classification,
    realBinary,
    startsProxy: classification.kind === "protected",
    childEnv: scrubChildSecrets({
      ...env,
      DG_SHIM_ACTIVE: shimNonce(manager, env),
      DG_SHIM_DEPTH: String(shimDepth(env) + 1)
    })
  };
}

export async function runPackageManager(
  manager: PackageManager,
  args: readonly string[],
  options: RunPackageManagerOptions = {}
): Promise<CommandResult> {
  const plan = createLaunchPlan(manager, args, options.env ?? process.env);
  const invoked = ["dg", manager, ...args].join(" ");

  if (plan.classification.kind === "unsupported") {
    return unavailable(invoked, plan.classification.reason);
  }

  if (!plan.realBinary.path) {
    return unavailable(invoked, `real ${plan.classification.realBinaryName} binary was not found outside dg shims`);
  }

  maybeWarnRootWithoutState(options.env ?? process.env);

  const depth = shimDepth(options.env ?? process.env);
  if (depth >= 2) {
    return {
      exitCode: EXIT_UNAVAILABLE,
      stdout: "",
      stderr: `dg: ${manager} shim exec loop detected (DG_SHIM_DEPTH=${depth}) — refusing to re-enter\n`
    };
  }
  if (plan.startsProxy) {
    // Reuse a parent dg proxy ONLY when one is genuinely live in this environment
    // (the parent set DG_PROXY_ACTIVE and a loopback proxy URL). An env var such as
    // a forged or stale DG_SHIM_DEPTH must never be what decides to skip
    // verification: if no live dg proxy is detected, start one rather than run the
    // install unproxied. DG_SHIM_DEPTH is only the >=2 infinite-recursion backstop.
    if (inheritedDgProxyActive(options.env ?? process.env)) {
      const child = await spawnPackageManager(plan, args, options);
      return {
        exitCode: child.exitCode,
        stdout: streamedOut(child.stdout, options),
        stderr: `dg: re-entered through its own shim — running the real ${plan.classification.realBinaryName} directly\n${streamedErr(child.stderr, options)}`
      };
    }
    if (!options.proxyVerdict) {
      return runWithProductionProxy(plan, args, options);
    }
    const decision = enforceProtectedInstall({
      classification: plan.classification,
      env: options.env ?? process.env,
      proxyVerdict: options.proxyVerdict,
      ...(options.forceOverride ? { forceOverride: options.forceOverride } : {}),
      ...(options.now ? { now: options.now } : {})
    });
    const rendered = renderDecisions([decision], options.env ?? process.env);
    if (decision.action === "block") {
      return {
        exitCode: EXIT_INSTALL_BLOCKED,
        stdout: "",
        stderr: rendered
      };
    }
    const child = await spawnPackageManager(plan, args, options);
    return {
      exitCode: child.exitCode,
      stdout: streamedOut(child.stdout, options),
      stderr: `${rendered}${streamedErr(child.stderr, options)}${scriptGateLine(plan, child.exitCode, options)}${setupNudgeAfterInstall(plan, child.exitCode, options)}`
    };
  }

  const child = await spawnPackageManager(plan, args, options);
  return {
    exitCode: child.exitCode,
    stdout: streamedOut(child.stdout, options),
    stderr: streamedErr(child.stderr, options)
  };
}

async function runWithProductionProxy(plan: LaunchPlan, args: readonly string[], options: RunPackageManagerOptions): Promise<CommandResult> {
  const env = options.env ?? process.env;
  const proxy = await startProxyWorker(plan.classification, env, options.forceOverride);
  if ("decision" in proxy) {
    return {
      exitCode: EXIT_INSTALL_BLOCKED,
      stdout: "",
      stderr: redactSecrets(renderInstallDecision(proxy.decision))
    };
  }

  const restoreSignalHandlers = installProxySignalHandlers(proxy);
  try {
    const cacheDir = prepareProxyCacheDir(plan.classification.manager, proxy.session.dir, env);
    const proxiedPlan: LaunchPlan = {
      ...plan,
      childEnv: buildProxyChildEnv({
        manager: plan.classification.manager as SupportedPackageManager,
        baseEnv: plan.childEnv,
        proxyUrl: proxy.proxyUrl,
        caBundlePath: proxy.session.files.ca,
        cacheDir
      })
    };
    const child = await spawnPackageManager(proxiedPlan, args, options);
    const proxyState = readProxySessionState(proxy.session);
    const rendered = renderDecisions(proxyState.decisions, env);
    const blocked = proxyState.decisions.find((decision) => decision.action === "block");
    if (blocked) {
      return {
        exitCode: EXIT_INSTALL_BLOCKED,
        stdout: streamedOut(child.stdout, options),
        stderr: `${rendered}${streamedErr(child.stderr, options)}`
      };
    }
    if (proxyState.decisions.length === 0) {
      // The proxy saw no artifact verdicts. If the wrapped command itself exited
      // with an error (e.g. pip's PEP 668 externally-managed error, a resolution
      // error, a crash before fetch), it failed for its own reasons — nothing was
      // installed, so there is nothing to verify. Keep its non-zero exit (still
      // fail-closed: no unverified install can SUCCEED) but propagate the
      // command's own error instead of a misleading "block / override" decision.
      if (child.exitCode !== 0) {
        return {
          exitCode: child.exitCode,
          stdout: streamedOut(child.stdout, options),
          stderr: `${streamedErr(child.stderr, options)}\n  ? dg did not check this install — ${plan.classification.manager} exited with an error before any package was fetched.\n`
        };
      }
      return {
        exitCode: EXIT_INSTALL_BLOCKED,
        stdout: streamedOut(child.stdout, options),
        stderr: `${streamedErr(child.stderr, options)}${cacheOnlyNotice(installOutcome(child.stdout).length > 0)}`
      };
    }
    return {
      exitCode: child.exitCode,
      stdout: streamedOut(child.stdout, options),
      stderr: `${rendered}${streamedErr(child.stderr, options)}${scriptGateLine(plan, child.exitCode, options)}${setupNudgeAfterInstall(plan, child.exitCode, options)}`
    };
  } finally {
    restoreSignalHandlers();
    stopProxyWorker(proxy);
  }
}

function scriptGateLine(plan: LaunchPlan, exitCode: number, options: RunPackageManagerOptions): string {
  if (exitCode !== 0) {
    return "";
  }
  return runScriptGateAfterInstall({
    classification: plan.classification,
    env: options.env ?? process.env,
    ...(options.projectDir ? { projectDir: options.projectDir } : {})
  });
}

function setupNudgeAfterInstall(plan: LaunchPlan, exitCode: number, options: RunPackageManagerOptions): string {
  if (exitCode !== 0) {
    return "";
  }
  return maybeSetupNudge(plan.classification.manager, { env: options.env ?? process.env });
}

export function deriveLiveView(
  state: ReturnType<typeof readProxySessionState>,
  phase: "scanning" | "done",
  resolvedTotal?: number
): LiveInstallView {
  const verified = state.decisions.filter((decision) => decision.action === "pass").length;
  const warnDecisions = state.decisions.filter((decision) => decision.action === "warn");
  const flagged = warnDecisions.length;
  const flaggedItems = warnDecisions.map(describeFlaggedWarn);
  const blocked = state.decisions.find((decision) => decision.action === "block");
  const current = state.inflight[state.inflight.length - 1];
  return {
    phase,
    total: state.decisions.length + state.inflight.length,
    verified,
    flagged,
    ...(flaggedItems.length > 0 ? { flaggedItems } : {}),
    ...(resolvedTotal !== undefined ? { resolvedTotal } : {}),
    ...(current ? { current } : {}),
    ...(blocked ? { blocked: describeBlockedInstall(blocked) } : {})
  };
}

export interface PreparedProxyWorker {
  readonly worker: Promise<ProxyWorkerReady | ProxyWorkerFailure>;
  readonly discard: () => void;
}

export function prepareProxyWorker(classification: PackageManagerClassification, env: NodeJS.ProcessEnv): PreparedProxyWorker {
  const worker = startProxyWorker(classification, env, undefined);
  let discarded = false;
  return {
    worker,
    discard: (): void => {
      if (discarded) {
        return;
      }
      discarded = true;
      void worker.then((proxy) => {
        if (!("decision" in proxy)) {
          stopProxyWorker(proxy);
        }
      });
    }
  };
}

export async function runWithProductionProxyLive(
  plan: LaunchPlan,
  args: readonly string[],
  options: RunPackageManagerOptions,
  onView: (view: LiveInstallView) => void,
  prepared?: PreparedProxyWorker
): Promise<CommandResult> {
  if (options.onStdout || options.onStderr) {
    throw new Error("live install mode renders its own UI and owns the terminal; streaming output callbacks are not supported");
  }
  const env = options.env ?? process.env;
  maybeWarnRootWithoutState(env);
  if (prepared && options.forceOverride) {
    prepared.discard();
    prepared = undefined;
  }
  const proxy = prepared
    ? await prepared.worker
    : await startProxyWorker(plan.classification, env, options.forceOverride);
  if ("decision" in proxy) {
    return { exitCode: EXIT_INSTALL_BLOCKED, stdout: "", stderr: redactSecrets(renderInstallDecision(proxy.decision)) };
  }

  if (options.preverified && options.preverified.length > 0) {
    writePreverifiedFile(proxy.session.dir, options.preverified);
  }

  const restoreSignalHandlers = installProxySignalHandlers(proxy);
  try {
    const childEnv = buildProxyChildEnv({
      manager: plan.classification.manager as SupportedPackageManager,
      baseEnv: plan.childEnv,
      proxyUrl: proxy.proxyUrl,
      caBundlePath: proxy.session.files.ca,
      cacheDir: prepareProxyCacheDir(plan.classification.manager, proxy.session.dir, env)
    });
    const spawner = options.spawner ?? defaultSpawner;
    const hardened = applyScriptGateHardening(plan, args, childEnv, env);
    const resolvedTotal =
      plan.classification.manager === "pip" ? cachedPipResolution(plan.realBinary.path ?? "", args)?.count : undefined;
    const poll = setInterval(() => {
      onView(deriveLiveView(readProxySessionState(proxy.session), "scanning", resolvedTotal));
    }, 90);
    let finished: SpawnStreamResult;
    try {
      finished = await spawner({
        binary: plan.realBinary.path ?? "",
        args: hardened.args,
        env: hardened.env
      });
    } finally {
      clearInterval(poll);
    }

    const proxyState = readProxySessionState(proxy.session);
    onView(deriveLiveView(proxyState, "done", resolvedTotal));

    if (proxyState.decisions.some((decision) => decision.action === "block")) {
      return { exitCode: EXIT_INSTALL_BLOCKED, stdout: "", stderr: "" };
    }
    if (proxyState.decisions.length === 0) {
      if (finished.exitCode !== 0) {
        return {
          exitCode: finished.exitCode,
          stdout: finished.stdout,
          stderr: `${finished.stderr}\n  ? dg did not check this install — ${plan.classification.manager} exited with an error before any package was fetched.\n`
        };
      }
      const outcome = installOutcome(finished.stdout);
      return { exitCode: EXIT_INSTALL_BLOCKED, stdout: outcome, stderr: cacheOnlyNotice(outcome.length > 0) };
    }
    return { exitCode: finished.exitCode, stdout: installOutcome(finished.stdout), stderr: `${scriptGateLine(plan, finished.exitCode, options)}${setupNudgeAfterInstall(plan, finished.exitCode, options)}` };
  } finally {
    restoreSignalHandlers();
    stopProxyWorker(proxy);
  }
}

function prepareProxyCacheDir(manager: PackageManager, sessionDir: string, env: NodeJS.ProcessEnv): string {
  const cacheDir = `${sessionDir}/pm-cache`;
  if (manager === "cargo") {
    prepareCargoHome(cacheDir, userCargoHome(env));
  }
  return cacheDir;
}

function cacheOnlyNotice(installedFresh: boolean): string {
  const theme = createTheme(resolvePresentation().color);
  const reason = installedFresh ? "used a saved copy" : "already installed";
  return `\n  ${theme.paint("muted", `– Nothing was downloaded, so nothing to verify (${reason}). Run dg scan to check installed packages.`)}\n`;
}

function installOutcome(stdout: string): string {
  const lines = stdout.split("\n").filter((line) =>
    /^Successfully installed /.test(line) ||
    /^(added|changed|removed|updated) \d/.test(line.trim())
  );
  return lines.length > 0 ? `${lines.join("\n")}\n` : "";
}

// scriptGate.mode === "enforce" is applied HERE, at the spawn boundary: it
// rewrites the install args (--ignore-scripts) and child env
// (npm_config_ignore_scripts) for npm/yarn so a reputation-clean package can't
// run a lifecycle script. observe/off leave the install untouched. Without this
// the mode setting was inert — the verdict screens what is fetched, this gates
// what the fetched package is allowed to execute.
function applyScriptGateHardening(
  plan: LaunchPlan,
  args: readonly string[],
  childEnv: NodeJS.ProcessEnv,
  configEnv: NodeJS.ProcessEnv
): { readonly args: readonly string[]; readonly env: NodeJS.ProcessEnv } {
  const mode = loadUserConfig(configEnv).scriptGate.mode;
  const manager = plan.classification.manager;
  const hardenedArgs = scriptGateInstallArgs({ mode, manager, args, env: childEnv });
  const gateEnv = scriptGateChildEnv({ mode, manager, args, env: childEnv });
  return {
    args: hardenedArgs,
    env: Object.keys(gateEnv).length > 0 ? { ...childEnv, ...gateEnv } : childEnv
  };
}

async function spawnPackageManager(plan: LaunchPlan, args: readonly string[], options: RunPackageManagerOptions): Promise<SpawnStreamResult> {
  if (!plan.realBinary.path) {
    return {
      exitCode: EXIT_UNAVAILABLE,
      stdout: "",
      stderr: `real ${plan.classification.realBinaryName} binary was not found outside dg shims\n`
    };
  }
  const spawner = options.spawner ?? defaultSpawner;
  const hardened = applyScriptGateHardening(plan, args, plan.childEnv, options.env ?? process.env);
  return spawner({
    binary: plan.realBinary.path,
    args: hardened.args,
    env: hardened.env,
    onStdout: options.onStdout,
    onStderr: options.onStderr
  });
}

const defaultSpawner: PackageManagerSpawner = (request) =>
  new Promise((resolve) => {
    const invocation = resolveSpawnInvocation(request.binary, request.args);
    const child = spawn(invocation.command, [...invocation.args], {
      env: request.env,
      stdio: ["inherit", "pipe", "pipe"],
      windowsVerbatimArguments: invocation.windowsVerbatimArguments
    });
    const stdout: string[] = [];
    const stderr: string[] = [];
    const stdoutRedactor = createStreamRedactor((chunk) => {
      stdout.push(chunk);
      request.onStdout?.(chunk);
    });
    const stderrRedactor = createStreamRedactor((chunk) => {
      stderr.push(chunk);
      request.onStderr?.(chunk);
    });
    child.stdout?.on("data", (chunk: Buffer) => stdoutRedactor.write(chunk.toString("utf8")));
    child.stderr?.on("data", (chunk: Buffer) => stderrRedactor.write(chunk.toString("utf8")));
    const settle = (exitCode: number, extraStderr?: string): void => {
      stdoutRedactor.flush();
      stderrRedactor.flush();
      if (extraStderr) {
        const redacted = redactSecrets(extraStderr);
        stderr.push(redacted);
        request.onStderr?.(redacted);
      }
      resolve({
        exitCode,
        stdout: redactSecrets(stdout.join("")),
        stderr: redactSecrets(stderr.join(""))
      });
    };
    child.on("error", (error) => settle(EXIT_UNAVAILABLE, `${error.message}\n`));
    child.on("close", (code, signal) => settle(code ?? signalExitCode(signal)));
  });

function signalExitCode(signal: NodeJS.Signals | null): number {
  if (!signal) {
    return EXIT_UNAVAILABLE;
  }
  const signalNumber = osConstants.signals[signal];
  return signalNumber ? 128 + signalNumber : EXIT_UNAVAILABLE;
}

function streamedOut(captured: string, options: RunPackageManagerOptions): string {
  return options.onStdout ? "" : captured;
}

function streamedErr(captured: string, options: RunPackageManagerOptions): string {
  return options.onStderr ? "" : captured;
}

function unavailable(invoked: string, reason: string): CommandResult {
  return {
    exitCode: EXIT_UNAVAILABLE,
    stdout: "",
    stderr: `${redactSecrets(invoked)} cannot run yet: ${redactSecrets(reason)}.\n`
  };
}

function renderDecisions(decisions: readonly EnforcementDecision[], env: NodeJS.ProcessEnv): string {
  const visible = isCiEnv(env) ? decisions.filter((decision) => decision.action !== "pass") : decisions;
  return visible.map((decision) => redactSecrets(renderInstallDecision(decision))).join("");
}

type ProxyWorkerReady = {
  readonly process: ChildProcessWithoutNullStreams;
  readonly session: SessionHandle;
  readonly proxyUrl: string;
};

type ProxyWorkerFailure = {
  readonly decision: ReturnType<typeof enforceProtectedInstall>;
};

export function loadProjectCooldownExemptions(env: NodeJS.ProcessEnv, cwd: string = process.cwd()): readonly CooldownExemption[] {
  try {
    const root = findProjectRoot(cwd, env);
    if (!root) {
      return [];
    }
    const file = loadDgFile(root);
    if (!file.readable) {
      return [];
    }
    return honoredOverrides(file, root, env, trustsProjectOverrides(env)).exemptions;
  } catch {
    return [];
  }
}

export function dgFileExemptionsNotice(exemptions: readonly CooldownExemption[]): string {
  if (exemptions.length === 0) {
    return "";
  }
  const plural = exemptions.length === 1 ? "exemption" : "exemptions";
  return `dg: applying ${exemptions.length} cooldown ${plural} from this project's dg.json\n`;
}

let dgFileExemptionNoticeWritten = false;

function maybeNoticeDgFileExemptions(exemptions: readonly CooldownExemption[]): void {
  if (dgFileExemptionNoticeWritten) {
    return;
  }
  const notice = dgFileExemptionsNotice(exemptions);
  if (!notice) {
    return;
  }
  dgFileExemptionNoticeWritten = true;
  process.stderr.write(notice);
}

async function startProxyWorker(
  classification: PackageManagerClassification,
  env: NodeJS.ProcessEnv,
  forceOverride: ForceOverrideRequest | undefined
): Promise<ProxyWorkerReady | ProxyWorkerFailure> {
  const paths = resolveDgPaths(env);
  const session = createSessionSync(paths);
  const sessionBootstrapPath = `${session.dir}/session.json`;
  const workerPath = fileURLToPath(new URL("../proxy/worker.js", import.meta.url));
  try {
    writeFileSync(sessionBootstrapPath, `${JSON.stringify(session)}\n`, {
      encoding: "utf8",
      mode: 0o600
    });
    if (!existsSync(workerPath)) {
      throw new Error("production proxy worker is not built");
    }
    const config = loadUserConfig(env);
    const exemptions = loadProjectCooldownExemptions(env);
    maybeNoticeDgFileExemptions(exemptions);
    const exemptionsEnv = writeCooldownExemptionsFile(session.dir, exemptions);
    const child = spawn(process.execPath, [workerPath, sessionBootstrapPath, config.api.baseUrl], {
      env: {
        ...env,
        DG_PROXY_CLASSIFICATION: JSON.stringify(classification),
        ...(forceOverride ? { DG_FORCE_OVERRIDE_REQUEST: JSON.stringify(forceOverride) } : {}),
        ...exemptionsEnv
      },
      stdio: ["pipe", "pipe", "pipe"]
    });
    const ready = await waitForProxyReady(session);
    if (!ready.ready || ready.port <= 0) {
      terminateProxyProcess(child);
      throw new Error("production proxy did not become ready");
    }
    return {
      process: child,
      session,
      proxyUrl: `http://127.0.0.1:${ready.port}`
    };
  } catch (error) {
    cleanupSessionSync(session);
    return {
      decision: enforceProtectedInstall({
        classification,
        env,
        proxyVerdict: {
          verdict: "block",
          cause: "proxy-setup-failure",
          reason: error instanceof Error ? error.message : "production proxy startup failed"
        }
      })
    };
  }
}

async function waitForProxyReady(session: SessionHandle): Promise<ReturnType<typeof readProxySessionState>> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    const state = readProxySessionState(session);
    if (state.ready && state.port > 0) {
      return state;
    }
    await delay(25);
  }
  return readProxySessionState(session);
}

function stopProxyWorker(proxy: ProxyWorkerReady): void {
  try {
    proxy.process.stdin.end();
  } catch {
    // The worker may already be gone after a package-manager crash or signal.
  }
  terminateProxyProcess(proxy.process);
  cleanupSessionSync(proxy.session);
}

function installProxySignalHandlers(proxy: ProxyWorkerReady): () => void {
  const registrations = (["SIGINT", "SIGTERM"] as const).map((signal) => {
    const handler = () => {
      if (process.stdin.isTTY) {
        process.stdin.setRawMode(false);
      }
      stopProxyWorker(proxy);
      process.exit(signal === "SIGINT" ? 130 : 143);
    };
    process.once(signal, handler);
    return {
      handler,
      signal
    };
  });

  return () => {
    for (const registration of registrations) {
      process.off(registration.signal, registration.handler);
    }
  };
}

function terminateProxyProcess(child: ChildProcessWithoutNullStreams): void {
  if (!isProcessAlive(child)) {
    return;
  }
  child.kill("SIGTERM");
  waitForProcessExitSync(child, 500);
  if (isProcessAlive(child)) {
    child.kill("SIGKILL");
    waitForProcessExitSync(child, 500);
  }
}

function waitForProcessExitSync(child: ChildProcessWithoutNullStreams, timeoutMs: number): void {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline && isProcessAlive(child)) {
    sleepSync(25);
  }
}

function isProcessAlive(child: ChildProcessWithoutNullStreams): boolean {
  if (!child.pid || child.exitCode !== null || child.signalCode !== null) {
    return false;
  }
  try {
    process.kill(child.pid, 0);
    return true;
  } catch {
    return false;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function shimNonce(manager: PackageManager, env: NodeJS.ProcessEnv): string {
  const existing = env.DG_SHIM_ACTIVE;
  const next = `${manager}:${process.pid}`;
  return existing ? `${existing},${next}` : next;
}
