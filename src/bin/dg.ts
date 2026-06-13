#!/usr/bin/env node
import { assertCurrentNode } from "../runtime/node-version.js";

await assertCurrentNode();

const { exitOnFatal } = await import("../runtime/fatal.js");

process.on("uncaughtException", (error) => {
  if ((error as NodeJS.ErrnoException).code === "EPIPE") {
    process.exit(process.exitCode ?? 0);
  }
  exitOnFatal(error);
});
process.on("unhandledRejection", exitOnFatal);
process.stdout.on("error", (error: NodeJS.ErrnoException) => {
  if (error.code === "EPIPE") {
    process.exit(process.exitCode ?? 0);
  }
  exitOnFatal(error);
});
process.stderr.on("error", () => {});

const { runCli, writeCliResult } = await import("../runtime/cli.js");
const { maybeShowFirstRun } = await import("../runtime/first-run.js");
const { maybePreflightInstallPrompt } = await import("../launcher/preflight-prompt.js");

const args = process.argv.slice(2);

const { maybeAgentHookExec } = await import("../launcher/agent-hook-exec.js");
const agentHookExec = await maybeAgentHookExec(args);
if (agentHookExec.handled) {
  writeCliResult(agentHookExec.result);
} else {
const { maybeOfferSetupWizard } = await import("../setup-ui/offer.js");
const wizardOffer = await maybeOfferSetupWizard(args);
if (wizardOffer.handled) {
  writeCliResult(wizardOffer.result);
} else {
if (wizardOffer.result.stderr) {
  process.stderr.write(wizardOffer.result.stderr);
}
maybeShowFirstRun(args);
import("../state/index.js")
  .then(({ pruneDeadSessionsSync, resolveDgPaths }) => {
    pruneDeadSessionsSync(resolveDgPaths());
  })
  .catch(() => {});

const { maybeDeviceLogin } = await import("../auth/device-login.js");
const { maybeVerifyPackage } = await import("../verify/package-check.js");
const { maybeAudit } = await import("../commands/audit.js");
const notHandled = { handled: false as const };
const deviceLogin = await maybeDeviceLogin(args);
const verifyPackage = deviceLogin.handled ? notHandled : await maybeVerifyPackage(args);
const audit = deviceLogin.handled || verifyPackage.handled ? notHandled : await maybeAudit(args);
if (deviceLogin.handled) {
  writeCliResult(deviceLogin.result);
} else if (verifyPackage.handled) {
  writeCliResult(verifyPackage.result);
} else if (audit.handled) {
  writeCliResult(audit.result);
} else {
  const preflight = await maybePreflightInstallPrompt(args, { decisionsCwd: process.cwd() });
  if (preflight.handled) {
    writeCliResult(preflight.result);
  } else {
    const { maybeRunLiveInstall } = await import("../launcher/live-install.js");
    const liveInstall = await maybeRunLiveInstall(args);
    if (liveInstall.handled) {
      writeCliResult(liveInstall.result);
    } else {
      writeCliResult(await runCli(args));
    }
  }
}

// The auth flows (browser login, paid-verify gate, deep audit upload) already
// tell the user exactly what to do; the throttled nudges would just be noise.
if (!deviceLogin.handled && !verifyPackage.handled && !audit.handled) {
  try {
    const { maybeShowNudges } = await import("../runtime/nudges.js");
    maybeShowNudges(args);
  } catch {
    // dg deleted its own files mid-run (uninstall of itself); nudges are cosmetic.
  }
}
}
}
