import type { CommandSpec } from "./types.js";
import { runPackageManager } from "../launcher/run.js";
import { packageManagerNames } from "../launcher/classify.js";
import { optionalPackageManagerNames, optionalSupportGate } from "../setup/optional-support.js";
import type { ForceOverrideRequest } from "../proxy/enforcement.js";

const gatedPackageManagers = optionalPackageManagerNames();

export const packageManagerCommandNames = packageManagerNames();

export function packageManagerCommands(): CommandSpec[] {
  return packageManagerCommandNames.map((name) => ({
    name,
    summary: `Run ${name} through dg prefix-mode routing.`,
    usage: `dg ${name} [--dg-force-install] [...args]`,
    args: [{ name: "[...args]", summary: `Arguments passed straight through to ${name}.` }],
    flags: [{ flag: "--dg-force-install", summary: "Proceed past a dg block where your policy permits an override." }],
    examples: [`dg ${name} <args>`, `dg ${name} <args> --dg-force-install`],
    details: commandDetails(name),
    handler: (context) => {
      const parsed = parsePrefixControlArgs(context.args);
      return runPackageManager(name, parsed.args, {
        onStdout: (chunk) => process.stdout.write(chunk),
        onStderr: (chunk) => process.stderr.write(chunk),
        ...(parsed.forceOverride ? { forceOverride: parsed.forceOverride } : {})
      });
    }
  }));
}

function commandDetails(name: (typeof packageManagerCommandNames)[number]): readonly string[] {
  const details = ["Protected fetch and install commands start enforcement; passthrough commands do not."];
  if (gatedPackageManagers.includes(name as (typeof gatedPackageManagers)[number])) {
    details.push(optionalSupportGate(name as (typeof gatedPackageManagers)[number]).message);
  } else if (name === "yarn") {
    details.push("This build claims Yarn classic routing only. Yarn Berry remains gated and unclaimed until its explicit support gate passes.");
  } else {
    details.push("Support for this ecosystem is required before the install-firewall task can complete.");
  }
  return details;
}

function parsePrefixControlArgs(args: readonly string[]): {
  readonly args: readonly string[];
  readonly forceOverride?: ForceOverrideRequest;
} {
  const childArgs: string[] = [];
  let force = false;

  for (const arg of args) {
    if (arg === "--dg-force-install") {
      force = true;
      continue;
    }
    childArgs.push(arg);
  }

  if (!force) {
    return { args: childArgs };
  }
  return {
    args: childArgs,
    forceOverride: { force: true }
  };
}
