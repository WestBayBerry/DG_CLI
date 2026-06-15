import { optionalPackageManagerNames, optionalSupportGate } from "../setup/optional-support.js";

export type SupportedPackageManager = "npm" | "npx" | "pnpm" | "pnpx" | "yarn" | "pip" | "pipx" | "uv" | "uvx" | "cargo";
export type GatedPackageManager = "bun" | "conda" | "mamba";
export type PackageManager = SupportedPackageManager | GatedPackageManager;
export type Ecosystem = "javascript" | "python" | "rust" | "gated";
export type ClassificationKind = "protected" | "passthrough" | "unsupported";

export interface PackageManagerClassification {
  readonly manager: PackageManager;
  readonly ecosystem: Ecosystem;
  readonly kind: ClassificationKind;
  readonly action: string;
  readonly reason: string;
  readonly realBinaryName: string;
  readonly args: readonly string[];
}

const supportedManagers: readonly SupportedPackageManager[] = ["npm", "npx", "pnpm", "pnpx", "yarn", "pip", "pipx", "uv", "uvx", "cargo"];
const gatedManagers: readonly GatedPackageManager[] = optionalPackageManagerNames();
const jsProtected = new Set(["install", "i", "ci", "add", "update", "dedupe", "exec", "create"]);
const pnpmProtected = new Set(["install", "i", "add", "update", "dlx", "exec", "create"]);
const yarnProtected = new Set(["add", "install", "upgrade", "dlx", "create"]);
const pipProtected = new Set(["install", "download", "wheel"]);
const pipxProtected = new Set(["install", "upgrade", "inject", "run"]);
const uvProtected = new Set(["add", "sync"]);
const cargoProtected = new Set(["add", "install", "fetch", "update", "build", "test", "check", "run"]);
const passthrough = new Set(["help", "--help", "-h", "version", "--version", "-v", "list", "ls", "show", "freeze"]);

// pip3, pip3.12, python3, python3.11 are the canonical install commands on
// macOS/Homebrew and many Linux distros (see BINARY_FALLBACKS in
// resolve-real-binary.ts). The classifier keys on the base name, so a
// version-suffixed spelling must normalize back to pip/python or it falls
// through to a silent allow. `pipx`/`pipenv` are left untouched — only a bare
// numeric/dotted version suffix is stripped.
export function normalizeManagerName(name: string): string {
  const m = /^(pip|python)(\d+(?:\.\d+)*)?$/.exec(name);
  return m && m[1] ? m[1] : name;
}

export function packageManagerNames(): readonly PackageManager[] {
  return [...supportedManagers, ...gatedManagers];
}

export function isSupportedPackageManager(manager: PackageManager): manager is SupportedPackageManager {
  return supportedManagers.includes(manager as SupportedPackageManager);
}

export function classifyPackageManagerInvocation(rawManager: PackageManager, args: readonly string[]): PackageManagerClassification {
  const manager = normalizeManagerName(rawManager) as PackageManager;
  if (!isSupportedPackageManager(manager)) {
    return unsupportedClassification(manager, args);
  }

  if (manager === "npx" || manager === "pnpx" || manager === "uvx") {
    return protectedClassification(manager, args, manager, `${manager} fetches and runs package artifacts`);
  }

  if (manager === "npm") {
    return classifyByCommand(manager, args, "npm", jsProtected, "npm install/fetch command", "javascript");
  }
  if (manager === "pnpm") {
    return classifyByCommand(manager, args, "pnpm", pnpmProtected, "pnpm install/fetch command", "javascript");
  }
  if (manager === "yarn") {
    // A bare `yarn` (no sub-command) runs `yarn install`, fetching every lockfile
    // dependency; classify it protected rather than passthrough. Read-only
    // version/help invocations stay passthrough.
    const readOnlyFlag = args.some((a) => a === "--version" || a === "-v" || a === "--help" || a === "-h");
    if (firstCommand(args) === "" && !readOnlyFlag) {
      return protectedClassification("yarn", args, "yarn", "bare yarn installs all lockfile dependencies");
    }
    return classifyByCommand(manager, args, "yarn", yarnProtected, "Yarn classic install/fetch command", "javascript");
  }
  if (manager === "pip") {
    return classifyByCommand(manager, args, "pip", pipProtected, "pip install/fetch command", "python");
  }
  if (manager === "pipx") {
    return classifyByCommand(manager, args, "pipx", pipxProtected, "pipx install/fetch command", "python");
  }
  if (manager === "uv") {
    return classifyUv(args);
  }
  return classifyByCommand(manager, args, "cargo", cargoProtected, "Cargo command can fetch crates", "rust");
}

function classifyByCommand(
  manager: SupportedPackageManager,
  args: readonly string[],
  realBinaryName: string,
  protectedCommands: ReadonlySet<string>,
  protectedReason: string,
  ecosystem: Ecosystem
): PackageManagerClassification {
  const action = firstCommand(args);
  if (protectedCommands.has(action) || containsFetchSpec(args) || initFetchesPackage(action, args, protectedCommands)) {
    return {
      manager,
      ecosystem,
      kind: "protected",
      action,
      reason: protectedReason,
      realBinaryName,
      args
    };
  }
  return {
    manager,
    ecosystem,
    kind: "passthrough",
    action,
    reason: passthrough.has(action) ? "read-only or local package-manager command" : "not classified as an install/fetch command",
    realBinaryName,
    args
  };
}

function classifyUv(args: readonly string[]): PackageManagerClassification {
  const action = firstCommand(args);
  if (action === "pip" && pipProtected.has(args[1] ?? "")) {
    return protectedClassification("uv", args, "uv", "uv pip install/fetch command");
  }
  if (action === "tool" && ["run", "install", "upgrade"].includes(args[1] ?? "")) {
    return protectedClassification("uv", args, "uv", "uv tool run/install/upgrade fetches package artifacts");
  }
  if (action === "run" && uvRunFetchesPackage(args)) {
    // `uv run --with <pkg> …` fetches <pkg> from PyPI and runs it: a real
    // fetch-and-execute path that the bare `run` verb otherwise waves through.
    return protectedClassification("uv", args, "uv", "uv run --with fetches and runs a package");
  }
  if (uvProtected.has(action) || containsFetchSpec(args)) {
    return protectedClassification("uv", args, "uv", "uv install/fetch command");
  }
  return {
    manager: "uv",
    ecosystem: "python",
    kind: "passthrough",
    action,
    reason: passthrough.has(action) ? "read-only or local uv command" : "not classified as an install/fetch command",
    realBinaryName: "uv",
    args
  };
}

function protectedClassification(
  manager: SupportedPackageManager,
  args: readonly string[],
  realBinaryName: string,
  reason: string
): PackageManagerClassification {
  return {
    manager,
    ecosystem: manager === "cargo" ? "rust" : manager === "pip" || manager === "pipx" || manager === "uv" || manager === "uvx" ? "python" : "javascript",
    kind: "protected",
    action: firstCommand(args),
    reason,
    realBinaryName,
    args
  };
}

function unsupportedClassification(manager: GatedPackageManager, args: readonly string[]): PackageManagerClassification {
  return {
    manager,
    ecosystem: "gated",
    kind: "unsupported",
    action: firstCommand(args),
    reason: optionalSupportGate(manager).message,
    realBinaryName: manager,
    args
  };
}

function firstCommand(args: readonly string[]): string {
  return args.find((arg) => !arg.startsWith("-")) ?? "";
}

// `npm/pnpm/yarn init <initializer>` aliases to fetching and running
// create-<initializer>, the same as the `create` form; bare `init` / `init -y`
// is a local scaffold with no fetch. Gated to the JS managers (their protected
// set carries "create"); cargo/pip `init` are local-only.
function initFetchesPackage(action: string, args: readonly string[], protectedCommands: ReadonlySet<string>): boolean {
  if (action !== "init" || !protectedCommands.has("create")) {
    return false;
  }
  const commandIndex = args.findIndex((arg) => !arg.startsWith("-"));
  return args.slice(commandIndex + 1).some((arg) => arg !== "--" && !arg.startsWith("-"));
}

export function uvRunFetchesPackage(args: readonly string[]): boolean {
  return args.some(
    (a) => a === "--with" || a === "--with-editable" || a === "--with-requirements" || a.startsWith("--with="),
  );
}

function containsFetchSpec(args: readonly string[]): boolean {
  return args.some((arg) => /^https?:\/\//.test(arg) || /^git\+https?:\/\//.test(arg) || /\.t(ar\.)?gz(?:$|[#?])/.test(arg));
}
