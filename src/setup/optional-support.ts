export type OptionalSupportId = "windows" | "python-hook" | "bun" | "yarn-berry" | "conda" | "mamba";
export type OptionalSupportKind = "platform" | "hook" | "package-manager";
export type GatedPackageManagerName = "bun" | "conda" | "mamba";

export interface OptionalSupportGate {
  readonly id: OptionalSupportId;
  readonly label: string;
  readonly kind: OptionalSupportKind;
  readonly status: "unclaimed";
  readonly message: string;
  readonly standaloneCommand?: boolean;
}

export const OPTIONAL_SUPPORT_GATES: readonly OptionalSupportGate[] = Object.freeze([
  {
    id: "windows",
    label: "Windows support",
    kind: "platform",
    status: "unclaimed",
    message: "Windows support is gated in this release; use dg prefix mode from a supported POSIX shell or run 'dg --help' for supported commands"
  },
  {
    id: "python-hook",
    label: "Python .pth hook",
    kind: "hook",
    status: "unclaimed",
    message: "Python .pth hook support is gated in this release; use 'dg pip ...', 'dg pipx ...', 'dg uv ...', or 'dg uvx ...' prefix mode instead"
  },
  {
    id: "bun",
    label: "Bun and bunx",
    kind: "package-manager",
    status: "unclaimed",
    standaloneCommand: true,
    message: "Bun support is gated in this release; use 'dg npm ...', 'dg pnpm ...', or 'dg yarn ...' for supported JavaScript installs"
  },
  {
    id: "yarn-berry",
    label: "Yarn Berry",
    kind: "package-manager",
    status: "unclaimed",
    standaloneCommand: false,
    message: "Yarn Berry support is gated in this release; use Yarn classic through 'dg yarn ...' or another supported prefix manager"
  },
  {
    id: "conda",
    label: "Conda",
    kind: "package-manager",
    status: "unclaimed",
    standaloneCommand: true,
    message: "Conda support is gated in this release; use 'dg pip ...' or 'dg uv ...' for supported Python package installs"
  },
  {
    id: "mamba",
    label: "Mamba",
    kind: "package-manager",
    status: "unclaimed",
    standaloneCommand: true,
    message: "Mamba support is gated in this release; use 'dg pip ...' or 'dg uv ...' for supported Python package installs"
  }
]);

export function optionalSupportGate(id: OptionalSupportId): OptionalSupportGate {
  const gate = OPTIONAL_SUPPORT_GATES.find((candidate) => candidate.id === id);
  if (!gate) {
    throw new Error(`unknown optional support gate: ${id}`);
  }
  return gate;
}

export function optionalPackageManagerNames(): readonly GatedPackageManagerName[] {
  return OPTIONAL_SUPPORT_GATES.filter(
    (gate) => gate.kind === "package-manager" && gate.standaloneCommand === true
  ).map((gate) => gate.id as GatedPackageManagerName);
}
