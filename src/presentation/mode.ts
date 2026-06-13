export type PresentationMode = "rich" | "plain";

export type Presentation = {
  mode: PresentationMode;
  color: boolean;
  isTTY: boolean;
  isCI: boolean;
};

type Stream = { isTTY?: boolean };

type ColorInput = {
  stream: Stream;
  env: NodeJS.ProcessEnv;
  noColorFlag?: boolean | undefined;
  forceColorFlag?: boolean | undefined;
};

export const CI_MARKERS = [
  "GITHUB_ACTIONS",
  "GITLAB_CI",
  "BUILDKITE",
  "CIRCLECI",
  "TRAVIS",
  "TEAMCITY_VERSION"
];

function truthyEnv(value: string | undefined): boolean {
  return value !== undefined && value !== "" && value !== "0" && value !== "false";
}

export function isCiEnv(env: NodeJS.ProcessEnv = process.env): boolean {
  if (truthyEnv(env.CI)) {
    return true;
  }
  return CI_MARKERS.some((marker) => env[marker] !== undefined && env[marker] !== "");
}

export function colorEnabled(input: ColorInput): boolean {
  if (input.forceColorFlag) {
    return true;
  }
  const forceColor = input.env.FORCE_COLOR;
  if (forceColor !== undefined) {
    return forceColor !== "0" && forceColor !== "false";
  }
  if (input.noColorFlag) {
    return false;
  }
  if (input.env.NO_COLOR !== undefined && input.env.NO_COLOR !== "") {
    return false;
  }
  if (input.env.DG_NO_COLOR !== undefined && input.env.DG_NO_COLOR !== "") {
    return false;
  }
  if (input.env.TERM === "dumb") {
    return false;
  }
  return Boolean(input.stream.isTTY);
}

export function resolvePresentation(options?: {
  stream?: Stream;
  env?: NodeJS.ProcessEnv;
  noColorFlag?: boolean;
  forceColorFlag?: boolean;
}): Presentation {
  const env = options?.env ?? process.env;
  const stream = options?.stream ?? process.stdout;
  const isTTY = Boolean(stream.isTTY);
  const isCI = isCiEnv(env);
  const color = colorEnabled({
    stream,
    env,
    noColorFlag: options?.noColorFlag,
    forceColorFlag: options?.forceColorFlag
  });
  const mode: PresentationMode = isTTY && !isCI ? "rich" : "plain";
  return { mode, color, isTTY, isCI };
}
