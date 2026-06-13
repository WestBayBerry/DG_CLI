import {
  analyzePackages,
  mergeAnalyzeResponses,
  scannerErrorFromUnknown,
  type AnalyzeEcosystem,
  type AnalyzePackageInput,
  type AnalyzeResponse
} from "../api/analyze.js";

type WorkerPayload = {
  readonly scanId?: string;
  readonly groups: ReadonlyArray<{
    readonly ecosystem: AnalyzeEcosystem;
    readonly packages: readonly AnalyzePackageInput[];
  }>;
};

async function readStdin(): Promise<string> {
  process.stdin.setEncoding("utf8");
  let raw = "";
  for await (const chunk of process.stdin) {
    raw += chunk;
  }
  return raw;
}

async function main(): Promise<void> {
  const raw = (await readStdin()).trim();
  if (!raw) {
    throw new Error("analyze-worker: missing input payload");
  }
  const payload = JSON.parse(raw) as WorkerPayload;
  const responses: AnalyzeResponse[] = [];
  for (const group of payload.groups) {
    if (group.packages.length === 0) {
      continue;
    }
    responses.push(await analyzePackages(group.packages, {
      ecosystem: group.ecosystem,
      ...(payload.scanId ? { scanId: payload.scanId } : {})
    }));
  }
  process.stdout.write(JSON.stringify(mergeAnalyzeResponses(responses)));
}

main().catch((error: unknown) => {
  process.stdout.write(JSON.stringify({ scannerError: scannerErrorFromUnknown(error) }));
  process.exit(1);
});
