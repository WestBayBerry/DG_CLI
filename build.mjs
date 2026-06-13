import { chmod, rename, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const dist = fileURLToPath(new URL("./dist", import.meta.url));
const staging = fileURLToPath(new URL("./dist.next", import.meta.url));
const previous = fileURLToPath(new URL("./dist.prev", import.meta.url));

// Build into a staging directory and swap it in with renames, rather than
// `rm -rf dist` then compile in place. The old build does not exist for the
// whole tsc run (seconds); anything that loads dist/bin/dg.js in that window —
// e.g. a dg shell shim wrapping the npm/npx that the check script itself calls
// — fails with a misleading "module not found". With the swap, dist always
// points at a complete build except for the two renames at the end.
await rm(staging, { force: true, recursive: true });
await rm(previous, { force: true, recursive: true });

const result = spawnSync(
  process.execPath,
  ["./node_modules/typescript/bin/tsc", "--project", "tsconfig.json", "--outDir", "dist.next"],
  {
    cwd: fileURLToPath(new URL(".", import.meta.url)),
    encoding: "utf8",
    stdio: "inherit"
  }
);

if (result.status !== 0) {
  await rm(staging, { force: true, recursive: true });
  process.exit(result.status ?? 1);
}

await chmod(fileURLToPath(new URL("./dist.next/bin/dg.js", import.meta.url)), 0o755);

await rename(dist, previous).catch((error) => {
  if (error?.code !== "ENOENT") throw error;
});
await rename(staging, dist);
await rm(previous, { force: true, recursive: true });
