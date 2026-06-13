import { copyFile, readFile, rename, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const internalScriptEntries = new Set([
  "check:architecture-cracks",
  "check:release-docs"
]);

export const PREPACK_BACKUP_NAME = ".package.json.prepack-backup";

export function stripInternalScripts(pkg) {
  for (const name of internalScriptEntries) {
    delete pkg.scripts[name];
  }
  if (typeof pkg.scripts.check === "string") {
    pkg.scripts.check = pkg.scripts.check
      .split(" && ")
      .filter((step) => !internalScriptEntries.has(step.replace(/^npm run /, "")))
      .join(" && ");
  }
  return pkg;
}

export async function prepack(root) {
  const backupPath = join(root, PREPACK_BACKUP_NAME);
  if (existsSync(backupPath)) {
    throw new Error(`${PREPACK_BACKUP_NAME} already exists; a previous pack did not restore. Run: node scripts/sync-shrinkwrap.mjs restore`);
  }
  const manifestPath = join(root, "package.json");
  const original = await readFile(manifestPath, "utf8");
  await writeFile(backupPath, original, "utf8");
  await copyFile(join(root, "package-lock.json"), join(root, "npm-shrinkwrap.json"));
  const pkg = stripInternalScripts(JSON.parse(original));
  await writeFile(manifestPath, `${JSON.stringify(pkg, null, 2)}\n`, "utf8");
}

export async function restore(root) {
  const backupPath = join(root, PREPACK_BACKUP_NAME);
  if (existsSync(backupPath)) {
    await rename(backupPath, join(root, "package.json"));
  }
  await rm(join(root, "npm-shrinkwrap.json"), { force: true });
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (invokedDirectly) {
  const mode = process.argv[2] ?? "prepack";
  const root = process.argv[3]
    ? resolve(process.argv[3])
    : resolve(new URL("..", import.meta.url).pathname);
  if (mode === "prepack") {
    await prepack(root);
  } else if (mode === "restore") {
    await restore(root);
  } else {
    process.stderr.write("usage: node scripts/sync-shrinkwrap.mjs [prepack|restore] [root]\n");
    process.exit(2);
  }
}
