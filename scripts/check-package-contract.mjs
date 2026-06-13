import { readFile } from "node:fs/promises";

const forbiddenLifecycleScripts = new Set(["preinstall", "install", "postinstall"]);
const semverPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

if (typeof packageJson.version !== "string" || !semverPattern.test(packageJson.version)) {
  throw new Error(`package version must be valid semver, got ${JSON.stringify(packageJson.version)}`);
}

if (packageJson.engines?.node !== ">=22.14.0") {
  throw new Error(`engines.node must be exactly >=22.14.0, got ${JSON.stringify(packageJson.engines?.node)}`);
}

const scripts = packageJson.scripts ?? {};
for (const scriptName of forbiddenLifecycleScripts) {
  if (Object.hasOwn(scripts, scriptName)) {
    throw new Error(`forbidden npm lifecycle script present: scripts.${scriptName}`);
  }
}

if (scripts.prepack !== "node scripts/sync-shrinkwrap.mjs") {
  throw new Error(`scripts.prepack must be "node scripts/sync-shrinkwrap.mjs" so published tarballs ship the audited npm-shrinkwrap.json, got ${JSON.stringify(scripts.prepack)}`);
}

if (scripts.postpack !== "node scripts/sync-shrinkwrap.mjs restore") {
  throw new Error(`scripts.postpack must be "node scripts/sync-shrinkwrap.mjs restore", got ${JSON.stringify(scripts.postpack)}`);
}

const approvedRuntimeDependencies = new Set([
  "node-forge",
  "ink",
  "ink-spinner",
  "react",
  "chalk"
]);

const dependencies = packageJson.dependencies ?? {};
for (const dependencyName of Object.keys(dependencies)) {
  if (!approvedRuntimeDependencies.has(dependencyName)) {
    throw new Error(`unapproved runtime dependency present: ${dependencyName}`);
  }
}

for (const [dependencyName, range] of Object.entries(dependencies)) {
  if (/^[~^<>=*]/.test(range)) {
    throw new Error(`${dependencyName} must be exact-pinned, got ${range}`);
  }
}

const files = packageJson.files ?? [];
const expectedFiles = ["dist", "LICENSE", "package.json", "npm-shrinkwrap.json"];
if (JSON.stringify(files) !== JSON.stringify(expectedFiles)) {
  throw new Error(`package files must be ${JSON.stringify(expectedFiles)}, got ${JSON.stringify(files)}`);
}

if (!files.includes("package.json")) {
  throw new Error("package files must ship package.json so version.ts can read it at runtime from the installed package");
}

if (packageJson.bin?.dg !== "./dist/bin/dg.js") {
  throw new Error("package bin.dg must point at ./dist/bin/dg.js");
}
