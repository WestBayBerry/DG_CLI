import { spawnSync } from "node:child_process";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join, sep } from "node:path";
import { gunzipSync } from "node:zlib";
import { internalScriptEntries } from "./sync-shrinkwrap.mjs";

const root = new URL("..", import.meta.url).pathname;
const destination = await mkdtemp(join(tmpdir(), "dg-tarball-"));

// A dev machine with dg shims installed must not route the pack spawn
// back through dg; the shim depth guard would refuse the nested npm.
const packEnv = { ...process.env, npm_config_ignore_scripts: "false" };
delete packEnv.DG_SHIM_DEPTH;
packEnv.PATH = (packEnv.PATH ?? "")
  .split(delimiter)
  .filter((entry) => !entry.endsWith(`${sep}.dg${sep}shims`))
  .join(delimiter);

function readTarString(header, start, length) {
  const slice = header.subarray(start, start + length);
  const end = slice.indexOf(0);
  return slice.subarray(0, end === -1 ? length : end).toString("utf8");
}

function parsePaxPath(body) {
  const text = body.toString("utf8");
  for (const record of text.split("\n")) {
    const space = record.indexOf(" ");
    if (space === -1) {
      continue;
    }
    const [key, ...rest] = record.slice(space + 1).split("=");
    if (key === "path") {
      return rest.join("=");
    }
  }
  return undefined;
}

function parseTarEntries(tar) {
  const entries = new Map();
  let offset = 0;
  let paxPath;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      break;
    }
    const size = Number.parseInt(readTarString(header, 124, 12).trim() || "0", 8);
    const type = String.fromCharCode(header[156]);
    const body = tar.subarray(offset + 512, offset + 512 + size);
    if (type === "x") {
      paxPath = parsePaxPath(body);
    } else {
      const name = readTarString(header, 0, 100);
      const prefix = readTarString(header, 345, 155);
      const path = paxPath ?? (prefix ? `${prefix}/${name}` : name);
      paxPath = undefined;
      if (type === "0" || type === "\0") {
        entries.set(path, body);
      }
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return entries;
}

try {
  const result = spawnSync("npm", ["pack", "--json", "--pack-destination", destination], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    env: packEnv
  });
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    process.exit(result.status ?? 1);
  }

  const tarballName = (await readdir(destination)).find((name) => name.endsWith(".tgz"));
  if (!tarballName) {
    throw new Error("npm pack produced no tarball");
  }
  const entries = parseTarEntries(gunzipSync(await readFile(join(destination, tarballName))));
  const files = [...entries.keys()].map((path) => path.replace(/^package\//, ""));

  const allowedRootFiles = new Set(["package.json", "LICENSE", "README.md", "npm-shrinkwrap.json"]);
  const disallowed = files.filter((path) => !allowedRootFiles.has(path) && !path.startsWith("dist/"));
  if (disallowed.length > 0) {
    throw new Error(`package tarball contains disallowed files: ${disallowed.join(", ")}`);
  }

  const required = [...allowedRootFiles, "dist/bin/dg.js"];
  for (const path of required) {
    if (!files.includes(path)) {
      throw new Error(`package tarball missing required file: ${path}`);
    }
  }

  const manifest = JSON.parse(entries.get("package/package.json").toString("utf8"));
  const packedScripts = manifest.scripts ?? {};
  const scriptsText = JSON.stringify(packedScripts);
  for (const name of internalScriptEntries) {
    if (scriptsText.includes(name)) {
      throw new Error(`packed package.json leaks internal script entry: ${name}`);
    }
  }
  for (const lifecycle of ["preinstall", "install", "postinstall"]) {
    if (Object.hasOwn(packedScripts, lifecycle)) {
      throw new Error(`packed package.json carries forbidden lifecycle script: ${lifecycle}`);
    }
  }
  if (manifest.bin?.dg !== "./dist/bin/dg.js") {
    throw new Error("packed package.json bin.dg must point at ./dist/bin/dg.js");
  }

  const shrinkwrap = JSON.parse(entries.get("package/npm-shrinkwrap.json").toString("utf8"));
  if (shrinkwrap.name !== manifest.name || shrinkwrap.version !== manifest.version) {
    throw new Error(`npm-shrinkwrap.json identity mismatch: ${shrinkwrap.name}@${shrinkwrap.version} vs ${manifest.name}@${manifest.version}`);
  }
  if (typeof shrinkwrap.lockfileVersion !== "number" || shrinkwrap.lockfileVersion < 2) {
    throw new Error(`npm-shrinkwrap.json lockfileVersion must be >= 2, got ${JSON.stringify(shrinkwrap.lockfileVersion)}`);
  }

  process.stdout.write(`tarball files verified from packed artifact ${tarballName}: ${files.length}\n`);
} finally {
  await rm(destination, {
    force: true,
    recursive: true
  });
}
