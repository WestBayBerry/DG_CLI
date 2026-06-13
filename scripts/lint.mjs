import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const forbiddenDirectories = new Set(["utils", "helpers", "manager"]);
const deferredMarkers = [
  "TO" + "DO:",
  "FIX" + "ME",
  "X" + "XX",
  "unimplemented" + "!",
  "panic!" + "(\"not yet"
];

async function walk(directory) {
  const entries = await readdir(directory, {
    withFileTypes: true
  });
  const files = [];

  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (["dist", "node_modules"].includes(entry.name)) {
        continue;
      }
      if (forbiddenDirectories.has(entry.name)) {
        throw new Error(`forbidden directory name in CLI source: ${relative(root, path)}`);
      }
      files.push(...await walk(path));
      continue;
    }
    if (entry.isFile()) {
      files.push(path);
    }
  }

  return files;
}

for (const file of await walk(join(root, "src"))) {
  const text = await readFile(file, "utf8");
  for (const marker of deferredMarkers) {
    if (text.includes(marker)) {
      throw new Error(`deferred marker '${marker}' found in ${relative(root, file)}`);
    }
  }
}
