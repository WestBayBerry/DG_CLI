import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const checkedExtensions = new Set([".json", ".md", ".mjs", ".ts"]);

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
      files.push(...await walk(path));
      continue;
    }
    if (entry.isFile()) {
      files.push(path);
    }
  }

  return files;
}

for (const file of await walk(root)) {
  const extension = file.slice(file.lastIndexOf("."));
  if (!checkedExtensions.has(extension)) {
    continue;
  }
  const text = await readFile(file, "utf8");
  if (text.includes("\r\n")) {
    throw new Error(`CRLF line endings found in ${relative(root, file)}`);
  }
  if (!text.endsWith("\n")) {
    throw new Error(`missing trailing newline in ${relative(root, file)}`);
  }
  const lines = text.split("\n");
  lines.forEach((line, index) => {
    if (/[ \t]$/.test(line)) {
      throw new Error(`trailing whitespace in ${relative(root, file)}:${index + 1}`);
    }
  });
}
