import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const forbiddenTerms = [
  "gallery",
  "confetti",
  "celebrate",
  "dry-run tree",
  "publish-check"
];
const forbiddenPaths = [
  "src/commands/gallery.ts",
  "src/commands/confetti.ts",
  "src/commands/celebrate.ts",
  "src/commands/publish-check.ts",
  "src/ui/apps/GalleryApp.tsx",
  "src/ui/apps/ConfettiDemoApp.tsx",
  "src/ui/apps/LoginCelebrateApp.tsx"
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
      files.push(...await walk(path));
      continue;
    }
    if (entry.isFile()) {
      files.push(path);
    }
  }

  return files;
}

for (const path of forbiddenPaths) {
  try {
    const info = await stat(join(root, path));
    if (info.isFile()) {
      throw new Error(`deleted legacy behavior path must not exist: ${path}`);
    }
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
}

for (const file of await walk(join(root, "src"))) {
  const rel = relative(root, file);
  const text = await readFile(file, "utf8");
  const lower = text.toLowerCase();
  for (const term of forbiddenTerms) {
    if (lower.includes(term)) {
      throw new Error(`deleted legacy behavior term '${term}' found in ${rel}`);
    }
  }
}
