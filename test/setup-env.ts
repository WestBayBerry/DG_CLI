import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, sep } from "node:path";

// A dev machine that dogfoods dg must not leak into the suite: a real
// ~/.dg login flips fail-closed tests onto live-API paths, and shimmed
// package managers intercept spawns. Isolate HOME and strip shim dirs.
const isolatedHome = mkdtempSync(join(tmpdir(), "dg-test-home-"));
process.env.HOME = isolatedHome;
process.env.USERPROFILE = isolatedHome;
delete process.env.DG_SHIM_DEPTH;

const shimSuffix = `${sep}.dg${sep}shims`;
process.env.PATH = (process.env.PATH ?? "")
  .split(delimiter)
  .filter((entry) => !entry.endsWith(shimSuffix))
  .join(delimiter);
