import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: [
      "test/**/*.test.ts"
    ],
    pool: "threads",
    testTimeout: 30000,
    globalSetup: "./test/global-setup.ts",
    setupFiles: ["./test/setup-env.ts"],
    // GitHub runners export XDG_*, which resolveDgPaths prefers over the
    // temp HOMEs tests isolate with — every test would share one real
    // config dir. Empty values make xdgPath fall back to $HOME/.dg, and
    // spawned dg children inherit the same neutralized values.
    env: {
      XDG_CONFIG_HOME: "",
      XDG_STATE_HOME: "",
      XDG_CACHE_HOME: ""
    }
  }
});
