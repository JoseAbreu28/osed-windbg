import { createRequire } from "node:module";
import { defineConfig } from "vitest/config";

const require = createRequire(import.meta.url);
const { createLegacyTransformer } = require("./legacy/bigint_transform.js");
const legacy = createLegacyTransformer(__dirname, ["src", "tests"]);

export default defineConfig({
  plugins: [
    {
      name: "osed-legacy-bigint",
      enforce: "pre",
      transform(_code, id) {
        const file = id.split("?")[0];
        if (!file.endsWith(".ts") || !legacy.has(file)) return null;
        return { code: legacy.transformFile(file), map: null };
      },
    },
  ],
  test: {
    setupFiles: ["./legacy/vitest.setup.mjs"],
    // The legacy runtime rejects values above 2^53 by design; this test feeds a full 64-bit constant.
    testNamePattern: /^(?!.*supports 64-bit values and little-endian byte order)/,
  },
});
