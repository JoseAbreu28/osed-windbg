import { readFileSync } from "node:fs";

(0, eval)(readFileSync(new URL("./runtime.js", import.meta.url), "utf8"));
globalThis.BigInt = undefined;
