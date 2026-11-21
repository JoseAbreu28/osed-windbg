import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";
import { beforeAll, describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const esbuild = require("esbuild");
const { buildOptions, legacyTarget } = require("../build.js");
const { MISSING_APIS, ALSO_MISSING, findEngineGaps } = require("../legacy/engine.js");

type Api = { path: string; polyfilled?: boolean };
const missing = (MISSING_APIS as Api[]).map((api) => api.path).concat(ALSO_MISSING as string[]);

// A fresh realm with every builtin classic WinDbg 10.0.19041 lacks deleted, so code that
// leans on one fails here the way it fails in the debugger.
function engineRealm(): { context: vm.Context; removed: string[] } {
  const context = vm.createContext({});
  const removed = vm.runInContext(
    `(function (paths, G) {
      var removed = [];
      paths.forEach(function (path) {
        var parts = path.split("."), name = parts.pop(), owner = G;
        for (var i = 0; i < parts.length && owner; i++) owner = owner[parts[i]];
        while (owner && !Object.prototype.hasOwnProperty.call(owner, name)) owner = Object.getPrototypeOf(owner);
        if (owner && delete owner[name] && !(name in owner)) removed.push(path);
      });
      return removed;
    })(${JSON.stringify(missing)}, this)`,
    context,
  ) as string[];
  return { context, removed };
}

function loadBundle(source: string) {
  const { context } = engineRealm();
  let log = "";
  const aliases: Record<string, () => any> = {};
  context.host = {
    diagnostics: { debugLog: (text: string) => { log += text; } },
    currentProcess: { Is64Bit: false, Modules: [] },
    functionAlias: function (fn: () => any, name: string) { aliases[name] = fn; },
  };
  vm.runInContext(source, context);
  context.initializeScript();
  return {
    osed: aliases.osed(),
    take() {
      const text = log;
      log = "";
      return text;
    },
  };
}

describe("legacy engine surface", () => {
  it("strips the engine gaps from the test realm", () => {
    const { removed } = engineRealm();
    for (const path of ["String.prototype.matchAll", "String.prototype.replaceAll", "Array.prototype.at", "Object.hasOwn", "BigInt", "globalThis"]) {
      expect(removed).toContain(path);
    }
  });

  it("runtime.js defines every API the engine table marks polyfilled", () => {
    const { context, removed } = engineRealm();
    vm.runInContext(readFileSync(join(__dirname, "..", "legacy", "runtime.js"), "utf8"), context);
    const polyfilled = (MISSING_APIS as Api[]).filter((api) => api.polyfilled && removed.includes(api.path));
    expect(polyfilled.length).toBeGreaterThan(0);
    for (const api of polyfilled) {
      expect(vm.runInContext(`typeof ${api.path}`, context), api.path).toBe("function");
    }
    const matches = vm.runInContext(`Array.from("a=0x10 b=0x2f".matchAll(/0x([0-9a-f]+)/g), function (m) { return m[1] + "@" + m.index; })`, context);
    expect(Array.from(matches as string[])).toEqual(["10@2", "2f@9"]);
    expect(() => vm.runInContext(`"x".matchAll(/x/)`, context)).toThrow(/non-global/);
  });

  it("flags unpolyfilled APIs and unsupported regex syntax", () => {
    const hits = findEngineGaps([
      `s.replaceAll("a", "b");`,
      `list.at(-1);`,
      `Object.hasOwn(o, "k");`,
      `new TextEncoder();`,
      `/(?<word>a)/.test(s);`,
      `/(?<=a)b/.test(s);`,
      `/a.b/s.test(s);`,
      `new RegExp("(?<n>x)", "g");`,
      `s.matchAll(/a/g); s.trimEnd(); o.replaceAll; ({ at: 1 }); "replaceAll(";`,
    ].join("\n"));
    expect(hits.map((h: { line: number; what: string }) => `${h.line} ${h.what}`)).toEqual([
      "1 String.prototype.replaceAll",
      "2 String.prototype.at / Array.prototype.at / Uint8Array.prototype.at",
      "3 Object.hasOwn",
      "4 TextEncoder",
      "5 regex named group",
      "6 regex lookbehind",
      "7 regex dotAll flag",
      "8 regex named group",
    ]);
  });

  describe("built legacy bundle", () => {
    let source = "";
    beforeAll(async () => {
      const result = await esbuild.build({ ...buildOptions(legacyTarget), write: false, logLevel: "silent" });
      source = result.outputFiles[0].text;
    }, 120_000);

    it("uses nothing the engine lacks", () => {
      expect(findEngineGaps(source)).toEqual([]);
    });

    it("runs leak.analyze in an engine-shaped realm", () => {
      const bundle = loadBundle(source);
      bundle.take();
      expect(bundle.osed.leak.analyze("fs_version = 0x73371040")).toMatchObject({ success: true });
      const leakLog = bundle.take();
      expect(leakLog).not.toMatch(/matchAll|is not a function/);
      expect(leakLog).toContain("0x73371040");
    });
  });
});
