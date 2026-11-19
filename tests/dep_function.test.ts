import { beforeEach, describe, expect, test } from "vitest";
import { createDepFunctionCommand } from "../src/commands/dep_function";
import { initializeScript, normalizeInvocation } from "../src/index";

const logs: string[] = [];

function loadApi(): Record<string, (...args: unknown[]) => unknown> {
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    currentProcess: { Is64Bit: false, Modules: [] },
  };
  initializeScript();
  logs.length = 0;
  return (globalThis as unknown as { osed: Record<string, (...args: unknown[]) => unknown> }).osed;
}

describe("dep_function", () => {
  beforeEach(() => {
    logs.length = 0;
    (globalThis as unknown as { host: unknown }).host = {
      diagnostics: { debugLog: (line: string) => logs.push(line) },
      currentProcess: { Is64Bit: false, Modules: [] },
    };
  });

  test("prints a VA frame with shellcodeAddr as lpAddress", () => {
    const result = createDepFunctionCommand().execute({ method: "VA" });
    expect(result.success).toBe(true);
    expect(result.findings[0]).toMatchObject({ method: "VA" });
    expect(logs.join("")).toContain('va += pack("<L", shellcodeAddr)         # lpAddress');
    expect(logs.join("")).not.toContain("0xFFFFFFFF");
  });

  test("prints a WPM frame with the pseudo process handle", () => {
    const result = createDepFunctionCommand().execute({ method: "wpm" });
    expect(result.success).toBe(true);
    expect(logs.join("")).toContain('wpm += pack("<L", 0xFFFFFFFF)');
    expect(logs.join("")).toContain("bytesWrittenAddr");
  });

  test("rejects unknown methods", () => {
    expect(createDepFunctionCommand().execute({ method: "VirtualProtect" }).success).toBe(false);
  });

  test("registers positional invocation and built-in help", () => {
    const api = loadApi();
    expect(normalizeInvocation("dep_function", ["VA"])).toEqual({ method: "VA" });
    expect(api.dep_function("VA")).toBe(true);
    expect(api.last_result()).toMatchObject({ command: "dep_function", success: true });
    logs.length = 0;
    expect(api.help("dep_function")).toBe(true);
    expect(logs.join("")).toContain('dep_function("VA"');
    expect(logs.join("")).toContain('dep_function("WPM"');
  });
});
