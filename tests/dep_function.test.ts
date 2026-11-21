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

  test("prints a VirtualAlloc frame with shellcodeAddr as lpAddress", () => {
    const result = createDepFunctionCommand().execute({ method: "VirtualAlloc" });
    expect(result.success).toBe(true);
    expect(result.findings[0]).toMatchObject({ method: "VirtualAlloc" });
    expect(logs.join("")).toContain("=== VirtualAlloc Python Call-Frame Skeleton ===");
    expect(logs.join("")).toContain('va += pack("<L", shellcodeAddr)         # lpAddress');
    expect(logs.join("")).not.toContain("0xFFFFFFFF");
  });

  test("prints a VirtualProtect frame in the order the API reads it", () => {
    const result = createDepFunctionCommand().execute({ method: "VirtualProtect" });
    expect(result.success).toBe(true);
    const text = logs.join("");
    expect(text).toContain("=== VirtualProtect Python Call-Frame Skeleton ===");
    const order = ["vpAddr", "shellcodeReturnAddr", "shellcodeAddr)", "dwSize", "0x40", "oldProtectAddr"].map((word) => text.indexOf(word));
    expect(order.every((index) => index >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(text).toContain("lpflOldProtect: writable address");
  });

  test("prints a WriteProcessMemory frame with the pseudo process handle", () => {
    const result = createDepFunctionCommand().execute({ method: "WriteProcessMemory" });
    expect(result.success).toBe(true);
    expect(logs.join("")).toContain("=== WriteProcessMemory Python Call-Frame Skeleton ===");
    expect(logs.join("")).toContain('wpm += pack("<L", 0xFFFFFFFF)');
    expect(logs.join("")).toContain("bytesWrittenAddr");
  });

  test.each([
    ["VA", "VirtualAlloc"], ["va", "VirtualAlloc"], ["virtualalloc", "VirtualAlloc"],
    ["VP", "VirtualProtect"], ["vp", "VirtualProtect"], [" VirtualProtect ", "VirtualProtect"],
    ["WPM", "WriteProcessMemory"], ["wpm", "WriteProcessMemory"], ["WRITEPROCESSMEMORY", "WriteProcessMemory"],
  ])("accepts %j as %s", (input, method) => {
    const result = createDepFunctionCommand().execute({ method: input });
    expect(result.success).toBe(true);
    expect(result.findings[0]).toMatchObject({ method });
  });

  test.each(["VirtualQuery", "VPX", ""])("rejects %j and names the accepted APIs", (input) => {
    const result = createDepFunctionCommand().execute({ method: input });
    expect(result.success).toBe(false);
    expect(result.errors[0]).toContain('"VirtualAlloc", "VirtualProtect" or "WriteProcessMemory"');
    expect(logs.join("")).not.toContain("Call-Frame Skeleton");
  });

  test("registers positional invocation and built-in help", () => {
    const api = loadApi();
    expect(normalizeInvocation("dep_function", ["VirtualProtect"])).toEqual({ method: "VirtualProtect" });
    expect((api.dep_function("VP") as { success: boolean }).success).toBe(true);
    expect(api.last_result()).toMatchObject({ command: "dep_function", success: true });
    logs.length = 0;
    expect((api.help("dep_function") as { success: boolean }).success).toBe(true);
    expect(logs.join("")).toContain('dep_function("VirtualAlloc"');
    expect(logs.join("")).toContain('dep_function("VirtualProtect"');
    expect(logs.join("")).toContain('dep_function("WriteProcessMemory"');
  });
});
