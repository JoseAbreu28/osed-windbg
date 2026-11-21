import { beforeEach, describe, expect, test } from "vitest";
import { createRopTemplateCommand } from "../src/commands/rop_template";
import { initializeScript, normalizeInvocation } from "../src/index";

type Result = { success: boolean; errors: string[] };
type Api = Record<string, (...args: unknown[]) => Result>;

const logs: string[] = [];

function setHost(): void {
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    currentProcess: { Is64Bit: false, Modules: [] },
  };
}

function loadApi(): Api {
  setHost();
  initializeScript();
  logs.length = 0;
  return (globalThis as unknown as { osed: Api }).osed;
}

const DEP_APIS = [
  { api: "VirtualAlloc", frame: "va", call: "KERNELBASE!VirtualAlloc" },
  { api: "VirtualProtect", frame: "vp", call: "KERNELBASE!VirtualProtect" },
  { api: "WriteProcessMemory", frame: "wpm", call: "KERNELBASE!WriteProcessMemory" },
] as const;

describe("rop_template", () => {
  beforeEach(() => {
    logs.length = 0;
    setHost();
  });

  test.each(DEP_APIS)("$api skeleton style prints the patch-and-pivot method", ({ api, frame, call }) => {
    const result = createRopTemplateCommand().execute({ api, module: "libbkup", style: "skeleton" });
    expect(result.success).toBe(true);
    expect(result.findings[0]).toMatchObject({ api, module: "libbkup", style: "skeleton" });
    const text = logs.join("\n");
    expect(text).toContain(`=== ${api} DEP Bypass — Skeleton Method (patch each field) ===`);
    for (const step of ["Step 1", "Step 2", "Step 3", "Step 4"]) expect(text).toContain(`=== ${step}`);
    expect(text).toContain(`dx @$osed().sc.iat_find("${api}")`);
    expect(text).toContain('dx @$osed().rop.scan_live("libbkup", "<bad chars>")');
    for (const capability of ["STACK_POINTER_CAPTURE", "MOVE_REGISTER", "MEMORY_READ", "MEMORY_WRITE"]) {
      expect(text).toContain(`rop.query("capability", "${capability}")`);
    }
    expect(text).toContain('dx @$osed().pivots("libbkup", 15)');
    expect(text).toContain(`${frame}  = p32(0x45454545)`);
    expect(text).toContain(`dep_function("${api}")`);
    expect(text).toContain(`bp ${call}`);
    expect(text).not.toContain("PUSHAD register map");
  });

  test.each(DEP_APIS)("$api pushad style prints the PUSHAD register map", ({ api, call }) => {
    const result = createRopTemplateCommand().execute({ api, module: "libbkup", style: "pushad" });
    expect(result.success).toBe(true);
    const text = logs.join("\n");
    expect(text).toContain(`=== ${api} DEP Bypass — PUSHAD Method ===`);
    expect(text).toContain("=== Step 2 — PUSHAD register map ===");
    expect(text).toContain('dx @$osed().find_bytes("libbkup", "60 C3")');
    expect(text).toContain("# pushad ; ret");
    expect(text).toContain(`bp ${call}`);
    expect(text).not.toContain("Skeleton Method");
  });

  test("skeleton is the default style and VirtualProtect the default api", () => {
    const api = loadApi();
    expect(api.rop_template().success).toBe(true);
    expect(logs.join("\n")).toContain("=== VirtualProtect DEP Bypass — Skeleton Method (patch each field) ===");
    logs.length = 0;
    expect(api.rop_template("WriteProcessMemory", "libbkup").success).toBe(true);
    expect(logs.join("\n")).toContain("=== WriteProcessMemory DEP Bypass — Skeleton Method (patch each field) ===");
  });

  test("the VirtualProtect PUSHAD map keeps dwSize out of the saved ESP slot", () => {
    createRopTemplateCommand().execute({ api: "VirtualProtect", style: "pushad" });
    const text = logs.join("\n");
    expect(text).toContain("[ESP+12] = saved ESP  <- lpAddress");
    expect(text).toContain("[ESP+16] = EBX        <- dwSize = 0x201");
  });

  test("the WriteProcessMemory PUSHAD map skips the saved ESP slot", () => {
    createRopTemplateCommand().execute({ api: "WriteProcessMemory", style: "pushad" });
    const text = logs.join("\n");
    expect(text).toContain("[ESP+0]  = EDI        <- add esp, 0xC ; ret");
    expect(text).toContain("[ESP+12] = saved ESP  <- skipped");
    expect(text).toContain("[ESP+16] = EBX        <- WriteProcessMemory address");
  });

  test.each(["LoadLibraryA", "GetProcAddress"])("%s prints its PUSHAD layout in either style", (name) => {
    for (const style of ["skeleton", "pushad"]) {
      logs.length = 0;
      expect(createRopTemplateCommand().execute({ api: name, style }).success).toBe(true);
      expect(logs.join("\n")).toContain(`=== ${name} — ROP Chain Skeleton ===`);
    }
  });

  test("positional invocation passes the style", () => {
    expect(normalizeInvocation("rop_template", ["VirtualAlloc", "libbkup", "pushad"])).toEqual({ api: "VirtualAlloc", module: "libbkup", style: "pushad" });
    const api = loadApi();
    expect(api.rop_template("VirtualAlloc", "libbkup", "pushad").success).toBe(true);
    expect(logs.join("\n")).toContain("=== VirtualAlloc DEP Bypass — PUSHAD Method ===");
  });

  test.each([
    [["VirtualQuery", "libbkup"], "api"],
    [["VirtualAlloc", "libbkup", "rop"], "style"],
  ])("rejects %j through the registry", (args, field) => {
    const api = loadApi();
    expect(api.rop_template(...args).success).toBe(false);
    expect(api.last_result().errors.join(" ")).toContain(`${field}: Expected one of`);
    expect(logs.join("\n")).not.toContain("DEP Bypass");
  });

  test("execute rejects an unknown style without printing a template", () => {
    const result = createRopTemplateCommand().execute({ api: "VirtualAlloc", style: "rop" });
    expect(result.success).toBe(false);
    expect(result.errors[0]).toContain("Styles: skeleton, pushad");
    expect(logs.join("\n")).not.toContain("DEP Bypass");
  });
});
