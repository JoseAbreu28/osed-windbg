import { beforeEach, describe, expect, test } from "vitest";
import { stripDml } from "../src/core/output";
import { initializeScript } from "../src/index";

type Result = { success: boolean; errors: string[]; findings: Array<Record<string, unknown>> };
type Api = { dep_plan: (...args: unknown[]) => unknown; last_result: () => Result };

const BASE = BigInt(0x11110000);
const logs: string[] = [];

function writeUint16LE(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}

function writeUint32LE(bytes: Uint8Array, offset: number, value: number): void {
  for (let i = 0; i < 4; i += 1) bytes[offset + i] = (value >>> (i * 8)) & 0xff;
}

// One executable .text section; each gadget sits at an address with no 00, 0A or 0D byte.
const GADGETS: Array<[number, number[]]> = [
  [0x1111, [0x54, 0x5e, 0xc3]], // push esp ; pop esi ; ret
  [0x1121, [0x8b, 0x00, 0xc3]], // mov eax, [eax] ; ret
  [0x1131, [0x89, 0x06, 0xc3]], // mov [esi], eax ; ret
  [0x1141, [0x46, 0xc3]], // inc esi ; ret
  [0x1151, [0x01, 0xce, 0xc3]], // add esi, ecx ; ret
  [0x1161, [0xf7, 0xd8, 0xc3]], // neg eax ; ret
  [0x1171, [0x94, 0xc3]], // xchg eax, esp ; ret
  [0x1181, [0x89, 0xc6, 0xc3]], // mov esi, eax ; ret
  [0x1211, [0x5f, 0xc3]], // pop edi ; ret
  [0x1221, [0x5e, 0xc3]], // pop esi ; ret
  [0x1231, [0x5d, 0xc3]], // pop ebp ; ret
  [0x1241, [0x5b, 0xc3]], // pop ebx ; ret
  [0x1251, [0x5a, 0xc3]], // pop edx ; ret
  [0x1261, [0x59, 0xc3]], // pop ecx ; ret
  [0x1271, [0x58, 0xc3]], // pop eax ; ret
  [0x1281, [0x60, 0xc3]], // pushad ; ret
  [0x1291, [0xff, 0xe4]], // jmp esp
  [0x1311, [0x83, 0xc4, 0x10, 0xc3]], // add esp, 0x10 ; ret
  [0x1321, [0x83, 0xf0, 0xff, 0x8b, 0xe5, 0x5d, 0xc3]], // xor eax, 0xffffffff ; mov esp, ebp ; pop ebp ; ret
];

function installHost(): void {
  const image = new Uint8Array(0x5000);
  const peOffset = 0x80;
  const sectionTable = peOffset + 0x18 + 0xe0;
  writeUint16LE(image, 0x0, 0x5a4d);
  writeUint32LE(image, 0x3c, peOffset);
  writeUint32LE(image, peOffset, 0x4550);
  writeUint16LE(image, peOffset + 0x6, 1);
  writeUint16LE(image, peOffset + 0x14, 0xe0);
  image.set(Array.from(".text").map((char) => char.charCodeAt(0)), sectionTable);
  writeUint32LE(image, sectionTable + 0x8, 0x2000);
  writeUint32LE(image, sectionTable + 0xc, 0x1000);
  writeUint32LE(image, sectionTable + 0x24, 0x60000020);
  for (const [offset, bytes] of GADGETS) image.set(bytes, offset);

  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    currentProcess: {
      Is64Bit: false,
      Modules: [{ Name: "libbkup.dll", Path: "C:\\labs\\libbkup.dll", BaseAddress: BASE, EndAddress: BASE + BigInt(image.length), Size: image.length }],
    },
    memory: {
      readMemoryValues(address: bigint | number, length: number) {
        const offset = Number(BigInt(address) - BASE);
        if (offset < 0 || offset + length > image.length) throw new Error("out of range");
        return Array.from(image.slice(offset, offset + length));
      },
    },
  };
}

function loadApi(): Api {
  installHost();
  initializeScript();
  logs.length = 0;
  return (globalThis as unknown as { osed: Api }).osed;
}

const text = (): string => stripDml(logs.join(""));
const SECTIONS = [1, 2, 3, 4, 5, 6, 7].map((n) => `=== [${n}/7]`);

describe("dep_plan", () => {
  let api: Api;
  beforeEach(() => {
    api = loadApi();
  });

  test.each(["VirtualAlloc", "VirtualProtect", "WriteProcessMemory"])("%s prints the seven sections in order in both styles", (name) => {
    for (const style of ["skeleton", "pushad"]) {
      logs.length = 0;
      api.dep_plan(name, "libbkup", "00 0A 0D", style);
      expect(api.last_result().success, `${name} ${style}`).toBe(true);
      const output = text();
      const positions = SECTIONS.map((header) => output.indexOf(header));
      expect(positions.every((position) => position >= 0), `${name} ${style}: ${positions}`).toBe(true);
      expect([...positions].sort((a, b) => a - b)).toEqual(positions);
      expect(output).toContain(`=== [2/7] IAT slot of ${name} ===`);
      expect(output).toContain("not a finished chain");
    }
  });

  test("skeleton style ranks the gadgets per job and fills the draft with them", () => {
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    const output = text();
    expect(output).toContain("=== [4/7] Best 3 candidates per job (skeleton style) ===");
    expect(output).toMatch(/capture ESP:\n\s+0x11111111  push esp ; pop esi ; ret\s+writes esi, esp \+0x4\n  copy/);
    expect(output).toMatch(/copy a register:\n\s+0x11111181  mov esi, eax ; ret\s+writes esi, esp \+0x4\n  add/);
    expect(output).toMatch(/write a field:\n\s+0x11111131  mov \[esi\], eax ; ret/);
    expect(output).toContain("rop += p32(0x11111111)    # capture ESP: push esp ; pop esi ; ret");
    expect(output).toContain("rop += p32(0x11111171)    # pivot ESP onto field 1: xchg eax, esp ; ret");
    expect(output).toContain("DIST_FIELD1 = ???");
    expect(output).toContain("#   bp 0x11111111 ; g ; r esp");
    expect(output).toContain("=== VirtualAlloc Python Call-Frame Skeleton ===");
    expect(api.last_result().findings[0]).toMatchObject({ api: "VirtualAlloc", module: "libbkup", style: "skeleton" });
  });

  test("no job but the pivot takes a gadget whose destination is esp", () => {
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    const output = text();
    const job = (title: string): string => output.slice(output.indexOf(`  ${title}:`)).split(/\n  (?=\S)/)[0];
    expect(job("add or subtract")).toContain("add esi, ecx ; ret");
    expect(job("add or subtract")).not.toContain("add esp");
    expect(job("copy a register")).not.toContain("mov esp, ebp");
    expect(job("pivot ESP onto the frame")).toContain("xchg eax, esp ; ret");
    expect(output).toContain("rop += p32(0x11111151)    # add the distance: add esi, ecx ; ret");
    expect(output).not.toContain("# add the distance: add esp");
  });

  test("pushad style lists a pop for each register, pushad and jmp esp, then the register map", () => {
    api.dep_plan("VirtualProtect", "libbkup", "00 0A 0D", "pushad");
    const output = text();
    for (const register of ["edi", "esi", "ebp", "ebx", "edx", "ecx", "eax"]) expect(output).toMatch(new RegExp(`pop ${register}:\\n\\s+0x1111`));
    expect(output).toMatch(/pushad ; ret:\n\s+0x11111281/);
    expect(output).toContain("jmp esp: 0x11111291");
    expect(output).toContain("=== [6/7] PUSHAD register map for VirtualProtect ===");
    expect(output).toContain("[ESP+16] = EBX        <- dwSize = 0x201");
  });

  test("warns only about base bytes that every address in the module shares", () => {
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    expect(text()).toContain("libbkup.dll spans 0x11110000 to 0x11114FFF: no ASLR, and its fixed high bytes are clean.");
    logs.length = 0;
    api.dep_plan("VirtualAlloc", "libbkup", "11 0A 0D");
    expect(text()).toContain("Every address in libbkup.dll (0x11110000 to 0x11114FFF) holds the bad byte(s) 11, so no gadget from it is usable.");
  });

  test.each([
    [["VirtualAlloc", "libbkup", "00 09 0A 0B 0C 0D 20"], '=== dx @$osed().dep_plan("VirtualAlloc", "libbkup", "00 09 0A 0B 0C 0D 20") ==='],
    [["VirtualProtect", "libbkup", "00 0A 0D", "pushad"], '=== dx @$osed().dep_plan("VirtualProtect", "libbkup", "00 0A 0D", "pushad") ==='],
  ])("the first line is the call %j as typed", (args, header) => {
    api.dep_plan(...args);
    const output = text();
    expect(output.split("\n").find((line) => line !== "")).toBe(header);
    expect(output.indexOf(header)).toBeLessThan(output.indexOf("=== [1/7]"));
  });

  test.each([
    ["VirtualAlloc", "skeleton", [
      '[1/7] modules("libbkup")',
      '[2/7] sc.iat_find("VirtualAlloc")',
      '[3/7] rop.scan_live("libbkup", "00 0A 0D")',
      '[5/7] rop.construct("eax", 0x1, "00 0A 0D")',
      '[5/7] rop.construct("eax", 0x1000, "00 0A 0D")',
      '[5/7] rop.construct("eax", 0x40, "00 0A 0D")',
      '[6/7] dep_function("VirtualAlloc")',
    ]],
    ["WriteProcessMemory", "pushad", [
      '[1/7] modules("libbkup")',
      '[2/7] sc.iat_find("WriteProcessMemory")',
      '[3/7] rop.scan_live("libbkup", "00 0A 0D")',
      '[4/7] find_bytes("libbkup", "FF E4", 20)',
      '[4/7] find_bytes("libbkup", "FF D4", 20)',
      '[5/7] rop.construct("eax", 0xFFFFFFFF, "00 0A 0D")',
      '[5/7] rop.construct("eax", 0x210, "00 0A 0D")',
      '[5/7] code_caves("libbkup", 0x4, 25, "00 0A 0D", "STAGING")',
      '[5/7] code_caves("libbkup", 0x210, 25, "00 0A 0D", "EXEC")',
    ]],
  ])("%s %s prints each sub-command in its section before its output", (name, style, expected) => {
    api.dep_plan(name, "libbkup", "00 0A 0D", style);
    let section = "";
    const echoed: string[] = [];
    for (const line of text().split("\n")) {
      section = /^=== (\[\d\/7\])/.exec(line)?.[1] ?? section;
      if (line.startsWith("dx @$osed().")) echoed.push(`${section} ${line.slice("dx @$osed().".length)}`);
    }
    expect(echoed).toEqual(expected);
  });

  test("pasting an echoed line prints the same output dep_plan printed under it", () => {
    api.dep_plan("WriteProcessMemory", "libbkup", "00 0A 0D", "pushad");
    const report = text();
    const calls = report.split("\n").filter((line) => line.startsWith("dx @$osed().") && !line.includes("code_caves("));
    expect(calls.length).toBeGreaterThan(5);
    const osed = (globalThis as unknown as { osed: unknown }).osed;
    for (const call of calls) {
      logs.length = 0;
      new Function("osed", `return osed.${call.slice("dx @$osed().".length)};`)(osed);
      expect(report, call).toContain(`${call}\n${text()}`);
    }
  });

  test.each([
    [["VirtualQuery", "libbkup", "00"], "api must be one of VirtualAlloc, VirtualProtect, WriteProcessMemory"],
    [["VirtualAlloc", "nosuchmod", "00"], 'Module "nosuchmod" is not loaded'],
    [["VirtualAlloc", "libbkup", "00", "rop"], "style must be one of skeleton, pushad"],
    [["VirtualAlloc", "libbkup", "zz"], "badchars must be hex bytes"],
  ])("rejects %j before printing any section", (args, message) => {
    api.dep_plan(...args);
    expect(api.last_result().success).toBe(false);
    expect(api.last_result().errors[0]).toContain(message);
    expect(text()).not.toContain("[1/7]");
  });
});
