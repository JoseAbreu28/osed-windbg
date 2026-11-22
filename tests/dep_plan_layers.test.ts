import { describe, expect, test } from "vitest";
import { stripDml } from "../src/core/output";
import { initializeScript } from "../src/index";
import { ReachIndex } from "../src/rop/reach";

// dep_plan from evidence alone: which modules can give gadgets, where the API's address comes from, which
// style the corpus supports, and whether a chain is needed at all. Each process here is built from real PE
// structures (headers, an import table, an export table) so the production lookups run unchanged.

type Result = { success: boolean; errors: string[]; findings: Array<Record<string, unknown>> };
type Api = {
  dep_plan: (...args: unknown[]) => unknown;
  palette: (...args: unknown[]) => unknown;
  dep_candidates: (...args: unknown[]) => unknown;
  rop: { scan_live: (...args: unknown[]) => unknown };
  last_result: () => Result;
};

type Module = {
  name: string;
  base: number;
  aslr?: boolean;
  nx?: boolean;
  /** RVA in .text (0x1000 to 0x2FFF) and the bytes there. */
  code?: Array<[number, number[]]>;
  /** One import descriptor per DLL; each slot holds `target`, the address the loader resolved. */
  imports?: Array<{ dll: string; symbol: string; target: number }>;
  exports?: Array<{ name: string; rva: number }>;
};

const ascii = (text: string): number[] => Array.from(text).map((char) => char.charCodeAt(0));
const u16 = (image: Uint8Array, at: number, value: number): void => { image[at] = value & 0xff; image[at + 1] = (value >>> 8) & 0xff; };
const u32 = (image: Uint8Array, at: number, value: number): void => { for (let i = 0; i < 4; i += 1) image[at + i] = (value >>> (i * 8)) & 0xff; };

function peImage(module: Module): Uint8Array {
  const image = new Uint8Array(0x5000);
  const pe = 0x80;
  const optional = pe + 0x18;
  u16(image, 0, 0x5a4d);
  u32(image, 0x3c, pe);
  u32(image, pe, 0x4550);
  u16(image, pe + 6, 1);
  u16(image, pe + 0x14, 0xe0);
  u16(image, optional, 0x10b);
  u32(image, optional + 0x1c, module.base);
  u16(image, pe + 0x5e, (module.aslr ? 0x40 : 0) | (module.nx ? 0x100 : 0));
  const section = optional + 0xe0;
  image.set(ascii(".text"), section);
  u32(image, section + 0x8, 0x2000);
  u32(image, section + 0xc, 0x1000);
  u32(image, section + 0x24, 0x60000020);
  for (const [rva, bytes] of module.code ?? []) image.set(bytes, rva);
  const dlls = [...new Set((module.imports ?? []).map((entry) => entry.dll))];
  if (dlls.length > 0) {
    u32(image, optional + 0x68, 0x3000);
    u32(image, optional + 0x6c, 0x14 * (dlls.length + 1));
    let name = 0x3400;
    dlls.forEach((dll, i) => {
      const [int, iat, dllName] = [0x3100 + i * 0x40, 0x3200 + i * 0x40, 0x3300 + i * 0x20];
      u32(image, 0x3000 + i * 0x14, int);
      u32(image, 0x3000 + i * 0x14 + 0xc, dllName);
      u32(image, 0x3000 + i * 0x14 + 0x10, iat);
      image.set(ascii(dll), dllName);
      (module.imports ?? []).filter((entry) => entry.dll === dll).forEach((entry, k) => {
        u32(image, int + k * 4, name);
        u32(image, iat + k * 4, entry.target);
        image.set(ascii(entry.symbol), name + 2);
        name += 0x20;
      });
    });
  }
  const exported = module.exports ?? [];
  if (exported.length > 0) {
    u32(image, optional + 0x60, 0x4000);
    u32(image, optional + 0x64, 0x28);
    u32(image, 0x4000 + 0x10, 1);
    u32(image, 0x4000 + 0x14, exported.length);
    u32(image, 0x4000 + 0x18, exported.length);
    u32(image, 0x4000 + 0x1c, 0x4100);
    u32(image, 0x4000 + 0x20, 0x4200);
    u32(image, 0x4000 + 0x24, 0x4300);
    exported.forEach((entry, i) => {
      u32(image, 0x4100 + i * 4, entry.rva);
      u32(image, 0x4200 + i * 4, 0x4400 + i * 0x20);
      u16(image, 0x4300 + i * 2, i);
      image.set(ascii(entry.name), 0x4400 + i * 0x20);
    });
  }
  return image;
}

const logs: string[] = [];
const commands: string[] = [];

/** `policy`: the NXSupportPolicy byte at 0x7FFE02D5. `registry`: what reg query prints for the program. */
function load(modules: Module[], options: { policy?: number; registry?: string } = {}): Api {
  const mapped = modules.map((module) => ({ ...module, image: peImage(module) }));
  const kuser = new Uint8Array(0x1000);
  if (options.policy !== undefined) kuser[0x2d5] = options.policy;
  const regions = [...mapped.map((entry) => ({ base: entry.base, image: entry.image })), ...(options.policy !== undefined ? [{ base: 0x7ffe0000, image: kuser }] : [])];
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    namespace: { Debugger: { Utility: { Control: { ExecuteCommand: (command: string) => {
      commands.push(command);
      return command.startsWith(".shell") && options.registry !== undefined ? options.registry.split("\n") : [];
    } } } } },
    currentProcess: {
      Is64Bit: false,
      Modules: mapped.map((entry) => ({ Name: entry.name, Path: `C:\\target\\${entry.name}`, BaseAddress: BigInt(entry.base), EndAddress: BigInt(entry.base + entry.image.length), Size: entry.image.length })),
    },
    memory: {
      readMemoryValues(address: bigint | number, length: number) {
        for (const region of regions) {
          const offset = Number(BigInt(address)) - region.base;
          if (offset >= 0 && offset + length <= region.image.length) return Array.from(region.image.slice(offset, offset + length));
        }
        throw new Error("out of range");
      },
    },
  };
  initializeScript();
  logs.length = 0;
  commands.length = 0;
  return (globalThis as unknown as { osed: Api }).osed;
}

const text = (): string => stripDml(logs.join(""));
const section = (output: string, header: string): string => {
  const start = output.indexOf(header);
  const rest = output.slice(start + header.length);
  const next = rest.search(/\n=== (\[\d\/7\]|STOP|Verdict)/);
  return output.slice(start, next < 0 ? undefined : start + header.length + next);
};

// What a module needs for either style, minus what each test takes away. The comment is the decoding.
const GADGETS: Array<[number, number[]]> = [
  [0x1111, [0x54, 0x5e, 0xc3]], // push esp ; pop esi ; ret
  [0x1121, [0x8b, 0x00, 0xc3]], // mov eax, [eax] ; ret
  [0x1141, [0x46, 0xc3]], // inc esi ; ret
  [0x1151, [0x01, 0xce, 0xc3]], // add esi, ecx ; ret
  [0x1161, [0xf7, 0xd8, 0x5d, 0xc3]], // neg eax ; pop ebp ; ret
  [0x1171, [0x94, 0xc3]], // xchg eax, esp ; ret
  [0x1211, [0x5f, 0xc3]], // pop edi ; ret
  [0x1221, [0x5e, 0xc3]], // pop esi ; ret
  [0x1231, [0x5d, 0xc3]], // pop ebp ; ret
  [0x1241, [0x5b, 0xc3]], // pop ebx ; ret
  [0x1251, [0x5a, 0xc3]], // pop edx ; ret
  [0x1261, [0x59, 0xc3]], // pop ecx ; ret
  [0x1271, [0x58, 0xc3]], // pop eax ; ret
  [0x1281, [0x60, 0xc3]], // pushad ; ret
  [0x1291, [0xff, 0xe4]], // jmp esp
  [0x1331, [0x89, 0xf7, 0xc3]], // mov edi, esi ; ret
  [0x1341, [0x89, 0x07, 0xc3]], // mov [edi], eax ; ret
  [0x1351, [0x47, 0xc3]], // inc edi ; ret
  [0x1361, [0x01, 0xc8, 0xc3]], // add eax, ecx ; ret
  [0x1181, [0x89, 0xc6, 0xc3]], // mov esi, eax ; ret
];
const without = (...rvas: number[]): Array<[number, number[]]> => GADGETS.filter(([rva]) => rvas.indexOf(rva) < 0);

describe("dep_plan, reproduced Sync Breeze shape", () => {
  // Not observed: Sync Breeze is not installed on the lab clone. The shape is his run's: four modules
  // without ASLR, three of them at a base whose top byte is 00, the gadget module importing nothing the
  // chain calls but a neighbour from kernel32, no ESP capture, a pushad gadget, and DEP forced on by
  // Exploit Protection while the executable says NX_COMPAT disabled.
  const BAD = "00 0A 0D 25 26 2B 3D";
  const K32 = 0x75310000;
  const kernel32: Module = { name: "KERNEL32.DLL", base: K32, aslr: true, nx: true, code: [[0x1501, [0xc3]]],
    exports: [{ name: "VirtualAlloc", rva: 0x1501 }, { name: "VirtualProtect", rva: 0x1600 }, { name: "WriteProcessMemory", rva: 0x1700 }, { name: "GetDriveTypeA", rva: 0x1800 },
      { name: "TerminateProcess", rva: 0x1900 }, { name: "SetUnhandledExceptionFilter", rva: 0x1a00 }] };
  // His run printed thousands of rows from slots like these: ODBC32.dll has ASLR, so each slot address moves
  // on every boot and no distance measured from it is usable without a leak.
  const odbc32: Module = { name: "ODBC32.dll", base: 0x72890000, aslr: true, nx: true, imports: [
    { dll: "KERNEL32.dll", symbol: "VirtualAlloc", target: K32 + 0x1501 },
    { dll: "KERNEL32.dll", symbol: "TerminateProcess", target: K32 + 0x1900 },
    { dll: "KERNEL32.dll", symbol: "SetUnhandledExceptionFilter", target: K32 + 0x1a00 },
  ] };
  const shape = (libspp: Partial<Module> = {}): Module[] => [
    { name: "syncbrs.exe", base: 0x00400000, code: GADGETS },
    { name: "libpal.dll", base: 0x00670000, code: GADGETS },
    { name: "libsync.dll", base: 0x00900000, code: GADGETS },
    { name: "libspp.dll", base: 0x10110000, code: without(0x1111), imports: [{ dll: "KERNEL32.dll", symbol: "GetDriveTypeA", target: K32 + 0x1800 }], ...libspp },
    kernel32,
  ];
  const FORCED = "HKEY_LOCAL_MACHINE\\...\\syncbrs.exe\n    MitigationOptions    REG_BINARY    010000000000000000000000";

  test("one call with only the bad chars reaches the route, the module and the style", () => {
    const api = load(shape(), { policy: 2, registry: FORCED });
    api.dep_plan(BAD);
    const output = text();
    // The echoed call names every choice this run made, so pasting it repeats the run.
    expect(output.split("\n").find((line) => line !== "")).toBe(`=== dx @$osed().dep_plan("VirtualAlloc", "libspp.dll", "${BAD}", "auto", 1) ===`);
    expect(output).toContain("=== DEP is on for syncbrs.exe ===");
    expect(output).toContain("Exploit Protection turns DEP on for syncbrs.exe (MitigationOptions in its Image File Execution Options key), whatever its NX_COMPAT flag says");
    expect(output).toContain("Gadgets come from every module that can give one: libspp.dll. Not usable: syncbrs.exe, every address holds the bad byte(s) 00; libpal.dll, every address holds the bad byte(s) 00; libsync.dll, every address holds the bad byte(s) 00; 1 with ASLR.");
    const slot = section(output, "=== [2/7]");
    expect(slot).toContain("No module with ASLR disabled imports VirtualAlloc itself, but libspp.dll imports kernel32!GetDriveTypeA, at slot 0x10113200.");
    expect(slot).toContain("VirtualAlloc = [0x10113200] - 0x000002FF, measured now with GetDriveTypeA at 0x75311800 and VirtualAlloc at 0x75311501");
    expect(slot).toContain("That distance holds for this build of kernel32 only. Any Windows update moves it");
    expect(slot).toContain("API_DELTA = 0xFFFFFD01");
    expect(output).toContain("=== [4/7] The gadget picked per job (pushad style: the skeleton style lacks capture ESP) ===");
    // The register loaders live in [5/7]: ESI gets the slot's pointer plus the distance. Which register
    // the distance is added in is the search's call, so what is asserted is the load, not one route: the
    // slot is read, API_DELTA goes on, and the value ends up in ESI.
    const loaders = section(output, "=== [5/7]");
    const esi = loaders.slice(loaders.indexOf("def load_virtualalloc"), loaders.indexOf("def load_return"));
    expect(esi).toContain("c.rop(MOV_EAX_MEM_EAX)");
    expect(esi).toContain("c.rop(POP_ECX, API_DELTA)");
    expect(esi).toMatch(/c\.rop\((MOV_ESI_EAX|ADD_ESI_ECX)\)/);
    expect(esi).not.toContain("hole(");
    expect(esi.slice(esi.lastIndexOf("c.rop"))).toMatch(/now \[IAT_SLOT\] \+ API_DELTA/);
    // Above the code, one line saying which gadgets were chosen for ESI and why that route.
    expect(loaders).toContain("What the chain does is below: one line per register, searched through libspp.dll rather than following one recipe.");
    expect(loaders).toMatch(/esi = VirtualAlloc \(\[IAT_SLOT\] \+ API_DELTA\): [A-Z_0-9 ->]*MOV_EAX_MEM_EAX[A-Z_0-9 ->]*\. \d gadgets: the value is the dword at IAT_SLOT, known only at run time/);
    expect(output).toContain("A VirtualAlloc chain from libspp.dll in the pushad style, the API reached from kernel32!GetDriveTypeA by a distance measured on this machine");
    expect(api.last_result().success).toBe(true);
  });

  // His run on Sync Breeze emitted `def load_virtualalloc(c):` with nothing in it but a hole, because the
  // only recipe was "build in EAX, then mov EAX into the target" and libspp has no mov into ESI. A
  // `push eax ; pop esi ; ret` was sitting in the same module: a move by another name.
  const NO_MOV_ESI = without(0x1111, 0x1181);
  const PUSH_POP_ESI: [number, number[]] = [0x1191, [0x50, 0x5e, 0xc3]];

  test("no mov into ESI, so the value goes through the stack instead of leaving the register a hole", () => {
    const api = load(shape({ code: [...NO_MOV_ESI, PUSH_POP_ESI] }), { policy: 2, registry: FORCED });
    api.dep_plan("VirtualAlloc", "libspp", BAD, "pushad");
    const output = text();
    const loaders = section(output, "=== [5/7]");
    const esi = loaders.slice(loaders.indexOf("def load_virtualalloc"), loaders.indexOf("def load_return"));
    expect(esi).not.toContain("hole(");
    expect(esi).not.toContain("no gadget moves eax into esi");
    expect(esi).toContain("c.rop(MOV_EAX_MEM_EAX)");
    expect(esi).toContain("c.rop(PUSH_EAX_POP_ESI)");
    expect(esi).toContain("c.rop(POP_ECX, API_DELTA)");
    // Every gadget the loader names is a real address from the scan, with its disassembly, in [4/7].
    const table = section(output, "=== [4/7]");
    expect(table).toContain("PUSH_EAX_POP_ESI = 0x10111191   # push eax ; pop esi ; ret");
    for (const name of esi.match(/c\.rop\(([A-Z_0-9]+)/g) ?? []) {
      expect(table, name).toContain(`${name.slice(6)} `);
    }
    expect(api.last_result().success).toBe(true);
  });

  test("nothing reaches ESI at all: the message names what was searched and the one gadget that would open it", () => {
    const api = load(shape({ code: NO_MOV_ESI }), { policy: 2, registry: FORCED });
    api.dep_plan("VirtualAlloc", "libspp", BAD, "pushad");
    const output = text();
    const loaders = section(output, "=== [5/7]");
    const esi = loaders.slice(loaders.indexOf("def load_virtualalloc"), loaders.indexOf("def load_return"));
    // Still a hole, because the module really cannot do it. What changes is that the hole says why.
    expect(esi).toContain("virtualalloc_value = hole(\"virtualalloc_value\")");
    expect(esi).toContain("esi = VirtualAlloc ([IAT_SLOT] + API_DELTA) cannot be reached.");
    expect(esi).toMatch(/searched: libspp\.dll gives \d+ distinct ways to write esi, with nothing to keep\. No combination of up to 8 of them reaches it\./);
    expect(esi).toContain("one gadget would unlock it: mov esi, dword [esi] ; ret");
    expect(esi).toContain("dx @$osed().palette(\"libspp.dll\", \"00 0A 0D 25 26 2B 3D\")");
    // And the same sentence, short, in the per-register route list and in the [7/7] payload.
    // Pinned whole, not by prefix: a prefix assertion would let the long form creep back in behind it.
    expect(loaders.split(/\r?\n/).map((line) => line.trim())).toContain(
      "[+]   esi = VirtualAlloc ([IAT_SLOT] + API_DELTA): no route among the 3 ways libspp.dll writes esi. "
      + "mov esi, dword [esi] ; ret would unlock it; load_virtualalloc below says what was searched.");
    expect(section(output, "=== [7/7]")).toContain("# esi = VirtualAlloc: no route, so load_virtualalloc below is a hole");
  });

  test("the pushad order is settled without searching the same register twice", () => {
    // The order is tried before any loader is written, and every loader then asks again. A search over a
    // real module costs tens of milliseconds on the debugger's engine, so asking twice is what turns a
    // pause into a wait. Measured at 1771 gadgets: 98 probes took 4816 ms unmemoised and 302 ms memoised.
    const reach = ReachIndex.prototype.reach;
    // One corpus per index: the message that names the unlocking gadget searches a corpus with that gadget
    // added, so those are different questions, not repeats. A repeat is the same question of one corpus.
    const corpora = new Map<ReachIndex, string[]>();
    ReachIndex.prototype.reach = function spy(this: ReachIndex, register, goal, options) {
      const asked = corpora.get(this) ?? [];
      asked.push(`${register}|${goal.mem?.at ?? ""}|${goal.k}|${goal.text}|${options.keep.slice().sort().join(",")}`);
      corpora.set(this, asked);
      return reach.call(this, register, goal, options);
    };
    try {
      const api = load(shape(), { policy: 2, registry: FORCED });
      api.dep_plan("VirtualAlloc", "libspp", BAD, "pushad");
      expect(api.last_result().success).toBe(true);
    } finally {
      ReachIndex.prototype.reach = reach;
    }
    const scanned = [...corpora.values()].sort((a, b) => b.length - a.length)[0];
    expect(scanned.length).toBeGreaterThan(6);
    expect(scanned.length, scanned.join(" | ")).toBe(new Set(scanned).size);
  });

  test("the distance is anchored only in a module without ASLR, and [2/7] ends on one pick", () => {
    // libsync.dll gives no gadget (its base holds 00) but has no ASLR, so its slot is a valid second anchor.
    const modules = shape();
    modules[2] = { ...modules[2], imports: [{ dll: "KERNEL32.dll", symbol: "TerminateProcess", target: K32 + 0x1900 }] };
    const api = load([...modules, odbc32], { policy: 2, registry: FORCED });
    api.dep_plan("VirtualAlloc", "libspp", BAD, "auto", 6);
    const slot = section(text(), "=== [2/7]");
    expect(slot).toContain("[+] No module with ASLR disabled imports VirtualAlloc itself, but libspp.dll imports kernel32!GetDriveTypeA, at slot 0x10113200.");
    expect(slot).toContain("[+] Chosen from 2 slots in modules without ASLR that reach VirtualAlloc by a distance: none is free of bad bytes, and this one is in libspp.dll, where the gadgets come from. The other one is in libsync.dll.");
    expect(slot).toContain("[+] ODBC32.dll imports VirtualAlloc itself, but has ASLR: its slot moves on every boot. No slot in a module with ASLR anchors the distance either.");
    expect(slot).toContain("[!] That distance holds for this build of kernel32 only.");
    // No slot of ODBC32.dll is offered, and no candidate table is printed.
    for (const offered of ["0x72893", "TerminateProcess", "derived-address", "Candidate for gadget feasibility", "rop.api_plan", "sc.iat_find"]) expect(slot).not.toContain(offered);
    expect(api.last_result().success).toBe(true);
  });

  test("a kernel32 export imported only by a module with ASLR is never offered as the anchor", () => {
    const api = load([...shape({ imports: [{ dll: "MSVCRT.dll", symbol: "memcpy", target: 0x10111121 }] }), odbc32], { policy: 2, registry: FORCED });
    api.dep_plan("VirtualAlloc", "libspp", BAD);
    const output = text();
    expect(output).toContain("[-] The API layer fails: no module with ASLR disabled imports VirtualAlloc (ODBC32.dll does, and it has ASLR), nor any other export of kernel32 or kernelbase to reach it from by a fixed distance. Its address needs a leak first.");
    expect(output).not.toContain("0x72893");
    expect(output).not.toContain("API_DELTA");
  });

  test("asked for the skeleton, it says the method is what fails and names the style that works", () => {
    const api = load(shape(), { policy: 2, registry: FORCED });
    api.dep_plan("VirtualAlloc", "libspp", BAD, "skeleton");
    const output = text();
    const picks = section(output, "=== [4/7]");
    expect(picks).toContain("  capture ESP: none in libspp.dll\n      absent from libspp.dll: every byte of libspp.dll searched for the 42 plain encodings of this job, no hit at all");
    expect(picks).toContain("capture ESP blocks the skeleton style, and the pushad style needs no such gadget: pushad pushes ESP itself.");
    expect(picks).toContain(`In libspp.dll the pushad style has a gadget for every job: dx @$osed().dep_candidates("libspp", "${BAD}", "pushad")`);
    expect(output).toContain(`No complete VirtualAlloc chain in the skeleton style: libspp.dll has no gadget for capture ESP, so [7/7] holds a hole for each. The pushad style has a gadget for every job: dx @$osed().dep_plan("VirtualAlloc", "libspp", "${BAD}", "pushad", 1)`);
    expect(api.last_result().success).toBe(false);
  });

  test("nothing fixed imports from kernel32: the API layer fails, in one line, with its reason", () => {
    const api = load(shape({ imports: [{ dll: "MSVCRT.dll", symbol: "memcpy", target: 0x10111121 }] }), { policy: 2, registry: FORCED });
    api.dep_plan(BAD);
    const output = text();
    const conclusion = "[-] The API layer fails: no module with ASLR disabled imports VirtualAlloc, VirtualProtect, WriteProcessMemory, nor any other export of kernel32 or kernelbase to reach it from by a fixed distance. Its address needs a leak first.";
    expect(output.split(conclusion).length - 1).toBe(2);
    expect(api.last_result().errors).toEqual([conclusion.slice(4)]);
  });

  test("no module can give a gadget: the module layer fails, and nothing is scanned", () => {
    const api = load(shape({ base: 0x00a10000 }), { policy: 2, registry: FORCED });
    api.dep_plan(BAD);
    const output = text();
    expect(output).toContain("[-] The module layer fails: no loaded module can give gadgets: syncbrs.exe (every address holds the bad byte(s) 00), libpal.dll (every address holds the bad byte(s) 00), libsync.dll (every address holds the bad byte(s) 00), libspp.dll (every address holds the bad byte(s) 00), and the rest have ASLR.");
    expect(output).not.toContain("rop.scan_live(");
  });
});

describe("dep_plan asks first whether a chain is needed", () => {
  const vuln = (nx: boolean): Module[] => [
    { name: "vuln.exe", base: 0x00400000, nx },
    { name: "libbkup.dll", base: 0x11110000, code: GADGETS, imports: [{ dll: "KERNEL32.dll", symbol: "VirtualAlloc", target: 0x11111121 }] },
  ];
  const ABSENT = "ERROR: The system was unable to find the specified registry key or value.";

  test("DEP off: the stack runs the shellcode, so it hands over jmp esp and skips the chain, visibly", () => {
    const api = load(vuln(false), { policy: 2, registry: ABSENT });
    api.dep_plan("00 0A 0D");
    const output = text();
    expect(output).toContain("=== DEP is OFF for vuln.exe: no chain needed ===");
    expect(output).toContain("[-] The stack executes: the system policy is OptIn, vuln.exe does not opt in (NX_COMPAT disabled) and no Exploit Protection setting turns DEP on for it.");
    expect(output).toContain('[-] Jump straight to your shellcode: payload = b"A" * OFFSET + p32(0x11111291) + b"\\x90" * 16 + shellcode');
    const anyway = 'dx @$osed().dep_plan("VirtualAlloc", "libbkup.dll", "00 0A 0D", "auto", 1, "", true)';
    expect(output).toContain(`To build the chain anyway, as an exercise: ${anyway}`);
    expect(output).not.toContain("=== [1/7]");
    // The registry was read through the debugger, for the program by name.
    expect(commands.some((command) => command.startsWith('.shell -ci "x" reg query') && command.includes("Image File Execution Options\\vuln.exe"))).toBe(true);

    logs.length = 0;
    new Function("osed", `return osed.${anyway.slice("dx @$osed().".length)};`)((globalThis as unknown as { osed: unknown }).osed);
    const built = text();
    for (const n of [1, 2, 3, 4, 5, 6, 7]) expect(built).toContain(`=== [${n}/7]`);
    expect(api.last_result().success).toBe(true);
  });

  test.each([
    [true, 2, ABSENT, "=== DEP is on for vuln.exe ===", "The system policy is OptIn and vuln.exe opts in (NX_COMPAT enabled)"],
    [false, 3, ABSENT, "=== DEP is on for vuln.exe ===", "The system policy is OptOut"],
    [false, 2, "", "=== DEP for vuln.exe: unknown ===", "its Exploit Protection setting could not be read"],
  ])("NX_COMPAT %s, policy %i: the verdict and its reason", (nx, policy, registry, header, why) => {
    const api = load(vuln(nx), { policy, registry });
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    const output = text();
    expect(output).toContain(header);
    expect(output).toContain(why);
    expect(output).toContain("=== [7/7]");
    expect(api.last_result().success).toBe(true);
  });
});

describe("dep_plan never reports an absence the scan did not settle", () => {
  const module = (code: Array<[number, number[]]>): Module[] => [
    { name: "libbkup.dll", base: 0x22220000, code, imports: [{ dll: "KERNEL32.dll", symbol: "VirtualAlloc", target: 0x22221121 }] },
  ];

  test("a gadget only at an address holding a bad byte is absent, and the count says why", () => {
    const api = load(module([...without(0x1111), [0x100a, [0x54, 0x5e, 0xc3]]]));
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D", "skeleton");
    expect(text()).toContain("      absent from libbkup.dll: every byte of libbkup.dll searched for the 42 plain encodings of this job, 1 hit(s), every one at an address holding a bad byte");
  });

  test("a gadget the scan never reached is found by searching the module, and used", () => {
    // 2048 copies of pop edx ; ret at addresses holding a bad byte: the pattern scan stops after 1500 of
    // them, and the one clean copy sits beyond. Before the search this job read "none in the corpus".
    const fill: number[] = [];
    for (let i = 0; i < 0x1000; i += 2) fill.push(0x5a, 0xc3);
    const bad = "00 0A 0D 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F";
    const api = load(module([...GADGETS, [0x1000, fill], [0x2051, [0x5a, 0xc3]]]));
    api.dep_plan("VirtualAlloc", "libbkup", bad, "pushad");
    const job = section(text(), "=== [4/7]");
    expect(job).toMatch(/pop edx[^\n]*:\n {2}> 0x22222051 {2}pop edx ; ret/);
    expect(job).toContain("      the scan had missed it: every byte of libbkup.dll searched for the 2 plain encodings of this job found it");
  });

  test("a complete scan he already ran is used, not thrown away and redone", () => {
    const api = load(module(GADGETS));
    api.rop.scan_live("libbkup", "00 0A 0D");
    logs.length = 0;
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    const output = text();
    expect(output).toContain("[+] Using the corpus already loaded: a complete live scan of libbkup.dll for these bad chars");
    expect(output).not.toContain("rop.scan_live(");
    // Other bad chars are another corpus, so that one is scanned.
    logs.length = 0;
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D 20");
    expect(text()).toContain('dx @$osed().rop.scan_live("libbkup", "00 0A 0D 20")');
  });
});

describe("palette", () => {
  // dec eax ; ret sits only at 0x1111100A, which holds the bad byte 0A. The three after it were offered by
  // the first run on the clone and are wrong: one returns into its own push, one pivots, one reads [ecx+0x1c].
  const module: Module[] = [{ name: "libbkup.dll", base: 0x11110000, code: [...GADGETS, [0x100a, [0x48, 0xc3]],
    [0x1401, [0x43, 0x6a, 0x5d, 0xc3]], // inc ebx ; push 0x5d ; ret
    [0x1411, [0x4a, 0x89, 0xdc, 0xc3]], // dec edx ; mov esp, ebx ; ret
    [0x1421, [0x8b, 0x41, 0x1c, 0xc3]], // mov eax, [ecx+0x1c] ; ret
  ] }];
  const SEPARATOR = "# ------------------ copy into your exploit ------------------";
  const blockOf = (output: string): string[] => output.slice(output.indexOf(SEPARATOR) + SEPARATOR.length).trim().split("\n");
  // The line for one name, with the padding before its = collapsed.
  const entry = (block: string[], name: string): string | undefined => block.find((line) => line.startsWith(`${name} `))?.replace(/ += /, " = ");

  test("one line per shape, valid Python, each name once, None only where the module has none", () => {
    const api = load(module);
    api.palette("libbkup", "00 0A 0D");
    const output = text();
    const block = blockOf(output);
    const names: string[] = [];
    for (const line of block) {
      if (line === "" || line.startsWith("# ")) continue;
      const match = /^(GADGET_[A-Z0-9_]+) += (0x[0-9A-F]{8}|None)( +# .*)?$/.exec(line);
      expect(match, line).not.toBeNull();
      names.push(match![1]);
    }
    expect(new Set(names).size).toBe(names.length);
    expect(names.length).toBeGreaterThan(250);
    expect(entry(block, "GADGET_POP_EAX")).toBe("GADGET_POP_EAX = 0x11111271   # pop eax ; ret");
    expect(entry(block, "GADGET_NEG_EAX")).toBe("GADGET_NEG_EAX = 0x11111161   # neg eax ; pop ebp ; ret   costs (1, 0): 1 extra pop, writes ebp");
    expect(entry(block, "GADGET_MOV_ESP2ESI")).toBe("GADGET_MOV_ESP2ESI = 0x11111111   # push esp ; pop esi ; ret");
    expect(entry(block, "GADGET_XCHG_EAX2ESP")).toBe("GADGET_XCHG_EAX2ESP = 0x11111171   # xchg eax, esp ; ret");
    expect(entry(block, "GADGET_WRITE_EAX2EDI")).toMatch(/^GADGET_WRITE_EAX2EDI = 0x11111341   # mov .*\[edi\], eax ; ret$/);
    expect(entry(block, "GADGET_DEC_EAX")).toMatch(/^GADGET_DEC_EAX = None +# 1 only at an address holding a bad byte$/);
    expect(entry(block, "GADGET_DEC_ECX")).toBe("GADGET_DEC_ECX = None");
    expect(entry(block, "GADGET_INC_EBX")).toBe("GADGET_INC_EBX = None");
    expect(entry(block, "GADGET_DEC_EDX")).toBe("GADGET_DEC_EDX = None");
    expect(entry(block, "GADGET_READ_ECX2EAX")).toMatch(/^GADGET_READ_ECX2EAX = 0x11111421   # mov eax, .*\[ecx\+0x1c\] ; ret   costs \(0, 0\): reads \[ecx\+0x1c\], not \[ecx\]$/);
    expect(output).toMatch(/\n {2}NEG +1 of 7 +NEG_EAX\r?\n/);
  });

  test("a shape only the byte search finds is not None", () => {
    // pop edx ; ret at 0x22222051, beyond 2048 copies at addresses holding a bad byte: the scan stops first.
    const fill: number[] = [];
    for (let i = 0; i < 0x1000; i += 2) fill.push(0x5a, 0xc3);
    const bad = "00 0A 0D 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F";
    const api = load([{ name: "libbkup.dll", base: 0x22220000, code: [[0x1000, fill], [0x2051, [0x5a, 0xc3]]] }]);
    api.palette("libbkup", bad);
    expect(entry(blockOf(text()), "GADGET_POP_EDX")).toBe("GADGET_POP_EDX = 0x22222051   # pop edx ; ret");
  });
});
