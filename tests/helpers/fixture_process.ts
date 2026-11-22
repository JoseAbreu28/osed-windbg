import { stripDml } from "../../src/core/output";
import { initializeScript } from "../../src/index";

// A debugger process built from real PE structures (headers, an import table, an export table), so the
// production lookups run unchanged. Every line the extension prints lands in `logs`.

export type Result = { success: boolean; errors: string[]; findings: Array<Record<string, unknown>> };
export type Api = {
  dep_plan: (...args: unknown[]) => unknown;
  palette: (...args: unknown[]) => unknown;
  dep_candidates: (...args: unknown[]) => unknown;
  rop: { scan_live: (...args: unknown[]) => unknown };
  last_result: () => Result;
};

export type Module = {
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

export const logs: string[] = [];
export const commands: string[] = [];

/** `policy`: the NXSupportPolicy byte at 0x7FFE02D5. `registry`: what reg query prints for the program. */
export function load(modules: Module[], options: { policy?: number; registry?: string } = {}): Api {
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

export const text = (): string => stripDml(logs.join(""));

// What a module needs for either style, minus what each test takes away. The comment is the decoding.
export const GADGETS: Array<[number, number[]]> = [
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
export const without = (...rvas: number[]): Array<[number, number[]]> => GADGETS.filter(([rva]) => rvas.indexOf(rva) < 0);

// The Sync Breeze shape, reproduced: see the describe that uses it in dep_plan_layers.test.ts.
export const syncBreeze = (() => {
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
  return { BAD, FORCED, K32, kernel32, odbc32, shape };
})();
