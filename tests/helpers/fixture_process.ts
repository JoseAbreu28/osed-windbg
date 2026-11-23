import { stripDml, unwrap } from "../../src/core/output";
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

/** The thread stopped at the crash: its EIP and ESP, and the stack bytes mapped at `stack.base`. `seh`
 * makes the first SEH record the one at `record`, and stands in for the dispatcher: `g` with a breakpoint
 * on the address in the record's handler field stops there with ESP at `handlerEsp`, and anything else
 * stops on the faulting instruction again. */
export type Crash = { eip: number; esp: number; stack: { base: number; bytes: Uint8Array }; seh?: { teb: number; record: number; handlerEsp: number } };

/** `policy`: the NXSupportPolicy byte at 0x7FFE02D5. `registry`: what reg query prints for the program. */
export function load(modules: Module[], options: { policy?: number; registry?: string; crash?: Crash } = {}): Api {
  const mapped = modules.map((module) => ({ ...module, image: peImage(module) }));
  const kuser = new Uint8Array(0x1000);
  if (options.policy !== undefined) kuser[0x2d5] = options.policy;
  const crash = options.crash;
  const teb = new Uint8Array(0x1000);
  if (crash?.seh) {
    u32(teb, 0, crash.seh.record);
    u32(teb, 0x18, crash.seh.teb);
  }
  const regions = [...mapped.map((entry) => ({ base: entry.base, image: entry.image })), ...(options.policy !== undefined ? [{ base: 0x7ffe0000, image: kuser }] : []),
    ...(crash ? [{ base: crash.stack.base, image: crash.stack.bytes }] : []), ...(crash?.seh ? [{ base: crash.seh.teb, image: teb }] : [])];
  const user: Record<string, bigint> = crash ? { eip: BigInt(crash.eip), esp: BigInt(crash.esp) } : {};
  const at = (address: number): { image: Uint8Array; offset: number } | undefined => {
    for (const region of regions) {
      const offset = address - region.base;
      if (offset >= 0 && offset + 4 <= region.image.length) return { image: region.image, offset };
    }
    return undefined;
  };
  const breakpoints: Record<string, number> = {};
  // Only the commands an SEH measurement sends; everything else prints nothing, as before.
  const debuggerCommand = (command: string): string[] => {
    const seh = crash?.seh;
    if (!seh) return [];
    let match: RegExpExecArray | null;
    if (command === "? @$teb") return [`Evaluate expression: ${seh.teb} = ${seh.teb.toString(16).padStart(8, "0")}`];
    if ((match = /^ed (0x[0-9a-f]+) (0x[0-9a-f]+)$/i.exec(command))) {
      const place = at(Number(match[1]));
      if (place) u32(place.image, place.offset, Number(match[2]));
    } else if ((match = /^bp(\d+) (0x[0-9a-f]+)$/i.exec(command))) breakpoints[match[1]] = Number(match[2]);
    else if ((match = /^bc (\d+)$/.exec(command))) delete breakpoints[match[1]];
    else if ((match = /^r (\w+)=(0x[0-9a-f]+)$/i.exec(command))) user[match[1]] = BigInt(match[2]);
    else if (command === "g") {
      const place = at(seh.record + 4);
      const handler = place ? (place.image[place.offset] | (place.image[place.offset + 1] << 8) | (place.image[place.offset + 2] << 16) | (place.image[place.offset + 3] << 24)) >>> 0 : 0;
      const hit = Object.keys(breakpoints).some((id) => breakpoints[id] === handler) && user.eip === BigInt(crash!.eip);
      user.eip = BigInt(hit ? handler : crash!.eip);
      user.esp = BigInt(hit ? seh.handlerEsp : crash!.esp);
    }
    return [];
  };
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    namespace: { Debugger: { Utility: { Control: { ExecuteCommand: (command: string) => {
      commands.push(command);
      return command.startsWith(".shell") && options.registry !== undefined ? options.registry.split("\n") : debuggerCommand(command);
    } } } } },
    currentThread: crash ? { Registers: { User: user } } : undefined,
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

/** The transcript with wrapped lines rejoined, for a check on what a section says rather than on where
 * output.ts broke it. The screenshot rule reads `text()`, because the break points are what it measures. */
export const prose = (): string => unwrap(text());

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

/** The harness's crash input on a stack: OFFSET bytes of A, BBBB as the saved EIP, then C. The crashing
 * function's `ret gap` leaves ESP `gap` bytes past the dword after EIP. */
export function crashOf(offset: number, gap: number): Crash {
  const base = 0x0019f000;
  const bytes = new Uint8Array(0x1000).fill(0x43);
  const eipAt = 0x400;
  bytes.fill(0x41, eipAt - offset, eipAt);
  bytes.set([0x42, 0x42, 0x42, 0x42], eipAt);
  return { eip: 0x42424242, esp: base + eipAt + 4 + gap, stack: { base, bytes } };
}

// T07's shape, an SEH overwrite under DEP: see the describe that uses it in dep_seh.test.ts.
export const sehShape = (() => {
  const OFFSET = 0x800;
  const STACK = 0x0019d000;
  const BUFFER = STACK + 0x1400;
  const RECORD = BUFFER + OFFSET;
  const HANDLER_ESP = BUFFER - 0x500;
  const FAULT_ESP = BUFFER - 0xc;
  const TEB = 0x003a5000;
  const TAIL = 0x200;

  // add esp, 0x600 ; ret lands inside the buffer; 0x100 lands in the dispatcher's own frames below the
  // faulting ESP, and 0x2000 above the record. Only the first can take the chain.
  const PIVOTS: Array<[number, number[]]> = [
    [0x1401, [0x81, 0xc4, 0x00, 0x06, 0x00, 0x00, 0xc3]],
    [0x1411, [0x81, 0xc4, 0x00, 0x01, 0x00, 0x00, 0xc3]],
    [0x1421, [0x81, 0xc4, 0x00, 0x20, 0x00, 0x00, 0xc3]],
  ];
  // The exchanges the pushad constants need to reach their registers, as in "dep_plan builds what it sends".
  const XCHG: Array<[number, number[]]> = [[0x1391, [0x89, 0xf8, 0xc3]], [0x13a1, [0x93, 0xc3]], [0x13b1, [0x92, 0xc3]], [0x13c1, [0x91, 0xc3]], [0x13d1, [0x29, 0xc8, 0xc3]]];
  const MODULES: Module[] = [
    { name: "vuln.exe", base: 0x00400000, nx: true },
    { name: "libbkup.dll", base: 0x11110000, code: [...GADGETS, ...XCHG, ...PIVOTS], imports: [{ dll: "KERNEL32.dll", symbol: "VirtualAlloc", target: 0x11111121 }] },
  ];

  /** The harness's crash input for an SEH target: OFFSET bytes of A, BBBB over nSEH, then C over the
   * handler and past it, faulting in the program while the record still holds what the overflow wrote. */
  function sehCrash(): Crash {
    const bytes = new Uint8Array(0x3000);
    bytes.fill(0x41, BUFFER - STACK, RECORD - STACK);
    bytes.set([0x42, 0x42, 0x42, 0x42], RECORD - STACK);
    bytes.fill(0x43, RECORD - STACK + 4, RECORD - STACK + 8 + TAIL);
    return { eip: 0x00401010, esp: FAULT_ESP, stack: { base: STACK, bytes }, seh: { teb: TEB, record: RECORD, handlerEsp: HANDLER_ESP } };
  }
  /** The same modules with some pivot RVAs taken out, for the crash that looks like an SEH delivery and
   * cannot be one. 0x1401 is the only pivot whose ret lands inside the buffer. */
  const modulesWithout = (...rvas: number[]): Module[] => MODULES.map((module) => module.name === "vuln.exe" ? module
    : { ...module, code: (module.code ?? []).filter(([rva]) => rvas.indexOf(rva) < 0) });
  return { OFFSET, STACK, BUFFER, RECORD, HANDLER_ESP, FAULT_ESP, TEB, TAIL, MODULES, sehCrash, modulesWithout };
})();

/** The SEH shape's dep_plan transcript. The delivery is not a style, so every style runs on the same
 * crash: what changes is only where in the buffer the chain starts and what the handler has to clear. */
export function sehRun(style = "pushad", modules: Module[] = sehShape.MODULES): string {
  load(modules, { policy: 2, registry: "", crash: sehShape.sehCrash() });
  (globalThis as unknown as { osed: Api }).osed.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D", style);
  return text();
}
