// A local reproduction of a dep_plan run against a real lab module, with no VM.
// The real PE is mapped the way the loader would map it (headers, then each section at its
// VirtualAddress) and handed to the same host shim the fixture tests use, so the production
// scan, the IAT walk and code_caves all run against the bytes the clone would have shown them.
//
//   node replay.cjs <module.pe> [more.pe ...] --bad "00 0a" [--api X] [--style auto] [--section N]
//
// What it cannot reproduce: the IAT slots of an on-disk image hold their unbound values, so a
// route that needs the dereferenced API address (the kernel32-neighbour-plus-distance route)
// reads nonsense. A direct import is faithful, because only the slot address is used.
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { stripDml } from "../../src/core/output";
import { initializeScript } from "../../src/index";

const u16 = (b: Uint8Array, at: number): number => b[at] | (b[at + 1] << 8);
const u32 = (b: Uint8Array, at: number): number => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;

type Region = { start: number; size: number; protect: number };
type Mapped = { name: string; base: number; image: Uint8Array; regions: Region[] };

// The page protection the loader gives a section, from its characteristics. code_caves asks !vprot
// before it will call a cave writable or executable, so without these the lever finds no cave and a
// route the live run took through a writable dword would look absent here.
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const IMAGE_SCN_MEM_READ = 0x40000000;
const IMAGE_SCN_MEM_WRITE = 0x80000000;
const protectOf = (characteristics: number): number => {
  const x = (characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0;
  const w = (characteristics & IMAGE_SCN_MEM_WRITE) !== 0;
  const r = (characteristics & IMAGE_SCN_MEM_READ) !== 0;
  if (x && w) return 0x40;
  if (x && r) return 0x20;
  if (x) return 0x10;
  if (w) return 0x04;
  if (r) return 0x02;
  return 0x01;
};

function mapPe(path: string): Mapped {
  const file = new Uint8Array(readFileSync(path));
  const pe = u32(file, 0x3c);
  const optional = pe + 0x18;
  const magic = u16(file, optional);
  if (magic !== 0x10b) throw new Error(`${path} is not PE32 (magic ${magic.toString(16)})`);
  const base = u32(file, optional + 0x1c);
  const size = u32(file, optional + 0x38);
  const headers = u32(file, optional + 0x3c);
  const sections = u16(file, pe + 6);
  const image = new Uint8Array(size);
  const regions: Region[] = [];
  image.set(file.subarray(0, Math.min(headers, file.length)), 0);
  const table = optional + u16(file, pe + 0x14);
  for (let i = 0; i < sections; i += 1) {
    const row = table + i * 40;
    const virtualAddress = u32(file, row + 0xc);
    const rawSize = u32(file, row + 0x10);
    const rawAt = u32(file, row + 0x14);
    const virtualSize = u32(file, row + 0x8) || rawSize;
    const alignment = u32(file, optional + 0x20) || 0x1000;
    const span = Math.ceil(virtualSize / alignment) * alignment;
    regions.push({ start: base + virtualAddress, size: span, protect: protectOf(u32(file, row + 0x24)) });
    if (rawSize === 0) continue;
    image.set(file.subarray(rawAt, Math.min(rawAt + rawSize, file.length)), virtualAddress);
  }
  regions.unshift({ start: base, size: headers, protect: 0x02 });
  return { name: basename(path), base, image, regions };
}

const logs: string[] = [];

function install(modules: Mapped[], policy: number): Record<string, (...args: unknown[]) => unknown> {
  const kuser = new Uint8Array(0x1000);
  kuser[0x2d5] = policy;
  const regions = [...modules, { base: 0x7ffe0000, image: kuser }];
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    namespace: { Debugger: { Utility: { Control: { ExecuteCommand: (command: string) => {
      const vprot = /^!vprot 0x([0-9a-f]+)$/i.exec(command.trim());
      if (!vprot) return [];
      const address = parseInt(vprot[1], 16);
      const region = modules.flatMap((entry) => entry.regions).find((entry) => address >= entry.start && address < entry.start + entry.size);
      if (!region) return ["BaseAddress: 00000000", "RegionSize: 00000000", "State: 00010000", "Protect: 00000001", "Type: 00000000"];
      return [
        `BaseAddress:       ${region.start.toString(16).padStart(8, "0")}`,
        `AllocationBase:    ${region.start.toString(16).padStart(8, "0")}`,
        `RegionSize:        ${region.size.toString(16).padStart(8, "0")}`,
        "State:             00001000  MEM_COMMIT",
        `Protect:           ${region.protect.toString(16).padStart(8, "0")}`,
        "Type:              01000000  MEM_IMAGE",
      ];
    } } } } },
    currentThread: undefined,
    currentProcess: {
      Is64Bit: false,
      Modules: modules.map((entry) => ({
        Name: entry.name, Path: `C:\target\${entry.name}`,
        BaseAddress: BigInt(entry.base), EndAddress: BigInt(entry.base + entry.image.length), Size: entry.image.length,
      })),
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
  return (globalThis as unknown as { osed: Record<string, (...args: unknown[]) => unknown> }).osed;
}

function main(): void {
  const argv = process.argv.slice(2);
  const flag = (name: string, fallback = ""): string => {
    const at = argv.indexOf(`--${name}`);
    return at >= 0 ? argv[at + 1] : fallback;
  };
  const paths = argv.filter((token, i) => !token.startsWith("--") && !(i > 0 && argv[i - 1].startsWith("--")));
  if (paths.length === 0) throw new Error("give at least one PE path");
  const modules = paths.map(mapPe);
  for (const entry of modules) console.error(`mapped ${entry.name} at 0x${entry.base.toString(16)}, 0x${entry.image.length.toString(16)} bytes`);
  const osed = install(modules, 1);
  const bad = flag("bad", "00 0a 0d");
  const style = flag("style", "auto");
  const command = flag("cmd", "dep_plan");
  if (command === "palette") {
    osed.palette(flag("module", modules[0].name), bad);
  } else if (command === "dep_candidates") {
    osed.dep_candidates(flag("module", modules[0].name), bad, style, flag("api", "VirtualAlloc"));
  } else if (flag("api")) {
    osed.dep_plan(flag("api"), flag("module", modules[0].name), bad, style, 1, flag("exclude"));
  } else {
    osed.dep_plan(bad, 1);
  }
  const text = stripDml(logs.join(""));
  const only = flag("section");
  if (!only) { console.log(text); return; }
  const wanted = only.split(",");
  let keep = false;
  for (const line of text.split("\n")) {
    if (/^=== /.test(line)) keep = wanted.some((n) => line.startsWith(`=== [${n}/7]`) || line.toLowerCase().includes(n.toLowerCase()));
    if (keep) console.log(line);
  }
}

main();
