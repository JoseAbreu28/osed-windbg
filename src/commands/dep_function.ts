import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { DepApi, PUSHAD_MAPS, printPushadMap } from "./rop_template";

type Style = "skeleton" | "pushad";
const STYLES: Style[] = ["skeleton", "pushad"];

const FRAMES: Record<DepApi, { alias: string; lines: string[] }> = {
  VirtualAlloc: {
    alias: "VA",
    lines: [
      'va  = pack("<L", vaAddr)                 # VirtualAlloc address',
      'va += pack("<L", shellcodeReturnAddr)   # Shellcode return address',
      'va += pack("<L", shellcodeAddr)         # lpAddress: shellcode destination',
      'va += pack("<L", dwSize)                # dwSize',
      'va += pack("<L", flAllocationType)      # flAllocationType',
      'va += pack("<L", flProtect)             # flProtect',
    ],
  },
  VirtualProtect: {
    alias: "VP",
    lines: [
      'vp  = pack("<L", vpAddr)                 # VirtualProtect address',
      'vp += pack("<L", shellcodeReturnAddr)   # Shellcode return address',
      'vp += pack("<L", shellcodeAddr)         # lpAddress: start of the region to make executable',
      'vp += pack("<L", dwSize)                # dwSize',
      'vp += pack("<L", 0x40)                  # flNewProtect: PAGE_EXECUTE_READWRITE',
      'vp += pack("<L", oldProtectAddr)        # lpflOldProtect: writable address, e.g. in .data',
    ],
  },
  WriteProcessMemory: {
    alias: "WPM",
    lines: [
      'wpm  = pack("<L", wpmAddr)              # WriteProcessMemory address',
      'wpm += pack("<L", shellcodeReturnAddr) # Shellcode return address',
      'wpm += pack("<L", 0xFFFFFFFF)          # pseudo process handle',
      'wpm += pack("<L", codeCaveAddr)        # code cave address',
      'wpm += pack("<L", stackBufferAddr)     # lpBuffer',
      'wpm += pack("<L", shellcodeSize)       # nSize',
      'wpm += pack("<L", bytesWrittenAddr)    # lpNumberOfBytesWritten',
    ],
  },
};

const NAMES = Object.keys(FRAMES) as DepApi[];

function parseApi(input: string): DepApi | undefined {
  const key = input.trim().toLowerCase();
  return NAMES.find((name) => name.toLowerCase() === key || FRAMES[name].alias.toLowerCase() === key);
}

export function createDepFunctionCommand(): Command {
  return {
    name: "dep_function",
    description: "Print the frame of VirtualAlloc, VirtualProtect or WriteProcessMemory: a Python call-frame skeleton by default, or with \"pushad\" the register each argument goes in for one PUSHAD. VA, VP and WPM work as short aliases.",
    usage: 'dx @$osed().dep_function("VirtualAlloc" | "VirtualProtect" | "WriteProcessMemory", style?)',
    examples: [
      'dx @$osed().dep_function("VirtualAlloc")',
      'dx @$osed().dep_function("VirtualProtect")',
      'dx @$osed().dep_function("WriteProcessMemory")',
      'dx @$osed().dep_function("VirtualProtect", "pushad")',
    ],
    compactExampleCount: 4,
    schema: { method: { type: "string", required: true }, style: { type: "string" } },
    execute(options: Record<string, unknown>): CommandResult {
      const method = parseApi(options.method as string);
      const style = String(options.style ?? "skeleton").trim().toLowerCase() as Style;
      const fail = (error: string): CommandResult =>
        ({ command: "dep_function", args: options, success: false, findings: [], warnings: [], errors: [error] });
      if (!method) return fail('Use "VirtualAlloc", "VirtualProtect" or "WriteProcessMemory" (aliases "VA", "VP", "WPM").');
      if (!STYLES.includes(style)) return fail('style must be "skeleton" or "pushad".');

      if (style === "pushad") {
        out.section(`${method} PUSHAD Register Map`);
        printPushadMap(method);
        return { command: "dep_function", args: { method, style }, success: true, findings: [{ method, style, lines: PUSHAD_MAPS[method] }], warnings: [], errors: [] };
      }
      const { lines } = FRAMES[method];
      out.section(`${method} Python Call-Frame Skeleton`);
      for (const line of lines) out.print(line);
      return { command: "dep_function", args: { method, style }, success: true, findings: [{ method, style, lines }], warnings: [], errors: [] };
    },
  };
}
