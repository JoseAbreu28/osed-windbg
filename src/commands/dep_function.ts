import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";

type DepApi = "VirtualAlloc" | "VirtualProtect" | "WriteProcessMemory";

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
    description: "Print a Python call-frame skeleton for VirtualAlloc, VirtualProtect or WriteProcessMemory. VA, VP and WPM work as short aliases.",
    usage: 'dx @$osed().dep_function("VirtualAlloc" | "VirtualProtect" | "WriteProcessMemory")',
    examples: [
      'dx @$osed().dep_function("VirtualAlloc")',
      'dx @$osed().dep_function("VirtualProtect")',
      'dx @$osed().dep_function("WriteProcessMemory")',
    ],
    compactExampleCount: 3,
    schema: { method: { type: "string", required: true } },
    execute(options: Record<string, unknown>): CommandResult {
      const method = parseApi(options.method as string);
      if (!method) {
        const error = 'Use "VirtualAlloc", "VirtualProtect" or "WriteProcessMemory" (aliases "VA", "VP", "WPM").';
        return { command: "dep_function", args: options, success: false, findings: [], warnings: [], errors: [error] };
      }

      const { lines } = FRAMES[method];
      out.section(`${method} Python Call-Frame Skeleton`);
      for (const line of lines) out.print(line);
      return { command: "dep_function", args: { method }, success: true, findings: [{ method, lines }], warnings: [], errors: [] };
    },
  };
}
