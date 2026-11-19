import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";

export function createDepFunctionCommand(): Command {
  return {
    name: "dep_function",
    description: "Print a Python call-frame skeleton for VirtualAlloc or WriteProcessMemory.",
    usage: 'dx @$osed().dep_function("VA" | "WPM")',
    examples: ['dx @$osed().dep_function("VA")', 'dx @$osed().dep_function("WPM")'],
    compactExampleCount: 2,
    schema: { method: { type: "string", required: true } },
    execute(options: Record<string, unknown>): CommandResult {
      const input = (options.method as string).trim().toLowerCase();
      const method = input === "va" || input === "virtualalloc" ? "VA"
        : input === "wpm" || input === "writeprocessmemory" ? "WPM" : undefined;
      if (!method) {
        return { command: "dep_function", args: options, success: false, findings: [], warnings: [], errors: ['Use "VA" or "WPM".'] };
      }

      const lines = method === "VA" ? [
        'va  = pack("<L", vaAddr)                 # VirtualAlloc address',
        'va += pack("<L", shellcodeReturnAddr)   # Shellcode return address',
        'va += pack("<L", shellcodeAddr)         # lpAddress: shellcode destination',
        'va += pack("<L", dwSize)                # dwSize',
        'va += pack("<L", flAllocationType)      # flAllocationType',
        'va += pack("<L", flProtect)             # flProtect',
      ] : [
        'wpm  = pack("<L", wpmAddr)              # WriteProcessMemory address',
        'wpm += pack("<L", shellcodeReturnAddr) # Shellcode return address',
        'wpm += pack("<L", 0xFFFFFFFF)          # pseudo process handle',
        'wpm += pack("<L", codeCaveAddr)        # code cave address',
        'wpm += pack("<L", stackBufferAddr)     # lpBuffer',
        'wpm += pack("<L", shellcodeSize)       # nSize',
        'wpm += pack("<L", bytesWrittenAddr)    # lpNumberOfBytesWritten',
      ];

      out.section(`${method} Python Call-Frame Skeleton`);
      for (const line of lines) out.print(line);
      return { command: "dep_function", args: { method }, success: true, findings: [{ method, lines }], warnings: [], errors: [] };
    },
  };
}
