import { overwrites, spoilsOwnInput } from "../rop/capabilities";
import { rankCandidates } from "../rop/emitter";
import { RopGadget } from "../rop/types";
import { extraPops, lastRetN } from "./dep_build";
import { dereferencedRegisters, gadgetAddress, hex32, holds, memoryBase, memoryWrites, sequence, writtenRegisters } from "./dep_plan";

// A gadget palette: every shape a hand-written chain reaches for, named by the instruction, so the gaps in a
// module show as None. The set is fixed, the same names on every target, and holds exactly the shapes whose
// plain x86 encodings are listed here: a shape is None only after every byte of the module was searched for
// them, so it never depends on how far a scan got.

export type Op = "POP" | "MOV" | "XCHG" | "ADD" | "SUB" | "NEG" | "INC" | "DEC" | "READ" | "WRITE" | "PUSHAD";

/** MOV: dst = src. XCHG: either order. ADD, SUB: dst op= src. READ: dst = [src + d]. WRITE: [dst + d] = src. */
export type Shape = { name: string; op: Op; src?: string; dst?: string; bodies: number[][] };

const REGS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
const GENERAL = REGS.filter((reg) => reg !== "esp");
const num = (reg: string): number => REGS.indexOf(reg);
const rm = (mod: number, reg: string, base: string): number => (mod << 6) | (num(reg) << 3) | num(base);
const up = (reg: string): string => reg.toUpperCase();
const two = (op: Op, src: string, dst: string, bodies: number[][]): Shape => ({ name: `GADGET_${op}_${up(src)}2${up(dst)}`, op, src, dst, bodies });
const one = (op: Op, dst: string, bodies: number[][]): Shape => ({ name: `GADGET_${op}_${up(dst)}`, op, dst, bodies });
const pairs = (regs: string[]): Array<[string, string]> => regs.flatMap((src) => regs.filter((dst) => dst !== src).map((dst): [string, string] => [src, dst]));
// [base] and [base + disp8]. ebp has no plain [ebp] form: mod 0 with base 101 means a bare disp32.
const memory = (op: number, reg: string, base: string): number[][] =>
  [...(base === "ebp" ? [] : [[op, rm(0, reg, base)]]), [op, rm(1, reg, base), -1]];

export const SHAPES: Shape[] = [
  ...[...GENERAL, "esp"].map((dst) => one("POP", dst, [[0x58 + num(dst)]])),
  ...GENERAL.map((dst) => two("MOV", "esp", dst, [[0x54, 0x58 + num(dst)], [0x89, rm(3, "esp", dst)], [0x8b, rm(3, dst, "esp")]])),
  ...pairs(GENERAL).map(([src, dst]) => two("MOV", src, dst, [[0x89, rm(3, src, dst)], [0x8b, rm(3, dst, src)]])),
  ...GENERAL.map((src) => two("MOV", src, "esp", [[0x89, rm(3, src, "esp")], [0x8b, rm(3, "esp", src)]])),
  ...pairs(REGS).filter(([a, b]) => num(a) < num(b)).map(([a, b]) =>
    two("XCHG", a, b, [...(a === "eax" ? [[0x90 + num(b)]] : []), [0x87, rm(3, a, b)], [0x87, rm(3, b, a)]])),
  ...pairs(GENERAL).map(([src, dst]) => two("ADD", src, dst, [[0x01, rm(3, src, dst)], [0x03, rm(3, dst, src)]])),
  ...pairs(GENERAL).map(([src, dst]) => two("SUB", src, dst, [[0x29, rm(3, src, dst)], [0x2b, rm(3, dst, src)]])),
  ...GENERAL.map((dst) => one("NEG", dst, [[0xf7, 0xd8 + num(dst)]])),
  ...GENERAL.map((dst) => one("INC", dst, [[0x40 + num(dst)]])),
  ...GENERAL.map((dst) => one("DEC", dst, [[0x48 + num(dst)]])),
  ...GENERAL.flatMap((src) => GENERAL.map((dst) => two("READ", src, dst, memory(0x8b, dst, src)))),
  ...GENERAL.flatMap((src) => GENERAL.map((dst) => two("WRITE", src, dst, memory(0x89, src, dst)))),
  { name: "GADGET_PUSHAD", op: "PUSHAD", bodies: [[0x60]] },
];

export const GROUPS: Array<{ op: Op; title: string }> = [
  { op: "POP", title: "POP <DST>: dst = the next dword. POP_ESP pivots" },
  { op: "MOV", title: "MOV <SRC>2<DST>: dst = src. MOV_ESP2<DST> captures ESP; MOV_<SRC>2ESP pivots" },
  { op: "XCHG", title: "XCHG <A>2<B>: swaps a and b. With ESP it pivots" },
  { op: "ADD", title: "ADD <SRC>2<DST>: dst += src" },
  { op: "SUB", title: "SUB <SRC>2<DST>: dst -= src" },
  { op: "NEG", title: "NEG <DST>: dst = -dst" },
  { op: "INC", title: "INC <DST>: dst += 1" },
  { op: "DEC", title: "DEC <DST>: dst -= 1" },
  { op: "READ", title: "READ <SRC>2<DST>: dst = [src]" },
  { op: "WRITE", title: "WRITE <SRC>2<DST>: [dst] = src" },
  { op: "PUSHAD", title: "PUSHAD" },
];

/** Every plain encoding of the shape, ending in `ret` or `ret N` (-1 is any byte). */
export function shapeEncodings(shape: Shape): number[][] {
  return shape.bodies.flatMap((body) => [[...body, 0xc3], [...body, 0xc2, -1, -1]]);
}

const operandsOf = (instruction: RopGadget["instructions"][number]): string[] => instruction.operands.map((operand) => operand.trim().toLowerCase());
const pivots = (shape: Shape): boolean => shape.dst === "esp" || (shape.op === "XCHG" && shape.src === "esp");

// Whether the gadget puts a new value in ESP: mov, xchg, lea, pop, leave, or arithmetic other than the
// add esp, N that extraPops counts as pops. The corpus's own STACK_PIVOT flag misses `... ; mov esp, ebx ; ...`.
function setsEsp(gadget: RopGadget): boolean {
  return gadget.instructions.some((instruction) => {
    const operands = operandsOf(instruction);
    if (instruction.mnemonic === "leave") return true;
    return overwrites(instruction, "esp") && !(instruction.mnemonic === "add" && /^(0x[0-9a-f]+|\d+)$/.test(operands[1] ?? ""));
  });
}

// A push the gadget does not pop again is where its ret lands: `inc ebx ; push 0x5d ; ret` returns to 0x5D.
function returnsIntoPush(gadget: RopGadget): boolean {
  let pushed = 0;
  for (const instruction of gadget.instructions) {
    if (instruction.mnemonic === "push") pushed += 1;
    else if (instruction.mnemonic === "pop" && pushed > 0) pushed -= 1;
  }
  return pushed > 0;
}

// The instruction of the gadget that does the shape, or undefined. A gadget only counts when what the
// shape promises still holds at its ret: nothing before the instruction changed its inputs, and nothing
// after it changed its result.
function own(gadget: RopGadget, shape: Shape): string | undefined {
  const { op, src, dst } = shape;
  const instructions = gadget.instructions;
  const untouchedBefore = (at: number, regs: Array<string | undefined>) =>
    regs.every((reg) => reg === undefined || !spoilsOwnInput(gadget, instructions[at].normalizedText, reg));
  const keptAfter = (at: number, regs: Array<string | undefined>) =>
    regs.every((reg) => reg === undefined || instructions.slice(at + 1).every((instruction) => !overwrites(instruction, reg)));
  if (op === "MOV" && dst !== "esp") {
    if (!holds(gadget, dst!, src!)) return undefined;
    return instructions.find((instruction) => operandsOf(instruction).indexOf(dst!) >= 0)?.normalizedText ?? "";
  }
  if (op === "XCHG" && src !== "esp" && dst !== "esp") {
    if (!holds(gadget, dst!, src!) || !holds(gadget, src!, dst!)) return undefined;
    return instructions.find((instruction) => instruction.mnemonic === "xchg")?.normalizedText ?? "";
  }
  for (let at = 0; at < instructions.length; at += 1) {
    const instruction = instructions[at];
    const operands = operandsOf(instruction);
    const mnemonic = instruction.mnemonic;
    const text = instruction.normalizedText;
    const matched =
      op === "PUSHAD" ? mnemonic === "pushad"
      : op === "POP" ? mnemonic === "pop" && operands[0] === dst && keptAfter(at, [dst])
      : op === "MOV" ? mnemonic === "mov" && operands[0] === "esp" && operands[1] === src && untouchedBefore(at, [src])
      : op === "XCHG" ? mnemonic === "xchg" && operands.length === 2 && operands.indexOf(src!) >= 0 && operands.indexOf(dst!) >= 0
      : op === "ADD" || op === "SUB" ? mnemonic === op.toLowerCase() && operands[0] === dst && operands[1] === src
        && untouchedBefore(at, [src, dst]) && keptAfter(at, [dst])
      : op === "NEG" || op === "INC" || op === "DEC" ? mnemonic === op.toLowerCase() && operands[0] === dst
        && untouchedBefore(at, [dst]) && keptAfter(at, [dst])
      : op === "READ" ? mnemonic === "mov" && operands[0] === dst && memoryBase(operands[1] ?? "").base === src
        && untouchedBefore(at, [src]) && keptAfter(at, [dst])
      : mnemonic === "mov" && operands[1] === src && memoryBase(operands[0] ?? "").base === dst && untouchedBefore(at, [src, dst]);
    if (matched) return text;
  }
  return undefined;
}

export type Pick = { gadget: RopGadget; costs: string[]; pops: number; retn: number };

// What the gadget does besides the shape, as the [4/7] block counts it: (extra pops, ret N), the other
// registers it writes, and the memory it reads through a register.
function costsOf(gadget: RopGadget, shape: Shape, text: string): Pick {
  const pops = extraPops(gadget, shape.op === "POP" ? 1 : 0);
  const retn = lastRetN(gadget);
  const mine = shape.op === "XCHG" ? [shape.src, shape.dst] : shape.op === "WRITE" ? [] : [shape.dst];
  const writes = writtenRegisters(gadget).filter((reg) => mine.indexOf(reg) < 0);
  const reads = dereferencedRegisters(gadget, text);
  const at = shape.op === "READ" || shape.op === "WRITE" ? memoryBase(text) : undefined;
  const reg = shape.op === "READ" ? shape.src : shape.dst;
  const costs = [
    at && at.offset !== 0 ? `${shape.op === "READ" ? "reads" : "writes"} [${reg}${at.offset > 0 ? "+" : "-"}0x${Math.abs(at.offset).toString(16)}], not [${reg}]` : "",
    pops > 0 ? `${pops} extra pop${pops > 1 ? "s" : ""}` : "",
    retn > 0 ? `ret 0x${retn.toString(16)}` : "",
    writes.length > 0 ? `writes ${writes.join(" ")}` : "",
    reads.length > 0 ? `reads memory through ${reads.join(", ")}` : "",
  ].filter(Boolean);
  return { gadget, costs, pops, retn };
}

/** The gadget for the shape with the fewest side effects, or undefined when the corpus has none. */
export function pickShape(gadgets: RopGadget[], shape: Shape): Pick | undefined {
  const fits: Pick[] = [];
  for (const gadget of rankCandidates(gadgets)) {
    const last = gadget.instructions[gadget.instructions.length - 1];
    if (!last || last.mnemonic !== "ret" || setsEsp(gadget) !== pivots(shape) || (shape.op !== "PUSHAD" && returnsIntoPush(gadget))) continue;
    const text = own(gadget, shape);
    if (text === undefined || memoryWrites(gadget, shape.op === "WRITE" ? text : "").length > 0) continue;
    fits.push(costsOf(gadget, shape, text));
  }
  // The ranking breaks ties, so the sort must keep its order: not every engine's sort is stable.
  return fits.map((fit, at) => ({ fit, at })).sort((left, right) => left.fit.costs.length - right.fit.costs.length || left.at - right.at)[0]?.fit;
}

export type Entry = { shape: Shape; pick?: Pick; dirty: number };

/** The copy block: one line per shape, in the order of SHAPES, then what the corpus has outside them. */
export function paletteLines(entries: Entry[], extras: Array<{ name: string; gadget: RopGadget }>, modules: string): string[] {
  const width = Math.max(...entries.map((entry) => entry.shape.name.length), ...extras.map((extra) => extra.name.length));
  const lines: string[] = [];
  for (const group of GROUPS) {
    const mine = entries.filter((entry) => entry.shape.op === group.op);
    lines.push(`# ${group.title}. ${mine.filter((entry) => entry.pick).length} of ${mine.length} in ${modules}`);
    for (const { shape, pick, dirty } of mine) {
      lines.push(pick
        ? `${shape.name.padEnd(width)} = ${hex32(gadgetAddress(pick.gadget))}   # ${sequence(pick.gadget)}${pick.costs.length > 0 ? `   costs (${pick.pops}, ${pick.retn ? `0x${pick.retn.toString(16)}` : 0}): ${pick.costs.join(", ")}` : ""}`
        : `${shape.name.padEnd(width)} = None${dirty > 0 ? `         # ${dirty} only at an address holding a bad byte` : ""}`);
    }
    lines.push("");
  }
  if (extras.length > 0) {
    lines.push(`# Also in the corpus, outside the fixed set above, so never None`);
    for (const extra of extras) lines.push(`${extra.name.padEnd(width)} = ${hex32(gadgetAddress(extra.gadget))}   # ${sequence(extra.gadget)}`);
  }
  while (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

// xor r, r and not r: in the corpus's capabilities but with no fixed encoding list here, so only shown when found.
export function extrasOf(gadgets: RopGadget[]): Array<{ name: string; gadget: RopGadget }> {
  const out: Array<{ name: string; gadget: RopGadget }> = [];
  for (const [kind, op] of [["ZERO_REGISTER", "ZERO"], ["REGISTER_NOT", "NOT"]] as const) {
    for (const reg of GENERAL) {
      const found = rankCandidates(gadgets).find((gadget) => !setsEsp(gadget) && !returnsIntoPush(gadget) && memoryWrites(gadget, "").length === 0
        && gadget.capabilities.some((capability) => capability.kind === kind && capability.register === reg)
        && writtenRegisters(gadget).every((written) => written === reg));
      if (found) out.push({ name: `GADGET_${op}_${up(reg)}`, gadget: found });
    }
  }
  return out;
}
