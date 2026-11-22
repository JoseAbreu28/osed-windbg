import { CapabilityIndex } from "../rop/capabilities";
import { rankCandidates } from "../rop/emitter";
import { CapabilityKind, RopGadget } from "../rop/types";
import { DepApi } from "./rop_template";

export type DepPlanStyle = "skeleton" | "pushad";

export const DEP_PLAN_APIS: DepApi[] = ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory"];
export const DEP_PLAN_STYLES: DepPlanStyle[] = ["skeleton", "pushad"];
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
  flow: Flow;
};

const SKELETON_JOBS: Job[] = [
  { key: "capture", title: "capture ESP", capabilities: ["STACK_POINTER_CAPTURE"], flow: { sets: { role: "pointer", port: "dest" } } },
  { key: "add", title: "add the distance to field 1", capabilities: ["REGISTER_ADD", "REGISTER_SUB"],
    flow: { reads: { dest: "pointer" }, sets: { role: "pointer", port: "dest" } } },
  { key: "copy", title: "copy a register", capabilities: ["MOVE_REGISTER", "EXCHANGE_REGISTER"],
    flow: { reads: { source: "pointer" }, sets: { role: "field", port: "dest" } } },
  { key: "read", title: "read a pointer", capabilities: ["MEMORY_READ"], flow: { sets: { role: "value", port: "dest" } } },
  { key: "write", title: "write a field", capabilities: ["MEMORY_WRITE"], flow: { reads: { address: "field", source: "value" } } },
  { key: "advance", title: "advance the pointer (inc reg)", capabilities: ["REGISTER_INCREMENT"],
    flow: { reads: { dest: "field" }, sets: { role: "field", port: "dest" } } },
  { key: "negate", title: "negate", capabilities: ["REGISTER_NEGATE"], flow: { sets: { role: "value", port: "dest" } } },
  { key: "pivot", title: "pivot ESP onto the frame", capabilities: ["STACK_PIVOT"], flow: { reads: { source: "field" } } },
];

// The order the draft loads them in: ESI first (the API, read from the slot), then the rest.
const PUSHAD_REGISTERS: Role[] = ["esi", "ebp", "ebx", "edx", "ecx", "edi", "eax"];

const PUSHAD_JOBS: Job[] = [
  { key: "read", title: "read a pointer (the IAT slot)", capabilities: ["MEMORY_READ"], flow: {} },
  ...PUSHAD_REGISTERS.map((register): Job => ({
    key: `pop_${register}`, title: `pop ${register}`, capabilities: ["LOAD_REGISTER"], register, flow: { sets: { role: register, port: "dest" } },
  })),
  { key: "pushad", title: "pushad ; ret", capabilities: ["DISPATCH_PUSHAD"],
    flow: { reads: PUSHAD_REGISTERS.reduce((reads, register) => ({ ...reads, [register]: register }), {}) } },
];

export function jobsFor(style: DepPlanStyle): Job[] {
  return style === "pushad" ? PUSHAD_JOBS : SKELETON_JOBS;
}

function readsOf(job: Job): Role[] {
  const reads = (job.flow.reads ?? {}) as Record<string, Role>;
  return Object.keys(reads).map((port) => reads[port]);
}

// A role is live after a job when a later job reads it before any job sets it again. The fill jobs
// (write, advance, negate) repeat once per field, so for them the list wraps: the next field's write
// reads the field address again. The role the job itself sets is its output, not something to keep.
export function liveAfter(jobs: Job[], index: number, withOwn = false): Role[] {
  const loop = jobs.filter((job) => ["write", "advance", "negate"].indexOf(job.key) >= 0);
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

function movesEsp(gadget: RopGadget): boolean {
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
function ranked(index: CapabilityIndex, job: Job): RopGadget[] {
  return rankCandidates(index.gadgets.filter((gadget) =>
    jobCapability(gadget, job) !== undefined && (job.key === "pivot" || !movesEsp(gadget))));
}

const REGISTER = /^e(ax|bx|cx|dx|si|di|bp|sp)$/;

function memoryBase(text: string): { base?: string; offset: number } {
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

type Ports = Partial<Record<Port, string>> & { offset?: number };

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

function writtenRegisters(gadget: RopGadget): string[] {
  const summary = gadget.semanticSummary.summary;
  const written: string[] = [];
  for (const register of [...summary.writes.values.exact, ...summary.writes.values.conservative].map(String)) {
    if (register !== "esp" && register !== "eip" && written.indexOf(register) < 0) written.push(register);
  }
  return written;
}

function memoryWrites(gadget: RopGadget, own: string): string[] {
  return gadget.instructions
    .filter((instruction) => instruction.mnemonic !== "push" && (instruction.operands[0] ?? "").indexOf("[") >= 0
      && instruction.normalizedText !== own)
    .map((instruction) => instruction.operands[0].trim());
}

function holds(gadget: RopGadget, dest: string, source: string): boolean {
  const transforms = gadget.semanticSummary.summary.registerTransforms as Record<string, { kind: string; base?: string; offset?: { kind: string; value?: number } }>;
  const transform = transforms[dest];
  return transform !== undefined && transform.kind === "affine" && transform.base === source
    && transform.offset?.kind === "constant" && transform.offset.value === 0;
}

export type Verdict = {
  gadget: RopGadget;
  at: Ports;
  usable: boolean;
  move?: string;
  reason: string;
};

export type JobPlan = {
  job: Job;
  live: Array<{ role: Role; register: string }>;
  verdicts: Verdict[];
  pick?: Verdict;
};

// Rejections no register move can fix: the gadget destroys a value the chain still needs, or it cannot do the job.
function rejection(gadget: RopGadget, job: Job, at: Ports, live: Array<{ role: Role; register: string }>, bound: Partial<Record<Role, string>>): string | undefined {
  const capability = jobCapability(gadget, job);
  if (job.key === "add") {
    if (capability?.kind === "REGISTER_SUB") return "subtracts: the distance to field 1 is negative, so pop it and add";
    if (!REGISTER.test(at.source ?? "")) return `adds a fixed ${at.source}, not the distance you pop`;
  }
  if (job.key === "copy" && at.dest && at.source && !holds(gadget, at.dest, at.source)) return `${at.dest} does not keep the copy`;
  if (job.key === "copy" && bound.pointer !== undefined && at.source !== bound.pointer) return `copies ${at.source}, but the captured ESP is in ${bound.pointer}`;
  if (job.key === "pivot" && !at.source) return "takes ESP from the stack, not from a register";
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
export function planJobs(index: CapabilityIndex | undefined, style: DepPlanStyle): JobPlan[] {
  const jobs = jobsFor(style);
  const bound: Partial<Record<Role, string>> = {};
  return jobs.map((job, position) => {
    const later = liveAfter(jobs, position, true);
    const live = liveAfter(jobs, position)
      .filter((role) => bound[role] !== undefined)
      .map((role) => ({ role, register: bound[role] as string }));
    const verdicts = (index ? ranked(index, job) : []).map((gadget): Verdict => {
      const at = ports(gadget, job);
      const rejected = rejection(gadget, job, at, live, bound);
      if (rejected) return { gadget, at, usable: false, reason: rejected };
      const needed = moves(job, at, bound);
      if (needed.length > 0) {
        const back = readsOf(job).some((role) => later.indexOf(role) >= 0) ? ", and back after" : "";
        const move = `${needed.join(", ")} first${back}`;
        return { gadget, at, usable: true, move, reason: `move ${move}` };
      }
      return { gadget, at, usable: true, reason: exactReason(gadget, job, at, live, bound) };
    });
    const pick = verdicts.filter((verdict) => verdict.usable && !verdict.move)[0] ?? verdicts.filter((verdict) => verdict.usable)[0];
    const sets = job.flow.sets;
    if (pick && sets) {
      const register = ports(pick.gadget, job)[sets.port];
      if (register && (bound[sets.role] === undefined || !pick.move)) bound[sets.role] = register;
    }
    return { job, live, verdicts, pick };
  });
}

export function gadgetAddress(gadget: RopGadget): number {
  return gadget.locations.find((location) => location.virtualAddress !== undefined)?.virtualAddress ?? 0;
}

export function hex32(value: number): string {
  return `0x${(value >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;
}

function sequence(gadget: RopGadget): string {
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

// The pick, up to three candidates the old ranking put above it, and up to two usable alternatives after it.
export function planLines(plan: JobPlan): string[] {
  const { job, live, verdicts, pick } = plan;
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
  else lines.push(`    none of the ${verdicts.length} keeps ${live.map((entry) => entry.register).join(", ")}`);
  for (const verdict of after) lines.push(...line(verdict, " ", "usable"));
  return lines;
}

export type DraftInput = {
  api: DepApi;
  style: DepPlanStyle;
  module: string;
  iatSlot?: number;
  writable?: number;
  cave?: number;
  picks: Record<string, Verdict | undefined>;
  jmpEsp?: number;
};

function slotLine(name: string, value: number | undefined, how: string): string {
  return value === undefined
    ? `${name.padEnd(9)}= 0x????????   # TODO ${how}`
    : `${name.padEnd(9)}= ${hex32(value)}   # ${how}`;
}

function gadgetLine(picks: Record<string, Verdict | undefined>, key: string, title: string): string {
  const pick = picks[key];
  if (!pick) return `rop += p32(0x????????)    # TODO ${title}: no candidate keeps the live registers`;
  const line = `rop += p32(${hex32(gadgetAddress(pick.gadget))})    # ${title}: ${sequence(pick.gadget)}`;
  return pick.move ? `# TODO move ${pick.move}\n${line}` : line;
}

const FRAME_DWORDS: Record<DepApi, number> = { VirtualAlloc: 6, VirtualProtect: 6, WriteProcessMemory: 7 };

function measureLines(input: DraftInput): string[] {
  const capture = input.picks.capture;
  const at = capture ? hex32(gadgetAddress(capture.gadget)) : "<capture gadget>";
  return [
    "# TODO measure: distance from the captured ESP to field 1 of the frame",
    `#   bp ${at} ; g ; r esp                      ESP here is the value push esp stores`,
    "#   s -d esp-400 L100 45454545                    address of field 1 (the first dummy)",
    "#   ? <field 1> - <captured ESP>                  negative: pop it into a register, then add",
    "DIST_FIELD1 = ???",
    "# TODO measure: distance from the captured ESP to the shellcode",
    "#   s -b esp L2000 90 90 90 90                    start of the NOP sled",
    "#   ? <sled> - <captured ESP>",
    "DIST_SHELLCODE = ???",
  ];
}

function skeletonFrame(api: DepApi): string[] {
  if (api === "VirtualAlloc") {
    return [
      "frame  = p32(0x45454545)   # VirtualAlloc address   <- [IAT_SLOT]",
      "frame += p32(0x46464646)   # return address         <- shellcode",
      "frame += p32(0x47474747)   # lpAddress              <- shellcode",
      "frame += p32(0x48484848)   # dwSize                 <- 0x1",
      "frame += p32(0x49494949)   # flAllocationType       <- 0x1000",
      "frame += p32(0x51515151)   # flProtect              <- 0x40",
    ];
  }
  if (api === "VirtualProtect") {
    return [
      "frame  = p32(0x45454545)   # VirtualProtect address <- [IAT_SLOT]",
      "frame += p32(0x46464646)   # return address         <- shellcode",
      "frame += p32(0x47474747)   # lpAddress              <- shellcode",
      "frame += p32(0x48484848)   # dwSize                 <- 0x201",
      "frame += p32(0x49494949)   # flNewProtect           <- 0x40",
      "frame += p32(WRITABLE)     # lpflOldProtect         literal when clean",
    ];
  }
  return [
    "frame  = p32(0x45454545)   # WriteProcessMemory     <- [IAT_SLOT]",
    "frame += p32(CAVE)         # return address         literal when clean",
    "frame += p32(0xFFFFFFFF)   # hProcess               literal",
    "frame += p32(CAVE)         # lpBaseAddress          literal when clean",
    "frame += p32(0x46464646)   # lpBuffer               <- shellcode",
    "frame += p32(0x47474747)   # nSize                  <- 0x210",
    "frame += p32(WRITABLE)     # lpNumberOfBytesWritten literal when clean",
  ];
}

// The read gadget names the register the slot goes in, and how far from it the read lands.
function slotLoad(read: Verdict | undefined): string {
  const at = read?.at;
  if (!at?.address) return "rop += p32(0x????????)    # TODO pop <reg> ; ret, followed by p32(IAT_SLOT) or its rop.construct recipe from [5/7]";
  const target = at.offset ? `IAT_SLOT ${at.offset > 0 ? "-" : "+"} 0x${Math.abs(at.offset).toString(16)}` : "IAT_SLOT";
  return `rop += p32(0x????????)    # TODO ${at.address} = ${target}: a pop, or the rop.construct recipe from [5/7] and a move`;
}

function writeNote(write: Verdict | undefined): string[] {
  const at = write?.at;
  return at?.address && at.offset ? [`# the write lands ${at.offset > 0 ? "+" : "-"}0x${Math.abs(at.offset).toString(16)} from ${at.address}: keep ${at.address} that far ${at.offset > 0 ? "before" : "after"} the field`] : [];
}

function skeletonChain(input: DraftInput): string[] {
  const { picks } = input;
  const patched = input.api === "WriteProcessMemory" ? "fields 1, 5 and 6" : input.api === "VirtualProtect" ? "fields 1 to 5" : "fields 1 to 6";
  return [
    'rop  = b""',
    gadgetLine(picks, "capture", "capture ESP"),
    "# captured ESP -> field 1: load DIST_FIELD1 with a pop, then",
    gadgetLine(picks, "add", "add the distance"),
    gadgetLine(picks, "copy", "keep the field address in its own register"),
    "# field 1: the API address",
    slotLoad(picks.read),
    gadgetLine(picks, "read", "read the API address from the slot"),
    ...writeNote(picks.write),
    gadgetLine(picks, "write", "write it into the field"),
    gadgetLine(picks, "advance", "advance to the next field, four times").replace(")    #", ") * 4  #"),
    `# repeat load / write / advance for ${patched}, with the recipes from [5/7]`,
    "# and the shellcode address = captured ESP + DIST_SHELLCODE",
    "# move the working pointer back to field 1, then",
    gadgetLine(picks, "pivot", "pivot ESP onto field 1"),
  ];
}

function pushadChain(input: DraftInput): string[] {
  const { picks } = input;
  const slot = picks.read?.at.address ?? "eax";
  const lines = [
    'rop  = b""',
    "# ESI = the API address: read the slot, then move it to ESI",
    gadgetLine(picks, `pop_${slot}`, `pop ${slot}`),
    "rop += p32(IAT_SLOT)",
    gadgetLine(picks, "read", "read the slot"),
    "rop += p32(0x????????)    # TODO mov esi, eax / xchg eax, esi (rop.query(\"capability\", \"MOVE_REGISTER\"))",
    "# the other registers, in an order where no later gadget overwrites an earlier register:",
    '#   dx @$osed().rop.setup("ebp=<jmp esp> ebx=... edx=... ecx=... edi=<ret> eax=0x90909090", "<bad chars>")',
  ];
  for (const register of ["ebp", "ebx", "edx", "ecx", "edi", "eax"]) {
    lines.push(gadgetLine(picks, `pop_${register}`, `pop ${register}`), `rop += p32(0x????????)    # TODO value for ${register.toUpperCase()}, see the map in [6/7]`);
  }
  lines.push(gadgetLine(picks, "pushad", "pushad ; ret"));
  if (input.jmpEsp !== undefined) lines.push(`# jmp esp for EBP: ${hex32(input.jmpEsp)}`);
  return lines;
}

export function draftLines(input: DraftInput): string[] {
  const head = [
    "# DRAFT. Verify every field in WinDbg before you trust it. This is not a finished chain:",
    "# the gadgets below are the [4/7] picks. Each keeps the registers the chain still needs,",
    "# and a '# TODO move' line marks where a value has to change register first.",
    "import struct",
    "def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)",
    "",
    "OFFSET   = ???              # TODO measure: bytes from buffer start to EIP (pattern.create / pattern.offset)",
    slotLine("IAT_SLOT", input.iatSlot, `IAT slot of ${input.api}`),
  ];
  if (input.api !== "VirtualAlloc") head.push(slotLine("WRITABLE", input.writable, "writable dword, from [5/7]"));
  if (input.api === "WriteProcessMemory") head.push(slotLine("CAVE", input.cave, "executable code cave, from [5/7]"));
  head.push("");

  if (input.style === "pushad") {
    return [...head, ...pushadChain(input), "", 'shellcode = b"\\x90" * 16 + b"..."', 'payload = b"A" * OFFSET + rop + shellcode'];
  }
  const frameBytes = FRAME_DWORDS[input.api] * 4;
  return [
    ...head,
    ...measureLines(input),
    "",
    `# frame, ${FRAME_DWORDS[input.api]} dwords just before EIP (bp <first gadget> ; dd esp-${(frameBytes + 4).toString(16)} L${FRAME_DWORDS[input.api]})`,
    ...skeletonFrame(input.api),
    "",
    ...skeletonChain(input),
    "",
    'shellcode = b"\\x90" * 16 + b"..."',
    'payload  = b"A" * (OFFSET - len(frame)) + frame + rop',
    'payload += b"C" * ???        # TODO measure: padding so the shellcode sits at captured ESP + DIST_SHELLCODE',
    "payload += shellcode",
  ];
}
