import { describe, expect, test } from "vitest";
import { buildExploit } from "../src/commands/dep_build";
import { stagedPops, stagingBase } from "../src/commands/dep_frames";
import { jobsFor, met, planJobs, planWrites, sequence } from "../src/commands/dep_plan";
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

  test("with no base for the frame the style says so instead of writing a chain", () => {
    const made = build(undefined);
    expect(made.holes[0]).toContain("no run of 28 writable bytes");
    expect((made.blocks[6] as { lines: string[] }).lines).toEqual([]);
  });
});

describe("where a staged frame can be laid", () => {
  const span = 0x1c;
  const plain = stagedPops("WriteProcessMemory", 0, 0);

  test("the base is dword-aligned and the whole frame fits the writable run", () => {
    expect(stagingBase({ at: 0x11221412, size: 0x20 }, span, plain, BAD)).toBe(0x11221414);
    expect(stagingBase({ at: 0x11221410, size: 0x10 }, span, plain, BAD)).toBeUndefined();
  });

  // The refusal that makes the style unavailable rather than wrong: the run is longer than the frame and
  // still no good, because the chain pops each field's address and cannot send one of them.
  test("a run long enough for the frame is refused when a field address carries a bad char", () => {
    expect(stagingBase({ at: 0x11220a10, size: 0x20 }, span, plain, BAD)).toBeUndefined();
    expect(stagingBase({ at: 0x11221410, size: 0x20 }, span, plain, BAD)).toBe(0x11221410);
  });

  // A write gadget that stores to [reg+4] is handed each field's address minus four, so the dword below
  // the frame is popped too and a base whose predecessor is dirty is no use. Measured on T06, where the
  // base one dword lower put 0xE0 in the first address the chain sends.
  test("the write gadget's displacement moves the base, because it shifts every popped dword", () => {
    const run = { at: 0x11221404, size: 0x24 };
    expect(stagingBase(run, span, plain, BAD)).toBe(0x11221404);
    expect(stagingBase(run, span, stagedPops("WriteProcessMemory", 4, 0), BAD)).toBe(0x11221408);
  });

  test("the pivot's own pops are popped off the base as well", () => {
    expect(stagedPops("WriteProcessMemory", 4, 1)).toEqual([-4, 0, 4, 8, 0xc, 0x10, 0x14, -4]);
    expect(stagedPops("VirtualProtect", 0, 0)).toEqual([0, 4, 8, 0xc, 0x10, 0x14, 0]);
  });
});
