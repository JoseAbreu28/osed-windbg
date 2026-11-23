import { describe, expect, test } from "vitest";
import { jobsFor, met, planJobs, planSkeleton, sequence } from "../src/commands/dep_plan";
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
    const { plans, tried } = planSkeleton(index, [], "VirtualProtect", facts, BAD);
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
    const { plans } = planSkeleton(index, [], "VirtualProtect", facts, BAD);
    const copy = plans.filter((plan) => plan.job.key === "copy")[0];
    const write = plans.filter((plan) => plan.job.key === "write")[0];
    expect(copy.pick?.at.dest ?? copy.path?.to).toBe(write.pick!.at.address);
    // Not the one the ranking reaches first: `mov edi, esi` sits at a lower address and is still usable.
    expect(sequence(copy.pick!.gadget)).toBe("mov ecx, esi ; ret");
  });

  test("a module with one write is left alone, and nothing is weighed", () => {
    const index = corpus(...TWO_WRITES.filter((line) => line !== "mov dword [ecx], eax ; ret"));
    const { plans, tried } = planSkeleton(index, [], "VirtualProtect", facts, BAD);
    expect(tried).toEqual([]);
    expect(sequence(plans.filter((plan) => plan.job.key === "write")[0].pick!.gadget)).toBe("mov dword [edi], ecx ; ret");
  });

  // The field address reaches the write's register by a sequence when no single gadget takes it there.
  test("with no single copy into the write's register, a path carries the field address", () => {
    const index = corpus(...TWO_WRITES.filter((line) => line !== "mov ecx, esi ; ret"), "xchg edi, ecx ; ret");
    const { plans } = planSkeleton(index, [], "VirtualProtect", facts, BAD);
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
