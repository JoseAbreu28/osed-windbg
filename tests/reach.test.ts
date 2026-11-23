import { describe, expect, test } from "vitest";
import { extraPops } from "../src/commands/dep_build";
import { sequence } from "../src/commands/dep_plan";
import { buildRopIndexFromRpPlusText } from "../src/rop";
import { LARGE_STACK_MOVE, MAX_HOPS, REGS, ReachIndex, constVal, effectOf, isPath, type Path, type Reg, type Val } from "../src/rop/reach";
import type { RopGadget } from "../src/rop/types";

// Loading a register is a search over gadgets, so the corpus a test needs is a list of disassembly lines.
// Addresses are given so a path can be read back by address, the way the emitted chain names them.
const corpus = (...lines: string[]): RopGadget[] =>
  buildRopIndexFromRpPlusText(lines.map((line, i) => `0x${(0x11110010 + i * 0x10).toString(16)}: ${line} ;  (1 found)`).join("\n")).gadgets;

const at = (lines: string[], i: number): number => 0x11110010 + i * 0x10;
const index = (...lines: string[]): ReachIndex => new ReachIndex(corpus(...lines));
const seek = (gadgets: ReachIndex, register: Reg, goal: Val, keep: string[] = [], bad: number[] = [0x00, 0x0a, 0x0d]): Path | undefined => {
  const result = gadgets.reach(register, goal, { bad, keep });
  return isPath(result) ? result : undefined;
};
const walk = (path: Path): string[] => path.hops.map((hop) => sequence(hop.gadget));

const PLAIN = ["pop eax ; ret", "pop ecx ; ret", "pop esi ; ret", "neg eax ; ret", "add eax, ecx ; ret"];

describe("effectOf", () => {
  test("a gadget whose first instruction destroys the register the rest would transform is no transition", () => {
    // sbb eax, eax runs before the neg, so this gadget cannot negate anything the chain put in eax. It
    // was once accepted as a negate; the register has to come out unknown, which drops it from the pool.
    const [gadget] = corpus("sbb eax, eax ; neg eax ; pop ebp ; ret");
    expect(effectOf(gadget)?.writes.eax).toEqual({ op: "unknown" });
    expect(seek(index("sbb eax, eax ; neg eax ; pop ebp ; ret", "pop eax ; ret"), "eax", constVal(0x00000001))).toBeUndefined();
  });

  test("push then pop is a move through the stack, and takes no dword from the chain", () => {
    const [gadget] = corpus("push eax ; pop esi ; ret");
    const effect = effectOf(gadget);
    expect(effect?.writes.esi).toEqual({ op: "reg", r: "eax" });
    expect(effect?.slots).toBe(0);
  });

  test("a gadget that moves ESP itself is no transition: the chain cannot resume after it", () => {
    for (const text of ["xchg eax, esp ; ret", "mov esp, ebp ; pop ebp ; ret", "leave ; ret"]) {
      expect(effectOf(corpus(text)[0]), text).toBeUndefined();
    }
  });

  test("a gadget whose ret is not last is no transition", () => {
    expect(effectOf(corpus("ret ; pop eax ; ret")[0])).toBeUndefined();
  });

  test("a dword read is recorded, so a path may only take it once it knows the address", () => {
    const effect = effectOf(corpus("mov esi, dword [esi] ; ret")[0]);
    expect(effect?.reads).toHaveLength(1);
    expect(effect?.writes.esi).toMatchObject({ op: "mem" });
  });
});

describe("reach", () => {
  test("a clean value is one pop", () => {
    const path = seek(index(...PLAIN), "eax", constVal(0x11223344));
    expect(walk(path as Path)).toEqual(["pop eax ; ret"]);
  });

  test("a value every pop would send as a bad byte is built in place instead", () => {
    // 0x00000001 cannot be popped under a 00 bad char, so the route pops its negative and negates.
    const path = seek(index(...PLAIN), "eax", constVal(0x00000001)) as Path;
    expect(walk(path)).toEqual(["pop eax ; ret", "neg eax ; ret"]);
    expect(path.hops[0].values[0]?.value).toBe(0xffffffff);
  });

  test("with no mov into the target, the value goes through the stack: push eax ; pop esi", () => {
    // This is the Sync Breeze case. A recipe that always moves EAX into the target dies here; a search
    // finds the push and pop, which is a move by another name.
    const lines = [...PLAIN, "push eax ; pop esi ; ret"];
    const path = seek(index(...lines), "esi", constVal(0x00000001)) as Path;
    expect(walk(path)).toEqual(["pop eax ; ret", "neg eax ; ret", "push eax ; pop esi ; ret"]);
  });

  test("an xchg reaches a register no mov writes", () => {
    const path = seek(index(...PLAIN, "xchg eax, esi ; ret"), "esi", constVal(0x00000001)) as Path;
    expect(walk(path)).toEqual(["pop eax ; ret", "neg eax ; ret", "xchg eax, esi ; ret"]);
  });

  test("a value only a run can give is read through a deref and carried by an add", () => {
    const goal: Val = { mem: { at: 0x10113200, text: "IAT_SLOT" }, k: 0xfffffd01, text: "API_DELTA" };
    const lines = [...PLAIN, "mov eax, dword [eax] ; ret", "push eax ; pop esi ; ret", "add esi, ecx ; ret"];
    const path = seek(index(...lines), "esi", goal) as Path;
    expect(walk(path)).toContain("mov eax, dword [eax] ; ret");
    expect(walk(path)).toContain("add esi, ecx ; ret");
    // The slot address holds a 00, so it is never popped raw: it arrives as a sum of two clean dwords.
    for (const hop of path.hops) for (const value of hop.values) {
      if (value) expect([0, 8, 16, 24].some((shift) => ((value.value >>> shift) & 0xff) === 0), value.text).toBe(false);
    }
  });

  test("the deref offset is taken off the address the chain pops, not left for the reader", () => {
    const goal: Val = { mem: { at: 0x11223344, text: "IAT_SLOT" }, k: 0, text: "0" };
    const path = seek(index("pop eax ; ret", "mov eax, dword [eax+0x04] ; ret"), "eax", goal) as Path;
    expect(walk(path)).toEqual(["pop eax ; ret", "mov eax, dword [eax+0x04] ; ret"]);
    expect(path.hops[0].values[0]?.value).toBe(0x11223340);
    expect(path.hops[0].values[0]?.text).toBe("IAT_SLOT - 0x00000004");
  });

  describe("a read that writes the old value back, as xchg dword [ecx], eax does", () => {
    const SWAP = ["pop ecx ; ret", "xchg dword [ecx], eax ; pop ebp ; ret"];
    const slot: Val = { mem: { at: 0x11223344, text: "IAT_SLOT" }, k: 0, text: "0" };

    test("faults on a read-only slot, so the search refuses it there", () => {
      expect(seek(index(...SWAP), "eax", slot)).toBeUndefined();
    });

    test("reads a slot the run showed writable, and says the old value is left in it", () => {
      const result = index(...SWAP).reach("eax", slot, { bad: [0x00], keep: [], writable: [0x11223344] });
      expect(isPath(result)).toBe(true);
      const path = result as Path;
      expect(walk(path)).toEqual(SWAP);
      expect(path.hops[1].clobbers).toEqual([0x11223344]);
      expect(path.hops[1].notes.join("; ")).toContain("the old value is left in that dword");
    });

    test("is one only when the swap is the gadget's sole memory access", () => {
      expect(effectOf(corpus("xchg dword [ecx], eax ; mov edx, dword [ecx] ; ret")[0])).toBeUndefined();
      expect(effectOf(corpus("xchg dword [ecx], eax ; mov dword [edx], ecx ; ret")[0])).toBeUndefined();
      expect(effectOf(corpus("xchg dword [ecx], eax ; ret")[0])?.swaps).toHaveLength(1);
    });
  });

  test("no hop writes a register the chain still needs", () => {
    // pop eax ; pop esi ; ret would load eax and destroy esi with it. With esi kept, it is out, and the
    // lone pop eax is the only route left.
    const lines = ["pop eax ; pop esi ; ret", "pop eax ; ret"];
    const kept = seek(index(...lines), "eax", constVal(0x11223344), ["esi"]) as Path;
    expect(walk(kept)).toEqual(["pop eax ; ret"]);
    expect(seek(index("pop eax ; pop esi ; ret"), "eax", constVal(0x11223344), ["esi"])).toBeUndefined();
  });

  test("a gadget that takes a frame of stack loses to a longer chain of ordinary ones", () => {
    const frame = `pop esi ; add esp, 0x${(LARGE_STACK_MOVE * 4).toString(16)} ; ret`;
    const path = seek(index(frame, "pop eax ; ret", "push eax ; pop esi ; ret"), "esi", constVal(0x11223344)) as Path;
    expect(walk(path)).toEqual(["pop eax ; ret", "push eax ; pop esi ; ret"]);
  });

  test("a gadget that takes a frame of stack still wins when nothing else does the job", () => {
    const frame = `pop esi ; add esp, 0x${(LARGE_STACK_MOVE * 4).toString(16)} ; ret`;
    const path = seek(index(frame, "pop eax ; ret"), "esi", constVal(0x11223344)) as Path;
    expect(walk(path)).toEqual([frame]);
  });

  test("a hop carries the gadgets with the same effect that ranked below it, and why each lost", () => {
    const path = seek(index("pop eax ; ret", "pop eax ; pop ebx ; ret"), "eax", constVal(0x11223344)) as Path;
    expect(walk(path)).toEqual(["pop eax ; ret"]);
    expect(path.hops[0].alts.map((alt) => alt.why)).toEqual(["also writes ebx"]);
  });

  test("an unreachable register says how many ways the module had to write it and how deep it looked", () => {
    const result = index("pop ebx ; ret", "pop eax ; ret").reach("ebx", constVal(0x00000001), { bad: [0x00], keep: [] });
    expect(isPath(result)).toBe(false);
    expect(result).toMatchObject({ providers: 1, maxHops: MAX_HOPS, exhausted: true });
  });

  test("a register the corpus cannot write at all is unreachable with nothing searched", () => {
    const result = index("pop eax ; ret").reach("ebp", constVal(0x11223344), { bad: [], keep: [] });
    expect(result).toMatchObject({ providers: 0, exhausted: true });
  });

  test("every address a path names is one of the gadgets it was given", () => {
    const lines = [...PLAIN, "mov eax, dword [eax] ; ret", "push eax ; pop esi ; ret", "add esi, ecx ; ret"];
    const addresses = lines.map((_, i) => at(lines, i));
    const goal: Val = { mem: { at: 0x10113200, text: "IAT_SLOT" }, k: 0xfffffd01, text: "API_DELTA" };
    const path = seek(index(...lines), "esi", goal) as Path;
    for (const hop of path.hops) expect(addresses).toContain(hop.gadget.locations[0].virtualAddress);
  });

  // Two mechanical invariants over a generated corpus, not over hand-picked ideal gadgets. Every finding
  // of the review that produced them was invisible to the tests above, because those always hand the
  // search a plain `pop <reg> ; ret` and it always wins on cost. A real module is not that tidy.
  describe("over a generated corpus", () => {
    const SHAPES = (a: string, b: string): string[] => [
      `pop ${a} ; ret`, `neg ${a} ; ret`, `inc ${a} ; ret`, `mov ${a}, ${b} ; ret`, `xchg ${a}, ${b} ; ret`,
      `add ${a}, ${b} ; ret`, `sub ${a}, ${b} ; ret`, `push ${b} ; pop ${a} ; ret`, `mov ${a}, dword [${b}] ; ret`,
      `mov ${a}, dword [${b}+0x4] ; ret`, `lea ${a}, dword [${b}+0x10] ; ret`, `mov dword [${a}], ${b} ; ret`,
      // The shapes the ideal corpus never has: a value in the second dword, a stack read, a wide stack
      // skip, a sub-register swap, a scaled index, and a read the ret itself would land on.
      `pop ${b} ; pop ${a} ; ret`, `add esp, 0x4 ; pop ${a} ; ret`, `pop ${a} ; add esp, 0x100 ; ret`,
      `mov ${a}, dword [esp] ; ret`, `mov ${a}, dword [esp+0x4] ; pop ${b} ; pop edi ; ret`,
      `xchg al, bl ; pop ${a} ; ret`, `xadd ${a}, ${b} ; pop edi ; ret`, `imul ${b} ; pop ${a} ; ret`,
      `mov ${a}, dword [${b}+edi*4] ; pop esi ; ret`, `sbb ${a}, ${a} ; neg ${a} ; pop ebp ; ret`,
      `pop ${a} ; ret 0x8`, `mov ${a}, dword [${b}] ; ret 0x4`,
    ];
    const lines = REGS.flatMap((a) => REGS.filter((b) => b !== a).flatMap((b) => SHAPES(a, b)));
    const gadgets = corpus(...lines);
    const goals: Array<[Reg, Val]> = [
      ["esi", { mem: { at: 0x10113200, text: "IAT_SLOT" }, k: 0xfffffd01, text: "API_DELTA" }],
      ["ebp", constVal(0x10111291, "JMP_ESP")], ["ebx", constVal(0x00000001)], ["edx", constVal(0x00001000)],
      ["ecx", constVal(0x00000040)], ["edi", constVal(0x10111123, "RET")], ["eax", constVal(0x90909090)],
    ];
    // Every register in turn, with the ones before it kept, which is how the pushad loaders ask. `thin`
    // drops the lone pops, so the multi-pop and stack-skip gadgets have to win: with a plain
    // `pop <reg> ; ret` present it always wins on cost and those shapes are never exercised at all.
    const paths = (thin = false): Path[] => {
      const index = new ReachIndex(thin ? corpus(...lines.filter((line) => !/^pop e[a-z]{2} ; ret$/.test(line))) : gadgets);
      const keep: string[] = [];
      const found: Path[] = [];
      for (const [register, goal] of goals) {
        const result = index.reach(register, goal, { bad: [0x00, 0x0a, 0x0d, 0x25, 0x26, 0x2b, 0x3d], keep: keep.slice() });
        if (isPath(result)) found.push(result);
        keep.push(register);
      }
      return found;
    };

    test("an accepted gadget takes exactly the stack dwords the emitter will pay for", () => {
      // reach counts the dwords after the gadget; the emitter counts them again from the instructions to
      // fill COST. They have to agree, or the chain gets the wrong number of junk dwords and derails.
      const accepted = gadgets.map((gadget) => ({ gadget, effect: effectOf(gadget) })).filter((row) => row.effect);
      expect(accepted.length).toBeGreaterThan(100);
      for (const { gadget, effect } of accepted) {
        expect(effect?.slots, sequence(gadget)).toBe(extraPops(gadget, 0));
      }
    });

    test("no gadget reads a stack dword its own ret would then jump to", () => {
      for (const gadget of gadgets) {
        const effect = effectOf(gadget);
        if (!effect) continue;
        // Such a gadget loads the register from the next chain address and returns into it. Rejecting it
        // is the only safe answer, so none may survive: `mov <reg>, dword [esp] ; ret` is the shape.
        expect(sequence(gadget), sequence(gadget)).not.toMatch(/^mov e[a-z]{2}, dword \[esp\] ; ret$/);
      }
    });

    test("no hop leaves a gap in its values, which would emit an empty call argument", () => {
      // Without the lone pops the search has to take `pop <other> ; pop <target> ; ret` and
      // `add esp, 0x4 ; pop <target> ; ret`, which want their value in a later dword. That is the shape
      // this whole change exists for, and it is the only one where a gap can arise.
      const found = [...paths(), ...paths(true)];
      const slotted = found.flatMap((path) => path.hops).filter((hop) => hop.values.length > 1);
      expect(slotted.length, "no hop wanted a value past its first dword, so nothing was exercised").toBeGreaterThan(0);
      for (const path of found) for (const hop of path.hops) {
        for (let i = 0; i < hop.values.length; i += 1) {
          expect(Object.prototype.hasOwnProperty.call(hop.values, i), `${sequence(hop.gadget)} slot ${i}`).toBe(true);
        }
      }
    });

    // The two gates that protect a kept register both read `effect.writes`, so a register the gadget
    // changes without `writes` naming it walks through both. These check the model against the
    // disassembly instead of against itself, which is the only way to see that kind of hole.
    const PARENT: Record<string, string> = { ax: "eax", al: "eax", ah: "eax", cx: "ecx", cl: "ecx", ch: "ecx",
      dx: "edx", dl: "edx", dh: "edx", bx: "ebx", bl: "ebx", bh: "ebx", si: "esi", di: "edi", bp: "ebp" };
    const BOTH = ["xchg", "xadd"];
    // The mnemonics whose first operand is a source, not a destination. Everything else here writes it.
    const READS_ONLY = ["push", "cmp", "test", "bt", "ret", "retn", "nop"];
    const operandRegisters = (gadget: RopGadget): string[] => {
      const written: string[] = [];
      for (const instruction of gadget.instructions) {
        if (READS_ONLY.indexOf(instruction.mnemonic) >= 0) continue;
        const operands = instruction.operands.map((operand) => operand.trim().toLowerCase());
        const take = BOTH.indexOf(instruction.mnemonic) >= 0 ? operands : operands.slice(0, 1);
        for (const operand of take) {
          const register = (REGS as string[]).indexOf(operand) >= 0 ? operand : PARENT[operand];
          if (register && written.indexOf(register) < 0) written.push(register);
        }
      }
      return written;
    };

    test("effectOf names every register an instruction writes, so none is destroyed behind the model", () => {
      let checked = 0;
      for (const gadget of gadgets) {
        const effect = effectOf(gadget);
        if (!effect) continue;
        // A destination operand the model does not list is a register the pool will promise to keep and
        // the gadget will overwrite. `xchg al, bl` and `xadd eax, ecx` are the shapes that do it.
        for (const register of operandRegisters(gadget)) {
          expect(Object.keys(effect.writes), sequence(gadget)).toContain(register);
          checked += 1;
        }
      }
      expect(checked).toBeGreaterThan(50);
    });

    test("a gadget whose real result lands in edx:eax is rejected, not modelled by its operand", () => {
      // One-operand imul, mul, div and idiv write edx:eax and leave the operand alone, so taking the
      // operand as the destination is the model wrong in both directions at once.
      for (const text of ["imul ecx ; ret", "mul ecx ; ret", "div ecx ; ret", "idiv ecx ; ret", "imul ecx ; pop eax ; ret"]) {
        expect(effectOf(corpus(text)[0]), text).toBeUndefined();
      }
      // The two and three operand forms write only their destination and stay usable as a clobber.
      expect(effectOf(corpus("imul eax, ecx ; ret")[0])?.writes.eax).toEqual({ op: "unknown" });
    });

    test("effectOf records every dereference, so no path takes one whose address nobody pinned", () => {
      let checked = 0;
      for (const gadget of gadgets) {
        const effect = effectOf(gadget);
        if (!effect) continue;
        // A scaled index is not something the search can write down, so the read has to be counted even
        // though its address cannot be solved: counted, it makes the gadget unusable instead of faulting.
        const reads = gadget.instructions.filter((instruction) =>
          instruction.mnemonic !== "lea" && instruction.mnemonic !== "pop" && instruction.mnemonic !== "push"
          && instruction.operands.slice(1).some((operand) => /\[/.test(operand) && !/\besp\b/.test(operand))).length;
        if (reads === 0) continue;
        expect(effect.reads.length, sequence(gadget)).toBeGreaterThanOrEqual(reads);
        checked += 1;
      }
      expect(checked).toBeGreaterThan(20);
    });
  });

  test("a path never runs past the hop limit", () => {
    const goal: Val = { mem: { at: 0x10113200, text: "IAT_SLOT" }, k: 0xfffffd01, text: "API_DELTA" };
    const lines = [...PLAIN, "mov eax, dword [eax] ; ret", "push eax ; pop esi ; ret", "add esi, ecx ; ret", "inc esi ; ret"];
    const path = seek(index(...lines), "esi", goal) as Path;
    expect(path.hops.length).toBeLessThanOrEqual(MAX_HOPS);
  });
});
