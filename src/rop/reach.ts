import { RopGadget } from "./types";

// Loading a register as a search. Each gadget is a transition over register state: a gadget's Effect says,
// for every register it changes, what that register holds at its ret in terms of what the registers held
// before it, the dwords the chain places after it, and the memory it reads. A load is a short sequence of
// such transitions, found backwards from the goal: "esi must hold [IAT_SLOT] + API_DELTA" through
// `add esi, ecx` becomes "esi must hold [IAT_SLOT] and ecx must hold API_DELTA", and so on until nothing
// is required. A gadget that writes a register the chain still needs is never a transition.

export type Reg = "eax" | "ecx" | "edx" | "ebx" | "esi" | "edi" | "ebp";
export const REGS: Reg[] = ["eax", "ecx", "edx", "ebx", "esi", "edi", "ebp"];

export type Expr =
  | { op: "reg"; r: Reg }
  | { op: "slot"; i: number }
  | { op: "const"; v: number }
  | { op: "add" | "sub" | "xor"; a: Expr; b: Expr }
  | { op: "neg" | "not"; a: Expr }
  | { op: "mem"; a: Expr; id: number }
  | { op: "unknown" };

export type Effect = {
  gadget: RopGadget;
  /** Every register the gadget changes, with its value at the ret. Unknown means clobbered. */
  writes: Partial<Record<Reg, Expr>>;
  /** Ids of the mem nodes the gadget reads. Each must be one the search pinned to an address. */
  reads: number[];
  stores: Array<{ at: Expr; value: Expr }>;
  /** Dwords the gadget takes from the chain after itself, before its ret. */
  slots: number;
  retn: number;
};

/** The value a register must hold: the dword at a known address, if any, plus a constant. */
export type Val = { mem?: { at: number; text: string }; k: number; text: string };

/** A gadget with the same effect on the register that lost to the one the hop took. */
export type Alternative = { gadget: RopGadget; why: string };

export type Hop = {
  gadget: RopGadget;
  /** Values for the dwords after the gadget, in order. Undefined is junk, and the array is dense: a
   * gadget can want its value in its second dword, and a hole renders as an empty call argument. */
  values: Array<{ value: number; text: string } | undefined>;
  /** What the gadget does to the registers the load needs, and what they hold after it. */
  notes: string[];
  kind: string;
  /** Same effect, ranked lower. Each is a drop-in for this hop and nothing else in the path moves. */
  alts: Alternative[];
};

export type Path = { hops: Hop[]; searched: number };

/** Why no path exists, in the terms the message needs: how wide the search was and how far it got. */
export type Unreached = { searched: number; exhausted: boolean; providers: number; maxHops: number };

export type ReachOptions = {
  bad: number[];
  /** Registers that already hold values the chain needs. */
  keep: string[];
  /** A writable dword without bad bytes, for the route through memory. */
  scratch?: { at: number; text: string };
  maxHops?: number;
  maxNodes?: number;
};

export const MAX_HOPS = 8;
export const MAX_NODES = 40000;
/** Stack a gadget may skip and still be a transition. Beyond this its junk dwords dwarf any payload. */
export const MAX_STACK_SKIP = 0x4000;
/** Bytes of stack a gadget may take before the cost function treats it as a frame, mirroring dep_plan. */
export const LARGE_STACK_MOVE = 0x40;

const MASK = (v: number): number => v >>> 0;
const hex = (v: number): string => `0x${MASK(v).toString(16).toUpperCase().padStart(8, "0")}`;
export const clean = (v: number, bad: number[]): boolean => [0, 8, 16, 24].every((s) => bad.indexOf((MASK(v) >>> s) & 0xff) < 0);

// ---------------------------------------------------------------------------------------------------------
// The interpreter: one Effect per gadget, or undefined when the gadget does something a load cannot use
// safely (moves ESP, jumps, writes memory through an address nobody controls, pushes then rets into it).

const SUB: Record<string, Reg> = { ax: "eax", al: "eax", ah: "eax", cx: "ecx", cl: "ecx", ch: "ecx", dx: "edx", dl: "edx", dh: "edx",
  bx: "ebx", bl: "ebx", bh: "ebx", si: "esi", di: "edi", bp: "ebp" };
const isReg = (s: string): s is Reg => (REGS as string[]).indexOf(s) >= 0;
const NO_EFFECT = ["nop", "cmp", "test", "clc", "stc", "cld", "cmc", "fwait", "wait", "fnop", "bt"];
const CLOBBER_FIRST = ["and", "or", "imul", "shl", "shr", "sar", "sal", "rol", "ror", "rcl", "rcr", "bswap", "adc", "sbb",
  "movzx", "movsx", "cmove", "cmovne", "cmovz", "cmovnz", "cmova", "cmovb", "cmovae", "cmovbe", "cmovg", "cmovl", "cmovge", "cmovle",
  "cmovs", "cmovns", "sete", "setne", "setz", "setnz", "seta", "setb", "bsf", "bsr", "xadd"];

const imm = (s: string): number | undefined => {
  const t = s.replace(/^(dword|word|byte)\s+/, "");
  if (/^-?0x[0-9a-f]+$/.test(t)) return MASK(parseInt(t, 16));
  if (/^-?[0-9]+$/.test(t)) return MASK(parseInt(t, 10));
  return undefined;
};

/** `dword [eax+0x04]` as base and offset; undefined for anything with an index or a size other than dword. */
function memOperand(s: string): { base: string; off: number; size: string } | undefined | "complex" {
  const m = /^(?:(dword|word|byte|qword)\s+(?:ptr\s+)?)?(?:[a-z]s:)?\[([^\]]+)\]$/.exec(s);
  if (!m) return undefined;
  const inner = m[2].replace(/\s+/g, "");
  const b = /^([a-z]{3})(?:([+-])(0x[0-9a-f]+|[0-9]+))?$/.exec(inner);
  if (!b || (!isReg(b[1]) && b[1] !== "esp")) return "complex";
  const off = b[3] ? parseInt(b[3], b[3].indexOf("0x") === 0 ? 16 : 10) * (b[2] === "-" ? -1 : 1) : 0;
  return { base: b[1], off, size: m[1] ?? "dword" };
}

let memIds = 0;

export function simplify(e: Expr): Expr {
  switch (e.op) {
    case "add": case "sub": case "xor": {
      const a = simplify(e.a);
      const b = simplify(e.b);
      if (a.op === "unknown" || b.op === "unknown") return { op: "unknown" };
      if (a.op === "const" && b.op === "const") return { op: "const", v: MASK(e.op === "add" ? a.v + b.v : e.op === "sub" ? a.v - b.v : a.v ^ b.v) };
      if (b.op === "const" && b.v === 0) return a;
      if (e.op === "add" && a.op === "const" && a.v === 0) return b;
      if (e.op === "sub" && a.op === "const" && b.op !== "const") return simplify({ op: "add", a: { op: "neg", a: b }, b: a });
      // keep constants on the right and fold chains of them: (x + 4) + 4 is x + 8
      if (e.op !== "xor" && b.op === "const" && (a.op === "add" || a.op === "sub") && a.b.op === "const") {
        const inner = a.op === "add" ? a.b.v : -a.b.v;
        const total = MASK(inner + (e.op === "add" ? b.v : -b.v));
        return simplify({ op: "add", a: a.a, b: { op: "const", v: total } });
      }
      if (e.op === "add" && a.op === "const") return { op: "add", a: b, b: a };
      if (e.op === "sub" && b.op === "const") return { op: "add", a, b: { op: "const", v: MASK(-b.v) } };
      if (e.op === "xor" && a.op === "reg" && b.op === "reg" && a.r === b.r) return { op: "const", v: 0 };
      return { op: e.op, a, b };
    }
    case "neg": case "not": {
      const a = simplify(e.a);
      if (a.op === "unknown") return a;
      if (a.op === "const") return { op: "const", v: MASK(e.op === "neg" ? -a.v : ~a.v) };
      if (a.op === e.op) return a.a;
      return { op: e.op, a };
    }
    case "mem": {
      const a = simplify(e.a);
      return a.op === "unknown" ? a : a === e.a ? e : { op: "mem", a, id: e.id };
    }
    default:
      return e;
  }
}

export function effectOf(gadget: RopGadget): Effect | undefined {
  const regs: Record<string, Expr> = {};
  for (const r of REGS) regs[r] = { op: "reg", r };
  const written = new Set<Reg>();
  const pushed: Record<number, Expr> = {};
  const reads: number[] = [];
  const stores: Array<{ at: Expr; value: Expr }> = [];
  let sp = 0;
  let deepest = 0;
  const value = (s: string): Expr | undefined => {
    if (isReg(s)) return regs[s];
    const n = imm(s);
    if (n !== undefined) return { op: "const", v: n };
    return undefined;
  };
  const stackAt = (off: number): Expr | undefined => {
    if (off % 4 !== 0) return undefined;
    if (pushed[off] !== undefined) return pushed[off];
    if (off < 0) return undefined;
    deepest = Math.max(deepest, off / 4 + 1);
    return { op: "slot", i: off / 4 };
  };
  const read = (m: { base: string; off: number }): Expr | undefined => {
    if (m.base === "esp") return stackAt(sp + m.off);
    const node: Expr = { op: "mem", a: simplify({ op: "add", a: regs[m.base], b: { op: "const", v: MASK(m.off) } }), id: ++memIds };
    reads.push((node as { id: number }).id);
    return node;
  };
  const set = (r: Reg, e: Expr | undefined): void => {
    regs[r] = e === undefined ? { op: "unknown" } : simplify(e);
    written.add(r);
  };
  const ins = gadget.instructions;
  for (let n = 0; n < ins.length; n += 1) {
    const mnemonic = ins[n].mnemonic.toLowerCase();
    const ops = ins[n].operands.map((o) => o.trim().toLowerCase());
    const [d, s] = ops;
    const dm = d !== undefined ? memOperand(d) : undefined;
    const sm = s !== undefined ? memOperand(s) : undefined;
    if (mnemonic === "ret" || mnemonic === "retn") {
      if (n !== ins.length - 1 || sp < 0 || pushed[sp] !== undefined) return undefined;
      break;
    }
    if (ops.indexOf("esp") >= 0 || ops.indexOf("sp") >= 0) {
      // A gadget that skips stack is still a transition: `c.rop` pays for the skipped dwords in junk, so
      // the cost function prices it and the search takes it only when nothing cheaper does the job. The
      // bound is there so `slots` stays a number worth printing, not to express a policy.
      if (mnemonic === "add" && d === "esp" && imm(s ?? "") !== undefined && (imm(s ?? "") as number) % 4 === 0 && (imm(s ?? "") as number) < MAX_STACK_SKIP) {
        sp += imm(s ?? "") as number;
        deepest = Math.max(deepest, sp / 4);
        continue;
      }
      if (mnemonic === "push" && d === "esp") { sp -= 4; pushed[sp] = { op: "unknown" }; continue; }
      return undefined;
    }
    if (dm === "complex" || sm === "complex") {
      if (dm !== undefined) return undefined;
      if (!d || !(isReg(d) || SUB[d])) return undefined;
      // `lea` computes the address and reads nothing. Anything else dereferences it, and the search cannot
      // pin an address it cannot write down, so the read gets an id no expression carries: the gadget is
      // then unusable rather than silently faulting on whatever the index register happened to hold.
      if (mnemonic !== "lea") reads.push(++memIds);
      set(isReg(d) ? d : SUB[d], undefined);
      continue;
    }
    if (NO_EFFECT.indexOf(mnemonic) >= 0) {
      if (sm && typeof sm === "object" && sm.base !== "esp") reads.push(++memIds);
      if (dm && typeof dm === "object" && dm.base !== "esp") reads.push(++memIds);
      continue;
    }
    if (mnemonic === "pop") {
      if (!d || !isReg(d)) return undefined;
      set(d, stackAt(sp));
      if (regs[d].op === "unknown") return undefined;
      sp += 4;
      continue;
    }
    if (mnemonic === "push") {
      if (!d) return undefined;
      let v: Expr | undefined = value(d);
      if (!v && dm && typeof dm === "object") v = read(dm);
      if (!v) return undefined;
      sp -= 4;
      pushed[sp] = v;
      continue;
    }
    if (dm && typeof dm === "object") {
      // A write to memory. Only a dword store of a register or constant is a transition, and the search
      // decides whether its address is the scratch dword. Anything else writes somewhere nobody chose.
      if (mnemonic !== "mov" || dm.size !== "dword" || dm.base === "esp" || !s) return undefined;
      const v = value(s);
      if (!v) return undefined;
      stores.push({ at: simplify({ op: "add", a: regs[dm.base], b: { op: "const", v: MASK(dm.off) } }), value: v });
      continue;
    }
    if (!d) return undefined;
    const target: Reg | undefined = isReg(d) ? d : SUB[d];
    if (!target) return undefined;
    // An instruction that writes through both its operands has to say so, or the pool hands it out as a
    // gadget that keeps a register it in fact destroys. `xadd` writes both; one-operand `imul` writes
    // edx:eax and leaves its operand alone, which is the model wrong in both directions, so it is out.
    if (mnemonic === "xadd" && s !== undefined && (isReg(s) || SUB[s])) set(isReg(s) ? s : SUB[s], undefined);
    else if (mnemonic === "xadd") return undefined;
    if ((mnemonic === "imul" || mnemonic === "mul" || mnemonic === "div" || mnemonic === "idiv") && ops.length === 1) return undefined;
    if (!isReg(d)) {
      // `xchg al, bl` swaps through both, and the sub-register form never reaches the xchg case below.
      if (mnemonic === "xchg") return undefined;
      if (sm && typeof sm === "object") { if (read(sm) === undefined) return undefined; }
      set(target, undefined);
      continue;
    }
    const src = (): Expr | undefined => (sm && typeof sm === "object" ? (sm.size === "dword" ? read(sm) : (read(sm), { op: "unknown" })) : s !== undefined ? value(s) ?? (SUB[s] ? { op: "unknown" } : undefined) : undefined);
    switch (mnemonic) {
      case "mov": { const v = src(); if (!v) return undefined; set(d, v); break; }
      case "lea": {
        const m = s ? memOperand(s) : undefined;
        if (!m || m === "complex" || m.base === "esp") return undefined;
        set(d, { op: "add", a: regs[m.base], b: { op: "const", v: MASK(m.off) } });
        break;
      }
      case "add": case "sub": case "xor": { const v = src(); if (!v) return undefined; set(d, { op: mnemonic, a: regs[d], b: v }); break; }
      case "inc": set(d, { op: "add", a: regs[d], b: { op: "const", v: 1 } }); break;
      case "dec": set(d, { op: "add", a: regs[d], b: { op: "const", v: MASK(-1) } }); break;
      case "neg": set(d, { op: "neg", a: regs[d] }); break;
      case "not": set(d, { op: "not", a: regs[d] }); break;
      case "xchg": {
        if (!s || !isReg(s)) return undefined;
        const a = regs[d];
        set(d, regs[s]);
        set(s, a);
        break;
      }
      default:
        if (CLOBBER_FIRST.indexOf(mnemonic) >= 0) {
          if (sm && typeof sm === "object") read(sm);
          set(d, undefined);
          break;
        }
        return undefined;
    }
  }
  const last = ins[ins.length - 1];
  if (!last || (last.mnemonic !== "ret" && last.mnemonic !== "retn")) return undefined;
  // The ret consumes the dword at the final ESP, so every stack dword the gadget read must sit below it.
  // `mov eax, [esp] ; ret` reads the dword the ret then jumps to: taking it as a value the chain supplies
  // would load the register correctly and send execution to that value. It is not a transition.
  if (deepest > sp / 4) return undefined;
  const writes: Partial<Record<Reg, Expr>> = {};
  written.forEach((r) => {
    const e = regs[r];
    if (!(e.op === "reg" && e.r === r)) writes[r] = e;
  });
  const retOperand = last.operands[0];
  const retn = retOperand ? (imm(retOperand.trim().toLowerCase()) ?? 0) : 0;
  return { gadget, writes, reads, stores, slots: Math.max(deepest, sp / 4), retn };
}

// ---------------------------------------------------------------------------------------------------------
// Values and their Python text.

const isLiteral = (text: string): boolean => /^0x[0-9A-F]{8}$/.test(text);
export const constVal = (k: number, text?: string): Val => ({ k: MASK(k), text: text ?? hex(k) });
const minus = (g: Val, c: number, cText?: string): Val => {
  const k = MASK(g.k - c);
  if (isLiteral(g.text) && (!cText || isLiteral(cText))) return { mem: g.mem, k, text: hex(k) };
  if (MASK(c) === 0) return g;
  return { mem: g.mem, k, text: c > 0x7fffffff && !cText ? `${g.text} + ${hex(-c)}` : `${g.text} - ${cText ?? hex(c)}` };
};
const negated = (g: Val): Val => ({ k: MASK(-g.k), text: isLiteral(g.text) ? hex(-g.k) : `neg(${g.text})` });
const inverted = (g: Val): Val => ({ k: MASK(~g.k), text: isLiteral(g.text) ? hex(~g.k) : `~(${g.text})` });
const xored = (g: Val, x: number): Val => ({ k: MASK(g.k ^ x), text: isLiteral(g.text) ? hex(g.k ^ x) : `(${g.text}) ^ ${hex(x)}` });

export function describe(g: Val): string {
  if (!g.mem) return g.text;
  if (g.k === 0) return `[${g.mem.text}]`;
  return `[${g.mem.text}] + ${g.text}`;
}

/** Clean seeds x with c - x clean too: a few uniform bytes first, then a fixed walk. */
function cleanPairs(c: number, combine: (c: number, x: number) => number, bad: number[], limit = 2): number[] {
  const found: number[] = [];
  const tryX = (x: number): void => {
    x = MASK(x);
    if (found.length < limit && found.indexOf(x) < 0 && clean(x, bad) && clean(combine(c, x), bad)) found.push(x);
  };
  for (let b = 0x01; b <= 0xff && found.length < limit; b += 0x11) tryX(b * 0x01010101);
  let seed = 0x9e3779b9;
  for (let i = 0; i < 4000 && found.length < limit; i += 1) {
    seed = MASK(seed * 1664525 + 1013904223);
    tryX(seed);
  }
  return found;
}

// ---------------------------------------------------------------------------------------------------------
// Regression: what must hold before a gadget so that `e` equals `g` after it.

type Need = { regs: Array<[Reg, Val]>; slots: Array<[number, number, string]>; pinned: number[]; scratch?: Val; fail?: boolean };

const join = (a: Need, b: Need): Need => ({
  regs: a.regs.concat(b.regs), slots: a.slots.concat(b.slots), pinned: a.pinned.concat(b.pinned),
  scratch: a.scratch ?? b.scratch,
});

function solve(e: Expr, g: Val, opts: ReachOptions, depth = 0): Need[] {
  if (depth > 4) return [];
  const pure = !g.mem;
  switch (e.op) {
    case "reg": return [{ regs: [[e.r, g]], slots: [], pinned: [] }];
    case "slot": return pure && clean(g.k, opts.bad) ? [{ regs: [], slots: [[e.i, g.k, g.text]], pinned: [] }] : [];
    case "const": return pure && MASK(e.v) === g.k ? [{ regs: [], slots: [], pinned: [] }] : [];
    case "unknown": return [];
    case "neg": return pure ? solve(e.a, negated(g), opts, depth + 1) : [];
    case "not": return pure ? solve(e.a, inverted(g), opts, depth + 1) : [];
    case "mem": {
      const out: Need[] = [];
      if (g.mem && g.k === 0) {
        for (const need of solve(e.a, constVal(g.mem.at, g.mem.text), opts, depth + 1)) out.push(join(need, { regs: [], slots: [], pinned: [e.id] }));
      }
      if (opts.scratch && !(g.mem && g.k === 0)) {
        for (const need of solve(e.a, constVal(opts.scratch.at, opts.scratch.text), opts, depth + 1)) {
          out.push(join(need, { regs: [], slots: [], pinned: [e.id], scratch: g }));
        }
      }
      return out;
    }
    case "add": case "sub": case "xor": {
      if (e.b.op === "const") {
        const c = e.b.v;
        const next = e.op === "xor" ? (pure ? xored(g, c) : undefined) : minus(g, e.op === "add" ? c : MASK(-c));
        // A corpus has hundreds of `lea eax, [ecx+N]` and `add eax, N`, each turning the goal into another
        // number. Only an adjustment that lands on something one more gadget finishes is a step forward: a
        // clean constant, zero, or a bare read. Small ones (inc, dec, +-4) are always allowed.
        const small = MASK(c) <= 4 || MASK(-c) <= 4;
        if (!next || (!small && depth === 0 && !(next.mem ? next.k === 0 : clean(next.k, opts.bad) || next.k === 0))) return [];
        return solve(e.a, next, opts, depth + 1);
      }
      // Two unknowns: split the value. The dword read goes whole to one side, the constant to the other;
      // a pure constant is cut into two clean halves, or into itself and zero.
      const splits: Array<[Val, Val]> = [];
      if (e.op === "add") {
        if (g.mem) {
          splits.push([{ mem: g.mem, k: 0, text: "0" }, constVal(g.k, g.text)]);
          splits.push([constVal(g.k, g.text), { mem: g.mem, k: 0, text: "0" }]);
        } else {
          for (const x of cleanPairs(g.k, (c, x) => c - x, opts.bad)) splits.push([minus(g, x), constVal(x)]);
          splits.push([g, constVal(0)], [constVal(0), g]);
        }
      } else if (e.op === "sub") {
        if (g.mem) splits.push([{ mem: g.mem, k: 0, text: "0" }, negated(constVal(g.k, g.text))]);
        else {
          for (const x of cleanPairs(g.k, (c, x) => c + x, opts.bad)) splits.push([minus(g, MASK(-x)), constVal(x)]);
          splits.push([g, constVal(0)]);
        }
      } else if (pure) {
        for (const x of cleanPairs(g.k, (c, x) => c ^ x, opts.bad)) splits.push([xored(g, x), constVal(x)]);
      }
      const out: Need[] = [];
      for (const [ga, gb] of splits) {
        for (const na of solve(e.a, ga, opts, depth + 1)) for (const nb of solve(e.b, gb, opts, depth + 1)) out.push(join(na, nb));
        if (out.length >= 6) break;
      }
      return out;
    }
  }
}

// ---------------------------------------------------------------------------------------------------------
// The search.

/** What the search draws from: per register the distinct effects on it, the gadgets that store to memory,
 * and for each kept effect the ones with the same effect that ranked below it. */
type Pool = { byReg: Record<string, Effect[]>; storers: Effect[]; alts: Map<Effect, Alternative[]> };

type Node = { regs: Map<Reg, Val>; scratch?: Val; cost: number; hops: number; prev?: Node; hop?: Hop; f?: number };
// A* bound: every outstanding requirement takes at least one more gadget, at 1000 per gadget.
const estimate = (node: Node): number => node.cost + 1000 * (node.regs.size + (node.scratch ? 1 : 0));

const sameVal = (a: Val, b: Val): boolean => a.k === b.k && (a.mem?.at ?? -1) === (b.mem?.at ?? -1);
const keyOf = (node: { regs: Map<Reg, Val>; scratch?: Val }): string => {
  const parts: string[] = [];
  node.regs.forEach((v, r) => parts.push(`${r}=${v.mem ? `[${v.mem.at}]` : ""}${v.k}`));
  parts.sort();
  if (node.scratch) parts.push(`M=${node.scratch.mem ? `[${node.scratch.mem.at}]` : ""}${node.scratch.k}`);
  return parts.join(",");
};

function show(e: Expr, slots: Map<number, string>): string {
  switch (e.op) {
    case "reg": return e.r;
    case "slot": return slots.get(e.i) ?? "junk";
    case "const": return hex(e.v);
    case "add": return e.b.op === "const" && e.b.v > 0x7fffffff ? `${show(e.a, slots)} - ${hex(-e.b.v)}` : `${show(e.a, slots)} + ${show(e.b, slots)}`;
    case "sub": return `${show(e.a, slots)} - ${show(e.b, slots)}`;
    case "xor": return `${show(e.a, slots)} ^ ${show(e.b, slots)}`;
    case "neg": return `-${show(e.a, slots)}`;
    case "not": return `~${show(e.a, slots)}`;
    case "mem": return `[${show(e.a, slots)}]`;
    case "unknown": return "?";
  }
}

function kindOf(e: Expr): string {
  switch (e.op) {
    case "slot": return "pop";
    case "mem": return "read";
    case "reg": return "move";
    case "neg": return "negate";
    case "not": return "invert";
    case "xor": return "xor";
    case "sub": return "subtract";
    case "add": return e.b.op === "const" ? "adjust" : "add";
    default: return "set";
  }
}

class Heap {
  private items: Node[] = [];
  get size(): number { return this.items.length; }
  push(node: Node): void {
    const a = this.items;
    a.push(node);
    let i = a.length - 1;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if ((a[p].f ?? a[p].cost) <= (a[i].f ?? a[i].cost)) break;
      [a[p], a[i]] = [a[i], a[p]];
      i = p;
    }
  }
  pop(): Node | undefined {
    const a = this.items;
    if (a.length === 0) return undefined;
    const top = a[0];
    const last = a.pop() as Node;
    if (a.length > 0) {
      a[0] = last;
      let i = 0;
      for (;;) {
        const l = 2 * i + 1;
        const r = l + 1;
        let m = i;
        if (l < a.length && (a[l].f ?? a[l].cost) < (a[m].f ?? a[m].cost)) m = l;
        if (r < a.length && (a[r].f ?? a[r].cost) < (a[m].f ?? a[m].cost)) m = r;
        if (m === i) break;
        [a[m], a[i]] = [a[i], a[m]];
        i = m;
      }
    }
    return top;
  }
}

/** Junk dwords the gadget leaves on the stack after the values the chain gives it. The payload grows by
 * four bytes each, so they are priced; past LARGE_STACK_MOVE the gadget is a frame and takes a penalty
 * no chain of ordinary gadgets can lose to, the same line dep_plan draws for its job picks. */
const spare = (effect: Effect, filled: number): number => Math.max(0, effect.slots - filled);
const stackCost = (effect: Effect, filled: number): number => {
  const dwords = spare(effect, filled);
  return dwords * 3 + (dwords * 4 > LARGE_STACK_MOVE ? 1000 * MAX_HOPS : 0);
};

/** Why one gadget of a pair with the same effect ranks above the other, in the reader's terms. */
function beatenBy(chosen: Effect, other: Effect): string {
  const clobbers = (effect: Effect): string[] => Object.keys(effect.writes);
  const extra = clobbers(other).filter((r) => clobbers(chosen).indexOf(r) < 0);
  if (extra.length > 0) return `also writes ${extra.join(", ")}`;
  if (other.slots > chosen.slots) return `takes 0x${(other.slots * 4).toString(16)} bytes of stack, against 0x${(chosen.slots * 4).toString(16)}`;
  if (other.retn > chosen.retn) return `ret 0x${other.retn.toString(16)} skips further past its values`;
  if (other.reads.length > chosen.reads.length) return "reads memory this one does not";
  return "more instructions, same effect";
}

/** Gadgets indexed by the register they write, keeping for each distinct effect on that register only the
 * ones no other gadget beats on every side effect. Built once per corpus and per set of kept registers. */
export class ReachIndex {
  private effects: Effect[];
  private cache: Record<string, Pool> = {};

  constructor(gadgets: RopGadget[]) {
    this.effects = [];
    for (const gadget of gadgets) {
      const effect = effectOf(gadget);
      if (effect) this.effects.push(effect);
    }
  }

  static fromEffects(effects: Effect[]): ReachIndex {
    const index = new ReachIndex([]);
    index.effects = effects;
    return index;
  }

  plus(extra: Effect[]): ReachIndex {
    return ReachIndex.fromEffects(this.effects.concat(extra));
  }

  get size(): number { return this.effects.length; }

  pool(keep: string[]): Pool {
    const key = keep.slice().sort().join(",");
    if (this.cache[key]) return this.cache[key];
    const usable = this.effects.filter((effect) => Object.keys(effect.writes).every((r) => keep.indexOf(r) < 0));
    const clobbers = (effect: Effect): number => Object.keys(effect.writes).length;
    const weight = (effect: Effect): number => clobbers(effect) * 10 + stackCost(effect, 1) + effect.retn + effect.gadget.instructions.length;
    const byReg: Record<string, Effect[]> = {};
    const alts = new Map<Effect, Alternative[]>();
    for (const r of REGS) {
      const groups: Record<string, Effect[]> = {};
      for (const effect of usable) {
        const e = effect.writes[r];
        if (!e || e.op === "unknown" || effect.stores.length > 0) continue;
        const sig = JSON.stringify(e, (k, v) => (k === "id" ? undefined : v));
        (groups[sig] = groups[sig] ?? []).push(effect);
      }
      const kept: Effect[] = [];
      for (const sig of Object.keys(groups)) {
        const members = groups[sig].sort((a, b) => weight(a) - weight(b));
        const front: Effect[] = [];
        for (const m of members) {
          const mw = Object.keys(m.writes);
          const beaten = front.some((f) => Object.keys(f.writes).every((w) => mw.indexOf(w) >= 0) && f.slots <= m.slots && f.retn <= m.retn && f.reads.length <= m.reads.length);
          if (!beaten) front.push(m);
          if (front.length >= 3) break;
        }
        kept.push(...front);
        // Every other member does the same thing to this register, so each is a drop-in for whichever of
        // the front the path takes. Two is what fits a screen beside the line it would replace.
        for (const chosen of front) {
          alts.set(chosen, members.filter((other) => other !== chosen).slice(0, 2)
            .map((other) => ({ gadget: other.gadget, why: beatenBy(chosen, other) })));
        }
      }
      byReg[r] = kept;
    }
    const storers = usable.filter((effect) => effect.stores.length === 1).sort((a, b) => weight(a) - weight(b)).slice(0, 40);
    this.cache[key] = { byReg, storers, alts };
    return this.cache[key];
  }

  /** The shortest sequence of gadgets that leaves `goal` in `target`, without writing `opts.keep`. */
  reach(target: Reg, goal: Val, opts: ReachOptions): Path | Unreached {
    const maxHops = opts.maxHops ?? MAX_HOPS;
    const maxNodes = opts.maxNodes ?? MAX_NODES;
    const { byReg, storers, alts } = this.pool(opts.keep);
    const providers = (byReg[target] ?? []).length;
    const start: Node = { regs: new Map([[target, goal]]), cost: 0, hops: 0 };
    const best: Record<string, number> = { [keyOf(start)]: 0 };
    const open = new Heap();
    open.push(start);
    let searched = 0;
    let truncated = false;
    while (open.size > 0) {
      const node = open.pop() as Node;
      if (node.regs.size === 0 && !node.scratch) {
        const hops: Hop[] = [];
        for (let at: Node | undefined = node; at && at.hop; at = at.prev) hops.push(at.hop);
        return { hops, searched };
      }
      if (best[keyOf(node)] < node.cost) continue;
      if (node.hops >= maxHops) continue;
      if (++searched > maxNodes) { truncated = true; break; }
      const seen = new Set<Effect>();
      const candidates: Effect[] = [];
      node.regs.forEach((_, r) => { for (const effect of byReg[r] ?? []) if (!seen.has(effect)) { seen.add(effect); candidates.push(effect); } });
      if (node.scratch) for (const effect of storers) if (!seen.has(effect)) { seen.add(effect); candidates.push(effect); }
      for (const effect of candidates) {
        for (const next of this.regress(node, effect, opts, alts.get(effect) ?? [])) {
          const key = keyOf(next);
          if (best[key] !== undefined && best[key] <= next.cost) continue;
          best[key] = next.cost;
          next.f = estimate(next);
          open.push(next);
        }
      }
    }
    return { searched, exhausted: !truncated, providers, maxHops };
  }

  private regress(node: Node, effect: Effect, opts: ReachOptions, alts: Alternative[]): Node[] {
    // Every register the gadget writes that the load needs is regressed through it; the rest stay.
    const needed: Array<[Reg, Val, Expr]> = [];
    let clobbered = 0;
    for (const r of Object.keys(effect.writes) as Reg[]) {
      const v = node.regs.get(r);
      if (v) needed.push([r, v, effect.writes[r] as Expr]);
      else clobbered += 1;
    }
    let alternatives: Need[] = [{ regs: [], slots: [], pinned: [] }];
    for (const [, v, e] of needed) {
      const next: Need[] = [];
      for (const need of solve(e, v, opts)) for (const alt of alternatives) next.push(join(alt, need));
      alternatives = next.slice(0, 8);
      if (alternatives.length === 0) return [];
    }
    let storeNote: string | undefined;
    if (effect.stores.length > 0) {
      if (!node.scratch || !opts.scratch || effect.stores.length !== 1) return [];
      const store = effect.stores[0];
      const next: Need[] = [];
      for (const alt of alternatives) {
        for (const at of solve(store.at, constVal(opts.scratch.at, opts.scratch.text), opts)) {
          for (const v of solve(store.value, node.scratch, opts)) next.push({ ...join(join(alt, at), v), scratch: alt.scratch });
        }
      }
      alternatives = next;
      storeNote = `[${opts.scratch.text}] = ${describe(node.scratch)}`;
    }
    const out: Node[] = [];
    for (const alt of alternatives) {
      if (effect.reads.some((id) => alt.pinned.indexOf(id) < 0)) continue;
      const regs = new Map<Reg, Val>();
      node.regs.forEach((v, r) => { if (!effect.writes[r]) regs.set(r, v); });
      let ok = true;
      for (const [r, v] of alt.regs) {
        if (opts.keep.indexOf(r) >= 0) { ok = false; break; }
        const have = regs.get(r);
        if (have && !sameVal(have, v)) { ok = false; break; }
        regs.set(r, v);
      }
      const slots = new Map<number, string>();
      const values: Array<{ value: number; text: string } | undefined> = [];
      for (const [i, value, text] of alt.slots) {
        if (values[i] && values[i]?.value !== value) { ok = false; break; }
        values[i] = { value, text };
        slots.set(i, text);
      }
      if (!ok) continue;
      let scratch = node.scratch;
      if (storeNote) scratch = undefined;
      if (alt.scratch) {
        if (scratch && !sameVal(scratch, alt.scratch)) continue;
        scratch = alt.scratch;
      }
      const notes = needed.map(([r, v, e]) => (e.op === "slot" ? `${r} = ${slots.get(e.i)}` : `${r} = ${show(e, slots)}, now ${describe(v)}`));
      if (storeNote) notes.push(storeNote);
      const kind = storeNote ? "store" : needed.length > 0 ? kindOf(needed[0][2]) : "set";
      const cost = node.cost + 1000 + clobbered * 10 + stackCost(effect, values.length) + effect.retn + effect.gadget.instructions.length;
      // `values` was filled by slot index, so a gadget that wants its value in its second dword leaves the
      // first unset. An unset index is a hole, which `map` and spread turn into an empty call argument and
      // the pasted file then fails to parse, so the gaps are made explicit before the hop carries them.
      const dense: Array<{ value: number; text: string } | undefined> = [];
      for (let i = 0; i < values.length; i += 1) dense.push(values[i]);
      out.push({ regs, scratch, cost, hops: node.hops + 1, prev: node, hop: { gadget: effect.gadget, values: dense, notes, kind, alts } });
    }
    return out;
  }
}

export const isPath = (result: Path | Unreached): result is Path => "hops" in result;
