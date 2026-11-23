import { describe, expect, test } from "vitest";
import { buildExploit, extraPops, lastRetN } from "../src/commands/dep_build";
import { gadgetAddress, hex32, planSkeleton, sequence } from "../src/commands/dep_plan";
import { buildCapabilityIndexFromRpPlusText } from "../src/rop";

// The emitted file pads junk for the stack dwords a gadget takes past the values the chain hands it, and
// it reads how many from one COST row per gadget. A row is therefore a fact about the gadget and nothing
// else: a count of leftovers measured at one call site is wrong at every other, and a dict keyed by
// address lets one gadget's drop-in swap define another gadget's row.
//
// This is what went wrong on T05. `pop ecx ; pop esi ; ret` was a chain gadget called with two values,
// so its leftover was zero and it was left out of COST, while the same address was also listed as a
// drop-in swap of `pop ecx ; ret` with a leftover of one. The swap's row was the only one Python saw, the
// chain padded a junk dword after the two values, and the next ret took 0x41414141.

const corpus = (...lines: string[]) =>
  buildCapabilityIndexFromRpPlusText(lines.map((line, i) => `0x${(0x11110010 + i * 0x10).toString(16)}: ${line} ;  (1 found)`).join("\n"));

const BAD = [0x00, 0x0a, 0x0d];
const FACTS = { iatSlot: 0x11225544, writable: 0x11224444 };

// Two pops of ECX, one of them taking ESI with it, so the pair is both a chain gadget in its own right
// and a lower-ranked swap of the other. The only route to 0x00000201 is pop-then-add, which needs both
// dwords of the two-pop gadget, so the chain calls it with two values.
const LINES = [
  "push esp ; pop eax ; ret",
  "add eax, ebx ; ret",
  "pop ebx ; ret",
  "mov edx, eax ; ret",
  "mov dword [edx], ecx ; ret",
  "inc edx ; ret",
  "add edx, ebx ; ret",
  "mov esp, edx ; ret",
  "pop ecx ; ret",
  "mov ecx, dword [ecx] ; ret",
  "pop ecx ; pop esi ; ret",
  "add ecx, esi ; ret",
];

const blockLines = (build: ReturnType<typeof buildExploit>): string[] => {
  const block = build.blocks[4];
  if ("none" in block) throw new Error("[4/7] has no copy block");
  return block.lines;
};

/** The address a COST key stands for: a literal, or the `NAME = 0x...` line above it. */
const addressIn = (lines: string[], name: string): number => {
  if (name.indexOf("0x") === 0) return Number(name);
  const line = lines.find((text) => text.split("=")[0].trim() === name) ?? "";
  return Number(/= (0x[0-9A-F]{8})/.exec(line)?.[1] ?? 0);
};

const built = () => {
  const index = corpus(...LINES);
  const { plans } = planSkeleton(index, [], "VirtualProtect", FACTS, BAD);
  const build = buildExploit({
    api: "VirtualProtect", style: "skeleton", module: "t.dll", badchars: BAD,
    index, plans, exclude: [], stage: 1, ...FACTS,
  });
  return { index, build };
};

/** The COST literal of [4/7], as the pairs Python would read, keyed by whatever the line wrote. */
const costOf = (lines: string[]): Array<[string, number, number]> => {
  const line = lines.find((text) => text.indexOf("COST = {") === 0) ?? "";
  const body = line.slice(line.indexOf("{") + 1, line.lastIndexOf("}"));
  const rows = [...body.matchAll(/(\S+): \((\d+), (0x[0-9a-f]+|0)\)/g)]
    .map(([, name, pops, retn]): [string, number, number] => [name, Number(pops), Number(retn)]);
  const pairs = (body.match(/\(/g) ?? []).length;
  if (rows.length !== pairs) throw new Error(`parsed ${rows.length} of ${pairs} COST entries from: ${body}`);
  return rows;
};

describe("the cost table the emitted chain pads from", () => {
  test("each gadget appears once, however many of the table's rows list it as a swap", () => {
    const { build } = built();
    const lines = blockLines(build);
    const addresses = costOf(lines).map(([name]) => addressIn(lines, name));
    expect(addresses).toEqual([...new Set(addresses)]);
    expect(addresses.every((address) => address !== 0)).toBe(true);
  });

  // A name in COST is a NAME = 0x... line above it, so a row for a named gadget and a row for the same
  // address written as a literal are the same Python key. Neither may disagree with the gadget.
  test("a row counts the dwords the gadget itself takes, not what one call site left over", () => {
    const { index, build } = built();
    const lines = blockLines(build);
    const rows = costOf(lines);
    for (const [name, pops, retn] of rows) {
      const address = addressIn(lines, name);
      const gadget = index.gadgets.find((candidate) => gadgetAddress(candidate) === address);
      expect(gadget, `COST names ${name} = ${hex32(address)}, which is not in the corpus`).toBeDefined();
      expect([sequence(gadget!), pops]).toEqual([sequence(gadget!), extraPops(gadget!, 0)]);
      expect(retn).toBe(lastRetN(gadget!));
    }
    expect(rows.length).toBeGreaterThan(0);
  });

  test("the emitted chain pads by what the gadget still wants after its values", () => {
    const { build } = built();
    const lines = blockLines(build);
    expect(lines).toContain("        self.extend([gadget] + [JUNK] * (self.skip // 4) + list(values) + [JUNK] * max(0, pops - len(values)))");
  });

  // The call site that proves the point: one gadget, both its dwords given, and a row that says two.
  test("a two-pop gadget called with both its dwords has a row saying it takes two", () => {
    const { build } = built();
    const two = build.table.find((entry) => entry.sequence === "pop ecx ; pop esi ; ret");
    expect(two, "this corpus no longer uses the two-pop gadget, so it no longer exercises the rule").toBeDefined();
    expect(two!.pops).toBe(2);
    expect(costOf(blockLines(build)).find(([name]) => name === two!.name)?.[1]).toBe(2);
  });
});
