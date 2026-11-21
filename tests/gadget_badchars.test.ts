import { describe, expect, test } from "vitest";
import { stripDml } from "../src/core/output";
import { initializeScript, normalizeInvocation } from "../src/index";

type Result = { success: boolean; errors: string[]; findings: unknown[]; args: Record<string, unknown> };
type Api = Record<string, (...args: unknown[]) => unknown> & { last_result: () => Result };

const BASE = BigInt(0x400000);
const TEXT = BASE + BigInt(0x1000);

function writeUint16LE(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}

function writeUint32LE(bytes: Uint8Array, offset: number, value: number): void {
  writeUint16LE(bytes, offset, value & 0xffff);
  writeUint16LE(bytes, offset + 2, (value >>> 16) & 0xffff);
}

// target.exe at 0x00400000 with one executable .text section at 0x00401000.
function loadTarget(code: Array<[number, number[]]>): { api: Api; logs: string[] } {
  const image = new Uint8Array(0x5000);
  const peOffset = 0x80;
  const sectionTable = peOffset + 0x18 + 0xe0;
  writeUint16LE(image, 0x0, 0x5a4d);
  writeUint32LE(image, 0x3c, peOffset);
  writeUint32LE(image, peOffset, 0x4550);
  writeUint16LE(image, peOffset + 0x6, 1);
  writeUint16LE(image, peOffset + 0x14, 0xe0);
  image.set(Array.from(".text").map((char) => char.charCodeAt(0)), sectionTable);
  writeUint32LE(image, sectionTable + 0x8, 0x2000);
  writeUint32LE(image, sectionTable + 0xc, 0x1000);
  writeUint32LE(image, sectionTable + 0x24, 0x20000000);
  for (const [address, bytes] of code) image.set(bytes, address - Number(BASE));

  const logs: string[] = [];
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    currentProcess: {
      Is64Bit: false,
      Modules: [{ Name: "target.exe", Path: "C:\\labs\\target.exe", BaseAddress: BASE, EndAddress: BASE + BigInt(image.length) }],
    },
    memory: {
      readMemoryValues(address: bigint | number, length: number) {
        const offset = Number((typeof address === "bigint" ? address : BigInt(address)) - BASE);
        if (offset < 0 || offset + length > image.length) throw new Error("out of range");
        return Array.from(image.slice(offset, offset + length));
      },
    },
  };
  initializeScript();
  logs.length = 0;
  return { api: (globalThis as unknown as { osed: Api }).osed, logs };
}

function addresses(result: Result): number[] {
  return result.findings.map((finding) => {
    const record = finding as { address?: bigint };
    return Number(record.address ?? finding);
  });
}

function holdsByte(address: number, byte: number): boolean {
  return [0, 8, 16, 24].some((shift) => ((address >>> shift) & 0xff) === byte);
}

const DIRTY_POP = 0x0040110a;
const CLEAN_POP = 0x00401120;
const POP_EAX_RET = [0x58, 0xc3];

describe("bad chars in the gadget scan commands", () => {
  test("rop_suggest with no list keeps an address that holds a bad char and prints no drop line", () => {
    const { api, logs } = loadTarget([[DIRTY_POP, POP_EAX_RET], [CLEAN_POP, POP_EAX_RET]]);
    api.rop_suggest("target", 10);
    const result = api.last_result();
    expect(result.success).toBe(true);
    expect(addresses(result)).toEqual(expect.arrayContaining([DIRTY_POP, CLEAN_POP]));
    expect(stripDml(logs.join(""))).not.toContain("Bad chars");
  });

  test("rop_suggest with a list drops the address that holds a bad char and counts it", () => {
    const { api, logs } = loadTarget([[DIRTY_POP, POP_EAX_RET], [CLEAN_POP, POP_EAX_RET]]);
    api.rop_suggest("target", 10, "0A");
    const result = api.last_result();
    expect(result.success).toBe(true);
    expect(addresses(result)).toContain(CLEAN_POP);
    expect(addresses(result)).not.toContain(DIRTY_POP);
    expect(addresses(result).filter((address) => holdsByte(address, 0x0a))).toEqual([]);
    expect(stripDml(logs.join(""))).toContain("Bad chars 0A: dropped 1 candidate address(es) that contain one.");
  });

  test("rop_suggest semantic engine filters the same way", () => {
    const { api } = loadTarget([[DIRTY_POP, POP_EAX_RET], [CLEAN_POP, POP_EAX_RET]]);
    api.rop_suggest("target", 10, "0A", true, "fast", "semantic");
    const result = api.last_result();
    expect(result.success).toBe(true);
    const found = result.findings.map((gadget) => (gadget as { locations: Array<{ virtualAddress: number }> }).locations[0].virtualAddress);
    expect(found).toContain(CLEAN_POP);
    expect(found).not.toContain(DIRTY_POP);
  });

  test("rop_suggest keeps the older boolean third argument as executableOnly", () => {
    const { api, logs } = loadTarget([[DIRTY_POP, POP_EAX_RET], [CLEAN_POP, POP_EAX_RET]]);
    api.rop_suggest("target", 10, true, "fast", "legacy");
    const result = api.last_result();
    expect(result.success).toBe(true);
    expect(result.args).toMatchObject({ executableOnly: true, mode: "fast", engine: "legacy", badchars: [] });
    expect(addresses(result)).toContain(DIRTY_POP);
    expect(stripDml(logs.join(""))).not.toContain("Bad chars");
  });

  test("a bad-char list that does not parse fails instead of scanning unfiltered", () => {
    const { api } = loadTarget([[DIRTY_POP, POP_EAX_RET]]);
    api.rop_suggest("target", 10, "zz");
    expect(api.last_result().success).toBe(false);
    expect(api.last_result().errors.join(" ")).toContain("badchars");
  });

  test("the spellings scan_live accepts and the \\x form parse to the same bytes", () => {
    const expected = [0x00, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20];
    for (const spelling of ["00 09 0A 0B 0C 0D 20", "00,09,0a,0b,0c,0d,20", "00090A0B0C0D20", "\\x00\\x09\\x0a\\x0b\\x0c\\x0d\\x20", "0x00 0x09 0x0A 0x0B 0x0C 0x0D 0x20"]) {
      expect(normalizeInvocation("rop_suggest", ["libbkup", 3, spelling]).badchars, spelling).toEqual(expected);
    }
  });

  test("the positional rule is the same for every gadget scan command", () => {
    for (const name of ["pivots", "retn", "add_esp"]) {
      expect(normalizeInvocation(name, ["m", 5, "0A", false, "thorough"])).toEqual({ module: "m", maxResults: 5, badchars: [0x0a], executableOnly: false, mode: "thorough" });
      expect(normalizeInvocation(name, ["m", 5, false, "thorough"])).toEqual({ module: "m", maxResults: 5, badchars: undefined, executableOnly: false, mode: "thorough" });
    }
    expect(normalizeInvocation("find_bytes", ["m", "FF E4", 5, "0A", false])).toMatchObject({ bytes: [0xff, 0xe4], maxResults: 5, badchars: [0x0a], executableOnly: false });
    expect(normalizeInvocation("find_bytes", ["m", "FF E4", 5, false, "thorough"])).toMatchObject({ badchars: undefined, executableOnly: false, mode: "thorough" });
  });

  test("find_bytes drops a hit whose address holds a bad char", () => {
    const { api, logs } = loadTarget([[DIRTY_POP, POP_EAX_RET], [CLEAN_POP, POP_EAX_RET]]);
    api.find_bytes("target", "58 C3", 10);
    expect(addresses(api.last_result())).toEqual([DIRTY_POP, CLEAN_POP]);
    api.find_bytes("target", "58 C3", 10, "\\x0a");
    expect(addresses(api.last_result())).toEqual([CLEAN_POP]);
    expect(stripDml(logs.join(""))).toContain("Bad chars 0A: dropped 1 candidate address(es) that contain one.");
    expect(stripDml(logs.join(""))).not.toContain("no byte matches found");
  });

  test("retn reports the first clean address for each N", () => {
    const { api } = loadTarget([[0x0040120a, [0xc2, 0x08, 0x00]], [0x00401230, [0xc2, 0x08, 0x00]]]);
    api.retn("target", 10);
    expect(api.last_result().findings).toEqual([{ n: 8, address: BigInt(0x0040120a), count: 2 }]);
    api.retn("target", 10, "0A");
    expect(api.last_result().findings).toEqual([{ n: 8, address: BigInt(0x00401230), count: 1 }]);
  });

  test("add_esp reports the first clean address for each N", () => {
    const { api } = loadTarget([[0x0040140a, [0x83, 0xc4, 0x10, 0xc3]], [0x00401450, [0x83, 0xc4, 0x10, 0xc3]]]);
    api.add_esp("target", 10);
    expect(addresses(api.last_result())).toEqual([0x0040140a]);
    api.add_esp("target", 10, "0A");
    expect(addresses(api.last_result())).toEqual([0x00401450]);
  });

  test("pivots shows a clean copy of a pivot instead of the first one", () => {
    const { api } = loadTarget([[0x0040130a, [0x94, 0xc3]], [0x00401340, [0x94, 0xc3]]]);
    api.pivots("target", 10);
    expect(addresses(api.last_result())).toEqual([0x0040130a]);
    api.pivots("target", 10, "0A");
    expect(addresses(api.last_result())).toEqual([0x00401340]);
  });

  test(".explain names the bad chars from the call, and reads the older order as executableOnly", () => {
    const { api } = loadTarget([[CLEAN_POP, POP_EAX_RET]]);
    const filtered = (api.rop_suggest("target", 3, "00 0A") as { explain: Record<string, string> }).explain;
    expect(filtered.Report).toBe("Surveyed the gadgets available in target with rop_suggest to plan the ROP chain, excluding addresses that contain the bad characters 00 0A.");
    expect(filtered.Arguments).toContain("<badchars> = 00 0A");

    const older = (api.rop_suggest("target", 3, false) as { explain: Record<string, string> }).explain;
    expect(older.Arguments).toContain("<executableOnly> = false");
    expect(older.Arguments).not.toContain("<badchars> =");
  });
});
