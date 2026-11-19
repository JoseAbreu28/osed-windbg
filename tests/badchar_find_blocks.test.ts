import { beforeEach, describe, expect, test } from "vitest";
import { stripDml } from "../src/core/output";
import { initializeScript } from "../src/index";

type Api = Record<string, unknown> & {
  badchar_find: (...args: unknown[]) => boolean;
  badchar_function: (...args: unknown[]) => boolean;
  last_result: () => { findings: Array<Record<string, unknown>> } | undefined;
};

const SLOT = 0x637444;
const ESP = SLOT + 4;
const STACK_AFTER_SPACE = [0xc9, 0x1c, 0x78, 0x00, 0xf8, 0x37, 0x1e, 0x01, 0xd8, 0x72, 0x1f, 0x01, 0xb0, 0x75, 0x1e, 0x01];
const logs: string[] = [];

function range(first: number, last: number): number[] {
  return Array.from({ length: last - first + 1 }, (_, i) => first + i);
}

function loadApi(): Api {
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    currentProcess: { Is64Bit: false, Modules: [] },
  };
  initializeScript();
  return (globalThis as unknown as { osed: Api }).osed;
}

// Lays out a crash after `ret`: A padding, EIP = 0x42424242, then `afterEip` at ESP.
function installCrash(afterEip: number[]): void {
  const memory = new Map<number, number>();
  for (let a = SLOT - 0x100; a < SLOT; a += 1) memory.set(a, 0x41);
  const tail = [0x42, 0x42, 0x42, 0x42, ...afterEip];
  while (tail.length < 0x900) tail.push(0x00);
  tail.forEach((byte, i) => memory.set(SLOT + i, byte));

  const h = (globalThis as unknown as { host: Record<string, unknown> }).host;
  h.currentThread = { Registers: { User: { esp: { value: BigInt(ESP) }, eip: { value: BigInt(0x42424242) } } } };
  h.memory = {
    readMemoryValues(address: bigint | number, length: number) {
      const start = Number(address);
      const values: number[] = [];
      for (let i = 0; i < length; i += 1) {
        const byte = memory.get(start + i);
        if (byte === undefined) throw new Error("out of range");
        values.push(byte);
      }
      return values;
    },
  };
  logs.length = 0;
}

function printed(): string {
  return stripDml(logs.join(""));
}

describe("badchar_find in block mode", () => {
  let api: Api;
  beforeEach(() => {
    api = loadApi();
  });

  test("a first block that arrived whole moves on to the next start without a false terminator", () => {
    installCrash([...range(0x01, 0x4c), ...STACK_AFTER_SPACE]);
    api.badchar_find(ESP, "00", 2048, 8, 0x01, 76);
    const finding = api.last_result()?.findings[0];
    expect(finding).toMatchObject({ badChars: [], allExclude: [0x00], block: { start: 0x01, size: 76, step: { kind: "next", start: 0x4d } } });
    expect(finding?.truncatedAt).toBeUndefined();
    expect(printed()).toContain("Block clean: 0x01..0x4C arrived.");
    expect(printed()).toContain('Exploit line: BADCHARS = b"\\x00"');
    expect(printed()).toContain("Payload line: payload += badchar_block(0x4D)");
    expect(printed()).toContain('Next command: dx @$osed().badchar_find(@esp, "00", 2048, 8, 0x4D, 76)');
    expect(printed()).not.toContain("Likely terminator");
  });

  test("a later block is compared from its own start", () => {
    installCrash([...range(0x4d, 0x98), ...STACK_AFTER_SPACE]);
    api.badchar_find(ESP, "00", 2048, 8, 0x4d, 76);
    expect(api.last_result()?.findings[0]).toMatchObject({
      badChars: [],
      survivorCount: 76,
      block: { step: { kind: "next", start: 0x99 } },
    });
    expect(printed()).toContain("Next block: 0x99..0xE4");
  });

  test("a byte replaced inside a later block is reported and the same block goes again", () => {
    const block = range(0x4d, 0x98).map((b) => (b === 0x60 ? 0x20 : b));
    installCrash([...block, ...STACK_AFTER_SPACE]);
    api.badchar_find(ESP, "00", 2048, 8, 0x4d, 76);
    expect(api.last_result()?.findings[0]).toMatchObject({ badChars: [0x60], block: { step: { kind: "resend", start: 0x4d } } });
    expect(printed()).toContain('Exploit line: BADCHARS = b"\\x00\\x60"');
    expect(printed()).toContain("Payload line: payload += badchar_block(0x4D)");
    expect(printed()).toContain('Next command: dx @$osed().badchar_find(@esp, "00 60", 2048, 8, 0x4D, 76)');
  });

  test("a copy that stops inside the block names the first missing byte as the terminator", () => {
    installCrash([...range(0x4d, 0x5f), ...STACK_AFTER_SPACE]);
    api.badchar_find(ESP, "00", 2048, 8, 0x4d, 76);
    expect(api.last_result()?.findings[0]).toMatchObject({ truncatedAt: 0x60, block: { step: { kind: "resend", start: 0x4d } } });
    expect(printed()).toContain("bytes 0x60-0x98 not tested");
    expect(printed()).toContain('Next command: dx @$osed().badchar_find(@esp, "00 60", 2048, 8, 0x4D, 76)');
  });

  test.each([
    ["a full block", 0xb4],
    ["a short block", 0xe5],
  ])("%s that ends at 0xFF finishes the run", (_label, start) => {
    installCrash([...range(start, 0xff), ...STACK_AFTER_SPACE]);
    api.badchar_find(ESP, "00 0A", 2048, 8, start, 76);
    expect(api.last_result()?.findings[0]).toMatchObject({ badChars: [], block: { step: { kind: "done" } } });
    expect(printed()).toContain("All bytes 0x01..0xFF tested; this was the last block. Final list: 00 0A");
    expect(printed()).not.toContain("Next command");
  });

  test("without start and size the whole-array output is unchanged", () => {
    installCrash([...range(0x01, 0x4c), ...STACK_AFTER_SPACE]);
    api.badchar_find(undefined, "00");
    const finding = api.last_result()?.findings[0];
    expect(finding).toMatchObject({ truncatedAt: 0x4d });
    expect(finding).not.toHaveProperty("block");
    expect(printed()).toContain('Next command: dx @$osed().badchar_find(@esp, "00 4D")');
    expect(printed()).not.toContain("Payload line");
  });
});

describe("badchar_function with a space limit", () => {
  test("prints SPACE, the block helper, and the first block command", () => {
    const api = loadApi();
    logs.length = 0;
    api.badchar_function("00", 76);
    const text = printed();
    expect(text).toContain("SPACE = 76  # contiguous bytes after EIP (0 = no limit)");
    expect(text).toContain("def badchar_block(start=0x01, size=SPACE, bad=BADCHARS):");
    expect(text).toContain("    return bytes(b for b in range(start, 256) if b not in bad)[:size or None]");
    expect(text).toContain("payload += badchar_block(0x01)");
    expect(text).toContain('First command: dx @$osed().badchar_find(@esp, "00", 2048, 8, 0x01, 76)');
  });

  test("without a space it keeps the whole-array usage line", () => {
    const api = loadApi();
    logs.length = 0;
    api.badchar_function("00");
    expect(printed()).toContain("SPACE = 0");
    expect(printed()).toContain("payload += badchar_array()  # where the test array goes");
    expect(printed()).not.toContain("First command");
  });
});
