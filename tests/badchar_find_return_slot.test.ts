import { describe, expect, test } from "vitest";
import { createBadcharFindCommand } from "../src/commands/badchars";

const ESP = 0x63744c;
const SLOT = 0x637444;

function installCrash(bytesFromSlot: number[], eip = 0x42424242): void {
  const memory = new Map<number, number>();
  for (let a = SLOT - 0x100; a < SLOT; a += 1) memory.set(a, 0x41);
  const tail = [...bytesFromSlot];
  while (tail.length < 0x900) tail.push(0x00);
  tail.forEach((byte, i) => memory.set(SLOT + i, byte));

  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: () => undefined },
    currentProcess: { Is64Bit: false, Modules: [] },
    currentThread: {
      Registers: { User: { esp: { value: BigInt(ESP) }, eip: { value: BigInt(eip) } } },
    },
    memory: {
      readMemoryValues(address: bigint | number, length: number) {
        const start = Number(address);
        const out: number[] = [];
        for (let i = 0; i < length; i += 1) {
          const byte = memory.get(start + i);
          if (byte === undefined) throw new Error("out of range");
          out.push(byte);
        }
        return out;
      },
    },
  };
}

const syncBreezeStack = [0xc9, 0x1c, 0x78, 0x00, 0xf8, 0x37, 0x1e, 0x01, 0xd8, 0x72, 0x1f, 0x01, 0xb0, 0x75, 0x1e, 0x01, 0xf8, 0x37, 0x1e, 0x01, 0x06];

describe("badchar_find after a ret N with the array cut early", () => {
  test("names the first array byte as the terminator when nothing arrived after EIP", () => {
    installCrash([0x42, 0x42, 0x42, 0x42, 0x00, 0x74, 0x63, 0x00, ...syncBreezeStack]);
    const result = createBadcharFindCommand().execute({ address: ESP, exclude: [0x00], windowBytes: 2048, minRun: 8 });
    expect(result.findings[0]).toMatchObject({
      located: true,
      locatedBy: "return-slot",
      landingAddress: BigInt(SLOT + 4),
      survivorCount: 0,
      truncatedAt: 0x01,
    });
  });

  test("keeps the bytes that arrived before a cut at the fourth byte", () => {
    installCrash([0x42, 0x42, 0x42, 0x42, 0x01, 0x02, 0x03, 0x00, ...syncBreezeStack]);
    const result = createBadcharFindCommand().execute({ address: ESP, exclude: [0x00], windowBytes: 2048, minRun: 8 });
    expect(result.findings[0]).toMatchObject({ locatedBy: "return-slot", badChars: [], truncatedAt: 0x04 });
  });

  test("still locates an intact array by content", () => {
    const array = Array.from({ length: 255 }, (_, i) => i + 1);
    installCrash([0x42, 0x42, 0x42, 0x42, 0x00, 0x00, 0x00, 0x00, ...array]);
    const result = createBadcharFindCommand().execute({ address: ESP, exclude: [0x00], windowBytes: 2048, minRun: 8 });
    expect(result.findings[0]).toMatchObject({ locatedBy: "content", landingAddress: BigInt(ESP), badChars: [] });
    expect(result.findings[0]).not.toHaveProperty("truncatedAt", 0x01);
  });

  test("counts the array bytes that ret 4 left below the stack pointer", () => {
    const array = Array.from({ length: 254 }, (_, i) => i + 2).map((b) => (b === 0x3d ? 0x20 : b));
    installCrash([0x42, 0x42, 0x42, 0x42, ...array]);
    const result = createBadcharFindCommand().execute({ address: ESP, exclude: [0x00, 0x01], windowBytes: 2048, minRun: 8 });
    expect(result.findings[0]).toMatchObject({ locatedBy: "content", landingAddress: BigInt(SLOT + 4), badChars: [0x3d] });
    expect(result.findings[0]).not.toHaveProperty("truncatedAt", expect.anything());
  });

  test("reports not found when IP was never overwritten with a value on the stack", () => {
    installCrash([0x43, 0x43, 0x43, 0x43, 0x00, 0x74, 0x63, 0x00, ...syncBreezeStack]);
    const result = createBadcharFindCommand().execute({ address: ESP, exclude: [0x00], windowBytes: 2048, minRun: 8 });
    expect(result.findings[0]).toEqual({ located: false });
  });
});
