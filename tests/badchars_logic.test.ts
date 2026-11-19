import { describe, expect, test } from "vitest";
import { compareBadchars, expectedBytes, nextBadcharCommand, pythonBadcharHelper, pythonBadcharsLine } from "../src/logic/badchars_logic";

describe("badchars logic", () => {
  test("writes the BADCHARS line sorted, deduplicated and lowercase", () => {
    expect(pythonBadcharsLine([0x0d, 0x00, 0x0a, 0x0d])).toBe('BADCHARS = b"\\x00\\x0a\\x0d"');
    expect(pythonBadcharsLine([])).toBe('BADCHARS = b""');
  });

  test("writes the next WinDbg command with the grown list and the same anchor", () => {
    expect(nextBadcharCommand("badchar_find", "0x0019ED3C", [0x3f, 0x00, 0x0a, 0x0d, 0x2b])).toBe(
      'dx @$osed().badchar_find(0x0019ED3C, "00 0A 0D 2B 3F")',
    );
    expect(nextBadcharCommand("badchar_find", "@esp", [0x00])).toBe('dx @$osed().badchar_find(@esp, "00")');
  });

  test("writes a Python helper that builds the test array from BADCHARS", () => {
    expect(pythonBadcharHelper([0x00, 0x0a], 76)).toEqual([
      'BADCHARS = b"\\x00\\x0a"  # add each new bad char here',
      "SPACE = 76  # contiguous bytes after EIP (0 = no limit)",
      "",
      "def badchar_array(bad=BADCHARS):",
      "    return bytes(b for b in range(256) if b not in bad)",
      "",
      "def badchar_block(start=0x01, size=SPACE, bad=BADCHARS):",
      "    return bytes(b for b in range(start, 256) if b not in bad)[:size or None]",
    ]);
  });

  test("builds expected bytes while excluding values", () => {
    const values = expectedBytes([0x00, 0x0a, 0x0d]);
    expect(values.includes(0x00)).toBe(false);
    expect(values.includes(0x0a)).toBe(false);
    expect(values.includes(0x0d)).toBe(false);
    expect(values.length).toBe(253);
  });

  test("detects dropped bytes as bad characters", () => {
    const expected = [0x01, 0x02, 0x03, 0x04, 0x05];
    const observed = Uint8Array.from([0x01, 0x02, 0x04, 0x05]);
    const result = compareBadchars(observed, expected);
    expect(result.badChars).toEqual([0x03]);
    expect(result.survivorCount).toBe(4);
    expect(result.expectedConsumed).toBe(5);
  });

  test("detects multiple dropped bytes", () => {
    const expected = expectedBytes([]);
    const observed = Uint8Array.from([
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0b, 0x0c, 0x0e, 0x0f, 0x10,
    ]);
    const result = compareBadchars(observed, expected);
    expect(result.badChars).toContain(0x00);
    expect(result.badChars).toContain(0x0a);
    expect(result.badChars).toContain(0x0d);
    expect(result.survivorCount).toBe(14);
  });

  test("reports no bad chars when all bytes survive", () => {
    const expected = [0x01, 0x02, 0x03, 0x04];
    const observed = Uint8Array.from([0x01, 0x02, 0x03, 0x04]);
    const result = compareBadchars(observed, expected);
    expect(result.badChars).toEqual([]);
    expect(result.survivorCount).toBe(4);
    expect(result.expectedConsumed).toBe(4);
  });

  test("handles truncated array with trailing junk", () => {
    const expected = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    const observed = Uint8Array.from([0x01, 0x02, 0x03, 0x00, 0x00]);
    const result = compareBadchars(observed, expected);
    expect(result.survivorCount).toBe(3);
    expect(result.expectedConsumed).toBe(3);
  });

  test("reports every lowered substitution in one pass", () => {
    const expected = expectedBytes([0x00]);
    const observed = Uint8Array.from(expected.map((value) => (value >= 0x61 && value <= 0x7a ? value - 0x20 : value)));
    const result = compareBadchars(observed, expected);
    expect(result.badChars).toEqual(expected.filter((value) => value >= 0x61 && value <= 0x7a));
    expect(result.expectedConsumed).toBe(expected.length);
    expect(result.truncatedAt).toBeUndefined();
  });

  test("reports a raised substitution without blaming its neighbours", () => {
    const expected = expectedBytes([0x00]);
    const observed = Uint8Array.from(expected.map((value) => (value === 0x0a ? 0x0d : value)));
    const result = compareBadchars(observed, expected);
    expect(result.badChars).toEqual([0x0a]);
    expect(result.mismatches).toEqual([{ offset: 0x09, expected: 0x0a, observed: 0x0d }]);
    expect(result.expectedConsumed).toBe(expected.length);
  });

  test("reports an expanded byte once", () => {
    const expected = expectedBytes([0x00]);
    const observed = Uint8Array.from(expected.flatMap((value) => (value === 0x0a ? [0x0d, 0x0a] : [value])));
    const result = compareBadchars(observed, expected);
    expect(result.badChars).toEqual([0x0a]);
    expect(result.expectedConsumed).toBe(expected.length);
  });

  test("collects drops and substitutions before a terminator and names the terminator", () => {
    const expected = expectedBytes([0x00]);
    const sent: number[] = [];
    for (const value of expected) {
      if (value === 0xc0) break;
      if (value === 0x20) continue;
      sent.push(value === 0x0a ? 0x00 : value);
    }
    const observed = Uint8Array.from([...sent, ...new Array(80).fill(0x43)]);
    const result = compareBadchars(observed, expected);
    expect(result.badChars).toEqual([0x0a, 0x20]);
    expect(result.expectedConsumed).toBe(expected.indexOf(0xc0));
    expect(result.truncatedAt).toBe(0xc0);
  });

  test("ignores a padding byte that matches the array by chance after the cut", () => {
    const expected = expectedBytes([0x00]);
    const sent = expected.slice(0, expected.indexOf(0x30));
    const observed = Uint8Array.from([...sent, ...new Array(300).fill(0x43)]);
    const result = compareBadchars(observed, expected);
    expect(result.badChars).toEqual([]);
    expect(result.truncatedAt).toBe(0x30);
  });

  test("recovers random replace and drop sets exactly, with and without a terminator", () => {
    let seed = 0x5eed;
    const next = (limit: number) => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % limit;
    };
    const expected = expectedBytes([0x00]);
    for (let trial = 0; trial < 2000; trial += 1) {
      const bad = new Set<number>();
      const count = 1 + next(12);
      while (bad.size < count) {
        const index = next(expected.length);
        if (![...bad].some((other) => Math.abs(other - index) < 3)) bad.add(index);
      }
      const cut = trial % 2 === 0 ? undefined : 40 + next(expected.length - 60);
      // A bad byte right before the cut leaves the same memory as a cut one byte earlier.
      if (cut !== undefined && [...bad].some((index) => index < cut && cut - index < 3)) continue;
      const sent: number[] = [];
      expected.forEach((value, index) => {
        if (cut !== undefined && index >= cut) return;
        if (!bad.has(index)) sent.push(value);
        else if (next(2) === 0) sent.push((value + 1 + next(255)) & 0xff);
      });
      const observed = Uint8Array.from([...sent, ...new Array(64).fill(0x00)]);
      const result = compareBadchars(observed, expected);
      const real = [...bad].filter((index) => cut === undefined || index < cut).sort((a, b) => a - b);
      const context = `trial ${trial}, cut ${cut}, bad ${real}`;
      expect(result.badChars, context).toEqual(real.map((index) => expected[index]));
      expect(result.truncatedAt, context).toBe(cut === undefined ? undefined : expected[cut]);
    }
  });
});

describe("compareBadchars on real stack junk after an early cut", () => {
  // Captured in WinDbg 10.0.19041 from a strcpy target cut at 0x04, read from just after the return address.
  const observed = new Uint8Array("01 02 03 00 00 00 6c 00 6c 00 2d 00 52 00 2d 00 00 00 00 00 00 00 00 00 00 00 00 00 9c 83 b5 77 62 7b 97 75 f0 00 00 00 58 ef 1a 00 01 00 00 00 a0 ef 1a 00 14 02 00 00 64 ef 1a 00 10 f2 1a 00 00 00 00 00 0b 00 00 00 10 f2 1a 00 14 f2 1a 00 e8 f1 1a 00 02 00 00 00 08 00 00 00 10 00 00 00 05 00 00 00 e0 f1 1a 00 95 7a 97 75 08 00 00 00 14 f2 1a 00 98 f2 1a 00 ad 7a 97 75 00 00 00 00 00 00 00 00 20 00 00 00 0c f0 1a 00 01 00 00 00 a0 ef 1a 00 1c 00 01 00 01 00 00 00 e3 dd b6 77 cc ef 1a 00 11 66 b4 77 c0 78 c1 77 f8 ef 1a 00 02 00 00 00 00 00 00 00 d8 9b af 77 01 00 00 00 fc ef 1a 00 cd 65 b4 77 f8 ef 1a 00 02 00 00 00 00 00 00 00 d8 9b af 77 01 00 00 00 01 00 00 00 d8 9b af 77 20 00 00 00 d8 9b af 77 52 00 af 77 10 f0 1a 00 20 00 00 00 7c f0 1a 00 01 00 00 00 d8 9b af 77 1c 00 01 00 01 00 00 00 e3 dd b6 77 3c f0 1a 00 11 66 b4 77 c0 78 c1 77 68 f0 1a 00 02 00 00 00 00 00 00 00 d8 9b af 77 01 00 00 00 6c f0 1a 00 cd 65 b4 77 68 f0 1a 00 02 00 00 00".split(" ").map((h) => parseInt(h, 16)));

  test("keeps the three bytes that arrived and names 0x04 as the terminator", () => {
    const compared = compareBadchars(observed, expectedBytes([0x00]));
    expect(compared).toMatchObject({ badChars: [], survivorCount: 3, expectedConsumed: 3, truncatedAt: 0x04, startOffset: 0 });
  });

  test("names 0x01 as the terminator when none of the array arrived", () => {
    const compared = compareBadchars(observed.slice(3), expectedBytes([0x00]));
    expect(compared).toMatchObject({ badChars: [], survivorCount: 0, truncatedAt: 0x01 });
  });
});
