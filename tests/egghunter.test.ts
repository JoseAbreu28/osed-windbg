import { describe, expect, test } from "vitest";
import { buildEgghunter } from "../src/commands/egghunter";

const NO_BADCHARS: number[] = [];
const DEFAULTS = { badchars: NO_BADCHARS, os: "win10", syscall: null };
const XP = { badchars: NO_BADCHARS, os: "xp", syscall: null };

describe("NtAccess egghunter", () => {
  test("generates 34-byte stub with tag embedded", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, ...DEFAULTS });
    expect(result.size).toBe(34);
    expect(result.badcharHits).toEqual([]);
    // Tag "W00T" = [0x57, 0x30, 0x30, 0x54] at offset 20
    expect(result.bytes[20]).toBe(0x57); // W
    expect(result.bytes[21]).toBe(0x30); // 0
    expect(result.bytes[22]).toBe(0x30); // 0
    expect(result.bytes[23]).toBe(0x54); // T
  });

  test("embeds custom tag correctly", () => {
    const result = buildEgghunter({ tag: "B33F", mode: "ntaccess", wow64: false, ...DEFAULTS });
    expect(result.bytes[20]).toBe(0x42); // B
    expect(result.bytes[21]).toBe(0x33); // 3
    expect(result.bytes[22]).toBe(0x33); // 3
    expect(result.bytes[23]).toBe(0x46); // F
  });

  test("default syscall number is 0x1C9", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, ...DEFAULTS });
    expect(result.syscallUsed).toBe(0x1c9);
    // mov eax, 0x1C9 at offset 8: b8 c9 01 00 00
    expect(result.bytes[7]).toBe(0xb8);
    expect(result.bytes[8]).toBe(0xc9);
    expect(result.bytes[9]).toBe(0x01);
    expect(result.bytes[10]).toBe(0x00);
    expect(result.bytes[11]).toBe(0x00);
  });

  test("custom syscall number is patched in", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: NO_BADCHARS, os: "win10", syscall: 0x02 });
    expect(result.syscallUsed).toBe(0x02);
    expect(result.bytes[8]).toBe(0x02);
    expect(result.bytes[9]).toBe(0x00);
    expect(result.bytes[10]).toBe(0x00);
    expect(result.bytes[11]).toBe(0x00);
  });

  test("win7 preset uses syscall 0x02", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: NO_BADCHARS, os: "win7", syscall: null });
    expect(result.syscallUsed).toBe(0x02);
    expect(result.bytes[8]).toBe(0x02);
  });

  test("syscall parameter overrides os preset", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: NO_BADCHARS, os: "win7", syscall: 0x1c9 });
    expect(result.syscallUsed).toBe(0x1c9);
    expect(result.bytes[8]).toBe(0xc9);
    expect(result.bytes[9]).toBe(0x01);
  });

  test("WoW64 variant matches the stub that found an egg in a WOW64 process", () => {
    // Run on Windows 11 x64 with tests/manual/egghunter_wow64; exit code 1337 = egg reached.
    const wow64 = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: true, ...DEFAULTS });
    const hex = wow64.bytes.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join("");
    expect(hex).toBe("33DB53535353535353535353B3C06681CAFF0F425252B82900000064FF135A5A3C0574EAB8573030548BFAAF75E5AF75E2FFE7");
    expect(wow64.syscallUsed).toBe(0x29);
  });

  test("WoW64 variant has no int 0x2e", () => {
    const wow64 = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: true, ...DEFAULTS });
    const text = wow64.bytes.join(",");
    expect(text).not.toContain([0xcd, 0x2e].join(","));
  });

  test("WoW64 explicit syscall is patched at offset 23", () => {
    const wow64 = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: true, badchars: [0x26], os: null, syscall: 0x26 });
    expect(wow64.bytes.slice(22, 27)).toEqual([0xb8, 0x26, 0x00, 0x00, 0x00]);
    expect(wow64.badcharHits).toEqual(["byte 0x26 at offset 23 in ntaccess wow64 egghunter"]);
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
    const result = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, ...DEFAULTS });
    // Stub contains 0x0f and 0xcd — test those as badchars
    const withBad = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, badchars: [0x0f, 0xcd], os: "win10", syscall: null });
    expect(withBad.badcharHits.length).toBeGreaterThan(0);
    expect(withBad.badcharHits.some((h) => h.includes("0x0F"))).toBe(true);
    expect(withBad.badcharHits.some((h) => h.includes("0xCD"))).toBe(true);
  });

  test("reports badchars in the tag itself", () => {
    const result = buildEgghunter({ tag: "A\x00BC", mode: "ntaccess", wow64: false, badchars: [0], os: "win10", syscall: null });
    expect(result.badcharHits.some((h) => h.includes("0x00"))).toBe(true);
  });
});

describe("NtDisplayString egghunter", () => {
  test("generates 32-byte stub with tag embedded", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, ...XP });
    expect(result.size).toBe(32);
    expect(result.badcharHits).toEqual([]);
    // Tag at offset 18
    expect(result.bytes[18]).toBe(0x57); // W
    expect(result.bytes[19]).toBe(0x30); // 0
    expect(result.bytes[20]).toBe(0x30); // 0
    expect(result.bytes[21]).toBe(0x54); // T
  });

  test("uses push imm8 / pop eax for syscall number", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, ...XP });
    // push 0x43 at offset 7-8, pop eax at offset 9
    expect(result.bytes[7]).toBe(0x6a);  // push imm8
    expect(result.bytes[8]).toBe(0x43);  // NtDisplayString syscall
    expect(result.bytes[9]).toBe(0x58);  // pop eax
    expect(result.syscallUsed).toBe(0x43);
  });

  test("custom syscall number is patched as single byte", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, badchars: NO_BADCHARS, os: "win10", syscall: 0x55 });
    expect(result.syscallUsed).toBe(0x55);
    expect(result.bytes[7]).toBe(0x6a);
    expect(result.bytes[8]).toBe(0x55);
  });

  test("is null-free with default syscall", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, badchars: [0x00], os: "xp", syscall: null });
    expect(result.badcharHits).toEqual([]);
  });

  test("is 2 bytes shorter than ntaccess", () => {
    const ntaccess = buildEgghunter({ tag: "W00T", mode: "ntaccess", wow64: false, ...DEFAULTS });
    const ntdisplay = buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, ...XP });
    expect(ntaccess.size - ntdisplay.size).toBe(2);
  });

  test("has no WoW64 variant", () => {
    expect(() => buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: true, ...XP })).toThrow("ntdisplay has no WOW64 stub");
  });

  test("win7 preset uses NtDisplayString 0x6D", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, badchars: NO_BADCHARS, os: "win7", syscall: null });
    expect(result.bytes[8]).toBe(0x6d);
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

  test("ends with jmp edi (FF E7)", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "ntdisplay", wow64: false, ...XP });
    expect(result.bytes[result.size - 2]).toBe(0xff);
    expect(result.bytes[result.size - 1]).toBe(0xe7);
  });
});

describe("SEH egghunter", () => {
  test("generates 70-byte stub with tag embedded", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "seh", wow64: false, ...DEFAULTS });
    expect(result.size).toBe(70);
    expect(result.badcharHits).toEqual([]);
    expect(result.syscallUsed).toBeNull();
    // Tag at offset 0x34
    expect(result.bytes[0x34]).toBe(0x57); // W
    expect(result.bytes[0x35]).toBe(0x30); // 0
    expect(result.bytes[0x36]).toBe(0x30); // 0
    expect(result.bytes[0x37]).toBe(0x54); // T
  });

  test("starts with jmp short past handler", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "seh", wow64: false, ...DEFAULTS });
    expect(result.bytes[0]).toBe(0xeb); // jmp short
    expect(result.bytes[1]).toBe(0x17); // skip 23 bytes of handler
  });

  test("ends with jmp edi (FF E7)", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "seh", wow64: false, ...DEFAULTS });
    expect(result.bytes[result.size - 2]).toBe(0xff);
    expect(result.bytes[result.size - 1]).toBe(0xe7);
  });

  test("contains null bytes and reports them as badchars", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "seh", wow64: false, badchars: [0], os: "win10", syscall: null });
    expect(result.badcharHits.length).toBeGreaterThan(0);
    expect(result.badcharHits.some((h) => h.includes("0x00"))).toBe(true);
  });

  test("embeds custom tag at the correct offset", () => {
    const result = buildEgghunter({ tag: "HACK", mode: "seh", wow64: false, ...DEFAULTS });
    expect(result.bytes[0x34]).toBe(0x48); // H
    expect(result.bytes[0x35]).toBe(0x41); // A
    expect(result.bytes[0x36]).toBe(0x43); // C
    expect(result.bytes[0x37]).toBe(0x4b); // K
  });

  test("scan loop uses or di,0xfff for page alignment", () => {
    const result = buildEgghunter({ tag: "W00T", mode: "seh", wow64: false, ...DEFAULTS });
    // or di, 0x0FFF at offset 0x2D
    expect(result.bytes[0x2d]).toBe(0x66);
    expect(result.bytes[0x2e]).toBe(0x81);
    expect(result.bytes[0x2f]).toBe(0xcf);
    expect(result.bytes[0x30]).toBe(0xff);
    expect(result.bytes[0x31]).toBe(0x0f);
  });
});

describe("egghunter tag padding", () => {
  test("pads short tags to 4 bytes with X", () => {
    const result = buildEgghunter({ tag: "AB", mode: "ntaccess", wow64: false, ...DEFAULTS });
    expect(result.bytes[20]).toBe(0x41); // A
    expect(result.bytes[21]).toBe(0x42); // B
    expect(result.bytes[22]).toBe(0x58); // X (padding)
    expect(result.bytes[23]).toBe(0x58); // X (padding)
  });

  test("truncates long tags to 4 bytes", () => {
    const result = buildEgghunter({ tag: "ABCDEF", mode: "ntaccess", wow64: false, ...DEFAULTS });
    expect(result.bytes[20]).toBe(0x41); // A
    expect(result.bytes[21]).toBe(0x42); // B
    expect(result.bytes[22]).toBe(0x43); // C
    expect(result.bytes[23]).toBe(0x44); // D
  });
});
