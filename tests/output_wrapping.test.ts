import { describe, expect, test } from "vitest";
import { unwrap, wrapped } from "../src/core/output";
import { SCREEN } from "../src/core/screenshot_rule";

// The guides' renderer cuts a figure at 130 columns, so a character past it never reaches the report.
// Everything printed with a [+], [!] or [-] tag is broken to fit before it gets there.
describe("a tagged line is broken to fit the screen", () => {
  const sentence = (words: number): string => Array.from({ length: words }, (_, i) => `word${i}`).join(" ");

  test("every line fits, and none is broken mid-word", () => {
    const lines = wrapped("[+] ", sentence(60));
    expect(lines.length).toBeGreaterThan(1);
    for (const line of lines) expect(line.length).toBeLessThanOrEqual(SCREEN.columns);
    expect(lines.join(" ").replace(/\[\+\] +/g, "")).toBe(sentence(60));
  });

  test("a line that already fits is left as one line", () => {
    expect(wrapped("[+] ", "short enough")).toEqual(["[+] short enough"]);
  });

  test("every line carries the tag, so the screenshot rule reads them all as evidence", () => {
    for (const line of wrapped("[!] ", sentence(60))) expect(line.indexOf("[!] ")).toBe(0);
  });

  test("the message's own indent is kept, and continuations sit further in", () => {
    const lines = wrapped("[+] ", `  ${sentence(60)}`);
    expect(lines[0].indexOf("[+]   word0")).toBe(0);
    for (const line of lines.slice(1)) expect(line.indexOf("[+]       ")).toBe(0);
  });

  // A broken command is a command nobody can paste in one drag, so a dx call moves whole to the next line.
  test("a dx call is never broken, even when it does not fit where it starts", () => {
    const call = 'dx @$osed().dep_plan("VirtualProtect", "wbcore.dll", "00 03 0a 0d 7c", "skeleton", 1)';
    const lines = wrapped("[+] ", `${sentence(8)} ${call}`);
    expect(lines.some((line) => line.indexOf(call) >= 0)).toBe(true);
    for (const line of lines) expect(line.length).toBeLessThanOrEqual(SCREEN.columns);
  });

  // A word with no room anywhere still has to be printed: cutting it would lose an address.
  test("a single word longer than the screen is printed rather than cut", () => {
    const long = "x".repeat(SCREEN.columns + 20);
    expect(wrapped("[+] ", long)).toEqual([`[+] ${long}`]);
  });

  test("unwrap puts a broken sentence back together", () => {
    expect(unwrap(wrapped("[-] ", sentence(60)).join("\n"))).toBe(`[-] ${sentence(60)}`);
    expect(unwrap(wrapped("[+] ", `  ${sentence(60)}`).join("\n"))).toBe(`[+]   ${sentence(60)}`);
  });

  test("unwrap leaves alone what was never wrapped", () => {
    const block = ["[+] one", "[+] two", "  > 0x11111111  pop eax ; ret", "IAT_SLOT = 0x10113200"].join("\n");
    expect(unwrap(block)).toBe(block);
  });
});
