import { describe, expect, test } from "vitest";
import { SCREEN, SEPARATOR, screenshotViolations } from "../src/core/screenshot_rule";
import { GADGETS, load, syncBreeze, text } from "./helpers/fixture_process";

const ECHO = '=== dx @$osed().dep_plan("VirtualAlloc", "libspp.dll", "00 0A", "pushad", 1) ===';
const rules = (transcript: string): string[] => screenshotViolations(transcript).map((v) => `${v.section} ${v.rule}`);

describe("the screenshot rule, one check per clause of GOAL.md", () => {
  test("a section that fits, with its block below the separator, passes", () => {
    expect(rules([ECHO, "=== [1/7] Module ===", "[+] fine", "", SEPARATOR, "def p32(v): return v"].join("\n"))).toEqual([]);
  });

  test(`evidence taller than ${SCREEN.rows} rows fails; the copy block below the separator does not count`, () => {
    const tall = Array.from({ length: SCREEN.rows }, (_, i) => `[+] row ${i}`);
    expect(rules([ECHO, "=== [1/7] Module ===", ...tall, SEPARATOR].join("\n"))).toEqual(["[1/7] height"]);
    expect(rules([ECHO, "=== [1/7] Module ===", "[+] one", SEPARATOR, ...tall.map((_, i) => `X${i} = ${i}`)].join("\n"))).toEqual([]);
  });

  test(`a line past ${SCREEN.columns} columns fails, above or below the separator`, () => {
    const long = `[+] ${"x".repeat(SCREEN.columns)}`;
    expect(rules([ECHO, "=== [1/7] Module ===", long, SEPARATOR].join("\n"))).toEqual(["[1/7] width"]);
    expect(rules([ECHO, "=== [1/7] Module ===", "[+] ok", SEPARATOR, `# ${"x".repeat(SCREEN.columns)}`].join("\n"))).toEqual(["[1/7] width"]);
  });

  test("the echo must write out the API, the module and the style the run chose", () => {
    const auto = ECHO.replace('"pushad"', '"auto"');
    expect(rules([auto, "=== Verdict ==="].join("\n"))).toEqual(["echo echo"]);
    expect(rules(['=== dx @$osed().dep_plan("00 0A") ===', "=== Verdict ==="].join("\n"))).toEqual(["echo echo"]);
    // A run that stopped chose nothing, so there is nothing for the echo to write.
    expect(rules(['=== dx @$osed().dep_plan("", "", "00 0A", "auto", 1) ===', "=== STOP: no chain ==="].join("\n"))).toEqual([]);
  });

  test("Python above the separator fails; prose, tables and indented maps do not", () => {
    const evidence = ["[+] lpflOldProtect = 0x10115000", "Type    Value", "    [ESP+0]  = EDI", "dx @$osed().modules()"];
    expect(rules([ECHO, "=== [5/7] Constants ===", ...evidence, SEPARATOR].join("\n"))).toEqual([]);
    expect(rules([ECHO, "=== [5/7] Constants ===", "from struct import pack", 'rop += pack("<I", 1)', SEPARATOR].join("\n"))).toEqual(["[5/7] python-above-separator"]);
  });

  test("a section with no separator must say there is nothing to copy, or that it was skipped", () => {
    expect(rules([ECHO, "=== [3/7] Corpus ===", "[+] 12 gadgets"].join("\n"))).toEqual(["[3/7] no-separator"]);
    expect(rules([ECHO, "=== [3/7] Corpus ===", "[+] Nothing to copy here: the corpus"].join("\n"))).toEqual([]);
    expect(rules([ECHO, "=== [5/7] Constants ===", "[-] Skipped: see the STOP above."].join("\n"))).toEqual([]);
  });

  test("evidence printed inside the copy block fails, because the block is one drag to select", () => {
    expect(rules([ECHO, "=== [2/7] Slot ===", "[+] slot", SEPARATOR, "IAT_SLOT = 1", "[!] careful"].join("\n"))).toEqual(["[2/7] evidence-below-separator"]);
  });
});

// The baseline: every violation dep_plan prints today on the reproduced Sync Breeze shape, in both
// styles. It is a ratchet. A new violation turns this red, and so does fixing one, until the fix also
// takes it off this list. Nothing here is accepted; it is the next iteration's work, written down.
describe("dep_plan's output against the screenshot rule, as measured on 2026-11-22", () => {
  const { BAD, FORCED, shape } = syncBreeze;
  const COMMON = ["DEP width", "[1/7] width", "[2/7] width", "[3/7] width", "[4/7] width", "[5/7] width", "Verdict width"];

  test("pushad, from the short call with only the bad chars", () => {
    load(shape(), { policy: 2, registry: FORCED }).dep_plan(BAD);
    // The echo says "auto": the header prints before the style is chosen, so a screenshot of it hides one.
    expect(rules(text()).sort()).toEqual([...COMMON, "echo echo"].sort());
  });

  test("skeleton, named in the long call", () => {
    load(shape({ code: GADGETS }), { policy: 2, registry: FORCED }).dep_plan("VirtualAlloc", "libspp.dll", BAD, "skeleton", 1);
    expect(rules(text()).sort()).toEqual([...COMMON].sort());
  });
});
