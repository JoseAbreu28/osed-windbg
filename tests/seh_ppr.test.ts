import { describe, expect, test } from "vitest";
import { load, prose } from "./helpers/fixture_process";

// seh_ppr had no test, which is how it came to score a module +30 for "SafeSEH is disabled" when the
// image is marked NO_SEH and the dispatcher will not call anything in it, and how it came to close with
// pop-pop-ret being central to the technique on a process running with DEP.
const PPR = 0x1401;
const run = (over: { aslr?: boolean; noSeh?: boolean } = {}) => {
  load([
    { name: "vuln.exe", base: 0x00400000, nx: true },
    { name: "libbkup.dll", base: 0x11110000, aslr: over.aslr, noSeh: over.noSeh, code: [[PPR, [0x5e, 0x5d, 0xc3]]] },
  ], { policy: 2, registry: "" });
  (globalThis as unknown as { osed: { seh_ppr: (...args: unknown[]) => unknown } }).osed.seh_ppr("libbkup", "00 0A 0D");
  return prose();
};

describe("seh_ppr", () => {
  test("a fixed base and no SafeSEH table ranks, and the DEP line says a pop-pop-ret is not the delivery there", () => {
    const output = run();
    expect(output).toContain("0x11111401");
    expect(output).toContain("A pop-pop-ret returns into the record on the stack, so with DEP on it is not the delivery");
    expect(output).toContain("dep_plan measures that ESP and picks the pivot.");
  });

  test("NO_SEH is refused although the image has no SafeSEH table either", () => {
    expect(run({ noSeh: true })).toContain("the dispatcher never calls a handler here: the image is marked NO_SEH");
  });

  test("a module whose base moves is refused: the handler is a constant the payload carries", () => {
    expect(run({ aslr: true })).toContain("the dispatcher never calls a handler here: ASLR");
  });
});
