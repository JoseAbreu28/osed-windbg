import { describe, expect, test } from "vitest";
import { constantsFor } from "../src/commands/dep_plan";
import { clearOfCopy, copyBytes, FRAMES, frameGoal, PUSHAD_TAIL, WPM_COPY, WPM_MIN_COPY } from "../src/commands/dep_frames";

// WriteProcessMemory copies nSize bytes into the cave, so nSize is a fact about the cave and not about
// the frame's design. A module whose largest clean executable cave is 0x180 bytes wide was refused
// outright while the design asked for 0x210, although 0x180 holds a shellcode.

const nSizeSlot = () => {
  const slot = FRAMES.WriteProcessMemory.find((entry) => entry.name === "nSize");
  expect(slot?.source.kind).toBe("copy");
  return slot!;
};

describe("how many bytes the copy moves", () => {
  test("the design size when the cave holds it, and the cave's size when it does not", () => {
    expect(copyBytes({})).toBe(WPM_COPY);
    expect(copyBytes({ caveBytes: WPM_COPY })).toBe(WPM_COPY);
    expect(copyBytes({ caveBytes: 0x1000 })).toBe(WPM_COPY);
    expect(copyBytes({ caveBytes: 0x180 })).toBe(0x180);
  });

  test("the slot the loaders search for carries that number, not the design's", () => {
    expect(frameGoal(nSizeSlot(), { caveBytes: 0x180 })?.k).toBe(0x180);
    expect(frameGoal(nSizeSlot(), {})?.k).toBe(WPM_COPY);
  });

  // The recipes [5/7] prints are evidence for the loaders below them, so a recipe for 0x210 above a
  // loader building 0x180 is the section contradicting itself.
  test("the printed recipe for nSize is the number the chain builds", () => {
    const value = (facts: { caveBytes?: number }) =>
      constantsFor("WriteProcessMemory", facts).find((constant) => constant.field === "nSize")?.value;
    expect(value({ caveBytes: 0x180 })).toBe(0x180);
    expect(value({})).toBe(WPM_COPY);
    // Every other field is untouched by what the cave holds.
    expect(constantsFor("WriteProcessMemory", { caveBytes: 0x180 }).find((c) => c.field === "hProcess")?.value).toBe(0xffffffff);
    expect(constantsFor("VirtualProtect", { caveBytes: 0x180 })).toEqual(constantsFor("VirtualProtect", {}));
  });

  test("the PUSHAD frame's tail dword is the same number", () => {
    const slot = PUSHAD_TAIL.WriteProcessMemory.find((entry) => entry.name === "nSize");
    expect(slot?.source.kind).toBe("copy");
    expect(frameGoal(slot!, { caveBytes: 0x180 })?.k).toBe(0x180);
  });

  test("the floor is below the design size, or nothing smaller would ever be accepted", () => {
    expect(WPM_MIN_COPY).toBeLessThan(WPM_COPY);
  });

  // An RWX run answers the executable-cave search and the writable-dword search alike, so the two can land
  // on the same bytes. Nothing downstream would report it: the chain is complete and the shellcode is
  // quietly wrong, which is the failure GOAL.md ranks worst.
  test("an address inside what the copy overwrites is refused, and one touching either edge is not", () => {
    const copy = { at: 0x10200001, size: 0x210 };
    expect(clearOfCopy(0x10200001, 4, copy)).toBe(false);
    expect(clearOfCopy(0x10200100, 4, copy)).toBe(false);
    expect(clearOfCopy(0x10200001 + 0x210 - 4, 4, copy)).toBe(false);
    expect(clearOfCopy(0x10200001 - 4, 4, copy)).toBe(true);
    expect(clearOfCopy(0x10200001 + 0x210, 4, copy)).toBe(true);
    // A staged frame straddling the first copied byte is as corrupt as one inside it.
    expect(clearOfCopy(0x101ffff0, 0x40, copy)).toBe(false);
    // With no copy in the frame, every API but WriteProcessMemory, nothing is reserved.
    expect(clearOfCopy(0x10200001, 0x210, undefined)).toBe(true);
  });
});
