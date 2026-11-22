import { readFileSync, existsSync } from "fs";
import { describe, expect, test } from "vitest";
import { stripDml } from "../src/core/output";
import { initializeScript } from "../src/index";
import { picksOf } from "./helpers/dep_plan_picks";

// The real lab DLL, mapped the way the loader maps it. Opt in with LIBBKUP_DLL=<path to libbkup.dll>.
const DLL = process.env.LIBBKUP_DLL ?? "";
const BAD = "00 09 0A 0B 0C 0D 20";
const logs: string[] = [];

function mapImage(file: Uint8Array): { base: bigint; image: Uint8Array } {
  const view = new DataView(file.buffer, file.byteOffset, file.byteLength);
  const pe = view.getUint32(0x3c, true);
  const sections = view.getUint16(pe + 6, true);
  const optional = pe + 0x18;
  const base = BigInt(view.getUint32(optional + 0x1c, true));
  const image = new Uint8Array(view.getUint32(optional + 0x38, true));
  image.set(file.subarray(0, view.getUint32(optional + 0x3c, true)));
  const table = optional + view.getUint16(pe + 0x14, true);
  for (let i = 0; i < sections; i += 1) {
    const s = table + i * 0x28;
    const rva = view.getUint32(s + 0xc, true);
    const size = view.getUint32(s + 0x10, true);
    const raw = view.getUint32(s + 0x14, true);
    image.set(file.subarray(raw, raw + size), rva);
  }
  return { base, image };
}

function loadApi(): { dep_plan: (...args: unknown[]) => unknown } {
  const { base, image } = mapImage(new Uint8Array(readFileSync(DLL)));
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    currentProcess: {
      Is64Bit: false,
      Modules: [{ Name: "libbkup.dll", Path: "C:\labs\libbkup.dll", BaseAddress: base, EndAddress: base + BigInt(image.length), Size: image.length }],
    },
    memory: {
      readMemoryValues(address: bigint | number, length: number) {
        const offset = Number(BigInt(address) - base);
        if (offset < 0 || offset + length > image.length) throw new Error("out of range");
        return Array.from(image.slice(offset, offset + length));
      },
    },
  };
  initializeScript();
  logs.length = 0;
  return (globalThis as unknown as { osed: ReturnType<typeof loadApi> }).osed;
}

const text = (): string => stripDml(logs.join(""));

describe.skipIf(!DLL || !existsSync(DLL))("dep_plan on the real libbkup.dll", () => {
  test("for each skeleton job the pick writes no register that is live at that job", () => {
    const api = loadApi();
    api.dep_plan("VirtualAlloc", "libbkup", BAD);
    const output = text();
    const jobs = picksOf(output);
    const titles = ["capture ESP", "add the distance to field 1", "copy a register", "read a pointer",
      "write a field", "advance the pointer", "negate", "pivot ESP onto the frame"];
    expect(jobs.map((job, i) => job.title.indexOf(titles[i]) === 0)).toEqual(titles.map(() => true));
    for (const job of jobs) {
      expect(job.pick, job.title).toBeDefined();
      expect(job.pick?.writes.filter((register) => job.keep.indexOf(register) >= 0), job.title).toEqual([]);
    }
    expect(output).toContain("no: reads through ecx: loading the slot there clobbers the field address");
    const picked = jobs.map((job) => job.pick?.address);
    const used = (output.slice(output.indexOf("=== [7/7]")).match(/rop \+= p32\(0x[0-9A-F]{8}\)/g) ?? []).map((line) => line.slice(11, 21));
    for (const address of used) expect(picked).toContain(address);
    if (process.env.DUMP) require("fs").writeFileSync(`${process.env.DUMP}/plan_skeleton.txt`, output);
  });

  test("for each pushad job the pick writes no register loaded before it", () => {
    const api = loadApi();
    api.dep_plan("VirtualAlloc", "libbkup", BAD, "pushad");
    const output = text();
    const jobs = picksOf(output).filter((job) => job.pick !== undefined);
    expect(jobs.length).toBe(9);
    for (const job of jobs) expect(job.pick?.writes.filter((register) => job.keep.indexOf(register) >= 0), job.title).toEqual([]);
    if (process.env.DUMP) require("fs").writeFileSync(`${process.env.DUMP}/plan_pushad.txt`, output);
  });
});
