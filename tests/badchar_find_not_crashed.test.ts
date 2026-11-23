import { afterEach, describe, expect, test } from "vitest";
import { createBadcharFindCommand } from "../src/commands/badchars";
import { unwrap } from "../src/core/output";

// Lab09 under cdb: the payload never crashed the target, a break-in stopped it in ntdll on a thread
// whose stack ends 1216 bytes above ESP.
const ESP = 0x0149fb40;
const STACK_END = ESP + 1216;
const NTDLL = 0x77a70000;
const EIP = 0x77ae320c;

let log = "";
let reads = 0;

function installStoppedTarget(): void {
  log = "";
  reads = 0;
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (text: string) => { log += text; } },
    currentProcess: { Is64Bit: false, Modules: [{ Name: "C:\\Windows\\SysWOW64\\ntdll.dll", BaseAddress: NTDLL, Size: 0x1a4000 }] },
    currentThread: { Registers: { User: { esp: { value: BigInt(ESP) }, eip: { value: BigInt(EIP) } } } },
    memory: {
      readMemoryValues(address: bigint | number, length: number) {
        reads += 1;
        const start = Number(address);
        if (start < ESP - 0x1000 || start + length > STACK_END) throw new Error("out of range");
        return new Array(length).fill(0);
      },
    },
  };
}

afterEach(() => {
  delete (globalThis as { host?: unknown }).host;
});

describe("badchar_find on a target that did not crash", () => {
  test("reports the bytes it really scanned and that IP is not on an overwritten return address", () => {
    installStoppedTarget();
    const result = createBadcharFindCommand().execute({ exclude: [0x00], windowBytes: 2048, minRun: 8 });
    expect(result.findings[0]).toEqual({ located: false });
    expect(log).toContain("Test array not found: scanned 1216 bytes from the anchor");
    expect(unwrap(log)).toContain("eip 0x77AE320C is inside");
    expect(unwrap(log)).toContain("the target has not crashed yet (break-in or breakpoint)");
    expect(reads).toBeLessThan(40);
  });
});
