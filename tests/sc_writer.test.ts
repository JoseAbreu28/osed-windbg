import { readFileSync } from "node:fs";
import { beforeEach, describe, expect, test } from "vitest";
import { initializeScript } from "../src/index";
import { SC_BUILDER_SOURCE } from "../src/shellcode/sc_builder_source";
import type { AsmLine } from "../src/shellcode/writer";

const logs: string[] = [];
type Api = Record<string, (...args: unknown[]) => unknown> & { sc: Record<string, (...args: unknown[]) => unknown> };

function loadApi(): Api {
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    currentProcess: { Is64Bit: false, Modules: [] },
  };
  initializeScript();
  logs.length = 0;
  return (globalThis as unknown as { osed: Api }).osed;
}

const output = (): string => logs.join("");
const lastFinding = (api: Api): Record<string, unknown> =>
  (api.last_result() as { findings: Array<Record<string, unknown>> }).findings[0];

/** Runs the emitted bytes for the subset the writers produce and returns the 32-bit stack. */
function execute(lines: AsmLine[]): { esp: number; regs: number[]; read: (addr: number, n: number) => number[] } {
  const regs = [0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x10000, 0x55555555, 0x66666666, 0x77777777];
  const mem = new Map<number, number>();
  const push = (value: number) => {
    regs[4] -= 4;
    for (let i = 0; i < 4; i += 1) mem.set(regs[4] + i, (value >>> (8 * i)) & 0xff);
  };
  const pop = (): number => {
    let value = 0;
    for (let i = 0; i < 4; i += 1) value |= (mem.get(regs[4] + i) ?? 0) << (8 * i);
    regs[4] += 4;
    return value >>> 0;
  };
  const imm32 = (b: number[], at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
  const alu = (ext: number, r: number, v: number) => {
    regs[r] = (ext === 0 ? regs[r] + v : ext === 5 ? regs[r] - v : regs[r] ^ v) >>> 0;
  };
  for (const line of lines) {
    const b = line.bytes!;
    const [op, modrm] = b;
    if (op === 0x6a) push((b[1] << 24) >> 24);
    else if (op === 0x68) push(imm32(b, 1));
    else if (op >= 0x50 && op <= 0x57) push(regs[op - 0x50]);
    else if (op >= 0x58 && op <= 0x5f) regs[op - 0x58] = pop();
    else if (op >= 0xb8 && op <= 0xbf) regs[op - 0xb8] = imm32(b, 1);
    else if ((op === 0x31 || op === 0x29) && modrm >= 0xc0) regs[modrm & 7] = 0;
    else if (op === 0x89 && modrm >= 0xc0) regs[modrm & 7] = regs[(modrm >> 3) & 7];
    else if (op === 0xf7) regs[modrm & 7] = ((modrm & 0x38) === 0x10 ? ~regs[modrm & 7] : -regs[modrm & 7]) >>> 0;
    else if (op === 0x05 || op === 0x2d || op === 0x35) alu(op >> 3, 0, imm32(b, 1));
    else if (op === 0x81) alu((modrm >> 3) & 7, modrm & 7, imm32(b, 2));
    else if (op === 0x83) alu((modrm >> 3) & 7, modrm & 7, ((b[2] << 24) >> 24) >>> 0);
    else throw new Error(`emulator does not know ${line.asm}`);
  }
  return { esp: regs[4], regs, read: (addr, n) => Array.from({ length: n }, (_, i) => mem.get(addr + i) ?? -1) };
}

const ascii = (text: string): number[] => [...text].map((c) => c.charCodeAt(0));

describe("sc.push_string", () => {
  let api: Api;
  beforeEach(() => {
    api = loadApi();
  });

  test.each(["a", "ab", "abc", "abcd", "abcde", "calc.exe"])("builds %j + NUL at ESP with no 00 byte", (text) => {
    expect(api.sc.push_string(text).success).toBe(true);
    const lines = lastFinding(api).lines as AsmLine[];
    expect(lines.flatMap((line) => line.bytes!)).not.toContain(0x00);
    const run = execute(lines);
    expect(run.read(run.esp, text.length + 1)).toEqual([...ascii(text), 0]);
  });

  test("pushes the last dword first and comments the 4 characters of each push", () => {
    api.sc.push_string("calc.exe");
    const text = output();
    expect(text.indexOf('"\\0\\0\\0\\0"')).toBeLessThan(text.indexOf('".exe"'));
    expect(text.indexOf('".exe"')).toBeLessThan(text.indexOf('"calc"'));
    expect(text).toContain("push 0x636c6163");
    expect(text).toContain('CODE = (');
    expect(text).toContain('"push 0x6578652e;"  # ".exe"');
  });

  test("avoids every given bad char and still builds the string, with a pointer in ebx", () => {
    const text = "cmd.exe /c echo ok > C:\\t\\sc.txt";
    const bad = [0x00, 0x0a, 0x0d, 0x20, 0x2e, 0x63, 0x68];
    expect(api.sc.push_string(text, "00 0A 0D 20 2E 63 68", "ebx").success).toBe(true);
    const lines = lastFinding(api).lines as AsmLine[];
    for (const byte of lines.flatMap((line) => line.bytes!)) expect(bad).not.toContain(byte);
    const run = execute(lines);
    expect(run.regs[3]).toBe(run.esp);
    expect(run.read(run.regs[3], text.length + 1)).toEqual([...ascii(text), 0]);
  });

  test("rejects an empty string, ESP as the pointer register, and unreadable bad chars", () => {
    expect(api.sc.push_string("").success).toBe(false);
    expect(api.sc.push_string("calc", "", "esp").success).toBe(false);
    expect(api.sc.push_string("calc", "zz").success).toBe(false);
  });
});

describe("sc.call_frame", () => {
  let api: Api;
  beforeEach(() => {
    api = loadApi();
  });

  test("pushes WinExec arguments in reverse, then its ROR13 hash and the resolver calls", () => {
    expect(api.sc.call_frame("WinExec", "<ptr to cmd>", "1").success).toBe(true);
    const finding = lastFinding(api);
    expect(finding.hash).toBe("0x0e8afe98");
    const asm = (finding.lines as AsmLine[]).map((line) => line.asm);
    expect(asm).toEqual(["push 0x1", "push <ptr to cmd>", "push 0xe8afe98", "push dword ptr [ebp-0x08]", "call dword ptr [ebp-0x04]", "call eax"]);
    expect(output()).toContain("arg2 uCmdShow = 1");
    expect(output()).toContain("arg1 lpCmdLine = <ptr to cmd> (placeholder)");
  });

  test("pushes zero and hashes without 00 or bad bytes", () => {
    expect(api.sc.call_frame("ExitProcess", "0", "bad=00 0A 0D 7E").success).toBe(true);
    const lines = lastFinding(api).lines as AsmLine[];
    const bytes = lines.flatMap((line) => line.bytes ?? []);
    for (const byte of [0x00, 0x0a, 0x0d, 0x7e]) expect(bytes).not.toContain(byte);
    const values = execute(lines.slice(0, -3));
    expect(values.read(values.esp, 8)).toEqual([0x7e, 0xd8, 0xe2, 0x73, 0, 0, 0, 0]);
  });

  test("does not use a register an argument reads as scratch", () => {
    api.sc.call_frame("TerminateProcess", "eax", "0");
    const asm = (lastFinding(api).lines as AsmLine[]).map((line) => line.asm);
    expect(asm[0]).toBe("xor ecx, ecx");
    expect(asm[2]).toBe("push eax");
  });

  test("still hashes an unknown API, with a warning, and rejects a malformed name", () => {
    expect(api.sc.call_frame("NotARealApi", "eax").success).toBe(true);
    expect(output()).toContain("is not in the prototype table");
    expect(lastFinding(api).known).toBe(false);
    expect(api.sc.call_frame("winexec", "ebx", "1").success).toBe(true);
    expect(lastFinding(api).hash).toBe("0x0e8afe98");
    expect(api.sc.call_frame("Win Exec").success).toBe(false);
  });
});

describe("sc.template", () => {
  let api: Api;
  beforeEach(() => {
    api = loadApi();
  });

  const script = (): string => lastFinding(api).script as string;

  test("prints a Keystone build script with resolver, call frames and epilogue", () => {
    expect(api.sc.template("winexec=calc.exe", "exit").success).toBe(true);
    const text = script();
    for (const piece of ["Ks(KS_ARCH_X86, KS_MODE_32)", "BADCHARS = bytes([0x00])", "shellcode.bin", '"pushad",', '"add esp, 0xfffff810",',
      '"mov eax, dword ptr fs:[ecx+0x30]",', '"resolve_hash:",', '"push 0xe8afe98",', '"push 0x73e2d87e",', '"popad",']) {
      expect(text).toContain(piece);
    }
    expect(text.indexOf("0xe8afe98")).toBeLessThan(text.indexOf("0x73e2d87e"));
    expect(output()).toContain("#!/usr/bin/env python3");
  });

  test("passes the bad chars into the script and keeps the generated lines clean", () => {
    expect(api.sc.template("show=0", "winexec=cmd.exe /c echo ok > C:\\o.txt", "terminate", "bad=00 0A 0D 20").success).toBe(true);
    expect(script()).toContain("BADCHARS = bytes([0x00, 0x0a, 0x0d, 0x20])");
    expect(script()).toContain("0x78b5b983");
  });

  test("defaults to calc and ExitProcess, and names the valid tasks on a typo", () => {
    expect(api.sc.template().success).toBe(true);
    expect(script()).toContain("Task 2: ExitProcess(0)");
    expect(api.sc.template("winexex=calc.exe").success).toBe(false);
    expect(output()).toContain("Tasks: winexec=<command line>");
  });
});

describe("writer help", () => {
  test("lists the dotted writers under shellcode and resolves their help", () => {
    const api = loadApi();
    expect(api.help("all").success).toBe(true);
    const all = output();
    for (const name of ["sc.push_string", "sc.call_frame", "sc.template", "sc.builder"]) expect(all).toContain(name);
    expect(all).not.toContain("sc_template");
    expect(all).not.toContain("sc_builder ");
    logs.length = 0;
    expect(api.help("shellcode").success).toBe(true);
    expect(output()).toContain("sc.template");
    logs.length = 0;
    api.sc.template("help");
    expect(output()).toContain("build_sc.py");
    logs.length = 0;
    api.sc.builder("help");
    expect(output()).toContain("sc_builder.py");
  });
});

describe("sc.builder", () => {
  let api: Api;
  beforeEach(() => {
    api = loadApi();
  });

  const shipped = readFileSync(new URL("../tools/sc_builder.py", import.meta.url), "utf8").replace(/\r\n/g, "\n");
  const script = (): string => lastFinding(api).script as string;
  const config = (text: string): string => text.split("# >>> CONFIG\n")[1].split("# <<< CONFIG\n")[0];
  const outsideConfig = (text: string): string => text.replace(/# >>> CONFIG\n[\s\S]*?# <<< CONFIG\n/, "");

  test("embeds tools/sc_builder.py unchanged (run npm run build after editing it)", () => {
    expect(SC_BUILDER_SOURCE).toBe(shipped);
  });

  test("prints the shipped script with no arguments", () => {
    expect(api.sc.builder().success).toBe(true);
    expect(script()).toBe(shipped);
    const text = output();
    expect(text).toContain("Save everything below this line as sc_builder.py");
    expect(text).toContain("#!/usr/bin/env python3\n");
    expect(text).toContain('k32.WinExec(s("calc.exe"), SW_SHOWNORMAL)');
  });

  test("fills only the CONFIG block from sc.template tasks, xor and max", () => {
    expect(api.sc.builder("show=0", 'winexec=cmd.exe /c echo "ok" > C:\\o.txt', "terminate", "bad=00 0A 0D 20 2F", "xor", "max=0x200").success).toBe(true);
    expect(outsideConfig(script())).toBe(outsideConfig(shipped));
    expect(config(script()).split("\n")).toEqual([
      'BADCHARS = b"\\x00\\x0a\\x0d\\x20\\x2f"',
      "MAX_SIZE = 512",
      'EXIT = "terminate"',
      "XOR_ENCODER = True",
      "CDECL = ()",
      "DEBUG = False",
      "",
      'k32.WinExec(s("cmd.exe /c echo \\"ok\\" > C:\\\\o.txt"), 0)',
      "",
    ]);
  });

  test("maps loadlibrary and getprocaddress to calls, and no exit task to ret", () => {
    expect(api.sc.builder("loadlibrary=user32.dll", "getprocaddress=MessageBoxA").success).toBe(true);
    const block = config(script());
    expect(block).toContain('hmod = k32.LoadLibraryA(s("user32.dll"))');
    expect(block).toContain('k32.GetProcAddress(hmod, s("MessageBoxA"))');
    expect(block).toContain('EXIT = "ret"');
    expect(api.sc.builder("getprocaddress=WinExec", "exit").success).toBe(true);
    expect(config(script())).toContain('k32.GetProcAddress(base("kernel32.dll"), s("WinExec"))');
    expect(config(script())).toContain('EXIT = "exit"');
  });

  test("gives each loadlibrary its own name, and resolves against the most recent one", () => {
    expect(api.sc.builder("loadlibrary=user32.dll", "getprocaddress=MessageBoxA", "loadlibrary=ws2_32.dll", "getprocaddress=WSASocketA").success).toBe(true);
    const block = config(script());
    expect(block).toContain('hmod = k32.LoadLibraryA(s("user32.dll"))');
    expect(block).toContain('k32.GetProcAddress(hmod, s("MessageBoxA"))');
    expect(block).toContain('hmod2 = k32.LoadLibraryA(s("ws2_32.dll"))');
    expect(block).toContain('k32.GetProcAddress(hmod2, s("WSASocketA"))');
  });

  test("names the valid tasks on a typo and rejects a bad max", () => {
    expect(api.sc.builder("winexex=calc.exe").success).toBe(false);
    expect(output()).toContain("xor, max=<bytes>");
    expect(api.sc.builder("winexec=calc.exe", "max=-4").success).toBe(false);
  });
});

