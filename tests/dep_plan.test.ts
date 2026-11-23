import { spawnSync } from "node:child_process";
import { beforeEach, describe, expect, test } from "vitest";
import { stripDml, unwrap } from "../src/core/output";
import { initializeScript } from "../src/index";
import { picksOf } from "./helpers/dep_plan_picks";

type Result = { success: boolean; errors: string[]; findings: Array<Record<string, unknown>> };
type Api = {
  dep_plan: (...args: unknown[]) => unknown;
  dep_candidates: (...args: unknown[]) => unknown;
  rop: { query: (...args: unknown[]) => unknown };
  last_result: () => Result;
};

const BASE = BigInt(0x11110000);
const logs: string[] = [];

function writeUint16LE(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}

function writeUint32LE(bytes: Uint8Array, offset: number, value: number): void {
  for (let i = 0; i < 4; i += 1) bytes[offset + i] = (value >>> (i * 8)) & 0xff;
}

// One executable .text section; each gadget sits at an address with no 00, 0A or 0D byte.
const GADGETS: Array<[number, number[]]> = [
  [0x1111, [0x54, 0x5e, 0xc3]], // push esp ; pop esi ; ret
  [0x1121, [0x8b, 0x00, 0xc3]], // mov eax, [eax] ; ret
  [0x1131, [0x89, 0x06, 0xc3]], // mov [esi], eax ; ret
  [0x1141, [0x46, 0xc3]], // inc esi ; ret
  [0x1151, [0x01, 0xce, 0xc3]], // add esi, ecx ; ret
  [0x1161, [0xf7, 0xd8, 0x5d, 0xc3]], // neg eax ; pop ebp ; ret
  [0x1171, [0x94, 0xc3]], // xchg eax, esp ; ret
  [0x1181, [0x89, 0xc6, 0xc3]], // mov esi, eax ; ret
  [0x1211, [0x5f, 0xc3]], // pop edi ; ret
  [0x1221, [0x5e, 0xc3]], // pop esi ; ret
  [0x1231, [0x5d, 0xc3]], // pop ebp ; ret
  [0x1241, [0x5b, 0xc3]], // pop ebx ; ret
  [0x1251, [0x5a, 0xc3]], // pop edx ; ret
  [0x1261, [0x59, 0xc3]], // pop ecx ; ret
  [0x1271, [0x58, 0xc3]], // pop eax ; ret
  [0x1281, [0x60, 0xc3]], // pushad ; ret
  [0x1291, [0xff, 0xe4]], // jmp esp
  [0x1311, [0x83, 0xc4, 0x10, 0xc3]], // add esp, 0x10 ; ret
  [0x1321, [0x83, 0xf0, 0xff, 0x8b, 0xe5, 0x5d, 0xc3]], // xor eax, 0xffffffff ; mov esp, ebp ; pop ebp ; ret
  // The chain the live set allows: the captured ESP goes from esi to edi, which then holds the field address.
  [0x1331, [0x89, 0xf7, 0xc3]], // mov edi, esi ; ret
  [0x1341, [0x89, 0x07, 0xc3]], // mov [edi], eax ; ret
  [0x1351, [0x47, 0xc3]], // inc edi ; ret
  [0x1361, [0xf7, 0xdf, 0xc3]], // neg edi ; ret  (ranks above neg eax ; pop ebp, but edi holds the field address)
];

const ascii = (text: string): number[] => Array.from(text).map((char) => char.charCodeAt(0));
const DEP_APIS = ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory"];
const MOVED = BigInt(0x22220000);

/** A one-descriptor import directory for KERNEL32, so sc.iat_find has a slot per symbol. */
function writeImports(image: Uint8Array, peOffset: number, base: bigint, symbols: string[]): void {
  const [directory, int, iat, dllName, names] = [0x3000, 0x3020, 0x3040, 0x3100, 0x3200];
  writeUint32LE(image, peOffset + 0x18 + 0x60 + 0x8, directory);   // data directory [1], the import table
  writeUint32LE(image, peOffset + 0x18 + 0x60 + 0xc, 0x28);
  writeUint32LE(image, directory + 0x0, int);                      // OriginalFirstThunk
  writeUint32LE(image, directory + 0xc, dllName);                  // Name
  writeUint32LE(image, directory + 0x10, iat);                     // FirstThunk, the slots themselves
  image.set(ascii("KERNEL32.dll"), dllName);
  symbols.forEach((symbol, i) => {
    writeUint32LE(image, int + i * 4, names + i * 0x20);
    writeUint32LE(image, iat + i * 4, Number(base) + 0x1111);      // resolved target, inside .text
    image.set(ascii(symbol), names + i * 0x20 + 2);                // after the two-byte hint
  });
}

/** One mapped module: a PE32 image with a .text section, optionally ASLR and an import table. */
function peImage(base: bigint, options: { aslr?: boolean; imports?: string[]; gadgets?: boolean; extra?: Array<[number, number[]]> }): Uint8Array {
  const image = new Uint8Array(0x5000);
  const peOffset = 0x80;
  const sectionTable = peOffset + 0x18 + 0xe0;
  writeUint16LE(image, 0x0, 0x5a4d);
  writeUint32LE(image, 0x3c, peOffset);
  writeUint32LE(image, peOffset, 0x4550);
  writeUint16LE(image, peOffset + 0x6, 1);
  writeUint16LE(image, peOffset + 0x14, 0xe0);
  writeUint16LE(image, peOffset + 0x18, 0x10b);                     // PE32 optional header, or the parser refuses it
  writeUint32LE(image, peOffset + 0x18 + 0x1c, Number(base));       // ImageBase, so nothing reads this as relocated
  if (options.aslr) writeUint16LE(image, peOffset + 0x5e, 0x0040);  // DllCharacteristics DYNAMIC_BASE
  image.set(ascii(".text"), sectionTable);
  writeUint32LE(image, sectionTable + 0x8, 0x2000);
  writeUint32LE(image, sectionTable + 0xc, 0x1000);
  writeUint32LE(image, sectionTable + 0x24, 0x60000020);
  if (options.gadgets !== false) for (const [offset, bytes] of [...GADGETS, ...(options.extra ?? [])]) image.set(bytes, offset);
  if (options.imports && options.imports.length > 0) writeImports(image, peOffset, base, options.imports);
  return image;
}

/** `imports`: what libbkup imports. `movable`: a second module, with ASLR, importing these. */
function installHost(options: { imports?: string[]; aslr?: boolean; movable?: string[]; extra?: Array<[number, number[]]> } = {}): void {
  const image = peImage(BASE, { aslr: options.aslr, imports: options.imports ?? DEP_APIS, extra: options.extra });
  const moved = options.movable ? peImage(MOVED, { aslr: true, imports: options.movable, gadgets: false }) : undefined;
  const mapped: Array<{ name: string; base: bigint; image: Uint8Array }> = [{ name: "libbkup.dll", base: BASE, image }];
  if (moved) mapped.push({ name: "movable.dll", base: MOVED, image: moved });

  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    currentProcess: {
      Is64Bit: false,
      Modules: mapped.map((entry) => ({
        Name: entry.name,
        Path: `C:\labs\${entry.name}`,
        BaseAddress: entry.base,
        EndAddress: entry.base + BigInt(entry.image.length),
        Size: entry.image.length,
      })),
    },
    memory: {
      readMemoryValues(address: bigint | number, length: number) {
        for (const entry of mapped) {
          const offset = Number(BigInt(address) - entry.base);
          if (offset >= 0 && offset + length <= entry.image.length) return Array.from(entry.image.slice(offset, offset + length));
        }
        throw new Error("out of range");
      },
    },
  };
}

function loadApi(options: { imports?: string[]; aslr?: boolean; movable?: string[]; extra?: Array<[number, number[]]> } = {}): Api {
  installHost(options);
  initializeScript();
  logs.length = 0;
  return (globalThis as unknown as { osed: Api }).osed;
}

const text = (): string => stripDml(logs.join(""));
// The same transcript with the lines output.ts wrapped rejoined, for a check on what it says.
const prose = (): string => unwrap(text());

const SECTIONS = [1, 2, 3, 4, 5, 6, 7].map((n) => `=== [${n}/7]`);
const SEPARATOR = "# ------------------ copy into your exploit ------------------";

/** The lines under each separator, in print order: exactly what the student drags out of the pane. */
function blocksOf(output: string): string[][] {
  const blocks: string[][] = [];
  let current: string[] | undefined;
  for (const line of output.split("\n")) {
    if (line === SEPARATOR) {
      current = [];
      blocks.push(current);
      continue;
    }
    if (line.startsWith("=== ")) current = undefined;
    else if (current) current.push(line);
  }
  for (const block of blocks) while (block.length > 0 && block[block.length - 1].trim() === "") block.pop();
  return blocks;
}

const PY_KEYWORDS = new Set(["def", "class", "return", "for", "in", "while", "not", "and", "or", "if", "else",
  "raise", "lambda", "None", "True", "False", "is", "pass", "import", "from", "as"]);
const PY_BUILTINS = new Set(["len", "range", "any", "all", "bytes", "int", "list", "print", "SystemExit", "self",
  "enumerate", "str", "hex", "bool", "tuple", "dict", "set", "min", "max", "sum", "abs"]);
// The two values no tool can measure for him: the crash gives OFFSET, the bad char hunt gives BADCHARS.
// Everything else the blocks use, they define, so the blocks alone make a file that runs.
const FROM_HIS_FILE = new Set(["OFFSET", "BADCHARS"]);
const HIS_FILE = 'OFFSET = 516\nBADCHARS = b"\\x00\\x0a\\x0d"\n';

const PYTHON = process.env.PYTHON ?? "python";
const HAS_PYTHON = spawnSync(PYTHON, ["--version"]).status === 0;
// A real interpreter on the pasted file: it must compile, every global any scope reads must be bound at
// module level or be a builtin, and the module level itself must run to the end.
const CHECK_PASTE = `
import builtins, symtable, sys
src = sys.stdin.read()
compile(src, "pasted", "exec")
top = symtable.symtable(src, "pasted", "exec")
bound = {s.get_name() for s in top.get_symbols() if s.is_assigned() or s.is_imported() or s.is_namespace()}
missing = set()
def walk(table):
    for s in table.get_symbols():
        name = s.get_name()
        reads_global = s.is_global() or (table is top and s.is_referenced())
        if reads_global and name not in bound and not hasattr(builtins, name): missing.add(name)
    for child in table.get_children(): walk(child)
walk(top)
if missing: sys.exit("undefined: " + ", ".join(sorted(missing)))
try:
    exec(src, {"__name__": "pasted"})
except SystemExit as stop:
    sys.exit("module level stopped: " + str(stop))
`;

const DEF = /\b(?:def|class)\s+([A-Za-z_]\w*)\s*\(([^)]*)\)/;
const FOR = /\bfor\s+([A-Za-z_][\w,\s]*?)\s+in\b/g;

/** The line with its comment, its string literals and their b/r/f prefixes gone. */
const bare = (line: string): string => line
  .replace(/\b[bruf]{1,2}(?=['"])/gi, "")
  .replace(/(['"])(?:\\.|(?!\1).)*\1/g, '""')
  .replace(/#.*$/, "");

/** `own`: what the line binds in its own scope. `inner`: parameters and loop targets, bound one level in. */
function bindings(line: string): { own: string[]; inner: string[] } {
  const code = bare(line);
  const own: string[] = [];
  const inner: string[] = [];
  const def = DEF.exec(code);
  if (def) {
    own.push(def[1]);
    inner.push(...def[2].split(",").map((part) => part.trim().split("=")[0].replace(/^\*+/, "").trim()).filter(Boolean));
  }
  for (const match of code.matchAll(FOR)) inner.push(...match[1].split(",").map((part) => part.trim()).filter(Boolean));
  const assign = def ? null : /^\s*([A-Za-z_][\w,.\s[\]]*?)\s*=(?!=)/.exec(code);
  for (const target of assign ? assign[1].split(",") : []) {
    const name = target.trim();
    if (/^[A-Za-z_]\w*$/.test(name)) own.push(name);
  }
  return { own, inner };
}

function uses(line: string): string[] {
  const code = bare(line).replace(DEF, "").replace(FOR, "");
  return [...code.matchAll(/(\.)?\b([A-Za-z_]\w*)\b/g)]
    .filter((match) => !match[1] && !PY_KEYWORDS.has(match[2]))
    .map((match) => match[2]);
}

describe("dep_plan", () => {
  let api: Api;
  beforeEach(() => {
    api = loadApi();
  });

  test.each(["VirtualAlloc", "VirtualProtect", "WriteProcessMemory"])("%s prints the seven sections in order in both styles", (name) => {
    for (const style of ["skeleton", "pushad"]) {
      logs.length = 0;
      api.dep_plan(name, "libbkup", "00 0A 0D", style);
      expect(api.last_result().success, `${name} ${style}`).toBe(true);
      const output = text();
      const positions = SECTIONS.map((header) => output.indexOf(header));
      expect(positions.every((position) => position >= 0), `${name} ${style}: ${positions}`).toBe(true);
      expect([...positions].sort((a, b) => a - b)).toEqual(positions);
      expect(output).toContain(`=== [2/7] IAT slot of ${name} ===`);
      expect(output).toContain("=== [7/7] The exploit, with a placeholder for every value only a run can give ===");
      // Six blocks and one honest "nothing to copy": [3/7] finds the corpus, which is search, not exploit.
      expect(blocksOf(output).length, `${name} ${style}`).toBe(6);
      expect(output).toContain("[+] Nothing to copy here: the corpus is the search");
    }
  });

  test("skeleton style picks per job a gadget that keeps every register the chain still needs", () => {
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    const jobs = picksOf(text());
    for (const job of jobs) {
      expect(job.pick, job.title).toBeDefined();
      expect(job.pick?.writes.filter((register) => job.keep.indexOf(register) >= 0), job.title).toEqual([]);
    }
    const pick = (title: string) => jobs.find((job) => job.title.indexOf(title) === 0)?.pick?.text;
    expect(pick("capture ESP")).toBe("push esp ; pop esi ; ret");
    expect(pick("add the distance")).toBe("add esi, ecx ; ret");
    expect(pick("copy a register")).toBe("mov edi, esi ; ret");
    expect(pick("write a field")).toBe("mov [edi], eax ; ret");
    expect(pick("advance the pointer")).toBe("inc edi ; ret");
    expect(jobs.find((job) => job.title.indexOf("negate") === 0)?.keep).toEqual(["edi"]);
  });

  test("a gadget that clobbers a live register is not the pick, even when it ranks first", () => {
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    const output = text();
    const negate = output.slice(output.indexOf("  negate"), output.indexOf("  pivot ESP"));
    // A rejected candidate is one row, so its reason sits beside its address rather than under it.
    expect(negate).toMatch(/^  negate \(keep edi = the field address\)[^\n]*\n    0x11111361  neg edi ; ret\s+no: clobbers edi, which still holds the field address\n  > 0x11111161  neg eax ; pop ebp ; ret/);
    const copy = output.slice(output.indexOf("  copy a register"), output.indexOf("  read a pointer"));
    expect(copy).toContain("no: copies eax, but the captured ESP is in esi");
    expect(copy).toContain("> 0x11111331  mov edi, esi ; ret");
  });

  test("every gadget the blocks name is one the [4/7] table found, and each pick the chain needs is there", () => {
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    const output = text();
    const table = blocksOf(output)[2];
    const named = new Map(table
      .map((line) => /^(\w+)\s+= (0x[0-9A-F]{8})/.exec(line))
      .filter((match): match is RegExpExecArray => match !== null)
      .map((match) => [match[1], match[2]]));
    expect(named.size).toBeGreaterThan(5);
    const addresses = (output.match(/0x1111[0-9A-F]{4}/g) ?? []);
    for (const address of named.values()) expect(addresses).toContain(address);
    // The jobs that carry the chain: each pick is in the table under the name of its first instruction.
    const pick = (title: string) => picksOf(output).find((job) => job.title.indexOf(title) === 0)?.pick;
    expect(named.get("PUSH_ESP_POP_ESI")).toBe(pick("capture ESP")?.address);
    expect(named.get("ADD_ESI_ECX")).toBe(pick("add the distance")?.address);
    expect(named.get("MOV_EDI_ESI")).toBe(pick("copy a register")?.address);
    expect(named.get("MOV_MEM_EDI_EAX")).toBe(pick("write a field")?.address);
    expect(named.get("INC_EDI")).toBe(pick("advance the pointer")?.address);
    expect(named.get("XCHG_EAX_ESP")).toBe(pick("pivot ESP")?.address);
    expect(table.find((line) => line.startsWith("COST = {"))).toContain("NEG_EAX: (1, 0)");
    expect(output).toContain("# confirm: bp 0x11111111 ; g ; r esp ; s -d esp-400 L100 45454545");
    // [6/7] prints the frame once, under the separator, with every argument named in call order. The
    // skeleton used to print dep_function's copy above it too, in pack() and with six undefined names.
    expect(blocksOf(output)[4].map((line) => /#\s*(\w+)/.exec(line)?.[1]).slice(0, 6))
      .toEqual(["VirtualAlloc", "return", "lpAddress", "dwSize", "flAllocationType", "flProtect"]);
    expect(output).not.toContain("Python Call-Frame Skeleton");
    expect(api.last_result().findings[0]).toMatchObject({ api: "VirtualAlloc", module: "libbkup", style: "skeleton" });
  });

  test("no job but the pivot takes a gadget whose destination is esp", () => {
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    const output = text();
    const job = (title: string): string => output.slice(output.indexOf(`  ${title}`)).split(/\n  (?=[a-z])/)[0];
    expect(job("add the distance")).toContain("add esi, ecx ; ret");
    expect(job("add the distance")).not.toContain("add esp");
    expect(job("copy a register")).not.toContain("mov esp, ebp");
    expect(job("pivot ESP onto the frame")).toContain("xchg eax, esp ; ret");
    expect(blocksOf(output)[2]).toContain("ADD_ESI_ECX      = 0x11111151   # add esi, ecx ; ret");
    expect(output).not.toContain("add esp, 0x10 ; ret\nCOST");
  });

  test.each([
    ["VirtualAlloc", "skeleton"], ["VirtualProtect", "skeleton"], ["WriteProcessMemory", "skeleton"],
    ["VirtualAlloc", "pushad"], ["VirtualProtect", "pushad"], ["WriteProcessMemory", "pushad"],
  ])("the %s %s blocks compose: pasted in print order they define every name they use, and none twice", (name, style) => {
    api.dep_plan(name, "libbkup", "00 0A 0D", style);
    const blocks = blocksOf(text());
    expect(blocks.length).toBe(6);
    const chain = blocks[5];

    // [7/7] is what he sends, so it arrives as a complete payloadN() returning bytes. Everything above
    // it is constants, which stay at module level: a constant is not something he sends.
    expect(chain[0]).toMatch(/^def payload\d+\(\):$/);
    for (const line of chain.slice(1)) if (line.trim()) expect(line.startsWith("    "), line).toBe(true);
    expect(chain[chain.length - 1]).toBe("    return sendable(payload)");
    expect(chain.some((line) => /^ {4}payload {1,2}=/.test(line) || /^ {4}payload \+=/.test(line))).toBe(true);
    for (const block of blocks.slice(0, 5)) {
      expect(block.some((line) => /^def payload\d+\(\)/.test(line)), block[0]).toBe(false);
    }

    // Every chain line sits under a `#--` header naming what it builds, so finding the lines that built
    // one field is a scroll to its header and never a count of dwords.
    let header: string | undefined;
    for (const line of chain.slice(1)) {
      if (line.trim().startsWith("#--")) header = line.trim();
      else if (line.includes("c.rop(")) expect(header, `${name} ${style}: ungrouped ${line.trim()}`).toBeDefined();
    }
    expect(chain.filter((line) => line.trim().startsWith("#--")).length).toBeGreaterThan(0);

    // Module level is blocks [1/7] to [6/7] at column 0; the chain's own lines are locals of the stage.
    const moduleLines = blocks.slice(0, 5).flat();
    const moduleNames: string[] = [];
    const locals = new Set<string>();
    for (const line of moduleLines) {
      const { own, inner } = bindings(line);
      if (line.startsWith(" ")) own.forEach((name) => locals.add(name));
      else moduleNames.push(...own);
      inner.forEach((name) => locals.add(name));
    }
    moduleNames.push(...bindings(chain[0]).own);
    for (const line of chain) {
      const { own, inner } = bindings(line);
      [...own, ...inner].forEach((name) => locals.add(name));
    }
    locals.delete(moduleNames[moduleNames.length - 1]);

    expect([...new Set(moduleNames)].sort()).toEqual([...moduleNames].sort());
    for (const reserved of ["OFFSET", "BADCHARS"]) expect(moduleNames, reserved).not.toContain(reserved);
    // A slot called "return" must not become `return = hole(...)`.
    for (const bound of [...moduleNames, ...locals]) expect(PY_KEYWORDS, bound).not.toContain(bound);

    const known = new Set([...moduleNames, ...locals, ...FROM_HIS_FILE, ...PY_BUILTINS]);
    for (const line of [...moduleLines, ...chain]) {
      for (const used of uses(line)) expect(known, `${name} ${style}: ${line}`).toContain(used);
    }
  });

  // Excluding the ESP capture leaves the skeleton without a chain, so [7/7] is a hole for him to write.
  test.skipIf(!HAS_PYTHON).each([
    ["VirtualAlloc", "skeleton", ""], ["VirtualProtect", "skeleton", ""], ["WriteProcessMemory", "skeleton", ""],
    ["VirtualAlloc", "pushad", ""], ["VirtualProtect", "pushad", ""], ["WriteProcessMemory", "pushad", ""],
    ["VirtualAlloc", "skeleton", "0x11111111"], ["WriteProcessMemory", "pushad", "0x11111281"],
  ])("the %s %s blocks, excluding [%s], pasted into a file holding only OFFSET and BADCHARS run in Python", (name, style, exclude) => {
    api.dep_plan(name, "libbkup", "00 0A 0D", style, 6, exclude);
    const pasted = HIS_FILE + blocksOf(text()).map((block) => block.join("\n")).join("\n\n") + "\n";
    const run = spawnSync(PYTHON, ["-I", "-c", CHECK_PASTE], { input: pasted, encoding: "utf-8" });
    expect(run.stderr.trim(), `${name} ${style}`).toBe("");
    expect(run.status, `${name} ${style}`).toBe(0);
  });

  test("pushad style lists a pop for each register, pushad and jmp esp, then the register map", () => {
    api.dep_plan("VirtualProtect", "libbkup", "00 0A 0D", "pushad");
    const output = text();
    // Every register has its job and a pop that does it. Only the pops the chain calls carry the >: the
    // other registers are loaded by the route [5/7] prints, or are holes.
    for (const register of ["edi", "esi", "ebp", "ebx", "edx", "ecx", "eax"]) expect(output).toMatch(new RegExp(`pop ${register}[^\\n]*:\\n  [> ] 0x1111\\w+  pop ${register} ; ret`));
    for (const register of ["ebp", "edi", "eax"]) expect(output).toMatch(new RegExp(`pop ${register}[^\\n]*:\\n  > 0x1111`));
    for (const register of ["esi", "ebx", "edx", "ecx"]) expect(output).toMatch(new RegExp(`pop ${register}[^\\n]*:\\n    0x1111[^\\n]*\\n      NOT IN THE CHAIN: `));
    expect(output).toMatch(/pushad ; ret[^\n]*:\n  > 0x11111281/);
    expect(output).toContain("jmp esp: 0x11111291");
    expect(output).toContain("=== [6/7] PUSHAD register map for VirtualProtect ===");
    expect(output).toContain("[ESP+16] = EBX        <- dwSize = 0x201");
  });

  // A gadget can be clean on paper and still fault, because it takes an address from a register the
  // chain never pointed anywhere. libbkup's pushad gadgets are the real example; this is the rule.
  test("a gadget that dereferences a register nothing points anywhere loses to one that does not", () => {
    // neg eax ; mov eax, dword [ebx] ; ret: fewer side effects than the clean neg, so it ranks above it.
    const fresh = loadApi({ extra: [[0x1371, [0xf7, 0xd8, 0x8b, 0x03, 0xc3]]] });
    fresh.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    const output = unwrap(text());
    const negate = output.slice(output.indexOf("  negate"), output.indexOf("  pivot ESP"));
    expect(negate).toContain("neg eax ; mov eax, dword [ebx] ; ret");
    expect(negate).toContain("reads through ebx, which nothing in the chain has pointed anywhere yet");
    // It ranked first and still lost, because a candidate without that property exists.
    expect(negate).toMatch(/> 0x11111161 {2}neg eax ; pop ebp ; ret/);
    expect(negate.indexOf("mov eax, dword [ebx]")).toBeLessThan(negate.indexOf("> 0x11111161"));
    expect(negate).not.toContain("!! every candidate for this job");
  });

  // pop ebp ; add esp, 0x1008 ; ret 0x4 does pop ebp, and swapping it in adds four kilobytes of junk.
  const FAR_POP_EBP: [number, number[]] = [0x1381, [0x5d, 0x81, 0xc4, 0x08, 0x10, 0x00, 0x00, 0xc2, 0x04, 0x00]];
  const NEAR_POP_EBP: [number, number[]] = [0x1391, [0x5d, 0xc2, 0x04, 0x00]];

  test("a gadget that takes a frame of stack is no drop-in swap, while a near one is", () => {
    const fresh = loadApi({ extra: [FAR_POP_EBP, NEAR_POP_EBP] });
    fresh.dep_plan("VirtualProtect", "libbkup", "00 0A 0D", "pushad");
    const output = text();
    // The swap list is the block's, not the ranking's: [4/7] prints the pick and the candidates ranked
    // above it, and the usable ones after it are the commented swaps below the separator.
    const table = blocksOf(output)[2];
    expect(table.some((line) => /^# POP_EBP.*= 0x11111391 .*drop-in swap/.test(line)), table.join("\n")).toBe(true);
    expect(table.join("\n")).not.toContain("0x11111381");
  });

  test("a frame-sized move wins a job only when nothing else does it, and says what it costs", () => {
    const fresh = loadApi({ extra: [[0x1381, [0x5f, 0x81, 0xc4, 0x08, 0x10, 0x00, 0x00, 0xc3]]] }); // pop edi ; add esp, 0x1008 ; ret
    fresh.dep_plan("VirtualProtect", "libbkup", "00 0A 0D", "pushad", 1, "11111211");
    const output = text();
    const job = output.slice(output.indexOf("  pop edi"), output.indexOf("  pop eax"));
    expect(job).toMatch(/> 0x11111381 {2}pop edi ; add esp, 0x1008 ; ret/);
    expect(job).toContain("!! every usable candidate for this job takes more than 0x40 bytes of stack");
    expect(blocksOf(output)[2].find((line) => line.startsWith("POP_EDI"))).toContain("<<< takes 0x100c bytes of stack");
  });

  test("warns only about base bytes that every address in the module shares", () => {
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    expect(text()).toContain("libbkup.dll spans 0x11110000 to 0x11114FFF: no ASLR, and its fixed high bytes are clean.");
    logs.length = 0;
    api.dep_plan("VirtualAlloc", "libbkup", "11 0A 0D");
    expect(text()).toContain("Every address in libbkup.dll (0x11110000 to 0x11114FFF) holds the bad byte(s) 11, so no gadget from it is usable.");
  });

  // Resolved, not as typed: pasting this line back reproduces the run, numbering included.
  test.each([
    [["VirtualAlloc", "libbkup", "00 09 0A 0B 0C 0D 20"], '=== dx @$osed().dep_plan("VirtualAlloc", "libbkup", "00 09 0A 0B 0C 0D 20", "skeleton", 1) ==='],
    [["VirtualProtect", "libbkup", "00 0A 0D", "pushad", 6], '=== dx @$osed().dep_plan("VirtualProtect", "libbkup", "00 0A 0D", "pushad", 6) ==='],
  ])("the first line is the call %j with the style and the stage resolved", (args, header) => {
    api.dep_plan(...args);
    const output = text();
    expect(output.split("\n").find((line) => line !== "")).toBe(header);
    expect(output.indexOf(header)).toBeLessThan(output.indexOf("=== [1/7]"));
  });

  test.each([
    ["VirtualAlloc", "skeleton", [
      '[1/7] modules("libbkup")',
      '[2/7] sc.iat_find("VirtualAlloc")',
      '[3/7] rop.scan_live("libbkup", "00 0A 0D")',
      '[4/7] dep_candidates("libbkup", "00 0A 0D", "skeleton", "VirtualAlloc")',
      '[5/7] rop.construct("eax", 0x1, "00 0A 0D")',
      '[5/7] rop.construct("eax", 0x1000, "00 0A 0D")',
      '[5/7] rop.construct("eax", 0x40, "00 0A 0D")',
      '[6/7] dep_function("VirtualAlloc")',
    ]],
    ["WriteProcessMemory", "pushad", [
      '[1/7] modules("libbkup")',
      '[2/7] sc.iat_find("WriteProcessMemory")',
      '[3/7] rop.scan_live("libbkup", "00 0A 0D")',
      '[4/7] dep_candidates("libbkup", "00 0A 0D", "pushad", "WriteProcessMemory")',
      '[4/7] find_bytes("libbkup", "FF E4", 20)',
      '[4/7] find_bytes("libbkup", "FF D4", 20)',
      '[5/7] rop.construct("eax", 0xFFFFFFFF, "00 0A 0D")',
      '[5/7] rop.construct("eax", 0x210, "00 0A 0D")',
      '[5/7] code_caves("libbkup", 0x4, 25, "00 0A 0D", "STAGING")',
      '[5/7] code_caves("libbkup", 0x210, 25, "00 0A 0D", "EXEC")',
      '[6/7] dep_function("WriteProcessMemory", "pushad")',
    ]],
  ])("%s %s prints each sub-command in its section before its output", (name, style, expected) => {
    api.dep_plan(name, "libbkup", "00 0A 0D", style);
    let section = "";
    const echoed: string[] = [];
    for (const line of text().split("\n")) {
      section = /^=== (\[\d\/7\])/.exec(line)?.[1] ?? section;
      if (line.startsWith("dx @$osed().")) echoed.push(`${section} ${line.slice("dx @$osed().".length)}`);
    }
    expect(echoed).toEqual(expected);
  });

  test.each([
    ["VirtualAlloc", "skeleton"],
    ["WriteProcessMemory", "pushad"],
  ])("pasting an echoed line of %s %s prints the same output dep_plan printed under it", (name, style) => {
    api.dep_plan(name, "libbkup", "00 0A 0D", style);
    const report = text();
    // Four commands are offered rather than run, so nothing prints under their echo and there is nothing
    // to compare: dep_plan reads the caves and the jmp esp hits quietly and keeps only the address,
    // rop.construct builds in eax whichever register the frame wants, and the skeleton dep_function
    // frame is the one the block below the separator prints correctly. The pushad map does print.
    const offered = (line: string): boolean => line.includes("code_caves(") || line.includes("find_bytes(")
      || line.includes("rop.construct(") || line.includes('dep_function("' + name + '")');
    const calls = report.split("\n").filter((line) => line.startsWith("dx @$osed().") && !offered(line));
    expect(calls.some((call) => call.includes(".dep_candidates("))).toBe(true);
    expect(calls.some((call) => call.includes(".dep_function("))).toBe(style === "pushad");
    const osed = (globalThis as unknown as { osed: unknown }).osed;
    for (const call of calls) {
      logs.length = 0;
      new Function("osed", `return osed.${call.slice("dx @$osed().".length)};`)(osed);
      expect(report, call).toContain(`${call}\n${text()}`);
    }
  });

  test("the stage number says where his file continues, and the echoed line carries it", () => {
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D", "skeleton", 6);
    const output = text();
    expect(output).toContain('=== dx @$osed().dep_plan("VirtualAlloc", "libbkup", "00 0A 0D", "skeleton", 6) ===');
    expect(blocksOf(output)[5][0]).toBe("def payload6():");
    logs.length = 0;
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    expect(blocksOf(text())[5][0]).toBe("def payload1():");
  });

  // The > is a claim about the chain, so it is checked against the chain: the names [4/7]'s block gives
  // each address, and the c.rop calls of the pasted file.
  test.each(["skeleton", "pushad"].flatMap((style) => ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory"].map((name) => [style, name])))(
    "every > in [4/7] is a gadget the %s %s chain calls, and every pick without one is not", (style, depApi) => {
      api.dep_plan(depApi, "libbkup", "00 0A 0D", style);
      const output = text();
      const four = output.slice(output.indexOf("=== [4/7]"), output.indexOf("\n=== [5/7]"));
      const ranking = four.slice(0, four.indexOf(SEPARATOR));
      const names: Record<string, string[]> = {};
      for (const [, name, address] of four.matchAll(/^(\w+)\s*= (0x[0-9A-F]{8})\s/gm)) (names[address] ??= []).push(name);
      const pasted = output.slice(output.indexOf("=== [5/7]"));
      const calls = new Set([...pasted.matchAll(/c\.rop\((\w+)/g)].map((match) => match[1]));
      const called = (address: string): boolean => (names[address] ?? []).some((name) => calls.has(name));
      const marked = [...ranking.matchAll(/^ {2}> (0x[0-9A-F]{8}) /gm)].map((match) => match[1]);
      const unmarked = [...ranking.matchAll(/^ {4}(0x[0-9A-F]{8}) [^\n]*\n {6}NOT IN THE CHAIN: /gm)].map((match) => match[1]);
      expect(marked.length).toBeGreaterThan(0);
      expect(output, "a [5/7] route line says the same thing twice").not.toMatch(/not searched: [^\n]*not searched/);
      for (const address of marked) expect(called(address), `${address} has a > and the chain never calls it`).toBe(true);
      for (const address of unmarked) expect(called(address), `${address} says NOT IN THE CHAIN and the chain calls it`).toBe(false);
    });

  test.each(["skeleton", "pushad"])("dep_candidates in a fresh session prints the whole [4/7] %s section and loads no corpus", (style) => {
    api.dep_plan("VirtualProtect", "libbkup", "00 0A 0D", style);
    const report = text();
    const whole = report.slice(report.indexOf("=== [4/7]"), report.indexOf("\n=== [5/7]"));
    // The block under the separator is dep_plan's own addition, so the comparison stops there.
    const section = whole.slice(0, whole.indexOf(`\n\n${SEPARATOR}`));
    const call = `dx @$osed().dep_candidates("libbkup", "00 0A 0D", "${style}", "VirtualProtect")`;
    expect(section.split("\n")[1]).toBe(call);

    const fresh = loadApi();
    fresh.dep_candidates("libbkup", "00 0A 0D", style, "VirtualProtect");
    expect(fresh.last_result()).toMatchObject({ command: "dep_candidates", success: true });
    expect(section.slice(section.indexOf(call) + call.length + 1)).toBe(text().replace(/\n$/, ""));
    fresh.rop.query("capability", "MEMORY_READ");
    expect(fresh.last_result().success).toBe(false);
  });

  // The layers a chain dies at. They look alike from outside and each has a different fix, so the run
  // ends on one line that names the layer and its evidence, stops the sections that would describe a call
  // that cannot happen, and never hands him a ladder of things to go and try.
  test("no route to the API at all: one conclusion naming the API layer, and no list of things to try", () => {
    const fresh = loadApi({ imports: [] });
    fresh.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    // The conclusion is one sentence and output.ts breaks it across lines to fit the screen, so this
    // reads the rejoined transcript rather than pinning where the break falls.
    const output = prose();
    const conclusion = "[-] The API layer fails: no module with ASLR disabled imports VirtualAlloc, nor any other export of kernel32 or kernelbase to reach it from by a fixed distance. Its address needs a leak first.";
    expect(output.split(conclusion).length - 1).toBe(2);
    for (const homework of ["in this order", 'sc.iat_find("GetProcAddress")', "last resort", "rop.generate", "Only if you are free"]) {
      expect(output, homework).not.toContain(homework);
    }
    // The expensive half still prints: the module, the corpus and a gadget per job do not depend on the API.
    for (const header of ["=== [1/7]", "=== [3/7]", "=== [4/7]"]) expect(output).toContain(header);
    expect(output).toContain("push esp ; pop esi ; ret");
    expect(output).toContain("[-] Skipped: these are the arguments of a VirtualAlloc call this chain cannot make.");
    expect(output).toContain("[-] Skipped: this is the frame of a VirtualAlloc call this chain cannot make.");
    expect(output).toContain("[-] Skipped: there is no chain to write.");
    expect(output).not.toContain("=== VirtualAlloc Python Call-Frame Skeleton ===");
    expect(output).not.toContain("return payload");
    expect(fresh.last_result()).toMatchObject({ success: false });
    expect(fresh.last_result().errors).toEqual([conclusion.slice(4)]);
  });

  test("a bad char in the slot address is the usual case here, and [5/7] already answers it", () => {
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D 30");
    const output = text();
    expect(output).toContain("[+] The slot address holds the bad byte(s) 30.");
    expect(output).toContain("That is the usual case and nothing breaks");
    expect(output).not.toContain("=== STOP:");
    expect(api.last_result()).toMatchObject({ success: true });
  });

  test("the API he named has no route, but another has: the conclusion is that route, in one line", () => {
    const fresh = loadApi({ imports: ["VirtualAlloc"], movable: ["WriteProcessMemory"] });
    fresh.dep_plan("WriteProcessMemory", "libbkup", "00 0A 0D");
    const output = text();
    expect(output).toContain("[-] The API layer fails: no module with ASLR disabled imports WriteProcessMemory (movable.dll does, and it has ASLR)");
    expect(output).toContain('[-] If you are free to choose the API, VirtualAlloc has a route: dx @$osed().dep_plan("VirtualAlloc", "libbkup", "00 0A 0D")');
    expect(output).toContain("=== [4/7]");
    expect(output).toContain("[-] Skipped: there is no chain to write.");
  });

  test("an importer without ASLR is preferred, so the ASLR stop does not fire when one exists", () => {
    const fresh = loadApi({ imports: ["VirtualAlloc", "WriteProcessMemory"], movable: ["WriteProcessMemory"] });
    fresh.dep_plan("WriteProcessMemory", "libbkup", "00 0A 0D");
    const output = text();
    expect(output).not.toContain("=== STOP:");
    expect(output).toContain("in libbkup.dll. The chain reads the API address from it");
    expect(fresh.last_result()).toMatchObject({ success: true });
  });

  test("the gadget module has ASLR: the module layer fails, and nothing is scanned for a chain it cannot hold", () => {
    const fresh = loadApi({ aslr: true });
    fresh.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    const output = text();
    expect(output).toContain("=== STOP: no VirtualAlloc chain from libbkup.dll ===");
    expect(output).toContain("[-] The module layer fails: libbkup.dll has ASLR: every gadget address in it moves on each run");
    expect(output).not.toContain("Keep VirtualAlloc and change where its address comes from");
    expect(output).not.toContain("rop.scan_live(");
    expect(output).toContain("[-] Skipped: there is no chain to write.");
  });

  test.each([
    [["nosuchmod", "00"], 'Module "nosuchmod" is not loaded'],
    [["libbkup", "00", "rop"], "style must be one of skeleton, pushad"],
    [["libbkup", "zz"], "badchars must be hex bytes"],
  ])("dep_candidates rejects %j", (args, message) => {
    api.dep_candidates(...args);
    expect(api.last_result()).toMatchObject({ command: "dep_candidates", success: false });
    expect(api.last_result().errors[0]).toContain(message);
    expect(text()).not.toContain("Ranked by fewest side effects");
  });

  test.each([
    [["VirtualQuery", "libbkup", "00"], "api must be one of VirtualAlloc, VirtualProtect, WriteProcessMemory"],
    [["VirtualAlloc", "nosuchmod", "00"], 'Module "nosuchmod" is not loaded'],
    [["VirtualAlloc", "libbkup", "00", "rop"], "style must be one of skeleton, pushad"],
    [["VirtualAlloc", "libbkup", "zz"], "badchars must be hex bytes"],
  ])("rejects %j before printing any section", (args, message) => {
    api.dep_plan(...args);
    expect(api.last_result().success).toBe(false);
    expect(api.last_result().errors[0]).toContain(message);
    expect(text()).not.toContain("[1/7]");
  });
});
