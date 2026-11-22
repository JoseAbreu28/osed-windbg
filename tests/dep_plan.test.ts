import { beforeEach, describe, expect, test } from "vitest";
import { stripDml } from "../src/core/output";
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

function installHost(): void {
  const image = new Uint8Array(0x5000);
  const peOffset = 0x80;
  const sectionTable = peOffset + 0x18 + 0xe0;
  writeUint16LE(image, 0x0, 0x5a4d);
  writeUint32LE(image, 0x3c, peOffset);
  writeUint32LE(image, peOffset, 0x4550);
  writeUint16LE(image, peOffset + 0x6, 1);
  writeUint16LE(image, peOffset + 0x14, 0xe0);
  image.set(Array.from(".text").map((char) => char.charCodeAt(0)), sectionTable);
  writeUint32LE(image, sectionTable + 0x8, 0x2000);
  writeUint32LE(image, sectionTable + 0xc, 0x1000);
  writeUint32LE(image, sectionTable + 0x24, 0x60000020);
  for (const [offset, bytes] of GADGETS) image.set(bytes, offset);

  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    currentProcess: {
      Is64Bit: false,
      Modules: [{ Name: "libbkup.dll", Path: "C:\\labs\\libbkup.dll", BaseAddress: BASE, EndAddress: BASE + BigInt(image.length), Size: image.length }],
    },
    memory: {
      readMemoryValues(address: bigint | number, length: number) {
        const offset = Number(BigInt(address) - BASE);
        if (offset < 0 || offset + length > image.length) throw new Error("out of range");
        return Array.from(image.slice(offset, offset + length));
      },
    },
  };
}

function loadApi(): Api {
  installHost();
  initializeScript();
  logs.length = 0;
  return (globalThis as unknown as { osed: Api }).osed;
}

const text = (): string => stripDml(logs.join(""));

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
// What the lab's own exploit_skeleton.py already holds when the student reaches dep_plan.
const FROM_HIS_FILE = new Set(["OFFSET", "BADCHARS", "p32"]);

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
    expect(negate).toMatch(/^  negate \(keep edi = the field address\):\n    0x11111361  neg edi ; ret.*\n      no: clobbers edi, which still holds the field address\n  > 0x11111161  neg eax ; pop ebp ; ret/);
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
    expect(table).toContain("COST = {NEG_EAX: (1, 0)}     # (extra pops, ret N)");
    expect(output).toContain("# confirm: bp 0x11111111 ; g ; r esp ; s -d esp-400 L100 45454545");
    expect(output).toContain("=== VirtualAlloc Python Call-Frame Skeleton ===");
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

    // [7/7] is the body of a stage function, so it carries no def line of its own and ends in a return.
    for (const line of chain) if (line.trim()) expect(line.startsWith("    "), line).toBe(true);
    expect(chain[chain.length - 1]).toBe("    return payload");
    expect(chain.some((line) => /^ {4}payload {1,2}?=/.test(line) || /^ {4}payload \+?=/.test(line))).toBe(true);

    // Every chain line sits under a `#--` header naming what it builds, so finding the lines that built
    // one field is a scroll to its header and never a count of dwords.
    let header: string | undefined;
    for (const line of chain) {
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
    for (const line of chain) {
      const { own, inner } = bindings(line);
      [...own, ...inner].forEach((name) => locals.add(name));
    }

    expect([...new Set(moduleNames)].sort()).toEqual([...moduleNames].sort());
    for (const reserved of ["OFFSET", "BADCHARS"]) expect(moduleNames, reserved).not.toContain(reserved);
    // A slot called "return" must not become `return = hole(...)`.
    for (const bound of [...moduleNames, ...locals]) expect(PY_KEYWORDS, bound).not.toContain(bound);

    const known = new Set([...moduleNames, ...locals, ...FROM_HIS_FILE, ...PY_BUILTINS]);
    for (const line of [...moduleLines, ...chain]) {
      for (const used of uses(line)) expect(known, `${name} ${style}: ${line}`).toContain(used);
    }
  });

  test("pushad style lists a pop for each register, pushad and jmp esp, then the register map", () => {
    api.dep_plan("VirtualProtect", "libbkup", "00 0A 0D", "pushad");
    const output = text();
    for (const register of ["edi", "esi", "ebp", "ebx", "edx", "ecx", "eax"]) expect(output).toMatch(new RegExp(`pop ${register}[^\\n]*:\\n  > 0x1111`));
    expect(output).toMatch(/pushad ; ret[^\n]*:\n  > 0x11111281/);
    expect(output).toContain("jmp esp: 0x11111291");
    expect(output).toContain("=== [6/7] PUSHAD register map for VirtualProtect ===");
    expect(output).toContain("[ESP+16] = EBX        <- dwSize = 0x201");
  });

  test("warns only about base bytes that every address in the module shares", () => {
    api.dep_plan("VirtualAlloc", "libbkup", "00 0A 0D");
    expect(text()).toContain("libbkup.dll spans 0x11110000 to 0x11114FFF: no ASLR, and its fixed high bytes are clean.");
    logs.length = 0;
    api.dep_plan("VirtualAlloc", "libbkup", "11 0A 0D");
    expect(text()).toContain("Every address in libbkup.dll (0x11110000 to 0x11114FFF) holds the bad byte(s) 11, so no gadget from it is usable.");
  });

  test.each([
    [["VirtualAlloc", "libbkup", "00 09 0A 0B 0C 0D 20"], '=== dx @$osed().dep_plan("VirtualAlloc", "libbkup", "00 09 0A 0B 0C 0D 20") ==='],
    [["VirtualProtect", "libbkup", "00 0A 0D", "pushad"], '=== dx @$osed().dep_plan("VirtualProtect", "libbkup", "00 0A 0D", "pushad") ==='],
  ])("the first line is the call %j as typed", (args, header) => {
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
      '[4/7] dep_candidates("libbkup", "00 0A 0D", "skeleton")',
      '[5/7] rop.construct("eax", 0x1, "00 0A 0D")',
      '[5/7] rop.construct("eax", 0x1000, "00 0A 0D")',
      '[5/7] rop.construct("eax", 0x40, "00 0A 0D")',
      '[6/7] dep_function("VirtualAlloc")',
    ]],
    ["WriteProcessMemory", "pushad", [
      '[1/7] modules("libbkup")',
      '[2/7] sc.iat_find("WriteProcessMemory")',
      '[3/7] rop.scan_live("libbkup", "00 0A 0D")',
      '[4/7] dep_candidates("libbkup", "00 0A 0D", "pushad")',
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
    const calls = report.split("\n").filter((line) => line.startsWith("dx @$osed().") && !line.includes("code_caves("));
    expect(calls.some((call) => call.includes(".dep_candidates("))).toBe(true);
    expect(calls.some((call) => call.includes(".dep_function("))).toBe(true);
    const osed = (globalThis as unknown as { osed: unknown }).osed;
    for (const call of calls) {
      logs.length = 0;
      new Function("osed", `return osed.${call.slice("dx @$osed().".length)};`)(osed);
      expect(report, call).toContain(`${call}\n${text()}`);
    }
  });

  test.each(["skeleton", "pushad"])("dep_candidates in a fresh session prints the whole [4/7] %s section and loads no corpus", (style) => {
    api.dep_plan("VirtualProtect", "libbkup", "00 0A 0D", style);
    const report = text();
    const whole = report.slice(report.indexOf("=== [4/7]"), report.indexOf("\n=== [5/7]"));
    // The block under the separator is dep_plan's own addition, so the comparison stops there.
    const section = whole.slice(0, whole.indexOf(`\n\n${SEPARATOR}`));
    const call = `dx @$osed().dep_candidates("libbkup", "00 0A 0D", "${style}")`;
    expect(section.split("\n")[1]).toBe(call);

    const fresh = loadApi();
    fresh.dep_candidates("libbkup", "00 0A 0D", style);
    expect(fresh.last_result()).toMatchObject({ command: "dep_candidates", success: true });
    expect(section.slice(section.indexOf(call) + call.length + 1)).toBe(text().replace(/\n$/, ""));
    fresh.rop.query("capability", "MEMORY_READ");
    expect(fresh.last_result().success).toBe(false);
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
