export type HelpExample = string | {
  label?: string;
  command: string;
};

export type HelpArgument = {
  name: string;
  description: string;
  required?: boolean;
};

export type HelpEntry = {
  name: string;
  description: string;
  /** Short listing text; description remains the detailed explanation. */
  summary?: string;
  /** Display-only grouping. It never changes command dispatch. */
  category?: string;
  usage: string;
  /** Legacy strings and labelled examples coexist during incremental migration. */
  examples: HelpExample[];
  compactExampleCount?: number;
  // Optional, shown only in the detail view (help("name")): a plain-language
  // note on what the command is for and where it fits a workflow.
  details?: string;
  arguments?: HelpArgument[];
  prerequisites?: string[];
  limitations?: string[];
  // Optional related helpers to suggest as likely next steps.
  seeAlso?: string[];
  keywords?: string[];
};

export type NormalizedHelpExample = {
  label?: string;
  command: string;
};

/**
 * Normalize only at the documentation boundary so existing catalog entries can
 * remain simple strings until richer prose is worth authoring.
 */
export function normalizeHelpExamples(examples: HelpExample[]): NormalizedHelpExample[] {
  return examples.map((example) => typeof example === "string" ? { command: example } : example);
}

export const NAMESPACE_HELP_ENTRIES: HelpEntry[] = [
  {
    name: "leak.classify",
    summary: "Classify a pointer value without dereferencing it.",
    description: "Classifies a supplied pointer value against loaded modules and memory regions. It does not inspect a pointer stored at an address and does not establish an information disclosure.",
    usage: "dx @$osed().leak.classify(value)",
    examples: ["dx @$osed().leak.classify(0x76A31240)"],
    limitations: ["Classification is debugger-observed evidence, not proof that an application exposes the value."],
  },
  {
    name: "leak.scan",
    description: "Scans an explicitly bounded range for pointer-sized values and classifies their current targets.",
    usage: "dx @$osed().leak.scan(address, length?)",
    examples: ["dx @$osed().leak.scan(0x0014DD28, 0x400)"],
    limitations: ["Reads debugger memory only; it does not establish that any pointer is externally disclosed."],
  },
  {
    name: "leak.analyze",
    description: "Extracts hexadecimal pointer candidates from supplied output text and correlates them with the current target.",
    usage: "dx @$osed().leak.analyze(text)",
    examples: ['dx @$osed().leak.analyze("Error processing request at 76A31240")'],
    limitations: ["Supplied text is leak-derived evidence, not independent proof of attacker observability."],
  },
  {
    name: "leak.base",
    description: "Calculates a candidate module base from a pointer and RVA, then validates it against the current target mapping.",
    usage: "dx @$osed().leak.base(pointer, rva)",
    examples: ["dx @$osed().leak.base(0x76A31240, 0x1240)"],
    limitations: ["A base is validated only when it matches a currently loaded module; this does not establish exploit usability."],
  },
  {
    name: "pattern.create",
    description: "Generates cyclic pattern text.",
    usage: "dx @$osed().pattern.create(length, type?)",
    examples: ["dx @$osed().pattern.create(300, \"msf\")"],
  },
  {
    name: "pattern.offset",
    description: "Finds an offset in the selected pattern family.",
    usage: "dx @$osed().pattern.offset(value, type?)",
    examples: ["dx @$osed().pattern.offset(0x39654138, \"msf\")"],
  },
  {
    name: "seh.visualize",
    description: "Walks the current thread SEH chain.",
    usage: "dx @$osed().seh.visualize()",
    examples: ["dx @$osed().seh.visualize()"],
  },
  {
    name: "fmt.build",
    description: "Builds a format-string write payload.",
    usage: "dx @$osed().fmt.build(addr, value, argIndex, width?, exclude?)",
    examples: ["dx @$osed().fmt.build(0x00402118, 0x625011AF, 6)"],
  },
  {
    name: "fmt.offset",
    description: "Finds the controlled format-string parameter index.",
    usage: "dx @$osed().fmt.offset(marker?, count?, firstArg?)",
    examples: ["dx @$osed().fmt.offset(0x41414141, 40)"],
  },
  {
    name: "fmt.inspect",
    description: "Inspects a paused x86 cdecl printf-family call, its format-string argument, and its format specifiers.",
    usage: "dx @$osed().fmt.inspect(family?, formatArgOffset?, max?)",
    examples: ['dx @$osed().fmt.inspect("printf")', 'dx @$osed().fmt.inspect("snprintf")'],
    limitations: ["Manual, read-only inspection only. x64 ABI argument decoding is not implemented.", "A dangerous specifier does not establish reachability or attacker control."],
  },
  {
    name: "str.read",
    description: "Reads a null-terminated ASCII or UTF-16LE string from memory.",
    usage: "dx @$osed().str.read(address, max?, encoding?)",
    examples: ["dx @$osed().str.read(0x0019F920)", "dx @$osed().str.read(0x0019F920, 128, \"utf16le\")"],
  },
  {
    name: "str.find",
    description: "Finds ASCII and/or UTF-16LE string bytes in loaded module sections.",
    usage: "dx @$osed().str.find(text, module?, encoding?, maxResults?)",
    examples: ["dx @$osed().str.find(\"VirtualProtect\")", "dx @$osed().str.find(\"cmd.exe\", \"target\", \"ascii\", 25)"],
  },
  {
    name: "str.refs",
    description: "Finds executable absolute-pointer references to a string address or literal.",
    usage: "dx @$osed().str.refs(target, module?, encoding?, maxResults?)",
    examples: ["dx @$osed().str.refs(\"VirtualProtect\")", "dx @$osed().str.refs(0x00403080, \"target\", \"ascii\", 25)"],
  },
  {
    name: "str.bytes",
    description: "Encodes text as payload bytes and reports bad-character hits.",
    usage: "dx @$osed().str.bytes(text, encoding?, terminator?, exclude?)",
    examples: ["dx @$osed().str.bytes(\"cmd.exe\")", "dx @$osed().str.bytes(\"W00T\", \"ascii\", true, \"00 0A 0D\")"],
  },
  {
    name: "rop_find",
    description: "Flat alias for legacy ROP helper/module triage.",
    usage: "dx @$osed().rop_find(module?, maxResults?, executableOnly?, mode?)",
    examples: ["dx @$osed().rop_find(\"essfunc\")"],
  },
  {
    name: "rop.find",
    description: "Runs the legacy ROP helper/module triage from the ROP namespace.",
    usage: "dx @$osed().rop.find(module?, maxResults?, executableOnly?, mode?)",
    examples: ["dx @$osed().rop.find(\"essfunc\")"],
  },
  {
    name: "rop.scan",
    description: "Loads pasted RP++ output into the semantic ROP corpus. Optionally filters gadgets whose addresses contain bad characters.",
    usage: "dx @$osed().rop.scan(text, badchars?)",
    examples: [
      "dx @$osed().rop.scan(\"0x1000: pop eax ; ret ;\")",
      'dx @$osed().rop.scan(rpOutput, "00 0A 0D")',
    ],
    seeAlso: ["rop.scan_live", "rop.capabilities", "rop.corpus.report", "rop.corpus.export"],
  },
  {
    name: "rop.scan_live",
    description: "Discovers live gadgets across one or more modules and replaces or appends to the semantic corpus.",
    usage: "dx @$osed().rop.scan_live(moduleOrModules?, badchars?, append?, maxPerPattern?, maxInstructionsPerGadget?, maxBackwardGadgets?)",
    examples: [
      'dx @$osed().rop.scan_live("compression", "00 0A 0D")',
      'dx @$osed().rop.scan_live("crypto", "00 0A 0D", true)',
      'dx @$osed().rop.scan_live("crypto", "00 0A 0D", true, 5)',
      'dx @$osed().rop.scan_live("libspp.dll", "00 0A 0D", true, 40, 6)',
      'dx @$osed().rop.scan_live("libspp.dll", "00 0A 0D", false, 40, 6, 50000)',
    ],
    seeAlso: ["rop.capabilities", "rop.corpus.export", "rop.generate"],
  },
  {
    name: "rop.corpus.lookup",
    description: "Read-only exact-address lookup in the active ROP corpus. Reports NOT_FOUND without scanning memory.",
    usage: "dx @$osed().rop.corpus.lookup(address)",
    examples: ["dx @$osed().rop.corpus.lookup(0x10154112)"],
    seeAlso: ["rop.scan_live", "rop.query", "rop.corpus.report"],
  },
  {
    name: "rop.api_plan",
    description: "Read-only Phase 1 API-resolution analysis. Finds direct IAT slots and same-image exact-export anchors, validates live pointer/module/export evidence, and reports byte constraints. It never constructs or ranks ROP chains.",
    usage: 'dx @$osed().rop.api_plan("MODULE!Symbol", badchars?)',
    examples: [
      'dx @$osed().rop.api_plan("KERNEL32!WriteProcessMemory", "00 0A 0D")',
      'dx @$osed().rop.api_plan("VirtualProtect")',
    ],
    seeAlso: ["sc.iat", "rop.slot_call", "rop.construct", "rop.prove"],
  },
  {
    name: "rop.api_build",
    description: "Bounded Phase 2 composer for API-address resolution into EAX. Revalidates Phase 1 evidence in the current stopped-debugger snapshot, then supports exact pop, mov-reg-[reg], add, and ret/ret-N gadgets. It requires an explicit continuation and never invokes the API.",
    usage: 'dx @$osed().rop.api_build(target, badchars?, continuation?, preserve?, maxGadgets?, owner?, anchor?)',
    examples: ['dx @$osed().rop.api_build("KERNEL32!WriteProcessMemory", "00 0A 0D", 0x10064A0F, "", 12, "libspp.dll", "QueryDosDeviceA")'],
    seeAlso: ["rop.api_plan", "rop.construct", "rop.verify", "rop.prove"],
  },
  {
    name: "dep_plan",
    summary: "Whole DEP bypass discovery in seven sections",
    description: "Runs the DEP bypass discovery for VirtualAlloc, VirtualProtect or WriteProcessMemory in one command. Each step prints under its own [n/7] header: module protections, IAT slot, gadget corpus, the best 3 gadgets per job with side effects, clean constants, the frame or PUSHAD map, and a Python draft to verify field by field.",
    usage: 'dx @$osed().dep_plan(api, module, badchars, style?)',
    examples: [
      'dx @$osed().dep_plan("VirtualAlloc", "libbkup", "00 09 0A 0B 0C 0D 20")',
      'dx @$osed().dep_plan("VirtualProtect", "libbkup", "00 0A 0D", "pushad")',
      'dx @$osed().dep_plan("WriteProcessMemory", "libbkup", "00 0A 0D")',
    ],
    details: "The draft is not a finished chain. It fills in the top-ranked gadget per job and marks with TODO the distances only a debugger run can give, with the commands that measure them. It does not check that one gadget's output register is the next gadget's input.",
    seeAlso: ["rop.scan_live", "rop.query", "rop.construct", "dep_candidates"],
  },
  {
    name: "dep_candidates",
    summary: "Best 3 gadgets per DEP chain job, ranked by side effects",
    description: "Prints what step [4/7] of dep_plan prints: for each job of the skeleton or pushad chain, the 3 gadgets from the module with the fewest side effects, with what else each one does. The pushad style also lists jmp esp and call esp addresses. It scans the module itself and leaves the loaded corpus as it was.",
    usage: 'dx @$osed().dep_candidates(module, badchars, style?)',
    examples: [
      'dx @$osed().dep_candidates("libbkup", "00 09 0A 0B 0C 0D 20", "skeleton")',
      'dx @$osed().dep_candidates("libbkup", "00 0A 0D", "pushad")',
    ],
    details: "Ranked by fewest side effects, then the smallest stack move. A gadget that moves ESP only counts for the pivot job. rop.query lists every gadget of one capability instead, in corpus order.",
    seeAlso: ["dep_plan", "rop.query", "rop.scan_live"],
  },
  {
    name: "rop.query",
    description: "Filters the loaded semantic ROP corpus.",
    usage: "dx @$osed().rop.query(field, value, executableOnly?, verbose?)",
    examples: ['dx @$osed().rop.query("capability", "LOAD_REGISTER")', 'dx @$osed().rop.query("capability", "MEMORY_WRITE", false, true)'],
    details: "The default table is compact: Address, Sequence, Capability, Stack, Score. Pass verbose:true in object form (or true as the fourth positional argument) to include module, reads/writes, memory effects, terminator, and all capabilities.",
  },
  {
    name: "rop.capabilities",
    description: "Summarizes capabilities in the loaded semantic ROP corpus.",
    usage: "dx @$osed().rop.capabilities()",
    examples: ["dx @$osed().rop.capabilities()"],
  },
  {
    name: "rop.plan",
    description: "Plans feasible exploit strategies from semantic capabilities without selecting gadget addresses. Strategies: VirtualProtect, VirtualAlloc, WriteProcessMemory, VirtualProtectEx, VirtualAllocEx, WinExec, Stack Pivot.",
    usage: "dx @$osed().rop.plan(strategy, apiResolution?)",
    examples: ['dx @$osed().rop.plan("VirtualAlloc")', 'dx @$osed().rop.plan("VirtualProtect", "iat")', 'dx @$osed().rop.plan("WinExec")'],
  },
  {
    name: "rop.emit",
    description: "Selects and ranks concrete gadgets for a plan strategy. Produces a gadget assignment, not an executable chain.",
    usage: "dx @$osed().rop.emit(planId, strategyId?)",
    examples: ["dx @$osed().rop.emit(1)", "dx @$osed().rop.emit(1, 3)"],
  },
  {
    name: "rop.synthesize",
    description: "Synthesizes a concrete stack layout from a plan and the current exploit state. Uses cached state from triage(); accepts optional overrides.",
    usage: "dx @$osed().rop.synthesize(planId)",
    examples: [
      "dx @$osed().rop.synthesize(1)",
    ],
  },
  {
    name: "rop.construct",
    description: "Builds a badchar-safe ROP recipe that loads a value into a register using pop/arithmetic gadgets. Models each gadget's full side effects: emits filler slots for extra pops and `add esp` skips so the chain stays aligned, reports every register the recipe clobbers (including non-pop writes like `mov eax, ...`), and excludes gadgets whose ESP shift cannot be padded (push, sub esp). Pass a preserve list to exclude gadgets that would overwrite registers you need to keep live (e.g. eax already staged for a stdcall frame).",
    usage: "dx @$osed().rop.construct(register, value, badchars?, preserve?)",
    examples: [
      'dx @$osed().rop.construct("ebx", 0x201, "00 0A 0D")',
      'dx @$osed().rop.construct("ebx", 0x201, "00 0A 0D", "eax")',
      'dx @$osed().rop.construct("edx", 0x1000, "00 0A 0D", "eax ecx")',
    ],
  },
  {
    name: "rop.setup",
    description: "Packs a whole set of target registers into a clobber-safe load sequence — the tool for staging a PUSHAD or stdcall frame. Exploits multi-pop gadgets to set several registers per gadget and orders gadgets so none overwrites an already-finalized register; reports honest conflicts when no ordering works. Values must be badchar-free (build tainted values with rop.construct first). Unlike rop.construct, it reasons about all target registers at once.",
    usage: 'dx @$osed().rop.setup("reg=value reg=value ...", badchars?)',
    examples: [
      'dx @$osed().rop.setup("edi=0x10001000 ebx=0x40", "00 0A 0D")',
      'dx @$osed().rop.setup("edi=0x10030000 esi=0x10040000 ebp=0x10050000 ebx=0x201 edx=0x40", "00 0A 0D")',
    ],
  },
  {
    name: "rop.frame_write",
    description: "Builds a stdcall call frame WITHOUT pushad: assembles it word-by-word in a writable buffer via a canonical `mov [eax], ecx ; ret` store (eax=pointer, ecx=value), then `xchg eax, esp` pivots ESP onto the frame so the trailing ret dispatches into the API. Null/badchar-heavy words are synthesised in ecx (preserving the eax pointer) instead of placed in the payload. Words are ordered: word0 = API address (ret enters it), word1 = post-call target (must be executable), then the stdcall args. BUF must be a writable, stable, badchar-free address.",
    usage: 'dx @$osed().rop.frame_write(buf, "word0 word1 arg1 arg2 ...", badchars?)',
    examples: [
      'dx @$osed().rop.frame_write("BUF", "VIRTUALALLOC POST_CALL 0x0 0x1000 0x3000 0x40", "00 0A 0D")',
      'dx @$osed().rop.frame_write("0x00420000", "[0x1005D060] 0x10017260 0x0 0x1000 0x3000 0x40", "00 0A 0D")',
    ],
    // A word written as [0xSLOT] dereferences that IAT slot at runtime (mov reg, [slot]) —
    // use it for an ASLR'd imported API (pass its non-ASLR IAT slot, not the resolved address).
  },
  {
    name: "rop.slot_call",
    description: "ASLR-proof stdcall call through a non-ASLR IAT slot, using a deref preamble dispatched by `jmp <reg>`. The deref/dispatch register is chosen from the loaded corpus (any register, or a two-register `mov <val>,[<ptr>]` split), ranked stable-first — not assumed to be eax. Emits, as data in a write-built frame: `pop <ptr>` (=slot), `mov <val>,[<ptr>]` (val = live API address), `jmp <val>` (dispatch), then the fake stdcall frame — arg0 = the API's return target (must be executable, e.g. shellcode / jmp esp), then the stdcall args. The API's real (ASLR'd) address is NEVER placed in the payload; it is read from the fixed IAT slot at runtime. Null/badchar args are synthesised in a register and stored (via the frame_write engine). BUF must be a writable, stable, badchar-free address. Reports honestly when the corpus has no composable deref/dispatch; warns if any preamble gadget is at a non-stable (relocating) address.",
    usage: 'dx @$osed().rop.slot_call(buf, iatSlot, "retaddr arg1 arg2 ...", badchars?, entrySkew?)',
    examples: [
      // VirtualAlloc(lpAddress, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE) via its IAT slot;
      // retaddr = arg1 = the shellcode address (re-commit the page RWX in place, then return into it).
      'dx @$osed().rop.slot_call("0x00420000", "0x1005D060", "SHELLCODE SHELLCODE 0x1000 0x1000 0x40", "00 0A 0D")',
      // entrySkew: if the vulnerable function returns with `ret N` (ESP is N bytes high on entry),
      // pass N so the right filler is inserted after the entry gadget. e.g. `ret 4` -> 4:
      'dx @$osed().rop.slot_call("0x00420000", "0x1005D060", "SHELLCODE SHELLCODE 0x1000 0x1000 0x40", "00 0A 0D", 4)',
    ],
  },
  {
    name: "rop.generate",
    description: "One-command exploit generator. Discovers the IAT slot and writable buffer, builds a slot_call ROP chain for the chosen DEP-bypass API, XOR-encodes shellcode, and emits a complete Python exploit. Use api: \"auto\" to enumerate all candidates and select the best. All discovery is optional — pass iatSlot, buf, retAddr manually to override. Requires a loaded corpus (rop.scan / rop.scan_live).",
    usage: 'dx @$osed().rop.generate(api, shellcode?, badchars?, module?, offset?)',
    examples: [
      'dx @$osed().rop.generate("auto", "", "00 0A 0D", "MSA2Mfilter03", 780)',
      'dx @$osed().rop.generate("VirtualAlloc", "FC E8 82 00 00 00 60", "00 0A 0D")',
      'dx @$osed().rop.generate("VirtualProtect")',
    ],
    seeAlso: ["rop.scan_live", "rop.verify", "rop.prove"],
  },
  {
    name: "rop.verify",
    description: "Chain verifier. Inspects a generated or manually supplied ROP chain for bad characters, unresolved placeholders, stack consumption, and register side effects. Reports static validity separately from a DWORD-by-DWORD runtime trace with ESP movement and register state. Never modifies the chain — read-only analysis.",
    usage: 'dx @$osed().rop.verify(chain?, badchars?, api?)',
    examples: [
      'dx @$osed().rop.verify()                                          // verify last rop.generate result',
      'dx @$osed().rop.verify("", "00 0A 0D")                            // verify last result with explicit badchars',
      'dx @$osed().rop.verify("10022D64 1005D060 DEADBEEF", "00 0A 0D")',
    ],
    seeAlso: ["rop.generate", "rop.prove"],
  },
  {
    name: "rop.prove",
    description: "Guided debugger-backed ROP proof. Predicts one checkpoint at a time, optionally owns one one-shot breakpoint, and never resumes execution. Reports gadget execution separately from the DEP objective.",
    usage: 'dx @$osed().rop.prove(modeOrAction?)',
    examples: [
      'dx @$osed().rop.prove("guided")',
      'dx @$osed().rop.prove("observe")',
      'dx @$osed().rop.prove()',
      'dx @$osed().rop.prove("status")',
      'dx @$osed().rop.prove("cancel")',
      'dx @$osed().rop.prove("export")',
    ],
    seeAlso: ["rop.generate", "rop.verify"],
  },
  {
    name: "rop.export",
    description: "Exports emitted gadgets (and optionally the synthesized stack layout) as a Python exploit stub. If a file path is given, writes to disk; otherwise prints to console.",
    usage: "dx @$osed().rop.export(planId, path?)",
    examples: [
      "dx @$osed().rop.export(1)",
      'dx @$osed().rop.export(1, "C:\\\\exploit\\\\rop.py")',
    ],
    details: "Turns an emitted plan (from rop.emit) into a ready-to-paste Python exploit stub. Needs a plan id — run rop.plan then rop.emit first. This exports a single chain as Python; to save the whole gadget corpus for reuse, use rop.corpus.export instead.",
    seeAlso: ["rop.plan", "rop.emit", "rop.corpus.export"],
  },
  {
    name: "rop.corpus.export",
    description: "Exports a compact, regenerable ROP corpus and live validation fingerprint as JSON.",
    usage: "dx @$osed().rop.corpus.export(path?)",
    examples: [
      'dx @$osed().rop.corpus.export("C:\\\\notes\\\\rop-corpus.json")  // Saves the current corpus to disk.',
      "dx @$osed().rop.corpus.export()                              // print JSON to the console",
    ],
    details: "Saves the gadgets you scanned this session so you don't have to re-scan next time. Scanning a large target is slow; export once, then rop.corpus.import it in a later session. The JSON also records a fingerprint (module bases + sampled gadget bytes) so a reloaded corpus can be checked against live memory before you trust its addresses. Run this after rop.scan / rop.scan_live has populated the corpus.",
    seeAlso: ["rop.scan_live", "rop.corpus.report", "rop.corpus.import", "rop.corpus.validate"],
  },
  {
    name: "rop.corpus.report",
    summary: "Write or print a human-readable gadget inventory.",
    description: "Formats the current ROP corpus as a deterministic one-line-per-gadget report. It is for visual gadget review; rop.corpus.export remains the lossless JSON archive.",
    usage: "dx @$osed().rop.corpus.report(path?)",
    examples: [
      "dx @$osed().rop.corpus.report()",
      'dx @$osed().rop.corpus.report("C:\\\\notes\\\\rop-gadgets.txt")',
    ],
    prerequisites: ["Run rop.scan(...) or rop.scan_live(...) first. Imported corpora are marked unverified until validation."],
    limitations: ["The report performs no additional gadget scanning. Unknown module metadata and semantic facts are rendered as ?."],
    seeAlso: ["rop.scan_live", "rop.capabilities", "rop.corpus.export"],
  },
  {
    name: "rop.corpus.import",
    description: "Imports a corpus as stale evidence. Run rop.corpus.validate() before querying or planning.",
    usage: "dx @$osed().rop.corpus.import(path)",
    examples: ['dx @$osed().rop.corpus.import("C:\\\\notes\\\\rop-corpus.json")'],
    details: "Loads a corpus you previously saved with rop.corpus.export, avoiding a full re-scan. The imported corpus is INACTIVE until you run rop.corpus.validate() against the live target — gadget addresses are only trustworthy if the modules still map where they did when you exported. Querying or planning is blocked until validation succeeds.",
    seeAlso: ["rop.corpus.validate", "rop.corpus.export"],
  },
  {
    name: "rop.corpus.validate",
    description: "Validates imported module mappings and sampled gadget bytes before enabling the corpus.",
    usage: "dx @$osed().rop.corpus.validate()",
    examples: ["dx @$osed().rop.corpus.validate()"],
    details: "Activates a corpus loaded by rop.corpus.import, but only if it still matches the live target: it re-reads the recorded module bases and sampled gadget bytes and refuses if anything moved or changed (e.g. a relocated DLL). On success the corpus becomes active for query/plan/generate; on failure it reports exactly what drifted so you can re-scan instead.",
    seeAlso: ["rop.corpus.import", "rop.scan_live", "rop.query"],
  },
  {
    name: "rop.pivots",
    description: "Finds, classifies, and ranks stack pivot gadgets from the semantic corpus. Optionally filters by source register or minimum ESP adjustment.",
    usage: "dx @$osed().rop.pivots(register?, minDelta?, verbose?)",
    examples: [
      "dx @$osed().rop.pivots()",
      'dx @$osed().rop.pivots("eax")',
      "dx @$osed().rop.pivots(undefined, 0x100)",
      'dx @$osed().rop.pivots("eax", 0, true)',
    ],
    details: "The default table is compact: Address, Sequence, Type, Stack, Score. Use verbose:true for source register, clobbers, and module metadata.",
  },
  {
    name: "rop.chain",
    description: "Builds a register-setup chain from the loaded ROP corpus.",
    usage: "dx @$osed().rop.chain(register, value, register2?, value2?, ...)",
    examples: ['dx @$osed().rop.chain("eax", 0xDEADBEEF, "ebx", 0x1000)'],
  },
  {
    name: "rop.chain_vp",
    description: "Builds a VirtualProtect PUSHAD chain from the loaded ROP corpus.",
    usage: "dx @$osed().rop.chain_vp(virtualProtect?, retGadget?, returnAddress?, lpAddress?, dwSize?, writable?, flNewProtect?, mode?)",
    examples: ["dx @$osed().rop.chain_vp(0x7C801AD0, 0x62501010, 0x625011AF)"],
  },
  {
    name: "rop.chain_wpm",
    description: "Builds a constrained WriteProcessMemory PUSHAD chain from the loaded ROP corpus.",
    usage: "dx @$osed().rop.chain_wpm(writeProcessMemory?, returnAddress?, lpBuffer?, nSize?, writable?)",
    examples: ["dx @$osed().rop.chain_wpm(0x7C802213, 0x625011AF, 0x0012F800, 0x200)"],
  },
  {
    name: "rop.chain_va",
    description: "Builds a constrained VirtualAlloc PUSHAD chain from the loaded ROP corpus.",
    usage: "dx @$osed().rop.chain_va(virtualAlloc?, returnAddress?, lpAddress?, flAllocationType?, flProtect?)",
    examples: ["dx @$osed().rop.chain_va(0x7C809AE1)"],
  },
  {
    name: "rop.frame_vp",
    description: "Builds a flat VirtualProtect stdcall frame without requiring ROP gadgets.",
    usage: "dx @$osed().rop.frame_vp(virtualProtect?, returnAddress?, lpAddress?, dwSize?, flNewProtect?, writable?, badchars?)",
    examples: ['dx @$osed().rop.frame_vp(0x7C801AD0, 0x625011AF, 0x0012F800, 0x201, 0x40, 0x62506000, "00 0A 0D")'],
  },
  {
    name: "rop.frame_wpm",
    description: "Builds a flat WriteProcessMemory stdcall frame without requiring ROP gadgets.",
    usage: "dx @$osed().rop.frame_wpm(writeProcessMemory?, returnAddress?, hProcess?, lpBaseAddress?, lpBuffer?, nSize?, writable?, badchars?)",
    examples: ['dx @$osed().rop.frame_wpm(0x7C802213, 0x625011AF, 0xFFFFFFFF, 0x62502000, 0x0012F800, 0x200, 0x62506000, "00")'],
  },
  {
    name: "rop.frame_va",
    description: "Builds a flat VirtualAlloc stdcall frame without requiring ROP gadgets.",
    usage: "dx @$osed().rop.frame_va(virtualAlloc?, returnAddress?, lpAddress?, dwSize?, flAllocationType?, flProtect?, badchars?)",
    examples: ['dx @$osed().rop.frame_va(0x7C809AE1, 0x625011AF, 0, 0x201, 0x1000, 0x40, "00 0A 0D")'],
  },
  {
    name: "code_caves",
    description: "Finds contiguous null/int3/nop padding regions in PE sections with exploitation classification, ASLR awareness, and bad-character filtering. Detection heuristics inspired by nop-tech/codecaver (https://github.com/nop-tech/codecaver).",
    usage: "dx @$osed().code_caves(module?, minSize?, maxResults?, badChars?, capability?)",
    examples: [
      "dx @$osed().code_caves()",
      'dx @$osed().code_caves("essfunc")',
      'dx @$osed().code_caves("essfunc", 100)',
      'dx @$osed().code_caves("essfunc", 50, 25, "00 0A 0D")',
      'dx @$osed().code_caves("", 50, 25, "", "EXEC")',
    ],
  },
  {
    name: "sc.iat",
    description: "Enumerates imported addresses for a module, optionally filtered by DLL or symbol substring.",
    usage: "dx @$osed().sc.iat(module?, filter?)",
    examples: ["dx @$osed().sc.iat()", "dx @$osed().sc.iat(\"app.exe\", \"Virtual\")"],
  },
  {
    name: "sc.iat_find",
    description: "Searches all loaded modules for matching IAT entries.",
    usage: "dx @$osed().sc.iat_find(symbol)",
    examples: ["dx @$osed().sc.iat_find(\"VirtualAlloc\")"],
  },
  {
    name: "sc.iat_ptr",
    description: "Resolves one imported symbol to its IAT slot and current target pointer.",
    usage: "dx @$osed().sc.iat_ptr(module, symbol)",
    examples: ["dx @$osed().sc.iat_ptr(\"app.exe\", \"VirtualProtect\")"],
  },
  {
    name: "sc.exportdir",
    description: "Shows PE export directory addresses and table metadata.",
    usage: "dx @$osed().sc.exportdir(module)",
    examples: ["dx @$osed().sc.exportdir(\"kernel32\")"],
  },
  {
    name: "sc.export",
    description: "Resolves an export by name and reports ordinal, RVA, VA, and forwarder data.",
    usage: "dx @$osed().sc.export(module, symbol)",
    examples: ["dx @$osed().sc.export(\"kernel32\", \"GetProcAddress\")"],
  },
  {
    name: "sc.exportwalk",
    description: "Walks PE export resolution checkpoints.",
    usage: "dx @$osed().sc.exportwalk(module, symbol?, verbose?)",
    examples: ["dx @$osed().sc.exportwalk(\"kernel32\", \"GetProcAddress\")"],
  },
  {
    name: "sc.exportat",
    description: "Resolves an export by ordinal index.",
    usage: "dx @$osed().sc.exportat(module, ordinalIndex)",
    examples: ["dx @$osed().sc.exportat(\"kernel32\", 842)"],
  },
  {
    name: "sc.hashresolve",
    description: "Resolves an API hash against module exports.",
    usage: "dx @$osed().sc.hashresolve(module, hashValue, algorithm?)",
    examples: ["dx @$osed().sc.hashresolve(\"kernel32\", 0x7c0dfcaa, \"ROR13\")"],
  },
  {
    name: "sc.exports",
    description: "Enumerates exported symbols, optionally filtered by substring.",
    usage: "dx @$osed().sc.exports(module, filter?)",
    examples: ["dx @$osed().sc.exports(\"kernel32\", \"Virtual\")"],
  },
  {
    name: "sc.resolve",
    description: "Resolves one export to an address.",
    usage: "dx @$osed().sc.resolve(module, symbol)",
    examples: ["dx @$osed().sc.resolve(\"kernel32\", \"WinExec\")"],
  },
  {
    name: "sc.hashes",
    description: "Hashes named exports with the selected shellforge-compatible algorithm.",
    usage: "dx @$osed().sc.hashes(module, algorithm?)",
    examples: ["dx @$osed().sc.hashes(\"kernel32\", \"crc32\")"],
  },
  {
    name: "sc.hash",
    description: "Hashes one API name.",
    usage: "dx @$osed().sc.hash(name, algorithm?)",
    examples: ["dx @$osed().sc.hash(\"WinExec\", \"ROR13\")"],
  },
  {
    name: "sc.push_string",
    description: "Prints x86 instructions that build a NUL-terminated string on the stack. Dwords are pushed last first; the terminator and a partial last dword are built without 00 bytes (xor/push, mov+not, mov+neg, mov+xor or mov+add) and every immediate avoids the given bad characters. Each push shows the 4 characters it holds and its bytes, then the same lines print as a Keystone CODE string.",
    usage: "dx @$osed().sc.push_string(text, badchars?, register?)",
    examples: [
      { label: "ESP points at the string", command: "dx @$osed().sc.push_string(\"calc.exe\")" },
      { label: "Spaces are bad chars, keep a pointer in ebx", command: "dx @$osed().sc.push_string(\"cmd.exe /c whoami\", \"00 0A 0D 20\", \"ebx\")" },
    ],
    details: "00 is always treated as bad. Encodings use eax, ecx or edx as scratch, so save those first if they hold values you need. Use the register argument to copy ESP right after the pushes, before more pushes move ESP away from the string.",
    seeAlso: ["sc.call_frame", "sc.template", "str.bytes"],
    keywords: ["shellcode", "string", "stack", "null-free", "custom shellcode"],
  },
  {
    name: "sc.call_frame",
    description: "Prints the pushes for one stdcall API call through the sc.template resolver: the arguments in reverse order with one comment each, the ROR13 hash of the export name, the module base slot, call [ebp-0x04] and call eax. Numeric arguments are pushed without 00 or bad bytes; registers, [ebp+n] slots and other expressions are pushed as written.",
    usage: "dx @$osed().sc.call_frame(api, args..., \"bad=<list>\"?)",
    examples: [
      { label: "WinExec with a placeholder pointer", command: "dx @$osed().sc.call_frame(\"WinExec\", \"<ptr to cmd>\", \"1\")" },
      { label: "Exit quietly, avoiding CR and LF", command: "dx @$osed().sc.call_frame(\"TerminateProcess\", \"-1\", \"0\", \"bad=00 0A 0D\")" },
    ],
    details: "Known prototypes (WinExec, ExitProcess, TerminateProcess, LoadLibraryA, GetProcAddress, VirtualAlloc, CreateProcessA, WSAStartup, connect, MessageBoxA and a few more) name each argument and warn about a wrong count. An unknown name still gets its hash, from the exact spelling given. Exports outside kernel32 use the [ebp-0x0c] slot that a LoadLibraryA task fills.",
    seeAlso: ["sc.template", "sc.hash", "sc.hashresolve"],
    keywords: ["shellcode", "stdcall", "hash", "ror13", "custom shellcode"],
  },
  {
    name: "sc.template",
    description: "Prints a complete build_sc.py for custom x86 shellcode. The assembly saves registers, reserves stack without 00 bytes, finds kernel32 through the PEB loader list, stores a ROR13 export resolver, runs one call frame per task, and returns. The Python part assembles with Keystone, prints the size and every bad byte with its offset and line, writes shellcode.bin and prints the bytes as a literal.",
    usage: "dx @$osed().sc.template(task..., \"bad=<list>\"?)",
    examples: [
      { label: "calc, then ExitProcess", command: "dx @$osed().sc.template(\"winexec=calc.exe\", \"exit\")" },
      { label: "Hidden command, spaces are bad", command: "dx @$osed().sc.template(\"show=0\", \"winexec=cmd.exe /c whoami\", \"terminate\", \"bad=00 0A 0D 20\")" },
      { label: "Load a DLL and resolve an export", command: "dx @$osed().sc.template(\"loadlibrary=user32.dll\", \"getprocaddress=MessageBoxA\")" },
    ],
    details: "Tasks run in order: winexec=<command line>, loadlibrary=<dll>, getprocaddress=<export>, exit (ExitProcess(0)), terminate (TerminateProcess(-1, 0)). show=<n> sets uCmdShow for later winexec tasks (default 1). Without an exit task the shellcode returns to its caller, which suits a test loader. With no tasks you get winexec=calc.exe and exit. Default output contains no 00 byte; other bad chars in the fixed routines are reported by the script for you to rewrite.",
    limitations: ["32-bit only. The kernel32 lookup matches the first 12-character module name starting with K in initialization order, which was kernel32.dll on the Windows 10 (19045) and Windows 11 (26200) builds tested."],
    seeAlso: ["sc.builder", "sc.push_string", "sc.call_frame", "sc.hash"],
    keywords: ["shellcode", "keystone", "peb", "export", "custom shellcode", "build_sc"],
  },
  {
    name: "sc.builder",
    description: "Prints sc_builder.py, a Python 3 builder for custom x86 shellcode driven by the CONFIG block at its top: BADCHARS, MAX_SIZE, EXIT, XOR_ENCODER, CDECL, DEBUG, and one API call per line in execution order, written as k32.Api(args) for kernel32.dll or dll(\"name\").Api(args) for a DLL the builder loads. It prints the ROR13 hash of each API, walks the PEB to kernel32, loads other DLLs once with LoadLibraryA, caches each API address next to EBP, and pushes strings and constants without bad bytes. Nothing is chosen without being checked against BADCHARS: the registers the PEB walk and the resolver run on, the form of every constant and string push, and the stack cleanup after a cdecl call. Keystone assembles it line by line; the script reports the size, every bad byte with its offset and line, and forward calls, and Capstone (when installed) disassembles the result. It writes shellcode.bin and prints a Python literal. Exit code 1 means a check failed.",
    usage: "dx @$osed().sc.builder(task..., \"bad=<list>\"?, \"xor\"?, \"max=<bytes>\"?)",
    examples: [
      { label: "The script with its default CONFIG", command: "dx @$osed().sc.builder()" },
      { label: "Hidden command, space and slash are bad", command: "dx @$osed().sc.builder(\"show=0\", \"winexec=cmd.exe /c whoami > C:\\\\out.txt\", \"terminate\", \"bad=00 0A 0D 20 2F\")" },
      { label: "Plan B: XOR decoder stub and a size limit", command: "dx @$osed().sc.builder(\"winexec=calc.exe\", \"exit\", \"bad=00 0A 0D\", \"xor\", \"max=400\")" },
    ],
    details: "With no arguments the script prints exactly as shipped (tools/sc_builder.py in the repository). Arguments take the sc.template tasks (winexec=, loadlibrary=, getprocaddress=, exit, terminate, show=, bad=) and fill CONFIG from them, plus xor and max=<bytes>. For any other API sequence, write one call per line. Each arg is an int, a Win32 constant the builder defines (NULL, GENERIC_WRITE, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, SW_HIDE, MB_OK and others), s(\"text\"), w(\"text\") for W APIs, buf(size) for scratch space below EBP, base(\"dll\"), or a name bound to an earlier call, as in handle = k32.CreateFileA(...) followed by k32.WriteFile(handle, ...). A name is bound when its call runs, so a call inserted above it cannot move it. buf(size) binds the same way: bind it to a name and every call that takes the name gets one address, so GetTempPathA can fill it and lstrcatA can append to it, while an inline buf(size) is its own space. Win32 is stdcall; the builder knows the varargs formatters (wsprintfA and the sprintf family) and the C runtime are cdecl and drops their arguments itself, and CDECL or .cdecl at the call site adds any other cdecl export. DEBUG = True puts an int3 after every name lookup, taken only when the lookup came back 0, at five bytes per lookup. With XOR_ENCODER = True the body's bad bytes are information, not problems, because the stub decodes them before they run. The older literal CALLS = [(dll, api, [args])] list with ref(n) for the result of call n (counted from 1) still builds the same bytes, and a CONFIG block that holds both forms fails. EXIT is terminate, exit or ret.",
    limitations: ["32-bit only. Forwarded exports (an export whose address is a \"DLL.Name\" string) are not followed; call the target DLL's export instead. buf() space is not zeroed. DEBUG needs the int3 byte 0xcc to be allowed."],
    seeAlso: ["sc.template", "sc.hash", "sc.push_string"],
    keywords: ["shellcode", "keystone", "capstone", "builder", "custom shellcode", "config", "ror13", "xor encoder", "cdecl", "wsprintfA", "buffer", "int3", "debug"],
  },
  {
    name: "sc.algorithms",
    description: "Lists supported API hash algorithms.",
    usage: "dx @$osed().sc.algorithms()",
    examples: ["dx @$osed().sc.algorithms()"],
  },
  {
    name: "sc.pe",
    description: "Prints PE header fields for a module.",
    usage: "dx @$osed().sc.pe(module)",
    examples: ["dx @$osed().sc.pe(\"kernel32\")"],
  },
  {
    name: "sc.base",
    description: "Resolves a module base address.",
    usage: "dx @$osed().sc.base(module)",
    examples: ["dx @$osed().sc.base(\"kernel32\")"],
  },
  {
    name: "sc.modules",
    description: "Lists loaded modules.",
    usage: "dx @$osed().sc.modules()",
    examples: ["dx @$osed().sc.modules()"],
  },
  {
    name: "sc.peb",
    description: "Dumps current PEB-oriented module evidence.",
    usage: "dx @$osed().sc.peb()",
    examples: ["dx @$osed().sc.peb()"],
  },
  {
    name: "sc.module_pages",
    description: "Reports module size and estimated page count.",
    usage: "dx @$osed().sc.module_pages(module)",
    examples: ["dx @$osed().sc.module_pages(\"kernel32\")"],
  },
  {
    name: "sc.page_summary",
    description: "Buckets module pages by protection value.",
    usage: "dx @$osed().sc.page_summary(module)",
    examples: ["dx @$osed().sc.page_summary(\"kernel32\")"],
  },
  {
    name: "stackmap",
    description: "Maps the call stack at crash time, classifying each slot as pattern bytes (PATTERN), verified return address (RET), saved frame pointer (SAVED_EBP), stale module pointer (STALE_PTR), null (NULL), or data (DATA). Reports controlled slot count, ROP room, and chain entry point.",
    usage: "dx @$osed().stackmap(depth?, patternLength?)",
    examples: [
      "dx @$osed().stackmap()",
      "dx @$osed().stackmap(128)",
      "dx @$osed().stackmap(64, 20000)",
    ],
  },
  {
    name: "exploit.workflow",
    description: "Prints a fixed list of dx commands for one workflow: egghunter, offset, or badchars.",
    usage: "dx @$osed().exploit.workflow(mode, tag?, offset?, address?)",
    examples: [
      'dx @$osed().exploit.workflow("offset")',
      'dx @$osed().exploit.workflow("egghunter", "W00T")',
      'dx @$osed().exploit.workflow("badchars", "", 0, 0x00B8F900)',
    ],
  },
  {
    name: "explain",
    summary: "Explain any command, with a report sentence",
    description: "Explains a command in plain words: what it does, how it works, when to use it, its arguments, how to read its output, and a sentence for an exam report. Append .explain to any call to explain that call with its real arguments and results.",
    usage: "dx @$osed().explain(command?, args...)",
    examples: [
      'dx @$osed().sc.resolve("kernel32", "WinExec").explain',
      'dx @$osed().explain("sc.resolve")',
      "dx @$osed().explain()",
    ],
    keywords: ["report", "why", "what"],
  },
  {
    name: "exploit.state",
    description: "Views or updates the cached exploit state used by rop.synthesize(). Populated automatically by triage(); individual fields can be set or overridden manually.",
    usage: "dx @$osed().exploit.state(overrides?)",
    examples: [
      "dx @$osed().exploit.state()",
    ],
  },
  {
    name: "exploit.clear",
    description: "Clears the cached exploit state.",
    usage: "dx @$osed().exploit.clear()",
    examples: ["dx @$osed().exploit.clear()"],
  },
];

export function findHelpEntry(name: string): HelpEntry | undefined {
  const normalized = name.trim().toLowerCase();
  return NAMESPACE_HELP_ENTRIES.find((entry) => entry.name.toLowerCase() === normalized);
}

export function helpRows(entry: HelpEntry): Array<Record<string, string>> {
  return [
    {
      Helper: entry.name,
      Usage: entry.usage,
      Description: entry.description,
    },
    ...normalizeHelpExamples(entry.examples).map((example) => ({
      Helper: "example",
      Usage: example.command,
      Description: "",
    })),
    ...(entry.seeAlso && entry.seeAlso.length > 0
      ? [{ Helper: "see also", Usage: entry.seeAlso.join(", "), Description: "" }]
      : []),
  ];
}
