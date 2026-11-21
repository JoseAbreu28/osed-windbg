# Changelog

This changelog reconstructs the functional history of `osed-windbg` from Git.
Development began inside the `OSED-Toolkit` repository and moved to this
standalone repository on 2026-07-09. Dates below describe when functionality
first appeared or materially changed; they are not package release dates.

## Timeline

### 2026-11-21 - dep_candidates, and dep_function prints the PUSHAD map

- `dep_candidates(module, badchars, style?)` prints what step `[4/7]` of `dep_plan` prints: the 3 gadgets per job with the fewest side effects, and in the PUSHAD style the `jmp esp` and `call esp` addresses. It scans the module on its own and leaves the loaded corpus as it was. `dep_plan` prints its line at the top of step 4, such as `dx @$osed().dep_candidates("libbkup", "00 09 0A 0B 0C 0D 20", "skeleton")`, and both print through the same code.
- `dep_function(method, style?)` takes `"pushad"` as its second argument and then prints only the PUSHAD register map, under `=== VirtualProtect PUSHAD Register Map ===`. Step `[6/7]` of a PUSHAD `dep_plan` now prints `dx @$osed().dep_function("VirtualProtect", "pushad")` and its output, so every step but the draft names the command that reproduces it.

### 2026-11-21 - dep_plan prints each command it runs

- `dep_plan` opens with the call as typed, such as `=== dx @$osed().dep_plan("VirtualAlloc", "libbkup", "00 09 0A 0B 0C 0D 20") ===`, so a log or a screenshot of the top names the API, the module, and the bad characters. `rop_template` opens the same way.
- Inside each `[n/7]` step, every command `dep_plan` runs prints first as the `dx` line that reruns it, then its output: `modules`, `sc.iat_find`, `rop.scan_live`, `find_bytes` in the PUSHAD style, one `rop.construct` per constant, `code_caves`, and `dep_function`. Pasting the line gives the same output, so one step can be repeated alone and the report can say which command produced it. The step 4 ranking, the PUSHAD map, and the draft are computed by `dep_plan` itself and print no line.

### 2026-11-21 - The gadget scans drop addresses with bad characters

- `rop_suggest(module, maxResults, badchars)` takes the bad characters as its third argument, as in `rop_suggest("libbkup", 3, "00 09 0A 0B 0C 0D 20")`, and leaves out every gadget whose address holds one. It reads more candidates than it prints, so up to `maxResults` clean addresses remain per pattern, and a `Bad chars` line counts the candidate addresses it dropped. `retn`, `add_esp`, `pivots`, and `find_bytes` take the list in the same place, right after `maxResults`. A boolean in the `badchars` slot is read as `executableOnly`, the older order, so calls written before the bad-char argument still work. With no list the output is unchanged.
- The test is the one `rop.scan_live` uses, `badcharAddressFilter`, with the same rule for how deep to scan, so the two agree on which address is bad.
- Byte lists also accept `\x00\x0a` and `0x00 0x0a`. Before, `rop.scan_live("libbkup", "\x00\x0a")` did not parse the list and scanned with no filter at all.
- `.explain` on these commands names the bad characters of the call in its report line.

### 2026-11-21 - The legacy build is checked against the 19041 engine

- `leak.analyze` failed in classic WinDbg 10.0.19041 with `Object doesn't support property or method 'matchAll'`, and so did the format string parser behind `fmt.inspect`. That engine has no `String.prototype.matchAll`. `legacy/runtime.js` now defines it.
- `legacy/engine.js` lists what the engine lacks, as measured by `legacy/engine_probe.js` inside cdb x86 10.0.19041.685: 33 builtins such as `replaceAll`, `Array.prototype.at`, `findLast`, and `Object.hasOwn`, plus regex named groups, lookbehind, and the `s` flag. `npm run build` deletes `dist/osed-legacy.js` and fails when the bundle uses one that `runtime.js` does not polyfill. `tests/legacy_engine.test.ts` builds the legacy bundle, scans it, and runs `leak.analyze` in a realm with those builtins removed.
- When `badchar_find` finds no array, it says how many bytes it scanned. It used to print the requested window even when the stack ended sooner. When the instruction pointer is inside a module, it says that the target has not crashed on the overflow yet, or faulted inside a module, rather than blaming the return address.

### 2026-11-21 - One command for the DEP bypass discovery

- `dep_plan(api, module, badchars, style?)` runs the discovery for VirtualAlloc, VirtualProtect, or WriteProcessMemory and prints seven sections, each under a `[n/7]` header: the module's protections, the IAT slot, the gadget corpus, the best 3 gadgets per job with their side effects, clean recipes for the constants plus writable and code cave addresses, the frame or PUSHAD map, and a Python draft. Each section calls the existing command, so `modules`, `sc.iat_find`, `rop.scan_live`, `rop.construct`, `code_caves`, `find_bytes`, and `dep_function` print what they print on their own.
- The draft fills in the top gadget per job and marks the distances that need a debugger run with `TODO measure`, with the `bp`, `s -d`, and `?` commands that measure them. It says that it is a draft to verify field by field, because nothing checks that one gadget's output register is the next one's input.
- A gadget that moves ESP is offered only as a pivot. `xchg eax, esp ; ret` also counts as a stack pointer capture in the corpus, and using it to capture ESP would throw the chain away.
- `rop_template` keeps its PUSHAD register maps in one table that `dep_plan` reuses, and the gadget ranking of the emitter is exported for the same reason.
- Section 1 warns about a bad byte in the module's base only when every address in the module shares that byte. The low 16 bits of every base are 00 because of the 64K alignment, and the gadget offset fills them, so the older check would have flagged every module when 00 is bad. Section 2 warns when the module does not import the API and the slot belongs to another module, and says when that module has ASLR.
- `code_caves` asks `!vprot` once per memory region instead of once per cave. Classic WinDbg echoes each `!vprot` it runs for a script, so `code_caves` and the cave lookup in `dep_plan` printed one line per cave, about 1200 lines for `libbkup.dll`.

### 2026-11-21 - Both DEP helpers cover all three APIs

- `rop_template(api, module, style)` takes a third argument. `"skeleton"`, the default, prints the method that puts a frame of dummy dwords before the return address, patches each field with a gadget, and pivots ESP onto the frame. It is printed for VirtualAlloc, VirtualProtect, and WriteProcessMemory in four steps: each field's real value and the `dx` command that gives it, the gadgets by `rop.query` capability, a Python skeleton, and the WinDbg checks for each field. `"pushad"` prints the register map instead. VirtualAlloc is a new `api` value.
- The VirtualProtect PUSHAD map was wrong. It put the saved ESP in `dwSize`, a stack address of about 0x0019xxxx, which asks VirtualProtect to change far more than the stack region. It now uses the usual layout: a ROP NOP in EDI, the API in ESI, the return in EBP, the saved ESP as `lpAddress`, then `dwSize`, `flNewProtect`, and `lpflOldProtect` from EBX, EDX, and ECX.
- The WriteProcessMemory PUSHAD map left out the saved ESP slot, so the printed register comments did not match what PUSHAD writes. The saved ESP falls on `lpBaseAddress`, so the map now puts `add esp, 0xC ; ret` in EDI and takes the last three arguments from the payload after the pushad gadget.
- `dep_function` takes `"VirtualAlloc"`, `"VirtualProtect"`, and `"WriteProcessMemory"`, with `VA`, `VP`, and `WPM` as aliases in any case. The VirtualProtect frame is new. The section title names the full API.
- The templates break on `KERNELBASE!` exports, which every call through kernel32 reaches, and point to `code_caves(..., "EXEC")` for the WriteProcessMemory cave and `code_caves(..., "STAGING")` for a writable dword.

### 2026-11-20 - sc_builder checks what it chooses

- A `buf(size)` result now binds where it is written, not where it is used. Before this change every use of a buffer allocated a fresh frame offset, so a buffer bound to a name and passed to two calls became two addresses and the builder reported no problem. A `path = buf(260)` used four times produced four buffers at `ebp-0x184`, `-0x288`, `-0x38c` and `-0x490`. One API can now fill a named buffer and the next can read it, as in `GetTempPathA` into `path` and then `lstrcatA(path, s("out.txt"))`, while an inline `buf(4)` out-parameter still gets space nothing else touches. The listing names each one, as in `arg1 = buf(260) #1, scratch at ebp-0x184`.
- The PEB walk and the resolver choose their registers against `BADCHARS`. They used to fix them up front, so `mov ebx, dword ptr [esp+0x18]`, which reads the resolver's first argument, encoded as `8b 5c 24 18` and blocked every config whose transport forbids `5c`. That is the OSED Lab14 and Lab15 set, `00 0A 0D 2E 3A 5C`, against which only 2 of the 24 register orders are clean. The module base, the export-name counter, the running hash, and the pointer into module data now take EBX, ECX, EDX, and EDI in whichever order assembles clean and shortest, and the script prints the choice. EAX and ESI stay put, since EAX is the return value and the destination `lodsb` writes and ESI the address it reads. A config that was already clean assembles to the same bytes as before.
- `XOR_ENCODER = True` no longer fails a correct build. The plain body never reaches the transport as written, so its bad bytes are printed as information and the build exits 0. A Lab14 config that produced 340 clean bytes used to print `1 problem(s)` and exit 1. Bad bytes and forward calls are now two checks, because the encoder hides one and cannot hide the other, and the body's bad bytes become problems again when no key works. The register search shared the same premise and refused to build at all; with the encoder on it keeps the order with the fewest bad bytes.
- The builder drops the arguments after a cdecl call. Every call used to assume the API drops its own, so `wsprintfA`, which is cdecl with varargs and cannot, left its three pushed dwords on the stack. The calling convention now belongs to the export: a table carries the varargs formatters and the C runtime, so `wsprintfA` needs nothing from the user, and `CDECL` in `CONFIG` or `.cdecl` at the call site adds to the same registry. The cleanup is picked like any other instruction, so forbidding `0x10` turns `add esp, 0x10` into `sub esp, -0x10`. The un-popped arguments leave ESP lower, not higher, so they consume stack rather than overwrite the frame, whose slots and buffers are addressed from EBP. The Lab15 payload passes the bench with and without the cleanup, measured on the clone. What the cleanup fixes is stack use that grows with every cdecl call and is never reclaimed until the exit.
- `DEBUG = True`, off by default, puts a `test` and an `int3` after every name lookup, the `LoadLibraryA` bases included, so a wrong hash or a misspelled export stops at the lookup instead of calling address 0 later. The jump clears its own `int3`, so it is two bytes however far apart the lookups sit. It costs five bytes per lookup, measured: a seven-call Lab15 config goes from 485 to 525 bytes. It refuses to build when `BADCHARS` forbids `0xcc`.
- `tests/manual/sc_builder/catches.py` runs `check.py`'s regression configs against the builder at an older revision and fails when one of them passes there, so a case that guards nothing cannot sit in the suite unnoticed. Against `b38da38` the buffer config reports four frame offsets where two are right, and the register, encoder, cdecl and `DEBUG` configs all exit 1.
- `tests/manual/sc_builder/check.py` builds 12 configs and rejects 4, one regression case per defect above. A named buffer passed to three calls must report one frame offset and an inline `buf(4)` another; the Lab14 bad characters must not leave the module base on EBX; an encoded body that needs the encoder must exit 0 with no bad byte in the file; and a cdecl call must emit the cleanup where a stdcall call does not. On the OSED-DEV clone the Lab14 command passed `sc_runner.exe` three times in a row, the Lab15 formatter passed `sc_runner_b.exe` three times in a row with `OSED lab15 pid=<pid>` in the proof file, a path composed at runtime by `GetTempPathA` and `lstrcatA` into one named buffer landed its file, and an encoded body whose plain form could not be clean ran and passed.

### 2026-11-20 - A call's result by name in sc_builder

- `tools/sc_builder.py` records the calls you write instead of taking a hand-written list. You write one call per line in `CONFIG`, `k32.WinExec(s("calc.exe"), SW_SHOWNORMAL)` for kernel32.dll and `dll("user32.dll").MessageBoxA(NULL, s("text"), s("caption"), MB_OK)` for a DLL the builder loads once with `LoadLibraryA`. A call returns its result, so `handle = k32.CreateFileA(...)` and then `k32.WriteFile(handle, ...)` passes the handle by name. The name holds the position captured when the call ran. Before this change, a call inserted above the `CreateFileA` shifted every later `ref(n)` onto the call before the one you meant, and the build still reported 0 bad bytes and 0 problems.
- The builder defines the Win32 constants a call needs under their MSDN names, so an argument reads `SW_HIDE` instead of `0`: `NULL`, `GENERIC_READ`, `GENERIC_WRITE`, `FILE_SHARE_READ`, `FILE_SHARE_WRITE`, `CREATE_NEW`, `CREATE_ALWAYS`, `OPEN_EXISTING`, `OPEN_ALWAYS`, `TRUNCATE_EXISTING`, `FILE_ATTRIBUTE_NORMAL`, `SW_HIDE`, `SW_SHOWNORMAL`, `SW_SHOW`, `MB_OK`, `MEM_COMMIT`, `MEM_RESERVE`, `PAGE_READWRITE`, `PAGE_EXECUTE_READWRITE`.
- The older literal `CALLS = [(dll, api, [args])]` list with `ref(n)` still builds the same bytes, and a `CONFIG` block that holds both forms fails with `CONFIG mixes both call forms`. `tests/manual/sc_builder/check.py` now builds seven configs. It keeps the command and the file write in both forms and requires each pair to assemble to identical bytes, and it builds the file write with a `CreateDirectoryA` call inserted above the `CreateFileA`, where the handle has to come out as `ref(2)`.
- `sc.builder` with task arguments emits the four settings, a blank line, and one call per task. A `loadlibrary=` task binds `hmod`, then `hmod2` and `hmod3`, a `getprocaddress=` task reads the most recent of those names or `base("kernel32.dll")`, and the block carries a comment that the builder loads DLLs and resolves exports on its own.

### 2026-11-20 - Explain any command

- Every call reachable from `@$osed()` returns an object with an `explain` property. `dx @$osed().sc.resolve("kernel32", "WinExec").explain` prints what the command does, how it works, when to use it, its arguments, how to read the output, and a report sentence, with the call's arguments and results filled into the placeholders. `explain()` lists all 106 explanations, and `explain("name", args...)` or `"explain"` as the first argument explains a command without running it. Read-only lookups run silently to fill their results.
- Commands that returned `true` or `false` now return an object whose `success` field holds that value. `can_execute` keeps its answer in `value`.
- The explanations live in `src/explain/catalog.ts`. `tests/explain.test.ts` fails when a reachable command has no entry or an entry uses an undeclared placeholder.
- Classic WinDbg 10.0.19041 cannot call a property or read one on a function, so `.explain()` and `sc.resolve.explain` do not work there; the docs say so.

### 2026-11-19 - Config-driven shellcode builder

- `sc.builder(task..., "bad=<list>"?, "xor"?, "max=<bytes>"?)` prints `sc_builder.py`, kept in the repository as `tools/sc_builder.py`. `npm run build` embeds it, and a test fails when the copies differ. Its `CONFIG` block takes `BADCHARS`, `MAX_SIZE`, `CALLS` as `(dll, api, [args])` with int, `s()`, `w()`, `ref(n)`, `buf(size)` and `base()` arguments, `EXIT` and `XOR_ENCODER`. Arguments fill `CONFIG` from the `sc.template` tasks.
- The script prints the ROR13 table, resolves each API once into a slot next to EBP after loading other DLLs with `LoadLibraryA`, pushes strings with a XOR key per dword that holds a bad character, and loads constants with the shortest clean form. It assembles with Keystone line by line, reports every bad byte with its offset and line, forward calls and `MAX_SIZE`, disassembles with Capstone when installed, and can prepend a XOR decoder stub.
- `tests/manual/sc_builder/check.py` builds a WinExec command with `00 0A 0D 20 2F` bad, a `MessageBoxA` from user32, a `CreateFileA` + `WriteFile` + `CloseHandle` file write, and the command with the XOR stub, all with 0 bad bytes. The command, the file write and the XOR-encoded command ran in a 32-bit loader on Windows 10 (19045) and wrote their files.

### 2026-11-19 - Custom shellcode writers

- `sc.push_string(text, badchars?, register?)` prints the pushes that build a NUL-terminated string on the stack, last dword first, with the bytes and the 4 characters of each push, then the same lines as a Keystone `CODE` string. The terminator and partial dwords are built through a scratch register (`not`, `neg`, `xor` key, or `add` split), so no line holds `00` or a given bad character.
- `sc.call_frame(api, args...)` prints one stdcall call through the template resolver: the arguments in reverse order with a comment each, the ROR13 hash, `call [ebp-0x04]`, and `call eax`. A prototype table names the arguments of common APIs, and an unknown name still gets its hash with a warning.
- `sc.template(task...)` prints a complete `build_sc.py`: prologue, kernel32 lookup through the PEB loader list, a ROR13 export resolver stored with a backward call, call frames for `winexec`, `loadlibrary`, `getprocaddress`, `exit`, and `terminate` tasks, and the epilogue. The script assembles with Keystone, maps each bad byte to its offset and line, and writes `shellcode.bin`. The default output is 213 bytes with no `00`, and the fixed routines also avoid `0A 0D 20`. A WinExec template ran in a 32-bit loader on Windows 10 (19045) and Windows 11 (26200) and wrote its marker file, both returning to the loader and through ExitProcess.

### 2026-11-19 - Bad characters in blocks

- `badchar_function(badchars?, space?)` adds a `SPACE` line and a `badchar_block(start, size, bad)` helper. A block starts at a byte value, so adding a bad char never shifts the blocks still to send.
- `badchar_find` takes `start` and `size` after `minRun`. It compares memory with that block only, so later blocks no longer report every byte before `start` as a bad char. A block that arrives whole moves on to the next start instead of naming the byte after it as a terminator. Each run ends with the `Payload line` and the `Next command` for the next block, and the last block ends with the final list. Without `start` and `size` the output is unchanged.

### 2026-11-19 - Null-free egghunters

- `egghunter` stubs no longer contain null bytes. `ntaccess` loads the syscall number with the shortest form that avoids `00` and the given bad characters (`push imm8 ; pop eax`, `xor eax, eax ; mov al/ah/ax`, or `mov eax, ~n ; not eax`) instead of `mov eax, imm32`, and its jumps are computed from labels. The Windows 10 and 11 WOW64 stub drops from 51 to 49 bytes and passes a `00 0A 0D` check; it was rerun in a WOW64 process and found the egg. The native Windows 10 stub is 35 bytes.
- The `seh` stub is 67 bytes and null-free: a backward `call` replaces `call $+5`, and the handler writes `CONTEXT.Eip` through a byte displacement.

### 2026-11-19 - dx argument fixes

- `egghunter` now reads its `os` and `syscall` arguments from `dx`. `os` picks the `NtAccessCheckAndAuditAlarm` number from a per-build table taken from j00ru's syscall tables, and an unknown or missing `os` prints a warning that names the default. The WOW64 stub now calls the `fs:[0xC0]` gate with the 64-bit number, because `int 0x2e` raises `STATUS_ILLEGAL_INSTRUCTION` under WOW64. `ntdisplay` lost its WOW64 stub and rejects numbers that do not fit `push imm8`.
- `findmsp(patternLength?, stackBytes?, probeBytes?)` accepts its arguments from `dx`. Before, any argument failed with `value: Unknown option key.`
- The workflow command is now `exploit.workflow(mode, tag?, offset?, address?)`. The old name `exploit(...)` could not be called from `dx`, because `exploit` is the object that holds `exploit.state` and `exploit.clear`.

### 2026-10-19 - Guided ROP proof workflow

- Added `rop.prove()` guided and observation-only modes with incremental semantic checkpoints, one extension-owned one-shot breakpoint, manual execution control, and first-divergence diagnostics.
- Added scoped target fingerprints, dynamic pivot and IAT target resolution, runtime stdcall-frame capture, and separate `executionStatus`/`objectiveStatus` outcomes.
- Added append-only in-memory evidence, JSON/Markdown export, deterministic replay acceptance tests, and a PE32 manual validation target. Live Windows x86 validation remains a required release gate.

### 2026-08-26 - Arithmetic value solver and backward scanner

- Added `rop.construct(register, value, badchars?)` to find short gadget sequences
  that construct arbitrary 32-bit values when the raw value contains badchar bytes.
  Seven recipes tried in preference order: direct pop, negate, complement, two-add
  decomposition, two-sub decomposition, zero-add, zero-sub-neg. Reports recipe used,
  scratch register, stack bytes, and emits Python pack lines.
- Added `planRegisterSetup` solver integration: accepts an optional `badchars` array
  and value-solver callback for automatic arithmetic fallback on registers that
  cannot be satisfied by direct pop.
- Deduplicated `firstKnownAddress` (previously duplicated in chain.ts and
  synthesizer.ts).

### 2026-08-26 - Backward scanner and arithmetic pipeline

- Added backward scanner to `scan_live` that discovers multi-instruction gadgets,
  `ret N` terminators, and register-register arithmetic the pattern scanner misses.
  Scans executable memory for `C3`/`C2` terminators and decodes backward using a
  lookup-table x86 mini-decoder (mod=11 register-register only). Covers ALU ops
  (`add`/`sub`/`or`/`and`/`adc`/`sbb`/`xor`/`neg`/`not`/`inc`/`dec`), mov/xchg/test,
  call/jmp reg, group-1 imm8, ALU eax-imm32 short forms, and FPU D9 ops.
- Extended the semantic engine with rules for `or`, `and`, `not`, `adc`, and `sbb`
  (register-register and register-immediate forms). These degrade to unknown net
  transforms since bitwise and carry-dependent operations do not fit the affine model.
- Added five new `CapabilityKind` values: `REGISTER_ADC`, `REGISTER_SBB`,
  `REGISTER_OR`, `REGISTER_AND`, `REGISTER_NOT`.
- Added `ARITHMETIC` query alias so `rop.query("capability", "ARITHMETIC")` matches
  all eleven arithmetic capability kinds in a single query.
- Backward scanner stats (terminators found, new gadgets) are now reported in the
  `scan_live` corpus summary.

### 2026-08-24 - Semantic ROP pipeline completion and exploit state

- Added `rop.plan()` to analyze semantic capabilities and produce feasible
  exploit strategies with feasibility levels, preconditions, and ranked
  recommendations for VirtualProtect, VirtualAlloc, and WriteProcessMemory.
- Added `rop.emit()` to select and rank concrete gadgets for a planned strategy,
  producing a gadget assignment with scores and side-effect counts.
- Added `rop.synthesize()` to combine a plan with exploit state and produce a
  concrete stack layout. Evaluates three entry paths (RET_TO_FRAME, DIRECT_API,
  PIVOT_TO_FRAME) and reports status as complete, complete-with-violations, or
  blocked.
- Added `rop.export()` to write emitted gadgets and synthesized layouts as
  Python exploit stubs with `struct.pack` lines. Supports console output or
  file write via WinDbg `.logopen`/`.logclose`.
- Added `rop.pivots()` to find, classify, and rank stack pivot gadgets from the
  corpus. Classifies pivots as register (xchg/mov esp), esp-adjust (add/sub
  esp), or memory (indirect). Supports filtering by source register or minimum
  ESP delta.
- Added `exploit.state()` and `exploit.clear()` to view, set, and manage the
  cached exploit state used by the synthesizer. State is populated automatically
  by `triage()` and individual fields can be overridden manually.
- Added badchar address filtering to `rop.scan()` for RP++ text input, matching
  the filtering already available in `rop.scan_live()`.

### 2026-07-22 - Live ROP indexing and native chain construction

- Added `rop.scan_live()` to discover known gadget patterns directly from live
  executable target memory, apply bad-character address filtering, and feed the
  surviving hits into the semantic capability index without RP++.
- Added `rop.chain()` to emit paste-ready register-setup chains from the loaded
  corpus using real gadget addresses, with support for xor-zero targets, pure
  multi-pop co-satisfaction, and single-pop fallback.
- Added PUSHAD goal planners for DEP-bypass workflows. `rop.chain_vp()` now
  defaults to the RET-slide VirtualProtect layout, while constrained
  `rop.chain_wpm()` and `rop.chain_va()` report their saved-ESP argument
  assumptions instead of presenting them as unconstrained complete chains.
- Added flat stdcall frame emitters (`rop.frame_vp()`, `rop.frame_wpm()`, and
  `rop.frame_va()`) for the no-gadget case. They require no loaded ROP corpus,
  emit the API return target plus arguments as data words, and check every
  concrete dword against the caller's bad-character set.

### 2026-03-24 - Initial WinDbg exploit-development toolkit

The first implementation appeared in `OSED-Toolkit` as a TypeScript/JavaScript
extension for WinDbg Preview. It already provided the core classic stack-
exploitation workflow:

- Cyclic-pattern creation and offset lookup.
- Bad-character comparison.
- Module enumeration with exploit-mitigation inspection.
- SEH-chain walking.
- ROP, stack-pivot, and raw-byte scanning.
- Egghunter generation.
- Shared memory, output, command-registry, scan-engine, and validation layers.

The remainder of the day was spent making that first command surface work in
the actual WinDbg JavaScript host. The bundle changed from CommonJS-style
output to a global `initializeScript` entry point, gained `dx` positional-
argument support and an `@$osed()` alias, and hardened module/address parsing.
SEH handling evolved to discover the 32-bit TEB under WoW64 and tolerate
WinDbg model pointer objects instead of assuming ordinary JavaScript numbers.

### 2026-03-29 - Ranked SEH gadget discovery

- Added validated `pop reg; pop reg; ret` instruction patterns.
- Added `seh_ppr()` to find and rank POP/POP/RET candidates.
- Expanded recognition from a narrow pattern to the full supported register
  combinations.

This was the first move from raw gadget searching toward exploit-specific
validation and ranking.

### 2026-04-12 - Egghunter workflow

- Added WinDbg-facing exploit/egghunter helpers, extending the toolkit beyond
  crash inspection and gadget discovery into payload construction.

### 2026-05-01 to 2026-05-12 - Shellcode and PE analysis

- Added the `sc` shellcode namespace: module and PE inspection, export walking,
  API hashing and resolution, and shellcode-oriented helpers.
- Added IAT discovery and inspection.
- Adapted nested results into objects WinDbg's `dx` evaluator could expand.
- Added shellcode analysis features developed alongside Shellforge.
- Added `triage()`, combining control-state, SEH, stack context, and gadget
  observations into a first-response command.

At this point the project had changed from a collection of independent
commands into a debugger-resident workflow assistant.

### 2026-06-22 - Payload and ROP workflow expansion

- Added XOR payload encoding with bad-character-aware key selection.
- Added NOP generation.
- Expanded ROP instruction validation and gadget suggestions.
- Added PUSHAD-oriented ROP templates.
- Hardened pattern, SEH, memory, and scan behavior with focused tests.

### 2026-07-05 - Semantic ROP engine

- Introduced a semantic intermediate representation for instructions and
  instruction sequences.
- Added canonicalization, effect composition, gadget classification,
  capability derivation, and scoring.
- Added an RP++ text provider and semantic-pipeline fixtures.
- Extended `rop_suggest()` with selectable `fast` and `semantic` engines.
- Added WinDbg alias fallback for hosts that could not publish the preferred
  namespace form.

This was the largest architectural change: gadgets could now be selected by
what they do, rather than only by matching byte or instruction patterns.

### 2026-07-08 to 2026-07-09 - Query surface and format strings

- Added page-protection summaries to the shellcode/PE inspection surface.
- Added `rop.scan()`, `rop.query()`, and `rop.capabilities()` over RP++ output.
- Added pivot queries backed by the same semantic machinery.
- Made negative memory constraints fail safely when semantics are unknown.
- Added `fmt.offset()` and `fmt.build()` for format-string argument discovery
  and `%n`-family write payload construction.

### 2026-07-09 - Standalone initial release

The complete extension was copied from `OSED-Toolkit/osed-windbg` into this
repository as commit `9db6bfb`. The snapshot contained the established command
surface, semantic ROP subsystem, tests, documentation, and a self-contained
`dist/osed.js` bundle. This is a repository migration boundary, not the true
beginning of the project.

The first standalone fix corrected `triage()` so instruction-pointer control
is reported only when the value actually contains recognizable user-controlled
evidence, rather than merely being nonzero.

### 2026-07-16 - Evidence-first analysis layer

- Added normalized `memory()` evidence with tri-state permission fields.
- Added `landing()` analysis for stack/address bytes, memory permissions,
  patterns, markers, NOP runs, and disassembly observations.
- Changed `triage()` to consume shared landing evidence instead of duplicating
  reads and interpretation.
- Added an explicit analysis-architecture contract separating evidence
  collection from user-facing conclusions.
- Fixed `dx` expansion by returning debugger-safe data shapes.

### 2026-07-19 - x64, math, help, and richer semantic queries

- Extended applicable commands to x64 register names, pointer widths,
  `JMP/CALL RSP`, and RSP pivot patterns.
- Added `math()` for signed, unsigned, hexadecimal, little-endian, and two's-
  complement views.
- Expanded semantic ROP queries with chain-oriented effects and constraints.
- Added IAT documentation and related semantic coverage.
- Rebuilt help around a centralized catalog with per-command schemas and
  executable examples.
- Published `rop` as a plain namespace object for more predictable `dx` use.

### 2026-07-20 to 2026-07-21 - WinDbg output and IAT hardening

- Added examples directly to help results.
- Introduced debugger markup/link result handling.
- Made IAT inspection tolerate unreadable thunks and improved thunk reading.
- Added build-derived version metadata and a `version()` command.
- Corrected table padding around DML links, then simplified markup where it
  impaired readability.

## Functional arc

In short, the project evolved through these stages:

1. Mechanical exploit primitives: patterns, bad characters, modules, SEH, and
   raw gadget scanning.
2. Workflow commands: ranked PPR discovery, shellcode/PE inspection, IAT
   resolution, and integrated crash triage.
3. Payload assistance: encoders, egghunters, NOPs, and ROP templates.
4. Semantic analysis: effect-based gadget classification, scoring, and query.
5. Evidence-first diagnostics: normalized memory and landing observations
   shared by commands.
6. Product hardening: x64 coverage, structured help, debugger-safe results,
   IAT resilience, versioning, and readable WinDbg output.

## History sources

- Pre-migration history: `OSED-Toolkit`, path `osed-windbg/`, commits
  `9eb9764` through `ad5b08d`.
- Standalone history: this repository, beginning with `9db6bfb`.
