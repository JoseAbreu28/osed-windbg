# osed-windbg

> **Fork notice.** This is a fork of [rogdooley/osed-windbg](https://github.com/rogdooley/osed-windbg) by Roger Dooley, the original author of this project. Everything below documents the upstream toolkit. Additions and behaviour changes made in this fork are listed in [What this fork adds](#what-this-fork-adds) and tagged **[fork]** where they appear in the command reference.

A WinDbg Preview JavaScript extension for Windows exploit development. Automates the mechanical work — pattern matching, bad-char comparison, gadget scanning, memory evidence, import/export inspection, and payload-layout math — so you stay focused on the exploit logic.

All commands run from the WinDbg `dx` evaluator. No Python, no external tools, no context switching.

See [CHANGELOG.md](CHANGELOG.md) for the reconstructed functional timeline,
including development before this project moved out of `OSED-Toolkit`.

## What this fork adds

| Area | Change | Tag |
| --- | --- | --- |
| Build | `dist/osed-legacy.js`, a BigInt-free bundle for classic WinDbg 10.0.19041 | **[fork: new]** |
| SEH | `seh.visualize()` and the other TEB consumers work without symbols | **[fork: changed]** |
| Bad characters | `badchar_function(badchars?)` prints a Python helper for the exploit | **[fork: new]** |
| Bad characters | `badchars` and `badchar_find` end with the exploit line and the next command | **[fork: changed]** |

### `dist/osed-legacy.js` for classic WinDbg 10.0.19041

The JavaScript provider (JsProvider) in classic WinDbg 10.0.19041 (x86) has no `BigInt`, so `dist/osed.js` fails to load there. `npm run build` now also writes `dist/osed-legacy.js`. A build-time source transform (`legacy/bigint_transform.js`) rewrites every `bigint` operation into calls to a small runtime (`legacy/runtime.js`) that works on safe JavaScript integers.

Load it the same way as the main bundle:

```text
.scriptload C:\path\to\osed-windbg\dist\osed-legacy.js
dx @$osed().version()
```

Values above 2^53 throw by design instead of losing precision silently. That covers every 32-bit address and value, so the x86 workflow is unaffected. Full 64-bit constants are out of scope for this bundle; use `dist/osed.js` on WinDbg Preview for x64 work.

`npm run test:legacy` runs the whole test suite against the transformed sources (one test that feeds a full 64-bit constant is excluded on purpose).

### SEH chain without symbols

`seh.visualize()`, `findmsp()`, `triage()` and `find_stack_bytes()` used to fail with `Current thread TEB is unavailable` on machines without symbols, because the data model only exposes the TEB through ntdll's `_TEB` type. The TEB lookup now asks the engine for `$teb`, which comes from the thread itself and works offline, like `!exchain`. On a WOW64 process the 32-bit TEB sits at the native TEB + `0x2000`. A candidate is accepted only when its self pointer at TEB + `0x18` points back at itself.

### Bad-character workflow

`badchar_function` prints one list to grow on each run and a helper that derives the test array from it, so you never paste 255 bytes into the exploit again:

```text
0:000> dx @$osed().badchar_function("00")
=== Bad Character Python Helper ===
BADCHARS = b"\x00"  # add each new bad char here

def badchar_array(bad=BADCHARS):
    return bytes(b for b in range(256) if b not in bad)

payload += badchar_array()  # where the test array goes
```

`badchars` and `badchar_find` now finish with the updated `BADCHARS` line and the exact `dx` command for the next run. Both lines already include the truncation byte. Example from a run where `0x3F` cut the array:

```text
[+] Copy-ready exclude list: 00 0A 0D 2B
[+] Exploit line: BADCHARS = b"\x00\x0a\x0d\x2b\x3f"
[+] Next command: dx @$osed().badchar_find(0x0035ED70, "00 0A 0D 2B 3F")
```

When the copy stops early, for example because a `ret N` cut the array, `badchar_find` reports where it was truncated and names the likely terminator: the first byte that never arrived. If nothing arrived after the return address at all, it says so and suggests moving the array before EIP. Without an address argument the next command uses `@esp`.

`dx` evaluates arithmetic before the call, so an address expression works directly:

```text
dx @$osed().badchar_find(0x0019ed34+8, "00 0A 0D")
```

### Known limitation: pseudo-registers

Pseudo-registers such as `@$t0` reach the script as 64-bit host `Int64` objects, and address arguments reject them. Cast them first:

```text
dx @$osed().badchar_find((unsigned int)@$t0, "00 0A 0D")
```

---

![triage example](Images/triage.gif)

## Requirements

- WinDbg Preview (WinDbgX) with DbgModel/JavaScript support
- x86 target for the full classic OSED workflow.
- x64 target for memory/landing evidence, PE/import/export helpers, math, triage context, `JMP/CALL RSP`, and x64 stack-pivot scanning.
- Classic WinDbg 10.0.19041 (x86) without `BigInt`: load `dist/osed-legacy.js` instead. **[fork]**

---

## Installation

Use the included bundle if you just want to load the toolkit immediately:

```
.scriptload C:\path\to\osed-windbg\dist\osed.js
```

Add it to your WinDbg workspace or drop it in the auto-load scripts folder to have it available on every session.

Verify:

```
dx @$osed().help()
dx @$osed().version()
```

The load banner should print embedded build metadata, for example:

```text
[+] osed loaded: v1.0.4 (ebd8fe50b82c, dirty, built 2026-08-21T01:41:30.133Z)
```

If the banner or `version()` reports `dev` / `unknown`, you are not loading a properly built `dist/osed.js`.

On classic WinDbg 10.0.19041, whose JavaScript provider has no `BigInt`, load the legacy bundle instead. **[fork]**

```
.scriptload C:\path\to\osed-windbg\dist\osed-legacy.js
```

---

## Quick start

```
; List all commands
dx @$osed().help()

; Detail on one command
dx @$osed().help("rop_suggest")

; Common first-session sequence
dx @$osed().triage(8000, "00 0A 0D", "essfunc", 2048)
dx @$osed().seh_ppr("libspp.dll", "00 0A 0D")
dx @$osed().rop_suggest("essfunc", 50)
```

## Command index

Every command registered by the extension, grouped like `dx @$osed().help("all")`. Call each one as `dx @$osed().<syntax>`. Where two names are listed, the second is an alias for the first. [Documentation/COMMANDS.md](Documentation/COMMANDS.md) has the detailed reference with examples and option notes.

### Crash

| Command | Syntax | What it does |
| --- | --- | --- |
| `findmsp` | `findmsp(patternLength?, stackBytes?, probeBytes?)` | Find cyclic offsets in registers and memory |
| `landing` | `landing(address?)` | Analyze execution landing and protections |
| `stackmap` | `stackmap(depth?, patternLength?)` | Identify controlled stack regions |
| `triage` | `triage(patternLength?, badchars?, module?, stackBytes?)` | Crash and mitigation summary |

### Target and memory

| Command | Syntax | What it does |
| --- | --- | --- |
| `code_caves` | `code_caves(module?, minSize?, maxResults?, badChars?, capability?)` | Find candidate staging regions |
| `find_bytes` | `find_bytes(module, bytes, maxResults?, executableOnly?, mode?)` | Find byte sequence in PE sections |
| `find_mem_bytes` | `find_mem_bytes(address, length, bytes, maxResults?)` | Find byte sequence in a memory range |
| `find_ptr` | `find_ptr(instruction, module?, badchars?, maxResults?, executableOnly?)` | Search executable memory for instruction bytes |
| `find_stack_bytes` | `find_stack_bytes(bytes, maxResults?, stackBytes?)` | Find byte sequence on the stack |
| `memory` | `memory(address)` | Inspect memory region and protections |
| `modules` | `modules(filter?)` | Modules, bases, and mitigations |

### Payload

| Command | Syntax | What it does |
| --- | --- | --- |
| `badchar_array` | `badchar_array(exclude?)` | Generate a bad-character test array |
| `badchar_find` | `badchar_find(address?, exclude?, windowBytes?, minRun?)` | Locate a sent bad-character array in memory **[fork: changed]** |
| `badchar_function` | `badchar_function(badchars?)` | Python BADCHARS list and array helper for the exploit **[fork: new]** |
| `badchars` | `badchars(address, exclude?)` | Compare candidate bytes with memory **[fork: changed]** |
| `pattern.create` / `pattern_create` | `pattern.create(length, type?)` | Generate cyclic pattern text |
| `pattern.offset` / `pattern_offset` | `pattern.offset(value, type?)` | Find an offset in a pattern family |

### ROP

| Command | Syntax | What it does |
| --- | --- | --- |
| `add_esp` | `add_esp(module?, maxResults?, executableOnly?, mode?)` | Scan for add esp, N gadgets |
| `pivots` | `pivots(module?, maxResults?, executableOnly?, mode?)` | Scan for stack pivot candidates |
| `retn` | `retn(module?, maxResults?, executableOnly?, mode?)` | Scan for retn N gadgets |
| `rop_suggest` | `rop_suggest(module?, maxResults?, executableOnly?, mode?, engine?)` | Suggest exploit-friendly gadget patterns |
| `rop_template` | `rop_template(api?, module?)` | Print a commented ROP chain skeleton |
| `rop.api_build` | `rop.api_build(target, badchars?, continuation?, preserve?, maxGadgets?, owner?, anchor?)` | Construct a bounded API-address resolution chain |
| `rop.api_plan` | `rop.api_plan("MODULE!Symbol", badchars?)` | Discover validated API address-resolution candidates |
| `rop.capabilities` | `rop.capabilities()` | Summarize available ROP primitives |
| `rop.chain` | `rop.chain(register, value, register2?, value2?, ...)` | Build a register-setup chain |
| `rop.chain_va` | `rop.chain_va(virtualAlloc?, returnAddress?, lpAddress?, flAllocationType?, flProtect?)` | Build a VirtualAlloc PUSHAD chain |
| `rop.chain_vp` | `rop.chain_vp(virtualProtect?, retGadget?, returnAddress?, lpAddress?, dwSize?, writable?, flNewProtect?, mode?)` | Build a VirtualProtect PUSHAD chain |
| `rop.chain_wpm` | `rop.chain_wpm(writeProcessMemory?, returnAddress?, lpBuffer?, nSize?, writable?)` | Build a WriteProcessMemory PUSHAD chain |
| `rop.construct` | `rop.construct(register, value, badchars?, preserve?)` | Build register-load ROP recipes |
| `rop.corpus.export` | `rop.corpus.export(path?)` | Save the semantic corpus to disk |
| `rop.corpus.import` | `rop.corpus.import(path)` | Load a corpus as inactive evidence |
| `rop.corpus.lookup` | `rop.corpus.lookup(address)` | Read-only exact-address lookup in the active ROP corpus |
| `rop.corpus.report` | `rop.corpus.report(path?)` | Print a human-readable gadget inventory |
| `rop.corpus.validate` | `rop.corpus.validate()` | Validate corpus against live memory |
| `rop.emit` | `rop.emit(planId, strategyId?)` | Select gadgets for a strategy |
| `rop.export` | `rop.export(planId, path?)` | Export gadgets and chain as Python |
| `rop.find` / `rop_find` | `rop.find(module?, maxResults?, executableOnly?, mode?)` | Legacy ROP helper and module triage |
| `rop.frame_va` | `rop.frame_va(virtualAlloc?, returnAddress?, lpAddress?, dwSize?, flAllocationType?, flProtect?, badchars?)` | Build a VirtualAlloc stdcall frame |
| `rop.frame_vp` | `rop.frame_vp(virtualProtect?, returnAddress?, lpAddress?, dwSize?, flNewProtect?, writable?, badchars?)` | Build a VirtualProtect stdcall frame |
| `rop.frame_wpm` | `rop.frame_wpm(writeProcessMemory?, returnAddress?, hProcess?, lpBaseAddress?, lpBuffer?, nSize?, writable?, badchars?)` | Build a WriteProcessMemory stdcall frame |
| `rop.frame_write` | `rop.frame_write(buf, "word0 word1 arg1 arg2 ...", badchars?)` | Construct stdcall frames in memory |
| `rop.generate` | `rop.generate(api, shellcode?, badchars?, module?, offset?)` | Generate an API-call chain |
| `rop.pivots` | `rop.pivots(register?, minDelta?, verbose?)` | Find and rank stack pivot gadgets |
| `rop.plan` | `rop.plan(strategy, apiResolution?)` | Compare API-call construction strategies |
| `rop.prove` | `rop.prove(modeOrAction?)` | Trace chain execution in WinDbg |
| `rop.query` | `rop.query(field, value, executableOnly?, verbose?)` | Search gadgets by capability or instruction |
| `rop.scan` | `rop.scan(text, badchars?)` | Load gadgets into the semantic corpus |
| `rop.scan_live` | `rop.scan_live(moduleOrModules?, badchars?, append?, maxPerPattern?, maxInstructionsPerGadget?, maxBackwardGadgets?)` | Discover gadgets in loaded modules |
| `rop.setup` | `rop.setup("reg=value reg=value ...", badchars?)` | Stage registers for a call frame |
| `rop.slot_call` | `rop.slot_call(buf, iatSlot, "retaddr arg1 arg2 ...", badchars?, entrySkew?)` | Call APIs through stable IAT slots |
| `rop.synthesize` | `rop.synthesize(planId)` | Build a concrete stack layout |
| `rop.verify` | `rop.verify(chain?, badchars?, api?)` | Verify chain structure and side effects |

### SEH

| Command | Syntax | What it does |
| --- | --- | --- |
| `seh_ppr` | `seh_ppr(module?, exclude?, maxResults?, executableOnly?, mode?)` | Find POP-POP-RET candidates |
| `seh.visualize` | `seh.visualize()` | Inspect the exception-handler chain **[fork: changed]** |

### Shellcode

| Command | Syntax | What it does |
| --- | --- | --- |
| `egghunter` | `egghunter(tag?, mode?, wow64?, badchars?, os?, syscall?)` | Generate an egghunter stub |
| `encode` | `encode(shellcode, exclude?, key?)` | Encode shellcode around forbidden bytes |
| `nop` | `nop(length, byte?)` | Generate a NOP sled |

### PE / API (`sc`)

| Command | Syntax | What it does |
| --- | --- | --- |
| `sc.algorithms` | `sc.algorithms()` | List supported API hash algorithms |
| `sc.base` | `sc.base(module)` | Resolve a module base address |
| `sc.export` | `sc.export(module, symbol)` | Resolve an export by name |
| `sc.exportat` | `sc.exportat(module, ordinalIndex)` | Resolve an export by ordinal |
| `sc.exportdir` | `sc.exportdir(module)` | Show PE export directory metadata |
| `sc.exports` | `sc.exports(module, filter?)` | Enumerate exported symbols |
| `sc.exportwalk` | `sc.exportwalk(module, symbol?, verbose?)` | Walk PE export resolution checkpoints |
| `sc.hash` | `sc.hash(name, algorithm?)` | Hash one API name |
| `sc.hashes` | `sc.hashes(module, algorithm?)` | Hash named exports with a given algorithm |
| `sc.hashresolve` | `sc.hashresolve(module, hashValue, algorithm?)` | Resolve an API hash against exports |
| `sc.iat` | `sc.iat(module?, filter?)` | Inspect imported APIs and IAT entries |
| `sc.iat_find` | `sc.iat_find(symbol)` | Search all modules for matching IAT entries |
| `sc.iat_ptr` | `sc.iat_ptr(module, symbol)` | Resolve an import to its IAT slot |
| `sc.module_pages` | `sc.module_pages(module)` | Report module size and page count |
| `sc.modules` | `sc.modules()` | List loaded modules |
| `sc.page_summary` | `sc.page_summary(module)` | Bucket module pages by protection |
| `sc.pe` | `sc.pe(module)` | Print PE header fields |
| `sc.peb` | `sc.peb()` | Dump PEB-oriented module evidence |
| `sc.resolve` | `sc.resolve(module, symbol)` | Resolve API exports |

### Strings (`str`)

| Command | Syntax | What it does |
| --- | --- | --- |
| `str.bytes` / `str_bytes` | `str.bytes(text, encoding?, terminator?, exclude?)` | Encode text as payload bytes |
| `str.find` / `str_find` | `str.find(text, module?, encoding?, maxResults?)` | Search process memory for strings |
| `str.read` / `str_read` | `str.read(address, max?, encoding?)` | Read a string from memory |
| `str.refs` / `str_refs` | `str.refs(target, module?, encoding?, maxResults?)` | Find executable pointers to a string |

### Format strings (`fmt`)

| Command | Syntax | What it does |
| --- | --- | --- |
| `fmt.build` / `fmt_build` | `fmt.build(addr, value, argIndex, width?, exclude?)` | Construct format-string payload components |
| `fmt.inspect` / `fmt_inspect` | `fmt.inspect(family?, formatArgOffset?, max?)` | Inspect a paused printf-family format argument |
| `fmt.offset` / `fmt_offset` | `fmt.offset(marker?, count?, firstArg?)` | Find the controlled parameter index |

### Tools, leaks and state

| Command | Syntax | What it does |
| --- | --- | --- |
| `exploit` | `exploit(mode, tag?, offset?, address?)` | Emit exploit-development command workflows |
| `exploit.clear` | `exploit.clear()` | Clear the cached exploit state |
| `exploit.state` | `exploit.state(overrides?)` | View or update cached exploit state |
| `help` | `help(command?, mode?)` | List commands or show detailed help |
| `leak.analyze` / `leak_analyze` | `leak.analyze(text)` | Analyze supplied output for pointer candidates |
| `leak.base` / `leak_base` | `leak.base(pointer, rva)` | Calculate and validate a module base |
| `leak.classify` / `leak_classify` | `leak.classify(value)` | Classify a pointer without dereferencing |
| `leak.scan` / `leak_scan` | `leak.scan(address, length?)` | Scan bounded memory for pointer candidates |
| `math` | `math(value, bits?)` | Format an integer as hex, signed, unsigned, LE |
| `reload` | `reload()` | Clear and re-register command registry |
| `version` | `version()` | Show loaded build identity |

### Runtime helpers

These live on `@$osed()` but are not in the command registry.

| Helper | Syntax | What it does |
| --- | --- | --- |
| `last_result` | `last_result()` | Return the full structured result of the last command |
| `last_summary` | `last_summary()` | Return a compact summary of the last command result |
| `clear_last_result` | `clear_last_result()` | Clear the stored result snapshot |
| `can_execute` | `can_execute(address)` | Project the executable flag of `memory(address)` as `true`, `false` or `null` |

---

## Commands

### Core

| Command | What it does |
| --- | --- |
| `help(command?)` | List commands or print the schema for one. |
| `triage(length?, badchars?, module?, stackBytes?)` | Fast crash triage: control detection, SEH chain, stack context, gadget summary. |
| `memory(address)` | Return normalized memory-region evidence, including tri-state access flags and raw protection metadata. |
| `can_execute(address)` | Project the normalized executable flag from `memory(address)` as `true`, `false`, or `null`. |
| `landing(address?)` | Analyze bytes and memory evidence at an address, defaulting to ESP/RSP. |
| `modules(filter?)` | List loaded modules with ASLR/SafeSEH/DEP state. |
| `badchars(address, exclude?)` | Compare memory against the expected byte sequence and highlight deviations. |

### Bad characters **[fork: changed]**

```
dx @$osed().badchar_array("00")            ; test array to send
dx @$osed().badchar_function("00")         ; Python BADCHARS line + badchar_array() helper [fork]
dx @$osed().badchar_find()                 ; locate the sent array near ESP
dx @$osed().badchars(0x0012F800, "00 0A 0D") ; compare at a known address
```

`badchars` and `badchar_find` end with `Exploit line: BADCHARS = b"..."` and `Next command: dx @$osed()...` for the next run. See [Bad-character workflow](#bad-character-workflow).

### Pattern / offset

```
dx @$osed().pattern_create(300)
dx @$osed().pattern_offset(0x39654138)
```

Also available as `pattern.create` / `pattern.offset`.

### Memory and landing evidence

```text
dx @$osed().memory(0x0012F800)
dx @$osed().can_execute(0x0012F800)
dx @$osed().landing()             ; defaults to ESP/RSP
dx @$osed().landing(0x0012F800)   ; inspect an explicit address
dx @$osed().math(0xFFFFFFD6, 32)  ; hex/signed/unsigned/LE bytes
```

`memory()` normalizes WinDbg protection metadata into `readable`, `writable`, `executable`, `guarded`, `noAccess`, `committed`, and `regionType`. Boolean fields use three states: `true`, `false`, and `null` when WinDbg cannot establish the value. Original numeric protection, state, and type values remain under `raw`.

`landing()` returns sampled bytes plus atomic observations such as NOP runs, repeated marker bytes, cyclic-pattern matches, memory permissions, disassembly status, and inaccessible or truncated ranges. These are observations, not claims that an address contains shellcode.

`triage()` consumes this same landing evidence instead of independently reading and classifying stack bytes.

`math()` formats integers as hex, signed, unsigned, little-endian bytes, and two's complement for the selected width (`8`, `16`, `32`, or `64`; default `32`).

### SEH

```
dx @$osed().seh.visualize()   ; walk the current SEH chain
dx @$osed().seh_ppr("essfunc", "00 0A 0D")   ; find pop;pop;ret gadgets
```

**[fork: changed]** The TEB lookup behind `seh.visualize()` falls back to the engine's `$teb`, so the chain is listed even without symbols. See [SEH chain without symbols](#seh-chain-without-symbols).

### ROP gadget scanning

```
dx @$osed().rop_suggest("essfunc", 50)                       ; validated gadget set
dx @$osed().rop_suggest("essfunc", 50, true, "fast", "semantic")  ; semantic engine
dx @$osed().retn("essfunc")                                  ; retn N gadgets
dx @$osed().add_esp("essfunc")                               ; add esp, N ; ret
dx @$osed().pivots("essfunc")                                ; stack pivots
dx @$osed().find_bytes("vulnserver", "FF E4")                ; module PE-section byte search
dx @$osed().find_stack_bytes("43 43 43 43")                  ; current-thread stack byte search
dx @$osed().find_mem_bytes(0x14800000, 0x16000, "43 43 43 43") ; explicit live-memory range search
dx @$osed().rop_template("VirtualProtect", "essfunc")        ; PUSHAD skeleton
```

`find_bytes(module, ...)` searches PE sections in the named loaded module. By default it searches executable sections only, which makes it useful for gadget hunting and opcode checks in module-backed memory.

`find_stack_bytes(bytes, ...)` searches the current thread stack starting at `ESP`/`RSP`. It does not search the heap or arbitrary process memory.

`find_mem_bytes(address, length, bytes, ...)` searches an explicit readable memory range that you provide. Use it for stack, heap, mapped regions, or module-backed memory when you already know the address window you want to inspect.

Use `findmsp()` when you need cyclic-pattern offsets, `find_bytes()` when you need module/image byte hits, `find_stack_bytes()` when you need to confirm that live input bytes landed on the current stack, and `find_mem_bytes()` when you need an explicit live-memory range search.

### Semantic ROP pipeline

The semantic pipeline takes you from raw gadgets to a concrete stack layout in five stages: **scan** → **plan** → **emit** → **synthesize** → **export**.

#### 1. Scan — build the corpus

Load gadgets from RP++ text or live target memory. Both paths accept badchars to filter gadgets whose addresses contain prohibited bytes.

```
; From RP++ output
dx @$osed().rop.scan(rpOutput, "00 0A 0D")

; From live target memory (discovers gadgets in-process)
dx @$osed().rop.scan_live("essfunc", "00 0A 0D")
dx @$osed().rop.scan_live(["essfunc", "compression"], "00 0A 0D")

; Query and inspect the corpus
dx @$osed().rop.query("capability", "LOAD_REGISTER")
dx @$osed().rop.capabilities()
```

Persist a corpus before restarting WinDbg, then explicitly revalidate it after
the target is attached again. Import alone never activates gadgets: validation
requires the saved module mapping and sampled gadget bytes to match live memory.

```js
dx @$osed().rop.corpus.export("C:\\labs\\rop-corpus.json")
dx @$osed().rop.corpus.import("C:\\labs\\rop-corpus.json")
dx @$osed().rop.corpus.validate()
```

#### 2. Plan — choose a strategy

Plans feasible exploit strategies from semantic capabilities. Reports feasibility, preconditions, and recommended approaches.

```
dx @$osed().rop.plan("VirtualProtect")
dx @$osed().rop.plan("VirtualAlloc", "iat")
dx @$osed().rop.plan("WriteProcessMemory")
```

Each plan gets an ID for use in later stages.

#### 3. Emit — assign concrete gadgets

Selects and ranks concrete gadgets for a planned strategy. Produces a gadget assignment, not an executable chain.

```
dx @$osed().rop.emit(1)          ; emit for plan 1
dx @$osed().rop.emit(1, 3)       ; emit for plan 1, strategy 3
```

#### 4. Synthesize — produce a stack layout

Combines a plan with the current exploit state (crash geometry, registers, constraints) to produce a concrete stack layout. The exploit state is populated automatically by `triage()` or set manually with `exploit.state()`.

```
dx @$osed().triage(8000, "00 0A 0D")     ; auto-populates exploit state
dx @$osed().rop.synthesize(1)
dx @$osed().rop.synthesize(1, {controlledBytesAfterEsp: 512})
```

Three entry paths are evaluated in order: RET_TO_FRAME (ret gadget in saved EIP), DIRECT_API (API address in saved EIP), PIVOT_TO_FRAME (stack pivot).

Status is one of: `complete`, `complete-with-violations` (layout produced but a concrete value contains a badchar), or `blocked` (structural impossibility).

#### 5. Export — write a Python exploit stub

Exports the emitted gadgets and (if available) the synthesized stack layout as a Python script with `struct.pack` lines and semantic comments.

```
dx @$osed().rop.export(1)                            ; print to console
dx @$osed().rop.export(1, "C:\\exploit\\rop.py")      ; write to file
```

#### Pivot finder

Finds, classifies, and ranks stack pivot gadgets from the corpus. Pivots are classified as `register` (xchg/mov esp), `esp-adjust` (add/sub esp), or `memory` (indirect).

```
dx @$osed().rop.pivots()                ; all pivots
dx @$osed().rop.pivots("eax")           ; only pivots sourced from EAX
dx @$osed().rop.pivots(undefined, 0x100) ; only esp-adjust with delta >= 0x100
```

#### Flat frame builders

Build stdcall API frames directly — no ROP gadgets needed. Useful with RET_TO_FRAME or DIRECT_API entry paths.

```
dx @$osed().rop.frame_vp(0x7C801AD0, 0x625011AF, 0x0012F800, 0x201, 0x40, 0x62506000, "00 0A 0D")
dx @$osed().rop.frame_wpm(0x7C802213, 0x625011AF, 0xFFFFFFFF, 0x62502000, 0x0012F800, 0x200)
dx @$osed().rop.frame_va(0x7C809AE1)
```

#### Legacy PUSHAD chain builders

Build register-setup chains that end with PUSHAD. These operate independently of the planner and are the classic OSED approach.

```
dx @$osed().rop.chain_vp(0x7C801AD0, 0x62501010, 0x625011AF)
dx @$osed().rop.chain_wpm(0x7C802213, 0x625011AF, 0x0012F800, 0x200)
dx @$osed().rop.chain_va(0x7C809AE1)
dx @$osed().rop.chain("eax", 0xDEADBEEF, "ebx", 0x1000)
```

### Exploit state (`exploit`)

The exploit state captures crash geometry — control mechanism, stack layout, register values, and constraints. It is populated automatically by `triage()` and consumed by `rop.synthesize()`.

```
dx @$osed().exploit.state()              ; view current state
dx @$osed().exploit.state({mechanism: "saved-ret", controlledBytesAfterEsp: 512})
dx @$osed().exploit.state({badchars: "00 0A 0D", apiResolution: "iat"})
dx @$osed().exploit.clear()              ; reset
```

You can set or override any field without rerunning triage. This is useful when the debugger has continued past the crash point, or when you want to model a different scenario.

### Shellcode helpers

```
dx @$osed().egghunter("W00T", "ntaccess")
dx @$osed().encode("fc e8 82 00 00 00...", "00 0A 0D")   ; XOR encode, auto-key
dx @$osed().nop(16)
```

### String helpers (`str`)

Read strings, search module sections, and convert text into payload bytes:

```
dx @$osed().str.read(0x0019F920)
dx @$osed().str.find("VirtualProtect", "target", "both", 25)
dx @$osed().str.refs("VirtualProtect", "target", "both", 25)
dx @$osed().str.bytes("cmd.exe", "ascii", true, "00 0A 0D")
```

### Format-string namespace (`fmt`)

At a breakpoint on a `printf`-family call:

```
; 1. Find which %N$ index reaches your buffer
dx @$osed().fmt.offset(0x41414141, 40)

; 2. Build the %n write-what-where payload
dx @$osed().fmt.build(0x00402118, 0x625011AF, 6)
```

`fmt.build` outputs: chunk breakdown table, address block bytes, the format string (`%4519c%6$hn%20641c%7$hn`), a Python `struct.pack` payload, and hex. It accounts for the address-block bytes already printed before the first `%c`, which is the off-by-block error that bites you when computing padding by hand.

`width` defaults to `"word"` (`%hn`). Pass `"byte"` (`%hhn`) or `"dword"` (`%n`) as the fourth argument.

### Shellcode / PE inspection (`sc`)

Module, PE header, export enumeration, hash resolution, and IAT inspection:

```
dx @$osed().sc.modules()
dx @$osed().sc.exports("kernel32", "Virtual")
dx @$osed().sc.hash("WinExec", "ROR13")
dx @$osed().sc.hashresolve("kernel32", 0x7c0dfcaa, "ROR13")
dx @$osed().sc.iat_find("VirtualAlloc")
```

---

## Inspecting results

Every command stores its structured output. Access it after the `dx` call returns:

```
dx @$osed().last_result()
dx @$osed().last_summary()
```

`memory()` returns its evidence object directly. `landing()` returns debugger-friendly observation rows; its complete evidence remains available through `last_result()`. `can_execute()` returns `true`, `false`, or `null`; it does not issue an independent query path beyond normalized memory evidence.

---

## Building from source

If you do not want to use the checked-in `dist/osed.js`, build your own copy locally.
This repo pins package versions in `package.json`, but does not commit `node_modules` or `package-lock.json`.

```
npm install
npm run build
```

That writes a fresh bundle to `dist/osed.js`.

The same build also writes `dist/osed-legacy.js`, the BigInt-free bundle for classic WinDbg 10.0.19041. **[fork]**

Verify the build:

```
npm test
```

Run `npm run test:legacy` to verify the same suite against the BigInt-free sources. **[fork]**

Then verify the loaded bundle in WinDbg:

```text
.scriptload C:\path\to\osed-windbg\dist\osed.js
dx @$osed().version()
```

TypeScript source is in `src/`. The build produces a single self-contained JS file via esbuild — no runtime dependencies.

---

## Notes

- Classic SEH, PPR, format-string offset mapping, PUSHAD ROP templates, and semantic ROP scoring remain x86-oriented.
- x64 support is evidence-first: register naming, pointer formatting, memory permissions, landing analysis, `JMP/CALL RSP`, and RSP pivot byte-pattern scans. The semantic ROP backend is still x86-only; x64 `rop_suggest(..., "semantic")` falls back to the x64 byte-pattern scanner with a warning.
- The `encode` command supports payloads up to 65535 bytes. The XOR decoder stub is 21 bytes (≤255-byte payload) or 23 bytes (256–65535 bytes); fixed bytes in the stub are checked against the badchar list.
- `fmt.offset` reads TEB `NtTib.StackBase`/`StackLimit` for stack pointer classification; it requires an x86 target broken in at the format call site.
- `dist/osed-legacy.js` throws on values above 2^53 by design. Use `dist/osed.js` for full 64-bit values. **[fork]**
- Pseudo-registers such as `@$t0` arrive as 64-bit host `Int64` objects and address arguments reject them. Pass `(unsigned int)@$t0` instead. **[fork]**
