# ROP and DEP commands

Use these commands to find gadgets and build chains that call VirtualProtect, VirtualAlloc, or WriteProcessMemory. Most `rop.*` commands need a loaded gadget corpus, so run `rop.scan_live` or `rop.scan` first. The `rop.frame_*` commands and `rop_template` work without a corpus.

Run each command as `dx @$osed().<command>` in WinDbg. The [command index](../COMMANDS.md#conventions) explains byte lists, addresses, and optional arguments. `dx @$osed().help("<command>", "full")` prints the built-in help.

| Command | What it does |
| --- | --- |
| [`rop_suggest`](#rop_suggest) | Scan a module and print common exploit gadgets grouped by what they do. |
| [`retn`](#retn) | Find `retn N` gadgets, which return and then drop N bytes from the stack. |
| [`add_esp`](#add_esp) | Find `add esp, N ; ret` gadgets, which skip stack slots. |
| [`pivots`](#pivots) | Find stack pivot gadgets, which move ESP to a register or an offset. |
| [`rop.find`](#ropfind) | Run the older ROP helper that scans one module and prints a module summary. |
| [`rop_template`](#rop_template) | Print a commented chain skeleton for one API, with the `dx` commands that find each address it needs. |
| [`rop.scan_live`](#ropscan_live) | Find gadgets in one or more loaded modules and load them into the corpus that the other `rop.*` commands use. |
| [`rop.scan`](#ropscan) | Load gadget text from RP++ output into the corpus. |
| [`rop.capabilities`](#ropcapabilities) | Count the gadgets in the corpus by capability, such as `LOAD_REGISTER`, `MEMORY_WRITE`, or `STACK_PIVOT`. |
| [`rop.query`](#ropquery) | Filter the corpus by capability or by a semantic field. |
| [`rop.corpus.lookup`](#ropcorpuslookup) | Look up one address in the corpus. |
| [`rop.pivots`](#roppivots) | Rank the stack pivot gadgets in the corpus, optionally for one source register or a minimum ESP change. |
| [`rop.construct`](#ropconstruct) | Build a short gadget sequence that loads a value into a register when the raw value contains bad characters. |
| [`rop.setup`](#ropsetup) | Load several registers at once in an order where no gadget overwrites a register that is already set. |
| [`rop.chain`](#ropchain) | Build a chain that sets one or more registers from the corpus. |
| [`rop.chain_vp`](#ropchain_vp) | Build a VirtualProtect PUSHAD chain from the corpus. |
| [`rop.chain_va`](#ropchain_va) | Build a VirtualAlloc PUSHAD chain from the corpus. |
| [`rop.chain_wpm`](#ropchain_wpm) | Build a WriteProcessMemory PUSHAD chain from the corpus. |
| [`rop.frame_vp`](#ropframe_vp) | Print a flat VirtualProtect stdcall frame without gadgets. |
| [`rop.frame_va`](#ropframe_va) | Print a flat VirtualAlloc stdcall frame without gadgets. |
| [`rop.frame_wpm`](#ropframe_wpm) | Print a flat WriteProcessMemory stdcall frame without gadgets. |
| [`rop.frame_write`](#ropframe_write) | Build a stdcall frame in a writable buffer one word at a time, then pivot ESP onto it, without PUSHAD. |
| [`rop.slot_call`](#ropslot_call) | Call an API through a fixed IAT slot, so the API's ASLR address never appears in the payload. |
| [`rop.api_plan`](#ropapi_plan) | List the ways to get an API address into a register: a direct IAT slot, or an export of the same module. |
| [`rop.api_build`](#ropapi_build) | Build a short chain that loads an API address into EAX from one `rop.api_plan` candidate. |
| [`rop.plan`](#ropplan) | List the strategies that the corpus can support for one API, without picking gadget addresses. |
| [`rop.emit`](#ropemit) | Pick concrete gadgets for a plan from `rop.plan`. |
| [`rop.synthesize`](#ropsynthesize) | Lay out the stack for a plan, using the state that `triage()` cached. |
| [`rop.export`](#ropexport) | Write the emitted gadgets and stack layout as a Python stub, to the console or to a file. |
| [`rop.generate`](#ropgenerate) | Build a complete Python exploit for one DEP bypass API from the corpus in one command. |
| [`rop.verify`](#ropverify) | Check a chain for bad characters, unresolved placeholders, stack use, and register side effects. |
| [`rop.prove`](#ropprove) | Step through a chain in the debugger, one predicted checkpoint at a time. |
| [`rop.corpus.export`](#ropcorpusexport) | Save the corpus and a fingerprint of the modules to a JSON file, or print it. |
| [`rop.corpus.import`](#ropcorpusimport) | Load a saved corpus. It stays inactive until `rop.corpus.validate()` succeeds. |
| [`rop.corpus.validate`](#ropcorpusvalidate) | Check the imported corpus against the current modules and gadget bytes, then activate it. |
| [`rop.corpus.report`](#ropcorpusreport) | Print the corpus as one line per gadget, or write it to a text file. |

## Quick gadget scans

These commands scan a module directly and need no corpus.

### rop_suggest

Scan a module and print common exploit gadgets grouped by what they do.

```text
rop_suggest(module?, maxResults?, executableOnly?, mode?, engine?)
```

```text
dx @$osed().rop_suggest("essfunc")
dx @$osed().rop_suggest("essfunc", 50, true, "fast", "semantic")
dx @$osed().rop_suggest("", 50, true, "thorough", "legacy")
```

`engine` is `semantic` or `legacy`. `mode` is `fast` or `thorough`. An empty module name scans every module.

### retn

Find `retn N` gadgets, which return and then drop N bytes from the stack.

```text
retn(module?, maxResults?, executableOnly?, mode?)
```

```text
dx @$osed().retn("essfunc")
dx @$osed().retn("essfunc", 100)
```

### add_esp

Find `add esp, N ; ret` gadgets, which skip stack slots.

```text
add_esp(module?, maxResults?, executableOnly?, mode?)
```

```text
dx @$osed().add_esp("essfunc")
dx @$osed().add_esp("essfunc", 100)
```

### pivots

Find stack pivot gadgets, which move ESP to a register or an offset.

```text
pivots(module?, maxResults?, executableOnly?, mode?)
```

```text
dx @$osed().pivots("essfunc")
dx @$osed().pivots("", 50, true, "thorough")
```

### rop.find

Run the older ROP helper that scans one module and prints a module summary.

```text
rop.find(module?, maxResults?, executableOnly?, mode?)
```

```text
dx @$osed().rop.find("essfunc")
dx @$osed().rop_find("essfunc")
```

Also callable as `rop_find`.

### rop_template

Print a commented chain skeleton for one API, with the `dx` commands that find each address it needs.

```text
rop_template(api?, module?)
```

```text
dx @$osed().rop_template("VirtualProtect", "essfunc")
dx @$osed().rop_template("WriteProcessMemory", "essfunc")
dx @$osed().rop_template("LoadLibraryA", "essfunc")
dx @$osed().rop_template("GetProcAddress", "essfunc")
```

Supported APIs are VirtualProtect, WriteProcessMemory, LoadLibraryA, and GetProcAddress. The skeleton shows the PUSHAD register map and a Python layout with `???` for each value that you still need to find.

## Build the gadget corpus

### rop.scan_live

Find gadgets in one or more loaded modules and load them into the corpus that the other `rop.*` commands use.

```text
rop.scan_live(moduleOrModules?, badchars?, append?, maxPerPattern?, maxInstructionsPerGadget?, maxBackwardGadgets?)
```

```text
dx @$osed().rop.scan_live("compression", "00 0A 0D")
dx @$osed().rop.scan_live("crypto", "00 0A 0D", true)
dx @$osed().rop.scan_live("crypto", "00 0A 0D", true, 5)
dx @$osed().rop.scan_live("libspp.dll", "00 0A 0D", true, 40, 6)
dx @$osed().rop.scan_live("libspp.dll", "00 0A 0D", false, 40, 6, 50000)
```

Positional order is `module, badchars, append, maxPerPattern, maxInstructionsPerGadget, maxBackwardGadgets`. `append` set to `true` keeps the current corpus. The instruction limit defaults to 6, from 1 to 12. `maxBackwardGadgets` defaults to 10000. The summary says whether the backward scan finished or hit that limit.

### rop.scan

Load gadget text from RP++ output into the corpus.

```text
rop.scan(text, badchars?)
```

```text
dx @$osed().rop.scan("0x1000: pop eax ; ret ;")
dx @$osed().rop.scan("0x1000: pop eax ; ret ;", "00 0A 0D")
```

Pass the RP++ lines as one string. Gadgets whose addresses contain a byte in `badchars` are dropped.

### rop.capabilities

Count the gadgets in the corpus by capability, such as `LOAD_REGISTER`, `MEMORY_WRITE`, or `STACK_PIVOT`.

```text
rop.capabilities()
```

```text
dx @$osed().rop.capabilities()
```

### rop.query

Filter the corpus by capability or by a semantic field.

```text
rop.query(field, value, executableOnly?, verbose?)
```

```text
dx @$osed().rop.query("capability", "LOAD_REGISTER")
dx @$osed().rop.query("capability", "MEMORY_WRITE", false, true)
dx @$osed().rop.query("capability", "ARITHMETIC")
dx @$osed().rop.query("preserves", "eax")
dx @$osed().rop.query("terminator", "JUMP", false, true)
```

Fields are `reads`, `writes`, `preserves`, `preservesThroughout`, `capability`, `terminator`, `stackDelta`, `memoryReads`, `memoryWrites`, and `executableOnly`. `ARITHMETIC` expands to every add, sub, xor, adc, sbb, or, and, not, neg, inc, and dec capability. Set `verbose` to `true` for each gadget's full effects. For one exact address, use `rop.corpus.lookup`.

### rop.corpus.lookup

Look up one address in the corpus.

```text
rop.corpus.lookup(address)
```

```text
dx @$osed().rop.corpus.lookup(0x10154112)
```

`NOT_FOUND` means that the scan did not record that address. It never scans memory.

### rop.pivots

Rank the stack pivot gadgets in the corpus, optionally for one source register or a minimum ESP change.

```text
rop.pivots(register?, minDelta?, verbose?)
```

```text
dx @$osed().rop.pivots()
dx @$osed().rop.pivots("eax")
dx @$osed().rop.pivots("eax", 0, true)
```

## Load values into registers

### rop.construct

Build a short gadget sequence that loads a value into a register when the raw value contains bad characters.

```text
rop.construct(register, value, badchars?, preserve?)
```

```text
dx @$osed().rop.construct("ebx", 0x201, "00 0A 0D")
dx @$osed().rop.construct("ebx", 0x201, "00 0A 0D", "eax")
dx @$osed().rop.construct("edx", 0x1000, "00 0A 0D", "eax ecx")
```

It tries these recipes in order: direct `pop`, `neg`, `not`, two values that add up, two values that subtract, `xor` then `add`, and `xor`, `sub`, then `neg`. The output names the recipe, the registers it clobbers, and the Python `pack()` lines, with filler words for extra pops. `preserve` lists registers that the recipe must not touch.

### rop.setup

Load several registers at once in an order where no gadget overwrites a register that is already set.

```text
rop.setup("reg=value reg=value ...", badchars?)
```

```text
dx @$osed().rop.setup("edi=0x10001000 ebx=0x40", "00 0A 0D")
dx @$osed().rop.setup("edi=0x10030000 esi=0x10040000 ebp=0x10050000 ebx=0x201 edx=0x40", "00 0A 0D")
```

Use it to stage the registers before PUSHAD. Values must be free of bad characters already. Build those with `rop.construct` first. It reports a conflict when no order works.

### rop.chain

Build a chain that sets one or more registers from the corpus.

```text
rop.chain(register, value, register2?, value2?, ...)
```

```text
dx @$osed().rop.chain("eax", 0xDEADBEEF, "ebx", 0x1000)
```

It uses `xor reg, reg` for zero, multi-pop gadgets where they fit, and `pop reg ; ret` otherwise. It prints a Python layout and lists any register it cannot set.

## Build a DEP bypass chain

The `chain_*` commands build a PUSHAD chain from the corpus. The `frame_*` commands print a flat stdcall frame and need no gadgets.

### rop.chain_vp

Build a VirtualProtect PUSHAD chain from the corpus.

```text
rop.chain_vp(virtualProtect?, retGadget?, returnAddress?, lpAddress?, dwSize?, writable?, flNewProtect?, mode?)
```

```text
dx @$osed().rop.chain_vp(0x7C801AD0, 0x62501010, 0x625011AF)
```

The default `ret-slide` mode sets EDI to a `ret`, ESI to VirtualProtect, EBX to `dwSize` (default `0x201`), EDX to `0x40`, and ECX to a writable address. The saved ESP becomes `lpAddress`. Missing values stay as named placeholders.

### rop.chain_va

Build a VirtualAlloc PUSHAD chain from the corpus.

```text
rop.chain_va(virtualAlloc?, returnAddress?, lpAddress?, flAllocationType?, flProtect?)
```

```text
dx @$osed().rop.chain_va(0x7C809AE1)
```

Defaults are `flAllocationType = 0x1000` and `flProtect = 0x40`. It warns that the saved ESP becomes `dwSize`.

### rop.chain_wpm

Build a WriteProcessMemory PUSHAD chain from the corpus.

```text
rop.chain_wpm(writeProcessMemory?, returnAddress?, lpBuffer?, nSize?, writable?)
```

```text
dx @$osed().rop.chain_wpm(0x7C802213, 0x625011AF, 0x0012F800, 0x200)
```

`hProcess` is `0xFFFFFFFF`, the current process. It warns that the saved ESP becomes `lpBaseAddress`.

### rop.frame_vp

Print a flat VirtualProtect stdcall frame without gadgets.

```text
rop.frame_vp(virtualProtect?, returnAddress?, lpAddress?, dwSize?, flNewProtect?, writable?, badchars?)
```

```text
dx @$osed().rop.frame_vp(0x7C801AD0, 0x625011AF, 0x0012F800, 0x201, 0x40, 0x62506000, "00 0A 0D")
```

The frame is `[VirtualProtect][return][lpAddress][dwSize][flNewProtect][lpflOldProtect]` as Python `pack()` lines and a table. It flags every word that contains a bad character, so you know which values to build with `rop.construct`.

### rop.frame_va

Print a flat VirtualAlloc stdcall frame without gadgets.

```text
rop.frame_va(virtualAlloc?, returnAddress?, lpAddress?, dwSize?, flAllocationType?, flProtect?, badchars?)
```

```text
dx @$osed().rop.frame_va(0x7C809AE1, 0x625011AF, 0, 0x201, 0x1000, 0x40, "00 0A 0D")
```

Defaults are `dwSize = 0x201`, `flAllocationType = 0x1000`, and `flProtect = 0x40`. Words that contain bad characters are flagged.

### rop.frame_wpm

Print a flat WriteProcessMemory stdcall frame without gadgets.

```text
rop.frame_wpm(writeProcessMemory?, returnAddress?, hProcess?, lpBaseAddress?, lpBuffer?, nSize?, writable?, badchars?)
```

```text
dx @$osed().rop.frame_wpm(0x7C802213, 0x625011AF, 0xFFFFFFFF, 0x62502000, 0x0012F800, 0x200, 0x62506000, "00")
```

`hProcess` defaults to `0xFFFFFFFF`. Words that contain bad characters are flagged.

### rop.frame_write

Build a stdcall frame in a writable buffer one word at a time, then pivot ESP onto it, without PUSHAD.

```text
rop.frame_write(buf, "word0 word1 arg1 arg2 ...", badchars?)
```

```text
dx @$osed().rop.frame_write("BUF", "VIRTUALALLOC POST_CALL 0x0 0x1000 0x3000 0x40", "00 0A 0D")
dx @$osed().rop.frame_write("0x00420000", "[0x1005D060] 0x10017260 0x0 0x1000 0x3000 0x40", "00 0A 0D")
```

Word order is the API address, the address to return to after the call, then the arguments. `BUF` must be a writable, stable address without bad characters. Words with bad characters are built in ECX instead of placed in the payload.

### rop.slot_call

Call an API through a fixed IAT slot, so the API's ASLR address never appears in the payload.

```text
rop.slot_call(buf, iatSlot, "retaddr arg1 arg2 ...", badchars?, entrySkew?)
```

```text
dx @$osed().rop.slot_call("0x00420000", "0x1005D060", "SHELLCODE SHELLCODE 0x1000 0x1000 0x40", "00 0A 0D")
dx @$osed().rop.slot_call("0x00420000", "0x1005D060", "SHELLCODE SHELLCODE 0x1000 0x1000 0x40", "00 0A 0D", 4)
```

The chain loads the slot address, reads the live API address from it, and jumps there. The first word of the argument string is where the API returns to, then the arguments. It warns when a gadget sits at an address that moves between runs.

## Resolve the API address

### rop.api_plan

List the ways to get an API address into a register: a direct IAT slot, or an export of the same module.

```text
rop.api_plan("MODULE!Symbol", badchars?)
```

```text
dx @$osed().rop.api_plan("KERNEL32!WriteProcessMemory", "00 0A 0D")
dx @$osed().rop.api_plan("VirtualProtect")
```

It checks each candidate against live memory and reports the bytes that collide with bad characters. It does not pick gadgets or build a chain.

### rop.api_build

Build a short chain that loads an API address into EAX from one `rop.api_plan` candidate.

```text
rop.api_build(target, badchars?, continuation?, preserve?, maxGadgets?, owner?, anchor?)
```

```text
dx @$osed().rop.api_build("KERNEL32!WriteProcessMemory", "00 0A 0D", 0x10064A0F, "", 12, "libspp.dll", "QueryDosDeviceA")
```

`continuation` is the address that runs after the address is in EAX, and it is required. `preserve` is a list of registers to keep. `owner` and `anchor` pick one candidate. It never calls the API.

## Plan, generate, and check a chain

### rop.plan

List the strategies that the corpus can support for one API, without picking gadget addresses.

```text
rop.plan(strategy, apiResolution?)
```

```text
dx @$osed().rop.plan("VirtualAlloc")
dx @$osed().rop.plan("VirtualProtect", "iat")
dx @$osed().rop.plan("WinExec")
```

Strategies are VirtualProtect, VirtualAlloc, WriteProcessMemory, VirtualProtectEx, VirtualAllocEx, WinExec, and Stack Pivot. Each plan gets an id for `rop.emit`.

### rop.emit

Pick concrete gadgets for a plan from `rop.plan`.

```text
rop.emit(planId, strategyId?)
```

```text
dx @$osed().rop.emit(1)
dx @$osed().rop.emit(1, 3)
```

The result is a gadget assignment, not a finished chain. Pass the plan id to `rop.synthesize` next.

### rop.synthesize

Lay out the stack for a plan, using the state that `triage()` cached.

```text
rop.synthesize(planId)
```

```text
dx @$osed().rop.synthesize(1)
```

### rop.export

Write the emitted gadgets and stack layout as a Python stub, to the console or to a file.

```text
rop.export(planId, path?)
```

```text
dx @$osed().rop.export(1)
dx @$osed().rop.export(1, "C:\\exploit\\rop.py")
```

### rop.generate

Build a complete Python exploit for one DEP bypass API from the corpus in one command.

```text
rop.generate(api, shellcode?, badchars?, module?, offset?)
```

```text
dx @$osed().rop.generate("auto", "", "00 0A 0D", "MSA2Mfilter03", 780)
dx @$osed().rop.generate("VirtualAlloc", "FC E8 82 00 00 00 60", "00 0A 0D")
dx @$osed().rop.generate("VirtualProtect")
```

It finds the IAT slot, a writable buffer, and the return gadget, builds a `slot_call` chain, and encodes the shellcode. `"auto"` tries every supported API and picks the best. It needs a corpus from `rop.scan_live` or `rop.scan`.

### rop.verify

Check a chain for bad characters, unresolved placeholders, stack use, and register side effects.

```text
rop.verify(chain?, badchars?, api?)
```

```text
dx @$osed().rop.verify()
dx @$osed().rop.verify("", "00 0A 0D")
dx @$osed().rop.verify("10022D64 1005D060 DEADBEEF", "00 0A 0D")
```

With no chain it checks the last `rop.generate` result. A chain is a string of hex words. It prints a static verdict and then a word-by-word trace of ESP and the registers. It never changes the chain.

### rop.prove

Step through a chain in the debugger, one predicted checkpoint at a time.

```text
rop.prove(modeOrAction?)
```

```text
dx @$osed().rop.prove("guided")
dx @$osed().rop.prove("observe")
dx @$osed().rop.prove()
dx @$osed().rop.prove("status")
dx @$osed().rop.prove("cancel")
dx @$osed().rop.prove("export")
```

Start with `"guided"`, run `g` yourself, then run `rop.prove()` at each stop. It sets at most one one-shot breakpoint and never resumes the target. It reports whether the gadgets ran separately from whether the DEP bypass worked. `"status"`, `"cancel"`, and `"export"` manage the session.

## Save and reload the corpus

### rop.corpus.export

Save the corpus and a fingerprint of the modules to a JSON file, or print it.

```text
rop.corpus.export(path?)
```

```text
dx @$osed().rop.corpus.export("C:\\notes\\rop-corpus.json")
dx @$osed().rop.corpus.export()
```

### rop.corpus.import

Load a saved corpus. It stays inactive until `rop.corpus.validate()` succeeds.

```text
rop.corpus.import(path)
```

```text
dx @$osed().rop.corpus.import("C:\\notes\\rop-corpus.json")
```

### rop.corpus.validate

Check the imported corpus against the current modules and gadget bytes, then activate it.

```text
rop.corpus.validate()
```

```text
dx @$osed().rop.corpus.validate()
```

It fails when the module names, paths, bases, sizes, or sampled bytes differ, for example after a reboot moved an ASLR module.

### rop.corpus.report

Print the corpus as one line per gadget, or write it to a text file.

```text
rop.corpus.report(path?)
```

```text
dx @$osed().rop.corpus.report()
dx @$osed().rop.corpus.report("C:\\notes\\rop-gadgets.txt")
```

Unknown values show as `?`. It does no new scanning.
