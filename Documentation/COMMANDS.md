# Command index

This page lists every command that the script registers. Each name links to its entry in a category file. The [README](../README.md#exam-workflow) shows the commands in exam order.

## Conventions

- Run each command as `dx @$osed().<command>(arguments)`.
- Arguments are positional. A `?` after a name in a signature marks an optional argument. To skip an optional string argument and set a later one, pass `""`, as in `code_caves("", 50, 25, "", "EXEC")`.
- `dx` does not accept JavaScript object literals such as `{mode: "guided"}`. Use the positional form.
- Pass byte lists, such as bad characters, as one string of hex bytes: `"00 0A 0D"`.
- Pass addresses as numbers (`0x0012F800`), hex strings (`"0012F800"`), or arithmetic (`0x0019ed34+8`). `dx` evaluates the arithmetic before the call.
- Pseudo-registers such as `@$t0` reach the script as 64-bit `Int64` objects, and address arguments reject them. Cast them first, as in `dx @$osed().badchar_find((unsigned int)@$t0, "00 0A 0D")`.
- Use double quotes for strings.
- Most commands print their output and return `true` or `false`. `dx @$osed().last_result()` returns the full structured result.
- `dx @$osed().help("<command>", "full")` prints the built-in help for one command. Most commands also print it when you pass `"help"` as the only argument.
- **[fork: new]** and **[fork: changed]** mark commands that this fork adds or changes.

## Categories

| Category | Commands |
| --- | --- |
| [Pattern and bad characters](commands/payload.md) | 6 |
| [Crash triage](commands/crash.md) | 4 |
| [Target and memory](commands/target.md) | 8 |
| [SEH](commands/seh.md) | 2 |
| [ROP and DEP](commands/rop.md) | 36 |
| [Format strings](commands/format.md) | 3 |
| [Shellcode](commands/shellcode.md) | 3 |
| [Strings](commands/strings.md) | 4 |
| [PE and API](commands/pe-api.md) | 20 |
| [Leak, math, and session](commands/tools.md) | 14 |

## All commands

| Command | Category | What it does |
| --- | --- | --- |
| [`add_esp`](commands/rop.md#add_esp) | [ROP and DEP](commands/rop.md) | Find `add esp, N ; ret` gadgets, which skip stack slots. |
| [`badchar_array`](commands/payload.md#badchar_array) | [Pattern and bad characters](commands/payload.md) | Print the bad-character test array, 0x00 to 0xFF minus the excluded bytes, as Python, C, and hex. |
| [`badchar_find`](commands/payload.md#badchar_find) | [Pattern and bad characters](commands/payload.md) | Find the test array or one block of it in memory near an address or ESP and report the first corrupted byte. |
| [`badchar_function`](commands/payload.md#badchar_function) | [Pattern and bad characters](commands/payload.md) | Print a Python `BADCHARS` line plus `badchar_array()` and `badchar_block()` helpers to paste into the exploit once. |
| [`badchars`](commands/payload.md#badchars) | [Pattern and bad characters](commands/payload.md) | Compare the bytes at a known address with the expected test array and list the bytes that differ. |
| [`can_execute`](commands/target.md#can_execute) | [Target and memory](commands/target.md) | Return `true`, `false`, or `null` for whether the memory at an address is executable. |
| [`clear_last_result`](commands/tools.md#clear_last_result) | [Leak, math, and session](commands/tools.md) | Clear the stored last result. |
| [`code_caves`](commands/target.md#code_caves) | [Target and memory](commands/target.md) | Find runs of null, `int3`, or NOP padding inside PE sections that can hold a payload. |
| [`egghunter`](commands/shellcode.md#egghunter) | [Shellcode](commands/shellcode.md) | Print an egghunter stub for a 4-byte tag, as hex and as Python bytes, and flag stub bytes that are bad characters. |
| [`encode`](commands/shellcode.md#encode) | [Shellcode](commands/shellcode.md) | XOR-encode a payload so that it contains none of the excluded bytes, and print the decoder stub with it. |
| [`exploit.clear`](commands/tools.md#exploitclear) | [Leak, math, and session](commands/tools.md) | Clear the cached exploit state. |
| [`exploit.state`](commands/tools.md#exploitstate) | [Leak, math, and session](commands/tools.md) | Show the exploit state that `triage()` cached, such as the control mechanism, the stack pointer, and the bad characters, which `rop.synthesize` reads. |
| [`exploit.workflow`](commands/tools.md#exploitworkflow) | [Leak, math, and session](commands/tools.md) | Print a fixed list of `dx` commands for one workflow: `offset`, `badchars`, or `egghunter`. |
| [`find_bytes`](commands/target.md#find_bytes) | [Target and memory](commands/target.md) | Search the PE sections of one loaded module for a byte sequence. |
| [`find_mem_bytes`](commands/target.md#find_mem_bytes) | [Target and memory](commands/target.md) | Search an address range that you give for a byte sequence. |
| [`find_ptr`](commands/target.md#find_ptr) | [Target and memory](commands/target.md) | Find addresses of `jmp <reg>`, `call <reg>`, or `push <reg> ; ret` and drop the addresses that contain bad characters. |
| [`find_stack_bytes`](commands/target.md#find_stack_bytes) | [Target and memory](commands/target.md) | Search the current thread stack, from ESP upward, for a byte sequence. |
| [`findmsp`](commands/crash.md#findmsp) | [Crash triage](commands/crash.md) | Find cyclic-pattern offsets in every register, in the stack, in the SEH record, and in the memory that registers point to. |
| `fmt_build` | [Format strings](commands/format.md) | Same as [`fmt.build`](commands/format.md#fmtbuild). |
| `fmt_inspect` | [Format strings](commands/format.md) | Same as [`fmt.inspect`](commands/format.md#fmtinspect). |
| `fmt_offset` | [Format strings](commands/format.md) | Same as [`fmt.offset`](commands/format.md#fmtoffset). |
| [`fmt.build`](commands/format.md#fmtbuild) | [Format strings](commands/format.md) | Build a `%n` write-what-where payload that writes `value` to `addr`. |
| [`fmt.inspect`](commands/format.md#fmtinspect) | [Format strings](commands/format.md) | Read the format-string argument of a paused `printf`, `fprintf`, `sprintf`, or `snprintf` call and list its conversions. |
| [`fmt.offset`](commands/format.md#fmtoffset) | [Format strings](commands/format.md) | Find which `%N# Command index

This page lists every command that the script registers. Each name links to its entry in a category file. The [README](../README.md#exam-workflow) shows the commands in exam order.

## Conventions

- Run each command as `dx @$osed().<command>(arguments)`.
- Arguments are positional. A `?` after a name in a signature marks an optional argument. To skip an optional string argument and set a later one, pass `""`, as in `code_caves("", 50, 25, "", "EXEC")`.
- `dx` does not accept JavaScript object literals such as `{mode: "guided"}`. Use the positional form.
- Pass byte lists, such as bad characters, as one string of hex bytes: `"00 0A 0D"`.
- Pass addresses as numbers (`0x0012F800`), hex strings (`"0012F800"`), or arithmetic (`0x0019ed34+8`). `dx` evaluates the arithmetic before the call.
- Pseudo-registers such as `@$t0` reach the script as 64-bit `Int64` objects, and address arguments reject them. Cast them first, as in `dx @$osed().badchar_find((unsigned int)@$t0, "00 0A 0D")`.
- Use double quotes for strings.
- Most commands print their output and return `true` or `false`. `dx @$osed().last_result()` returns the full structured result.
- `dx @$osed().help("<command>", "full")` prints the built-in help for one command. Most commands also print it when you pass `"help"` as the only argument.
- **[fork: new]** and **[fork: changed]** mark commands that this fork adds or changes.

## Categories

| Category | Commands |
| --- | --- |
| [Pattern and bad characters](commands/payload.md) | 6 |
| [Crash triage](commands/crash.md) | 4 |
| [Target and memory](commands/target.md) | 8 |
| [SEH](commands/seh.md) | 2 |
| [ROP and DEP](commands/rop.md) | 36 |
| [Format strings](commands/format.md) | 3 |
| [Shellcode](commands/shellcode.md) | 3 |
| [Strings](commands/strings.md) | 4 |
| [PE and API](commands/pe-api.md) | 20 |
| [Leak, math, and session](commands/tools.md) | 14 |

## All commands

| Command | Category | What it does |
| --- | --- | --- |
 parameter reaches your buffer and which stack slots hold pointers worth leaking. |
| [`help`](commands/tools.md#help) | [Leak, math, and session](commands/tools.md) | List the commands, or print the help for one command. |
| [`landing`](commands/crash.md#landing) | [Crash triage](commands/crash.md) | Show what sits at ESP, or at an address, and whether the memory there is executable. |
| [`last_result`](commands/tools.md#last_result) | [Leak, math, and session](commands/tools.md) | Return the full structured result of the last command. |
| [`last_summary`](commands/tools.md#last_summary) | [Leak, math, and session](commands/tools.md) | Return the command name and the counts of findings, warnings, and errors from the last command. |
| `leak_analyze` | [Leak, math, and session](commands/tools.md) | Same as [`leak.analyze`](commands/tools.md#leakanalyze). |
| `leak_base` | [Leak, math, and session](commands/tools.md) | Same as [`leak.base`](commands/tools.md#leakbase). |
| `leak_classify` | [Leak, math, and session](commands/tools.md) | Same as [`leak.classify`](commands/tools.md#leakclassify). |
| `leak_scan` | [Leak, math, and session](commands/tools.md) | Same as [`leak.scan`](commands/tools.md#leakscan). |
| [`leak.analyze`](commands/tools.md#leakanalyze) | [Leak, math, and session](commands/tools.md) | Pull hex pointer values out of text that the application printed and classify each one. |
| [`leak.base`](commands/tools.md#leakbase) | [Leak, math, and session](commands/tools.md) | Compute a module base from a leaked pointer and its RVA, and check it against the loaded modules. |
| [`leak.classify`](commands/tools.md#leakclassify) | [Leak, math, and session](commands/tools.md) | Say which module or memory region a pointer value falls in, without reading memory at it. |
| [`leak.scan`](commands/tools.md#leakscan) | [Leak, math, and session](commands/tools.md) | Scan an address range, up to `0x10000` bytes, for pointer-sized values and classify each one. |
| [`math`](commands/tools.md#math) | [Leak, math, and session](commands/tools.md) | Print a number as hex, unsigned, signed, little-endian bytes, and two's complement. |
| [`memory`](commands/target.md#memory) | [Target and memory](commands/target.md) | Show the memory region that holds an address and its protection flags. |
| [`modules`](commands/target.md#modules) | [Target and memory](commands/target.md) | List the loaded modules with their base, size, and the ASLR, SafeSEH, and DEP state of each. |
| [`nop`](commands/shellcode.md#nop) | [Shellcode](commands/shellcode.md) | Print a NOP sled of `length` bytes. |
| `pattern_create` | [Pattern and bad characters](commands/payload.md) | Same as [`pattern.create`](commands/payload.md#patterncreate). |
| `pattern_offset` | [Pattern and bad characters](commands/payload.md) | Same as [`pattern.offset`](commands/payload.md#patternoffset). |
| [`pattern.create`](commands/payload.md#patterncreate) | [Pattern and bad characters](commands/payload.md) | Print a cyclic pattern of `length` characters to send instead of your buffer. |
| [`pattern.offset`](commands/payload.md#patternoffset) | [Pattern and bad characters](commands/payload.md) | Print the offset of a 4-byte value inside the pattern. |
| [`pivots`](commands/rop.md#pivots) | [ROP and DEP](commands/rop.md) | Find stack pivot gadgets, which move ESP to a register or an offset. |
| [`reload`](commands/tools.md#reload) | [Leak, math, and session](commands/tools.md) | Clear the command registry and register every command again, without reloading the script file. |
| [`retn`](commands/rop.md#retn) | [ROP and DEP](commands/rop.md) | Find `retn N` gadgets, which return and then drop N bytes from the stack. |
| `rop_find` | [ROP and DEP](commands/rop.md) | Same as [`rop.find`](commands/rop.md#ropfind). |
| [`rop_suggest`](commands/rop.md#rop_suggest) | [ROP and DEP](commands/rop.md) | Scan a module and print common exploit gadgets grouped by what they do. |
| [`rop_template`](commands/rop.md#rop_template) | [ROP and DEP](commands/rop.md) | Print a commented chain skeleton for one API, with the `dx` commands that find each address it needs. |
| [`rop.api_build`](commands/rop.md#ropapi_build) | [ROP and DEP](commands/rop.md) | Build a short chain that loads an API address into EAX from one `rop.api_plan` candidate. |
| [`rop.api_plan`](commands/rop.md#ropapi_plan) | [ROP and DEP](commands/rop.md) | List the ways to get an API address into a register: a direct IAT slot, or an export of the same module. |
| [`rop.capabilities`](commands/rop.md#ropcapabilities) | [ROP and DEP](commands/rop.md) | Count the gadgets in the corpus by capability, such as `LOAD_REGISTER`, `MEMORY_WRITE`, or `STACK_PIVOT`. |
| [`rop.chain_va`](commands/rop.md#ropchain_va) | [ROP and DEP](commands/rop.md) | Build a VirtualAlloc PUSHAD chain from the corpus. |
| [`rop.chain_vp`](commands/rop.md#ropchain_vp) | [ROP and DEP](commands/rop.md) | Build a VirtualProtect PUSHAD chain from the corpus. |
| [`rop.chain_wpm`](commands/rop.md#ropchain_wpm) | [ROP and DEP](commands/rop.md) | Build a WriteProcessMemory PUSHAD chain from the corpus. |
| [`rop.chain`](commands/rop.md#ropchain) | [ROP and DEP](commands/rop.md) | Build a chain that sets one or more registers from the corpus. |
| [`rop.construct`](commands/rop.md#ropconstruct) | [ROP and DEP](commands/rop.md) | Build a short gadget sequence that loads a value into a register when the raw value contains bad characters. |
| [`rop.corpus.export`](commands/rop.md#ropcorpusexport) | [ROP and DEP](commands/rop.md) | Save the corpus and a fingerprint of the modules to a JSON file, or print it. |
| [`rop.corpus.import`](commands/rop.md#ropcorpusimport) | [ROP and DEP](commands/rop.md) | Load a saved corpus. It stays inactive until `rop.corpus.validate()` succeeds. |
| [`rop.corpus.lookup`](commands/rop.md#ropcorpuslookup) | [ROP and DEP](commands/rop.md) | Look up one address in the corpus. |
| [`rop.corpus.report`](commands/rop.md#ropcorpusreport) | [ROP and DEP](commands/rop.md) | Print the corpus as one line per gadget, or write it to a text file. |
| [`rop.corpus.validate`](commands/rop.md#ropcorpusvalidate) | [ROP and DEP](commands/rop.md) | Check the imported corpus against the current modules and gadget bytes, then activate it. |
| [`rop.emit`](commands/rop.md#ropemit) | [ROP and DEP](commands/rop.md) | Pick concrete gadgets for a plan from `rop.plan`. |
| [`rop.export`](commands/rop.md#ropexport) | [ROP and DEP](commands/rop.md) | Write the emitted gadgets and stack layout as a Python stub, to the console or to a file. |
| [`rop.find`](commands/rop.md#ropfind) | [ROP and DEP](commands/rop.md) | Run the older ROP helper that scans one module and prints a module summary. |
| [`rop.frame_va`](commands/rop.md#ropframe_va) | [ROP and DEP](commands/rop.md) | Print a flat VirtualAlloc stdcall frame without gadgets. |
| [`rop.frame_vp`](commands/rop.md#ropframe_vp) | [ROP and DEP](commands/rop.md) | Print a flat VirtualProtect stdcall frame without gadgets. |
| [`rop.frame_wpm`](commands/rop.md#ropframe_wpm) | [ROP and DEP](commands/rop.md) | Print a flat WriteProcessMemory stdcall frame without gadgets. |
| [`rop.frame_write`](commands/rop.md#ropframe_write) | [ROP and DEP](commands/rop.md) | Build a stdcall frame in a writable buffer one word at a time, then pivot ESP onto it, without PUSHAD. |
| [`rop.generate`](commands/rop.md#ropgenerate) | [ROP and DEP](commands/rop.md) | Build a complete Python exploit for one DEP bypass API from the corpus in one command. |
| [`rop.pivots`](commands/rop.md#roppivots) | [ROP and DEP](commands/rop.md) | Rank the stack pivot gadgets in the corpus, optionally for one source register or a minimum ESP change. |
| [`rop.plan`](commands/rop.md#ropplan) | [ROP and DEP](commands/rop.md) | List the strategies that the corpus can support for one API, without picking gadget addresses. |
| [`rop.prove`](commands/rop.md#ropprove) | [ROP and DEP](commands/rop.md) | Step through a chain in the debugger, one predicted checkpoint at a time. |
| [`rop.query`](commands/rop.md#ropquery) | [ROP and DEP](commands/rop.md) | Filter the corpus by capability or by a semantic field. |
| [`rop.scan_live`](commands/rop.md#ropscan_live) | [ROP and DEP](commands/rop.md) | Find gadgets in one or more loaded modules and load them into the corpus that the other `rop.*` commands use. |
| [`rop.scan`](commands/rop.md#ropscan) | [ROP and DEP](commands/rop.md) | Load gadget text from RP++ output into the corpus. |
| [`rop.setup`](commands/rop.md#ropsetup) | [ROP and DEP](commands/rop.md) | Load several registers at once in an order where no gadget overwrites a register that is already set. |
| [`rop.slot_call`](commands/rop.md#ropslot_call) | [ROP and DEP](commands/rop.md) | Call an API through a fixed IAT slot, so the API's ASLR address never appears in the payload. |
| [`rop.synthesize`](commands/rop.md#ropsynthesize) | [ROP and DEP](commands/rop.md) | Lay out the stack for a plan, using the state that `triage()` cached. |
| [`rop.verify`](commands/rop.md#ropverify) | [ROP and DEP](commands/rop.md) | Check a chain for bad characters, unresolved placeholders, stack use, and register side effects. |
| [`sc.algorithms`](commands/pe-api.md#scalgorithms) | [PE and API](commands/pe-api.md) | List the supported hash algorithms: `crc32`, `metasploit_ror13` (alias `ror13`), and `rol7_add`. |
| [`sc.api_plan`](commands/pe-api.md#scapi_plan) | [PE and API](commands/pe-api.md) | Return the raw snapshot that `rop.api_plan` reads. It is internal and prints nothing, so use `rop.api_plan` instead. |
| [`sc.base`](commands/pe-api.md#scbase) | [PE and API](commands/pe-api.md) | Give the base address of one module. |
| [`sc.export`](commands/pe-api.md#scexport) | [PE and API](commands/pe-api.md) | Give the ordinal, RVA, address, and forwarder of one export. |
| [`sc.exportat`](commands/pe-api.md#scexportat) | [PE and API](commands/pe-api.md) | Resolve an export by its ordinal index. |
| [`sc.exportdir`](commands/pe-api.md#scexportdir) | [PE and API](commands/pe-api.md) | Show the addresses and sizes of the export directory tables. |
| [`sc.exports`](commands/pe-api.md#scexports) | [PE and API](commands/pe-api.md) | List the exports of a module, optionally filtered by name. |
| [`sc.exportwalk`](commands/pe-api.md#scexportwalk) | [PE and API](commands/pe-api.md) | Walk the export tables step by step for one name. |
| [`sc.hash`](commands/pe-api.md#schash) | [PE and API](commands/pe-api.md) | Hash one API name with an API-hash algorithm. |
| [`sc.hashes`](commands/pe-api.md#schashes) | [PE and API](commands/pe-api.md) | Hash every export of a module. |
| [`sc.hashresolve`](commands/pe-api.md#schashresolve) | [PE and API](commands/pe-api.md) | Find the export whose name matches a hash. |
| [`sc.iat_find`](commands/pe-api.md#sciat_find) | [PE and API](commands/pe-api.md) | Search the import tables of every loaded module for an API name. |
| [`sc.iat_ptr`](commands/pe-api.md#sciat_ptr) | [PE and API](commands/pe-api.md) | Give the IAT slot address of one import and the API address stored in it. |
| [`sc.iat`](commands/pe-api.md#sciat) | [PE and API](commands/pe-api.md) | List the imports of a module, optionally filtered by DLL or API name. |
| [`sc.module_pages`](commands/pe-api.md#scmodule_pages) | [PE and API](commands/pe-api.md) | Give the size of one module and its number of 4 KiB pages. |
| [`sc.modules`](commands/pe-api.md#scmodules) | [PE and API](commands/pe-api.md) | List the loaded modules. |
| [`sc.call_frame`](commands/shellcode.md#sccall_frame) | [Shellcode](commands/shellcode.md) | Print the pushes and calls for one stdcall API call through the `sc.template` resolver, with the ROR13 hash. |
| [`sc.page_summary`](commands/pe-api.md#scpage_summary) | [PE and API](commands/pe-api.md) | Count the pages of one module by protection value. |
| [`sc.pe`](commands/pe-api.md#scpe) | [PE and API](commands/pe-api.md) | Print the PE header fields of one module. |
| [`sc.peb`](commands/pe-api.md#scpeb) | [PE and API](commands/pe-api.md) | Show the PEB address, `Ldr`, `ProcessParameters`, `BeingDebugged`, and `ImageBase`. |
| [`sc.push_string`](commands/shellcode.md#scpush_string) | [Shellcode](commands/shellcode.md) | Print x86 pushes that build a NUL-terminated string on the stack with no `00` or bad byte. |
| [`sc.resolve`](commands/pe-api.md#scresolve) | [PE and API](commands/pe-api.md) | Give the address of one exported function. |
| [`sc.template`](commands/shellcode.md#sctemplate) | [Shellcode](commands/shellcode.md) | Print a complete `build_sc.py` that assembles custom shellcode with Keystone and reports every bad byte. |
| `sc_call_frame` | [Shellcode](commands/shellcode.md) | Same as [`sc.call_frame`](commands/shellcode.md#sccall_frame). |
| `sc_push_string` | [Shellcode](commands/shellcode.md) | Same as [`sc.push_string`](commands/shellcode.md#scpush_string). |
| `sc_template` | [Shellcode](commands/shellcode.md) | Same as [`sc.template`](commands/shellcode.md#sctemplate). |
| [`seh_ppr`](commands/seh.md#seh_ppr) | [SEH](commands/seh.md) | Find and rank `pop r32 ; pop r32 ; ret` gadgets for an SEH overwrite. |
| [`seh.visualize`](commands/seh.md#sehvisualize) | [SEH](commands/seh.md) | Walk the SEH chain of the current thread and show each `Next` and `Handler` value. |
| [`stackmap`](commands/crash.md#stackmap) | [Crash triage](commands/crash.md) | Classify each stack slot at the crash as pattern bytes, a return address, a saved EBP, a stale pointer, null, or data. |
| `str_bytes` | [Strings](commands/strings.md) | Same as [`str.bytes`](commands/strings.md#strbytes). |
| `str_find` | [Strings](commands/strings.md) | Same as [`str.find`](commands/strings.md#strfind). |
| `str_read` | [Strings](commands/strings.md) | Same as [`str.read`](commands/strings.md#strread). |
| `str_refs` | [Strings](commands/strings.md) | Same as [`str.refs`](commands/strings.md#strrefs). |
| [`str.bytes`](commands/strings.md#strbytes) | [Strings](commands/strings.md) | Turn text into payload bytes and report any bad characters in it. |
| [`str.find`](commands/strings.md#strfind) | [Strings](commands/strings.md) | Find a string in the sections of the loaded modules, as ASCII, UTF-16LE, or both. |
| [`str.read`](commands/strings.md#strread) | [Strings](commands/strings.md) | Read a null-terminated ASCII or UTF-16LE string at an address. |
| [`str.refs`](commands/strings.md#strrefs) | [Strings](commands/strings.md) | Find code that holds the absolute address of a string, like a cross reference in a disassembler. |
| [`triage`](commands/crash.md#triage) | [Crash triage](commands/crash.md) | Print a one-screen crash summary with control of EIP, the SEH chain, the stack, gadgets, and a module score table. |
| [`version`](commands/tools.md#version) | [Leak, math, and session](commands/tools.md) | Print the version, build time, and git commit of the loaded bundle. |
