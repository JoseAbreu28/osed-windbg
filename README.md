# osed-windbg

Fork of [rogdooley/osed-windbg](https://github.com/rogdooley/osed-windbg) by Roger Dooley.

osed-windbg is a WinDbg JavaScript extension for x86 exploit development. It does the offset, bad-character, gadget, and PE lookups for you. You run every command from the WinDbg prompt as `dx @$osed().<command>`.

![triage example](Images/triage.gif)

## What you need

You need WinDbg and one `.js` file. You do not need Python, mona, an internet connection, or a build step.

| Debugger | File to load |
| --- | --- |
| Classic WinDbg 10.0.19041 (x86), the version in the OSED VM | [`dist/osed-legacy.js`](dist/osed-legacy.js) **[fork: new]** |
| WinDbg Preview (WinDbgX) | [`dist/osed.js`](dist/osed.js) |

The JavaScript engine in classic WinDbg has no `BigInt`, so `osed.js` fails to load there. `osed-legacy.js` has the same commands with every `BigInt` operation rewritten. It throws on values above 2^53, which is far above any 32-bit address. For x64 targets, use `osed.js` in WinDbg Preview.

## Load the script

1. Copy the file to the machine that runs WinDbg, for example to `C:\tools\osed-legacy.js`.
2. Attach WinDbg to the target.
3. Load the script and list the commands:

```text
.scriptload C:\tools\osed-legacy.js
dx @$osed().help()
```

The load prints a line such as `[+] osed loaded: v1.0.4 (<commit>, clean, built <time>)`. Run `.scriptload` again in each new WinDbg session. `dx @$osed().help("<command>")` prints the help for one command, and `dx @$osed().help("all")` lists every command.

## Three rules for arguments

- Pass byte lists as one string of hex bytes, for example `"00 0A 0D"`.
- Pass addresses as numbers such as `0x0012F800` or arithmetic such as `0x0019ed34+8`. Cast pseudo-registers first, for example `(unsigned int)@$t0`, because the script rejects the 64-bit object that `@$t0` becomes.
- Arguments are positional. `dx` does not accept JavaScript object literals. Most commands print their output and return `true` or `false`. `dx @$osed().last_result()` shows the full result.

The [command index](Documentation/COMMANDS.md#conventions) has the full conventions.

## Exam workflow

The steps follow the order of a typical x86 exploit. Skip the steps that your target does not need. The module names in the examples (`essfunc`, `libspp.dll`, `app.exe`) stand for your target's modules.

### 1. Triage the crash

```text
dx @$osed().triage()
```

You get the control state of EIP, the SEH chain, the stack around ESP, a gadget summary, and a module table that lists the modules without ASLR first.

### 2. Find the offset

Create a pattern and send it in place of the buffer:

```text
dx @$osed().pattern_create(3000)
```

After the crash, pass the value in EIP, or run `findmsp` to check every register and the stack at once:

```text
dx @$osed().pattern_offset(0x39654138)
dx @$osed().findmsp()
```

You get `Offset: 146` for that EIP value. `findmsp()` lists the offset for each register, stack slot, and SEH field that holds pattern bytes.

### 3. Find the bad characters

Print the helper once and paste it into the exploit:

```text
dx @$osed().badchar_function("00")
```

Send `badchar_array()` after the return address, crash the target, then run:

```text
dx @$osed().badchar_find()
```

The output ends with the updated `BADCHARS` line and the exact command for the next run. Add the byte, send again, and repeat until it reports no corrupted byte. If you know where the array starts, run `dx @$osed().badchars(0x0012F800, "00 0A 0D")` instead.

### 4. Pick a module

```text
dx @$osed().modules()
```

You get each module's base and its ASLR, SafeSEH, and DEP state. Take addresses from a module without ASLR whose addresses have no bad character.

### 5. Return to the stack (JMP ESP)

```text
dx @$osed().find_ptr("jmp esp", "essfunc", "00 0A 0D")
dx @$osed().landing()
```

`find_ptr` lists the `jmp esp` addresses that contain no bad character. After the jump, `landing()` shows the bytes at ESP and whether that memory is executable.

### 6. Overwrite SEH

```text
dx @$osed().seh.visualize()
dx @$osed().pattern_offset(0x43396F43)
dx @$osed().seh_ppr("libspp.dll", "00 0A 0D")
```

`seh.visualize()` shows each `Next` and `Handler` value in the chain. Pass the `Handler` value to `pattern_offset`. `Offset: 2007` means that nSEH starts at 2003. `seh_ppr` ranks the `pop ; pop ; ret` addresses that contain no bad character. Use a module without SafeSEH.

### 7. Hunt for the egg

```text
dx @$osed().egghunter("W00T", "ntaccess", true, "00 0A 0D", "win10")
dx @$osed().egghunter("W00T", "ntaccess", false, "00 0A 0D", "win10-1909")
dx @$osed().egghunter("W00T", "seh")
```

You get the stub as hex and as Python bytes, with a warning for each stub byte that is a bad character. Put `W00TW00T` in front of the payload. Use `true` as the third argument for a 32-bit process on 64-bit Windows. The fifth argument names the Windows build, which sets the syscall number. Without it you get the Windows 10 22H2 number and a warning. The [shellcode reference](Documentation/commands/shellcode.md#egghunter) lists the builds and shows how to pass the number yourself.

### 8. Bypass DEP with ROP

Find the API, load the gadgets of a module without ASLR, and print a chain skeleton:

```text
dx @$osed().sc.iat_find("VirtualProtect")
dx @$osed().rop.scan_live("libspp.dll", "00 0A 0D")
dx @$osed().rop_template("VirtualProtect", "libspp.dll")
```

Build the values that contain bad characters, then the chain:

```text
dx @$osed().rop.construct("ebx", 0x201, "00 0A 0D")
dx @$osed().rop.setup("edi=0x10001000 ebx=0x40", "00 0A 0D")
dx @$osed().rop.chain_vp(0x7C801AD0, 0x62501010, 0x625011AF)
dx @$osed().math(-0x201, 32)
```

Check the chain, then step through it in the debugger:

```text
dx @$osed().rop.verify("10022D64 1005D060 DEADBEEF", "00 0A 0D")
dx @$osed().rop.prove("guided")
```

`sc.iat_find` gives the IAT slot that holds the API address. `rop.construct` gives a gadget recipe and Python `pack()` lines for a value such as `0x201`. `math(-0x201, 32)` gives the negated value `0xFFFFFDFF` to pop before a `neg` gadget. `rop.verify` flags bad characters and stack problems in the chain. After `rop.prove("guided")`, run `g` yourself and then `dx @$osed().rop.prove()` at each stop. The [ROP reference](Documentation/commands/rop.md) covers the other chain builders.

### 9. Defeat ASLR with a leak

```text
dx @$osed().leak.analyze("Error processing request at 76A31240")
dx @$osed().leak.base(0x76A31240, 0x1240)
```

`leak.analyze` takes text that the application printed and says which module each pointer in it falls in. `leak.base` subtracts the RVA from the leaked pointer and checks the result against the loaded modules. Get the RVA from a test run, as the leaked pointer minus `dx @$osed().sc.base("<module>")`.

### 10. Exploit a format string

Break on the `printf` call that takes your input, then run:

```text
dx @$osed().fmt.inspect("printf")
dx @$osed().fmt.offset(0x41414141, 40)
dx @$osed().fmt.build(0x00402118, 0x625011AF, 6)
```

`fmt.offset` gives the `%N$` index that reaches your `AAAA` marker and the stack slots that hold pointers worth leaking. `fmt.build` gives the `%hn` format string and a Python payload that writes the value to the address.

### 11. Prepare the shellcode

```text
dx @$osed().encode("FC E8 82 00 00 00 60", "00 0A 0D")
dx @$osed().nop(16)
dx @$osed().sc.hash("WinExec", "ROR13")
dx @$osed().str.bytes("W00T", "ascii", true, "00 0A 0D")
```

`encode` gives a XOR decoder stub and the encoded bytes as one Python string without the excluded bytes. `sc.hash` gives the API hash for hand-written shellcode. `str.bytes` turns a string into payload bytes and lists the bad characters in it.

### 12. Reverse the target (IDA-style helpers)

```text
dx @$osed().str.find("VirtualProtect")
dx @$osed().str.refs(0x00403080, "app.exe", "ascii", 25)
dx @$osed().str.read(0x0019F920)
```

`str.find` lists the addresses of a string in the loaded modules. `str.refs` lists the code that holds a string's address, like a cross reference. `str.read` reads a string at an address.

### 13. Read imports, exports, and PE headers

```text
dx @$osed().sc.iat("app.exe", "Virtual")
dx @$osed().sc.iat_ptr("app.exe", "VirtualProtect")
dx @$osed().sc.export("kernel32", "WinExec")
dx @$osed().sc.pe("kernel32")
```

You get the imports of a module, the IAT slot of one import with the address stored in it, the RVA and address of one export, and the PE header fields.

## Command reference

Each file documents one category with a signature, examples, and the meaning of the output for every command. The [command index](Documentation/COMMANDS.md) lists all commands from A to Z.

| Category | Commands |
| --- | --- |
| [Pattern and bad characters](Documentation/commands/payload.md) | `pattern.create`, `pattern.offset`, `badchar_function`, `badchar_find`, `badchars`, and 1 more |
| [Crash triage](Documentation/commands/crash.md) | `triage`, `findmsp`, `stackmap`, `landing` |
| [Target and memory](Documentation/commands/target.md) | `modules`, `memory`, `find_ptr`, `find_bytes`, `code_caves`, and 3 more |
| [SEH](Documentation/commands/seh.md) | `seh.visualize`, `seh_ppr` |
| [ROP and DEP](Documentation/commands/rop.md) | `rop.scan_live`, `rop.construct`, `rop.chain_vp`, `rop.verify`, `rop.prove`, and 31 more |
| [Format strings](Documentation/commands/format.md) | `fmt.inspect`, `fmt.offset`, `fmt.build` |
| [Shellcode](Documentation/commands/shellcode.md) | `egghunter`, `encode`, `nop` |
| [Strings](Documentation/commands/strings.md) | `str.find`, `str.refs`, `str.read`, `str.bytes` |
| [PE and API](Documentation/commands/pe-api.md) | `sc.iat_find`, `sc.iat_ptr`, `sc.export`, `sc.hash`, `sc.peb`, and 15 more |
| [Leak, math, and session](Documentation/commands/tools.md) | `leak.analyze`, `leak.base`, `math`, `help`, `last_result`, and 9 more |

## Known limitations

- The `egghunter` WOW64 stub supports Windows 10 and 11 only.
- `exploit(...)` is listed by `help("all")` but is not callable. `exploit.state()` and `exploit.clear()` work.
- Pseudo-registers such as `@$t0` need a cast, as in `(unsigned int)@$t0`.

## Changes in this fork

- `dist/osed-legacy.js`, a bundle without `BigInt` for classic WinDbg 10.0.19041.
- `seh.visualize()`, `triage()`, `findmsp()`, and `find_stack_bytes()` read the TEB from `$teb`, so they work without symbols.
- `badchar_function` is a new command.
- `badchars` and `badchar_find` end with the `Exploit line` and the `Next command` for the next run.

## Build from source

You need this only to change the code. It needs Node.js 20 or later.

```text
npm install
npm run build
npm test
npm run test:legacy
```

`npm run build` writes `dist/osed.js` and `dist/osed-legacy.js`. `npm run test:legacy` runs the tests against the sources that the legacy bundle uses.

## Design notes

Upstream design documents are in [Documentation](Documentation/README.md): [analysis architecture](Documentation/ANALYSIS_ARCHITECTURE.md), [semantic ROP design](Documentation/SEMANTIC_ROP_DESIGN.md), [ROP workflow](Documentation/ROP_WORKFLOW.md), [chain commands](Documentation/CHAIN_COMMANDS.md), [gadget discovery](Documentation/GADGET_DISCOVERY.md), [ROP API reference](Documentation/ROP_API_REFERENCE.md), and [development](Documentation/DEVELOPMENT.md). The history is in [CHANGELOG.md](CHANGELOG.md). The license is in [LICENSE](LICENSE).
