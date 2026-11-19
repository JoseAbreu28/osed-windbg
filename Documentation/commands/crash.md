# Crash triage commands

Run these commands right after the crash, while the debugger is stopped on the exception.

Run each command as `dx @$osed().<command>` in WinDbg. The [command index](../COMMANDS.md#conventions) explains byte lists, addresses, and optional arguments. `dx @$osed().help("<command>", "full")` prints the built-in help.

| Command | What it does |
| --- | --- |
| [`triage`](#triage) | Print a one-screen crash summary with control of EIP, the SEH chain, the stack, gadgets, and a module score table. |
| [`findmsp`](#findmsp) | Find cyclic-pattern offsets in every register, in the stack, in the SEH record, and in the memory that registers point to. |
| [`stackmap`](#stackmap) | Classify each stack slot at the crash as pattern bytes, a return address, a saved EBP, a stale pointer, null, or data. |
| [`landing`](#landing) | Show what sits at ESP, or at an address, and whether the memory there is executable. |

### triage

Print a one-screen crash summary with control of EIP, the SEH chain, the stack, gadgets, and a module score table.

```text
triage(patternLength?, badchars?, module?, stackBytes?)
```

```text
dx @$osed().triage()
dx @$osed().triage(10000, "00 0A 0D", "vulnserver")
```

Sections are `CONTROL`, `SEH`, `STACK`, `GADGETS`, `CONTEXT`, `MODULE SCORE`, `BYTE OBSERVATIONS`, and `EXPLOIT STRATEGY`. `MODULE SCORE` lists every module without ASLR first, because those are the ones you can take addresses from. Defaults are a 10000-byte pattern, bad characters `00 0A 0D`, and 1024 stack bytes. `triage()` also fills the cached state that `rop.synthesize` uses.

### findmsp

Find cyclic-pattern offsets in every register, in the stack, in the SEH record, and in the memory that registers point to.

```text
findmsp()
```

```text
dx @$osed().findmsp()
```

Sections are `INSTRUCTION POINTER` and `PATTERN MATCHES`. Each hit has an offset and a confidence. `EXACT` means a unique offset and `CONSERVATIVE` means the pattern repeats.

Limitation: in this build, `findmsp` accepts no arguments from `dx`. A call such as `findmsp(20000, 4096)` fails with `value: Unknown option key.` It always uses a 10000-byte pattern, 2048 stack bytes, and 32 probe bytes. For a longer pattern, use `pattern_offset` on the register value.

### stackmap

Classify each stack slot at the crash as pattern bytes, a return address, a saved EBP, a stale pointer, null, or data.

```text
stackmap(depth?, patternLength?)
```

```text
dx @$osed().stackmap()
dx @$osed().stackmap(128)
dx @$osed().stackmap(64, 20000)
```

Slot labels are `PATTERN`, `RET`, `SAVED_EBP`, `STALE_PTR`, `NULL`, and `DATA`. The summary gives the number of slots you control, the room for a ROP chain, and the slot where the chain starts.

### landing

Show what sits at ESP, or at an address, and whether the memory there is executable.

```text
landing(address?)
```

```text
dx @$osed().landing()
dx @$osed().landing(0x0012F800)
```

You get sampled bytes plus observations such as NOP runs, marker bytes, cyclic-pattern matches, and the memory protection. These are observations. They do not prove that the bytes are your shellcode.
