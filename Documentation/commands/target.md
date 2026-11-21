# Target and memory commands

Use these commands to pick modules, check memory protections, and search for bytes and pointers.

Run each command as `dx @$osed().<command>` in WinDbg. The [command index](../COMMANDS.md#conventions) explains byte lists, addresses, and optional arguments. `dx @$osed().help("<command>", "full")` prints the built-in help. Append `.explain` to any call, as in `dx @$osed().modules().explain`, for a plain-language explanation and a report sentence.

| Command | What it does |
| --- | --- |
| [`modules`](#modules) | List the loaded modules with their base, size, and the ASLR, SafeSEH, and DEP state of each. |
| [`memory`](#memory) | Show the memory region that holds an address and its protection flags. |
| [`can_execute`](#can_execute) | Return `true`, `false`, or `null` for whether the memory at an address is executable. |
| [`find_ptr`](#find_ptr) | Find addresses of `jmp <reg>`, `call <reg>`, or `push <reg> ; ret` and drop the addresses that contain bad characters. |
| [`find_bytes`](#find_bytes) | Search the PE sections of one loaded module for a byte sequence. |
| [`find_stack_bytes`](#find_stack_bytes) | Search the current thread stack, from ESP upward, for a byte sequence. |
| [`find_mem_bytes`](#find_mem_bytes) | Search an address range that you give for a byte sequence. |
| [`code_caves`](#code_caves) | Find runs of null, `int3`, or NOP padding inside PE sections that can hold a payload. |

### modules

List the loaded modules with their base, size, and the ASLR, SafeSEH, and DEP state of each.

```text
modules(filter?)
```

```text
dx @$osed().modules()
dx @$osed().modules("kernel32")
```

Pick modules without ASLR for return addresses, and modules without SafeSEH for SEH gadgets.

### memory

Show the memory region that holds an address and its protection flags.

```text
memory(address)
```

```text
dx @$osed().memory(0x41414141)
dx @$osed().memory("0012F800")
```

The flags `readable`, `writable`, `executable`, `guarded`, `noAccess`, and `committed` are `true`, `false`, or `null`. `null` means that WinDbg could not tell. The raw protection values are under `raw`.

### can_execute

Return `true`, `false`, or `null` for whether the memory at an address is executable.

```text
can_execute(address)
```

```text
dx @$osed().can_execute(0x0012F800)
```

It is the `executable` field of `memory(address)`. `null` means unknown, not `false`.

### find_ptr

Find addresses of `jmp <reg>`, `call <reg>`, or `push <reg> ; ret` and drop the addresses that contain bad characters.

```text
find_ptr(instruction, module?, badchars?, maxResults?, executableOnly?)
```

```text
dx @$osed().find_ptr("jmp esp")
dx @$osed().find_ptr("call eax", "essfunc", "00 0A 0D")
dx @$osed().find_ptr("jmp esp", "essfunc", "00 0A 0D")
dx @$osed().find_ptr("pushret esp", "essfunc", "00 0A 0D")
```

The instruction text is a mnemonic and a register: `jmp`, `call`, or `pushret`. Each hit is printed as `module+offset` with its address.

### find_bytes

Search the PE sections of one loaded module for a byte sequence.

```text
find_bytes(module, bytes, maxResults?, badchars?, executableOnly?, mode?)
```

```text
dx @$osed().find_bytes("vulnserver", "FF E4")
dx @$osed().find_bytes("essfunc", "58 C3", 25)
dx @$osed().find_bytes("libbkup", "FF E4", 20, "00 09 0A 0B 0C 0D 20")
```

By default it searches executable sections only. It does not search the stack or the heap, and it says so when it finds nothing.

### find_stack_bytes

Search the current thread stack, from ESP upward, for a byte sequence.

```text
find_stack_bytes(bytes, maxResults?, stackBytes?)
```

```text
dx @$osed().find_stack_bytes("43 43 43 43")
dx @$osed().find_stack_bytes("43 43 43 43", 20, 4096)
```

Use it to confirm where your buffer landed. It does not search the heap.

### find_mem_bytes

Search an address range that you give for a byte sequence.

```text
find_mem_bytes(address, length, bytes, maxResults?)
```

```text
dx @$osed().find_mem_bytes(0x14800000, 0x16000, "43 43 43 43")
dx @$osed().find_mem_bytes("14800000", 4096, "FF E4", 20)
```

Use it for the heap, a mapped region, or any window that you already know.

### code_caves

Find runs of null, `int3`, or NOP padding inside PE sections that can hold a payload.

```text
code_caves(module?, minSize?, maxResults?, badChars?, capability?)
```

```text
dx @$osed().code_caves()
dx @$osed().code_caves("essfunc")
dx @$osed().code_caves("essfunc", 100)
dx @$osed().code_caves("essfunc", 50, 25, "00 0A 0D")
dx @$osed().code_caves("", 50, 25, "", "EXEC")
```

Each cave has its size, protection, ASLR state, and a bad-character check. `capability` filters by use, for example `"EXEC"`. The detection follows nop-tech/codecaver.
