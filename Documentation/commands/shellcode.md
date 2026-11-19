# Shellcode commands

Use these commands to build the egghunter, encode a payload around bad characters, and pad the landing zone.

Run each command as `dx @$osed().<command>` in WinDbg. The [command index](../COMMANDS.md#conventions) explains byte lists, addresses, and optional arguments. `dx @$osed().help("<command>", "full")` prints the built-in help.

| Command | What it does |
| --- | --- |
| [`egghunter`](#egghunter) | Print an egghunter stub for a 4-byte tag, as hex and as Python bytes, and flag stub bytes that are bad characters. |
| [`encode`](#encode) | XOR-encode a payload so that it contains none of the excluded bytes, and print the decoder stub with it. |
| [`nop`](#nop) | Print a NOP sled of `length` bytes. |

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
