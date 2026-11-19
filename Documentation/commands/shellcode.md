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
dx @$osed().egghunter("W00T")
dx @$osed().egghunter("W00T", "ntdisplay")
dx @$osed().egghunter("W00T", "ntdisplay", false, "00 0A 0D")
dx @$osed().egghunter("B33F", "seh")
dx @$osed().egghunter("W00T", "ntaccess", true)
dx @$osed().egghunter("W00T", "ntaccess", false, "00 0A 0D")
```

Modes are `ntaccess` (default, 34 bytes, `NtAccessCheckAndAuditAlarm`), `ntdisplay` (`NtDisplayString`), and `seh` (70 bytes, no syscall, contains null bytes). Set `wow64` to `true` for a 32-bit process on 64-bit Windows. Put the tag twice in front of the payload, for example `b"W00TW00T"`.

Limitation: from `dx`, the `os` and `syscall` arguments are ignored in this build, so the `ntaccess` stub always uses the Windows 10 syscall number `0x1C9`. For another Windows version, read the number with `u ntdll!NtAccessCheckAndAuditAlarm L1` and edit the `mov eax` bytes `B8 C9 01 00 00` in the stub.

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
