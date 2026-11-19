# Pattern and bad-character commands

Use these commands to find the offset to the overwritten return address or SEH record, and to find which bytes the target corrupts.

Run each command as `dx @$osed().<command>` in WinDbg. The [command index](../COMMANDS.md#conventions) explains byte lists, addresses, and optional arguments. `dx @$osed().help("<command>", "full")` prints the built-in help.

| Command | What it does |
| --- | --- |
| [`pattern.create`](#patterncreate) | Print a cyclic pattern of `length` characters to send instead of your buffer. |
| [`pattern.offset`](#patternoffset) | Print the offset of a 4-byte value inside the pattern. |
| [`badchar_function`](#badchar_function) | Print a Python `BADCHARS` line and a `badchar_array()` helper to paste into the exploit once. |
| [`badchar_array`](#badchar_array) | Print the bad-character test array, 0x00 to 0xFF minus the excluded bytes, as Python, C, and hex. |
| [`badchar_find`](#badchar_find) | Find the test array in memory near an address or ESP and report the first corrupted byte. |
| [`badchars`](#badchars) | Compare the bytes at a known address with the expected test array and list the bytes that differ. |

### pattern.create

Print a cyclic pattern of `length` characters to send instead of your buffer.

```text
pattern.create(length, type?)
```

```text
dx @$osed().pattern.create(300, "msf")
dx @$osed().pattern_create(300, "msf")
dx @$osed().pattern_create(800, "cyclic")
dx @$osed().pattern_create(3000)
```

`type` is `msf` (default, the Metasploit `Aa0Aa1...` pattern) or `cyclic`. Copy the pattern line into the exploit.

Also callable as `pattern_create`.

### pattern.offset

Print the offset of a 4-byte value inside the pattern.

```text
pattern.offset(value, type?)
```

```text
dx @$osed().pattern.offset(0x39654138, "msf")
dx @$osed().pattern_offset(0x39654138, "msf")
dx @$osed().pattern_offset("41326341", "cyclic")
```

Pass the value from the register, for example EIP after the crash. `Offset: 146` means that the 4 bytes start 146 bytes into your buffer. Use the same `type` that you used for `pattern.create`.

Also callable as `pattern_offset`.

### badchar_function

**[fork: new]**

Print a Python `BADCHARS` line and a `badchar_array()` helper to paste into the exploit once.

```text
badchar_function(badchars?)
```

```text
dx @$osed().badchar_function("00")
dx @$osed().badchar_function("00 0A 0D")
```

Each later run only adds a byte to `BADCHARS`. The helper builds the test array from that list, so you never paste 255 bytes again.

### badchar_array

Print the bad-character test array, 0x00 to 0xFF minus the excluded bytes, as Python, C, and hex.

```text
badchar_array(exclude?)
```

```text
dx @$osed().badchar_array()
dx @$osed().badchar_array("00 0A 0D")
```

Send the array in place of the shellcode, crash the target, then run `badchar_find`.

### badchar_find

**[fork: changed]**

Find the test array in memory near an address or ESP and report the first corrupted byte.

```text
badchar_find(address?, exclude?, windowBytes?, minRun?)
```

```text
dx @$osed().badchar_find()
dx @$osed().badchar_find(0x0012F800, "00 0A 0D")
dx @$osed().badchar_find(0x0019ed34+8, "00 0A 0D")
```

With no address it searches around ESP. The last lines are the updated list and the command for the next run, with the new byte already added:

```text
[+] Copy-ready exclude list: 00 0A 0D 2B
[+] Exploit line: BADCHARS = b"\x00\x0a\x0d\x2b\x3f"
[+] Next command: dx @$osed().badchar_find(0x0035ED70, "00 0A 0D 2B 3F")
```

If the copy stops early, for example because a `ret N` cut the array, it reports where the array was truncated and names the first byte that never arrived. If nothing arrived after the return address, it says so and suggests moving the array before EIP. `dx` evaluates arithmetic before the call, so an expression such as `0x0019ed34+8` works.

### badchars

**[fork: changed]**

Compare the bytes at a known address with the expected test array and list the bytes that differ.

```text
badchars(address, exclude?)
```

```text
dx @$osed().badchars(0x00B8F900)
dx @$osed().badchars("00B8F900", "00 0A 0D")
```

Use it when you already know where the array starts. Like `badchar_find`, it ends with `Exploit line: BADCHARS = b"..."` and `Next command: dx @$osed().badchars(<addr>, "<list>")`.
