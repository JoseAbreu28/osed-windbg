# Pattern and bad-character commands

Use these commands to find the offset to the overwritten return address or SEH record, and to find which bytes the target corrupts.

Run each command as `dx @$osed().<command>` in WinDbg. The [command index](../COMMANDS.md#conventions) explains byte lists, addresses, and optional arguments. `dx @$osed().help("<command>", "full")` prints the built-in help. Append `.explain` to any call, as in `dx @$osed().modules().explain`, for a plain-language explanation and a report sentence.

| Command | What it does |
| --- | --- |
| [`pattern.create`](#patterncreate) | Print a cyclic pattern of `length` characters to send instead of your buffer. |
| [`pattern.offset`](#patternoffset) | Print the offset of a 4-byte value inside the pattern. |
| [`badchar_function`](#badchar_function) | Print a Python `BADCHARS` line plus `badchar_array()` and `badchar_block()` helpers to paste into the exploit once. |
| [`badchar_array`](#badchar_array) | Print the bad-character test array, 0x00 to 0xFF minus the excluded bytes, as Python, C, and hex. |
| [`badchar_find`](#badchar_find) | Find the test array or one block of it in memory near an address or ESP and report the first corrupted byte. |
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

Print a Python `BADCHARS` line plus `badchar_array()` and `badchar_block()` helpers to paste into the exploit once.

```text
badchar_function(badchars?, space?)
```

```text
dx @$osed().badchar_function("00")
dx @$osed().badchar_function("00 0A 0D")
dx @$osed().badchar_function("00", 76)
```

Each later run only adds a byte to `BADCHARS`. The helper builds the test array from that list, so you never paste 255 bytes again.

`space` is the number of contiguous bytes that fit after EIP. It becomes the `SPACE` line, and `0`, the default, means no limit. `badchar_block(start)` returns at most `SPACE` bytes, counted from the byte value `start` and skipping every byte in `BADCHARS`. Because a block starts at a byte value and not at a slice index, adding a bad char never shifts the blocks you still have to send. With a non-zero `space`, the output also prints the first block line and the first `badchar_find` command. [Test in blocks](#test-in-blocks-when-the-space-after-eip-is-small) shows a full run.

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

Find the test array or one block of it in memory near an address or ESP and report the first corrupted byte.

```text
badchar_find(address?, exclude?, windowBytes?, minRun?, start?, size?)
```

```text
dx @$osed().badchar_find()
dx @$osed().badchar_find(0x0012F800, "00 0A 0D")
dx @$osed().badchar_find(0x0019ed34+8, "00 0A 0D")
dx @$osed().badchar_find(@esp, "00 0A", 2048, 8, 0x4E, 76)
```

`start` and `size` describe the block that you sent. `start` is its first byte value and defaults to `0x01`. `size` is its length, and `0` or no value means the rest of the array. Without either argument, `badchar_find` expects the whole array, as before.

With no address it searches around ESP. The last lines are the updated list and the command for the next run, with the new byte already added:

```text
[+] Copy-ready exclude list: 00 0A 0D 2B
[+] Exploit line: BADCHARS = b"\x00\x0a\x0d\x2b\x3f"
[+] Next command: dx @$osed().badchar_find(0x0035ED70, "00 0A 0D 2B 3F")
```

If the copy stops early, for example because a `ret N` cut the array, it reports where the array was truncated and names the first byte that never arrived. If nothing arrived after the return address, it says so and suggests moving the array before EIP. `dx` evaluates arithmetic before the call, so an expression such as `0x0019ed34+8` works.

#### Test in blocks when the space after EIP is small

If only 76 bytes fit after EIP, the 254-byte array goes in four blocks. Print the helper with the space once:

```text
dx @$osed().badchar_function("00 0A", 76)
```

```text
BADCHARS = b"\x00\x0a"  # add each new bad char here
SPACE = 76  # contiguous bytes after EIP (0 = no limit)
...
def badchar_block(start=0x01, size=SPACE, bad=BADCHARS):
    return bytes(b for b in range(start, 256) if b not in bad)[:size or None]

payload += badchar_block(0x01)  # first block, right after EIP

First command: dx @$osed().badchar_find(@esp, "00 0A", 2048, 8, 0x01, 76)
```

Send the first block, crash the target, and run the first command. When the whole block arrives, `badchar_find` moves to the next block. The stack after the block is outside the space, so the byte after the block is not reported as a terminator:

```text
[+] Block: 0x01..0x4D, 76 bytes.
[+] Survivors: 76 of 76 tested bytes
[+] Exploit line: BADCHARS = b"\x00\x0a"
[+] Block clean: 0x01..0x4D arrived. Bytes past the block are outside the space, not bad chars.
[+] Next block: 0x4E..0x99
[+] Payload line: payload += badchar_block(0x4E)
[+] Next command: dx @$osed().badchar_find(@esp, "00 0A", 2048, 8, 0x4E, 76)
```

Paste the payload line, send again, and run the next command. If a byte in the block is corrupted, the same block goes again with the byte added to the list:

```text
[+] Block: 0x4E..0x99, 76 bytes.
[!] Bad characters found: 0x5C
[+] Exploit line: BADCHARS = b"\x00\x0a\x5c"
[+] Send the same block again with the grown list.
[+] Payload line: payload += badchar_block(0x4E)
[+] Next command: dx @$osed().badchar_find(@esp, "00 0A 5C", 2048, 8, 0x4E, 76)
```

If fewer bytes than `size` arrive, the copy stopped inside the block. The first byte that never arrived is a real terminator candidate, so it goes into the list, and the same block goes again. When the last block reaches 0xFF with no bad character, the run ends:

```text
[+] Block: 0xE7..0xFF, 25 bytes.
[+] Exploit line: BADCHARS = b"\x00\x0a\x5c"
[+] All bytes 0x01..0xFF tested; this was the last block. Final list: 00 0A 5C
```

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
