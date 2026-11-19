# String commands

Use these commands the way you use the Strings window and cross references in a disassembler, but on the live process.

Run each command as `dx @$osed().<command>` in WinDbg. The [command index](../COMMANDS.md#conventions) explains byte lists, addresses, and optional arguments. `dx @$osed().help("<command>", "full")` prints the built-in help.

| Command | What it does |
| --- | --- |
| [`str.find`](#strfind) | Find a string in the sections of the loaded modules, as ASCII, UTF-16LE, or both. |
| [`str.refs`](#strrefs) | Find code that holds the absolute address of a string, like a cross reference in a disassembler. |
| [`str.read`](#strread) | Read a null-terminated ASCII or UTF-16LE string at an address. |
| [`str.bytes`](#strbytes) | Turn text into payload bytes and report any bad characters in it. |

### str.find

Find a string in the sections of the loaded modules, as ASCII, UTF-16LE, or both.

```text
str.find(text, module?, encoding?, maxResults?)
```

```text
dx @$osed().str.find("VirtualProtect")
dx @$osed().str.find("cmd.exe", "target", "ascii", 25)
```

`encoding` is `ascii`, `utf16le`, or `both`. Each hit gives the address and the module section.

Also callable as `str_find`.

### str.refs

Find code that holds the absolute address of a string, like a cross reference in a disassembler.

```text
str.refs(target, module?, encoding?, maxResults?)
```

```text
dx @$osed().str.refs("VirtualProtect")
dx @$osed().str.refs(0x00403080, "target", "ascii", 25)
```

`target` is a string or an address. It scans executable sections for the 4-byte address and shows nearby bytes. It does not disassemble, and it does not find x64 RIP-relative references.

Also callable as `str_refs`.

### str.read

Read a null-terminated ASCII or UTF-16LE string at an address.

```text
str.read(address, max?, encoding?)
```

```text
dx @$osed().str.read(0x0019F920)
dx @$osed().str.read(0x0019F920, 128, "utf16le")
```

Also callable as `str_read`.

### str.bytes

Turn text into payload bytes and report any bad characters in it.

```text
str.bytes(text, encoding?, terminator?, exclude?)
```

```text
dx @$osed().str.bytes("cmd.exe")
dx @$osed().str.bytes("W00T", "ascii", true, "00 0A 0D")
```

Set `terminator` to `true` to add the null byte. The output gives hex, Python bytes, and each bad byte with its position, for example `0x00@4`.

Also callable as `str_bytes`.
