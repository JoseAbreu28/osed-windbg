# Format-string commands

Use these commands at a breakpoint on a `printf`-family call that takes your input as the format string. They decode x86 cdecl arguments only.

Run each command as `dx @$osed().<command>` in WinDbg. The [command index](../COMMANDS.md#conventions) explains byte lists, addresses, and optional arguments. `dx @$osed().help("<command>", "full")` prints the built-in help.

| Command | What it does |
| --- | --- |
| [`fmt.inspect`](#fmtinspect) | Read the format-string argument of a paused `printf`, `fprintf`, `sprintf`, or `snprintf` call and list its conversions. |
| [`fmt.offset`](#fmtoffset) | Find which `%N$` parameter reaches your buffer and which stack slots hold pointers worth leaking. |
| [`fmt.build`](#fmtbuild) | Build a `%n` write-what-where payload that writes `value` to `addr`. |

### fmt.inspect

Read the format-string argument of a paused `printf`, `fprintf`, `sprintf`, or `snprintf` call and list its conversions.

```text
fmt.inspect(family?, formatArgOffset?, max?)
```

```text
dx @$osed().fmt.inspect("printf")
dx @$osed().fmt.inspect("snprintf")
dx @$osed().fmt.inspect("printf", 4, 512)
```

It flags `%n`. A flagged conversion does not prove that you control the string.

Also callable as `fmt_inspect`.

### fmt.offset

Find which `%N$` parameter reaches your buffer and which stack slots hold pointers worth leaking.

```text
fmt.offset(marker?, count?, firstArg?)
```

```text
dx @$osed().fmt.offset(0x41414141, 40)
dx @$osed().fmt.offset()
dx @$osed().fmt.offset(0x41414141, 40, 8)
```

Send a buffer that starts with a marker such as `AAAA`, break on the call, and run it. `Controlled parameter index: %6$` means that you pass 6 to `fmt.build`. Slots labeled `ptr->kernel32` or `ptr->stack` are candidates for a `%N$s` or `%N$x` leak. `firstArg` (default 8) is the byte offset from ESP to the first variable argument.

Also callable as `fmt_offset`.

### fmt.build

Build a `%n` write-what-where payload that writes `value` to `addr`.

```text
fmt.build(addr, value, argIndex, width?, exclude?, prefix?)
```

```text
dx @$osed().fmt.build(0x00402118, 0x625011AF, 6)
dx @$osed().fmt.build(0x00402118, 0x625011AF, 6, "word", "00 0A 0D")
```

`width` is `"byte"` (`%hhn`), `"word"` (`%hn`, default), or `"dword"` (`%n`). The output has the chunk table, the address block, the format string, a Python payload, and the payload hex. The padding already counts the bytes of the address block. If an address contains a bad character, it warns that the address cannot be delivered as is. From `dx` you can write one value per call.

Also callable as `fmt_build`.
