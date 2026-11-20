# Leak, math, and session commands

Use these commands for ASLR leaks, number conversion, help, and the state that the toolkit keeps between commands.

Run each command as `dx @$osed().<command>` in WinDbg. The [command index](../COMMANDS.md#conventions) explains byte lists, addresses, and optional arguments. `dx @$osed().help("<command>", "full")` prints the built-in help. Append `.explain` to any call, as in `dx @$osed().modules().explain`, for a plain-language explanation and a report sentence.

| Command | What it does |
| --- | --- |
| [`leak.analyze`](#leakanalyze) | Pull hex pointer values out of text that the application printed and classify each one. |
| [`leak.classify`](#leakclassify) | Say which module or memory region a pointer value falls in, without reading memory at it. |
| [`leak.base`](#leakbase) | Compute a module base from a leaked pointer and its RVA, and check it against the loaded modules. |
| [`leak.scan`](#leakscan) | Scan an address range, up to `0x10000` bytes, for pointer-sized values and classify each one. |
| [`math`](#math) | Print a number as hex, unsigned, signed, little-endian bytes, and two's complement. |
| [`help`](#help) | List the commands, or print the help for one command. |
| [`explain`](#explain) | Explain a command in plain words, with a sentence for the exam report. |
| [`version`](#version) | Print the version, build time, and git commit of the loaded bundle. |
| [`reload`](#reload) | Clear the command registry and register every command again, without reloading the script file. |
| [`last_result`](#last_result) | Return the full structured result of the last command. |
| [`last_summary`](#last_summary) | Return the command name and the counts of findings, warnings, and errors from the last command. |
| [`clear_last_result`](#clear_last_result) | Clear the stored last result. |
| [`exploit.state`](#exploitstate) | Show the exploit state that `triage()` cached, such as the control mechanism, the stack pointer, and the bad characters, which `rop.synthesize` reads. |
| [`exploit.clear`](#exploitclear) | Clear the cached exploit state. |
| [`exploit.workflow`](#exploitworkflow) | Print a fixed list of `dx` commands for one workflow: `offset`, `badchars`, or `egghunter`. |

## ASLR leaks

These commands classify pointers. They do not prove that the application discloses them to you.

### leak.analyze

Pull hex pointer values out of text that the application printed and classify each one.

```text
leak.analyze(text)
```

```text
dx @$osed().leak.analyze("Error processing request at 76A31240")
```

Paste the application output as the argument. Each candidate gets the module or region it falls in.

Also callable as `leak_analyze`.

### leak.classify

Say which module or memory region a pointer value falls in, without reading memory at it.

```text
leak.classify(value)
```

```text
dx @$osed().leak.classify(0x76A31240)
dx @$osed().leak_classify(0x76A31240)
```

Also callable as `leak_classify`.

### leak.base

Compute a module base from a leaked pointer and its RVA, and check it against the loaded modules.

```text
leak.base(pointer, rva)
```

```text
dx @$osed().leak.base(0x76A31240, 0x1240)
```

Get the RVA from `sc.export` or from the leaked pointer minus the module base in a test run. A base that matches no loaded module is reported as not validated.

Also callable as `leak_base`.

### leak.scan

Scan an address range, up to `0x10000` bytes, for pointer-sized values and classify each one.

```text
leak.scan(address, length?)
```

```text
dx @$osed().leak.scan(0x0014DD28, 0x400)
```

Also callable as `leak_scan`.

## Numbers

### math

Print a number as hex, unsigned, signed, little-endian bytes, and two's complement.

```text
math(value, bits?)
```

```text
dx @$osed().math(0xFFFFFFD6)
dx @$osed().math(-42, 32)
dx @$osed().math(0x625011D3, 32)
```

`bits` is 8, 16, 32 (default), or 64. Use it for negated values in ROP chains: `math(-42, 32)` gives `0xFFFFFFD6` and `D6 FF FF FF`.

## Help and build

### help

List the commands, or print the help for one command.

```text
help(command?, mode?)
```

```text
dx @$osed().help()
dx @$osed().help("all")
dx @$osed().help("sc.iat", "full")
dx @$osed().help("?egg")
dx @$osed().help("rop")
```

`help("all")` lists every command by category. `help("<name>", "full")` adds notes and limits. `help("?text")` searches names and descriptions. A category or namespace name, such as `"rop"` or `"sc"`, lists its commands. Most commands also print their help when you pass `"help"` as the only argument.

### explain

Explain a command in plain words, with a sentence for the exam report.

```text
explain(command?, args...)
<any call>.explain
```

```text
dx @$osed().explain()
dx @$osed().explain("sc.resolve")
dx @$osed().explain("sc.resolve", "kernel32", "WinExec")
dx @$osed().sc.resolve("kernel32", "WinExec").explain
dx @$osed().sc.resolve("explain", "kernel32", "WinExec")
```

`explain()` lists every command. The other forms print the sections `What it does`, `How it works`, `When to use`, `Arguments`, `Results`, `Example`, `Reading output`, and `Report`. A placeholder such as `<module>` takes the argument of that name, and a result such as `<address>` takes the value the command found. `.explain` on a call runs the command first. `explain("name", args...)` and `"explain"` as the first argument do not run it, except for read-only lookups such as `sc.resolve`, `sc.hash`, and `pattern_offset`, which run silently and leave `last_result()` unchanged. Write `.explain` without parentheses. [Explain any command](../../README.md#explain-any-command) shows the output.

### version

Print the version, build time, and git commit of the loaded bundle.

```text
version()
```

```text
dx @$osed().version()
dx @$osed().help("version")
```

If it shows `dev` or `unknown`, the file you loaded is not a built bundle from `dist/`.

### reload

Clear the command registry and register every command again, without reloading the script file.

```text
reload()
```

```text
dx @$osed().reload()
```

## Results and cached state

### last_result

Return the full structured result of the last command.

```text
last_result()
```

```text
dx @$osed().last_result()
```

Most commands return only a `success` field and `explain` to `dx`. Use `last_result()` to browse the findings, warnings, and errors.

### last_summary

Return the command name and the counts of findings, warnings, and errors from the last command.

```text
last_summary()
```

```text
dx @$osed().last_summary()
```

### clear_last_result

Clear the stored last result.

```text
clear_last_result()
```

```text
dx @$osed().clear_last_result()
```

### exploit.state

Show the exploit state that `triage()` cached, such as the control mechanism, the stack pointer, and the bad characters, which `rop.synthesize` reads.

```text
exploit.state(overrides?)
```

```text
dx @$osed().exploit.state()
```

### exploit.clear

Clear the cached exploit state.

```text
exploit.clear()
```

```text
dx @$osed().exploit.clear()
```

### exploit.workflow

Print a fixed list of `dx` commands for one workflow: `offset`, `badchars`, or `egghunter`.

```text
exploit.workflow(mode, tag?, offset?, address?)
```

```text
dx @$osed().exploit.workflow("offset")
dx @$osed().exploit.workflow("egghunter", "W00T")
dx @$osed().exploit.workflow("badchars", "", 0, 0x00B8F900)
```

`badchars` needs `address`, the start of the test array in memory. No mode reads `offset` yet. Earlier builds documented this command as `exploit(...)`, which `dx` could not call: `@$osed().exploit` is the object that holds `exploit.state` and `exploit.clear`, so the workflow now sits next to them.
