# PE and API commands

Use these commands to read imports, exports, PE headers, and API hashes from the loaded modules. They are all in the `sc` namespace.

Run each command as `dx @$osed().<command>` in WinDbg. The [command index](../COMMANDS.md#conventions) explains byte lists, addresses, and optional arguments. `dx @$osed().help("<command>", "full")` prints the built-in help.

| Command | What it does |
| --- | --- |
| [`sc.iat_find`](#sciat_find) | Search the import tables of every loaded module for an API name. |
| [`sc.iat_ptr`](#sciat_ptr) | Give the IAT slot address of one import and the API address stored in it. |
| [`sc.iat`](#sciat) | List the imports of a module, optionally filtered by DLL or API name. |
| [`sc.resolve`](#scresolve) | Give the address of one exported function. |
| [`sc.export`](#scexport) | Give the ordinal, RVA, address, and forwarder of one export. |
| [`sc.exports`](#scexports) | List the exports of a module, optionally filtered by name. |
| [`sc.exportat`](#scexportat) | Resolve an export by its ordinal index. |
| [`sc.exportdir`](#scexportdir) | Show the addresses and sizes of the export directory tables. |
| [`sc.exportwalk`](#scexportwalk) | Walk the export tables step by step for one name. |
| [`sc.hash`](#schash) | Hash one API name with an API-hash algorithm. |
| [`sc.hashresolve`](#schashresolve) | Find the export whose name matches a hash. |
| [`sc.hashes`](#schashes) | Hash every export of a module. |
| [`sc.algorithms`](#scalgorithms) | List the supported hash algorithms: `crc32`, `metasploit_ror13` (alias `ror13`), and `rol7_add`. |
| [`sc.modules`](#scmodules) | List the loaded modules. |
| [`sc.base`](#scbase) | Give the base address of one module. |
| [`sc.pe`](#scpe) | Print the PE header fields of one module. |
| [`sc.peb`](#scpeb) | Show the PEB address, `Ldr`, `ProcessParameters`, `BeingDebugged`, and `ImageBase`. |
| [`sc.module_pages`](#scmodule_pages) | Give the size of one module and its number of 4 KiB pages. |
| [`sc.page_summary`](#scpage_summary) | Count the pages of one module by protection value. |
| [`sc.api_plan`](#scapi_plan) | Return the raw snapshot that `rop.api_plan` reads. It is internal and prints nothing, so use `rop.api_plan` instead. |

## Imports (IAT)

### sc.iat_find

Search the import tables of every loaded module for an API name.

```text
sc.iat_find(symbol)
```

```text
dx @$osed().sc.iat_find("VirtualAlloc")
```

Use it to find a module without ASLR that imports VirtualProtect, VirtualAlloc, or WriteProcessMemory.

### sc.iat_ptr

Give the IAT slot address of one import and the API address stored in it.

```text
sc.iat_ptr(module, symbol)
```

```text
dx @$osed().sc.iat_ptr("app.exe", "VirtualProtect")
```

The slot address is fixed when the module has no ASLR. That address is what a ROP chain dereferences.

### sc.iat

List the imports of a module, optionally filtered by DLL or API name.

```text
sc.iat(module?, filter?)
```

```text
dx @$osed().sc.iat()
dx @$osed().sc.iat("app.exe", "Virtual")
```

## Exports and API addresses

### sc.resolve

Give the address of one exported function.

```text
sc.resolve(module, symbol)
```

```text
dx @$osed().sc.resolve("kernel32", "WinExec")
```

### sc.export

Give the ordinal, RVA, address, and forwarder of one export.

```text
sc.export(module, symbol)
```

```text
dx @$osed().sc.export("kernel32", "GetProcAddress")
```

The RVA is what `leak.base` needs to turn a leaked pointer into a module base.

### sc.exports

List the exports of a module, optionally filtered by name.

```text
sc.exports(module, filter?)
```

```text
dx @$osed().sc.exports("kernel32", "Virtual")
```

### sc.exportat

Resolve an export by its ordinal index.

```text
sc.exportat(module, ordinalIndex)
```

```text
dx @$osed().sc.exportat("kernel32", 842)
```

### sc.exportdir

Show the addresses and sizes of the export directory tables.

```text
sc.exportdir(module)
```

```text
dx @$osed().sc.exportdir("kernel32")
```

### sc.exportwalk

Walk the export tables step by step for one name.

```text
sc.exportwalk(module, symbol?, verbose?)
```

```text
dx @$osed().sc.exportwalk("kernel32", "GetProcAddress")
dx @$osed().sc.exportwalk("kernel32", "GetProcAddress", true)
```

## API hashes

### sc.hash

Hash one API name with an API-hash algorithm.

```text
sc.hash(name, algorithm?)
```

```text
dx @$osed().sc.hash("WinExec", "ROR13")
```

`ROR13` is the Metasploit-style hash. Run `sc.algorithms()` for the full list.

### sc.hashresolve

Find the export whose name matches a hash.

```text
sc.hashresolve(module, hashValue, algorithm?)
```

```text
dx @$osed().sc.hashresolve("kernel32", 0x7c0dfcaa, "ROR13")
```

### sc.hashes

Hash every export of a module.

```text
sc.hashes(module, algorithm?)
```

```text
dx @$osed().sc.hashes("kernel32", "crc32")
```

### sc.algorithms

List the supported hash algorithms: `crc32`, `metasploit_ror13` (alias `ror13`), and `rol7_add`.

```text
sc.algorithms()
```

```text
dx @$osed().sc.algorithms()
```

## Modules and PE headers

### sc.modules

List the loaded modules.

```text
sc.modules()
```

```text
dx @$osed().sc.modules()
```

### sc.base

Give the base address of one module.

```text
sc.base(module)
```

```text
dx @$osed().sc.base("kernel32")
```

### sc.pe

Print the PE header fields of one module.

```text
sc.pe(module)
```

```text
dx @$osed().sc.pe("kernel32")
```

### sc.peb

Show the PEB address, `Ldr`, `ProcessParameters`, `BeingDebugged`, and `ImageBase`.

```text
sc.peb()
```

```text
dx @$osed().sc.peb()
```

`Ldr` is the loader data that position-independent shellcode walks to find kernel32.

### sc.module_pages

Give the size of one module and its number of 4 KiB pages.

```text
sc.module_pages(module)
```

```text
dx @$osed().sc.module_pages("kernel32")
```

### sc.page_summary

Count the pages of one module by protection value.

```text
sc.page_summary(module)
```

```text
dx @$osed().sc.page_summary("kernel32")
```

### sc.api_plan

Return the raw snapshot that `rop.api_plan` reads. It is internal and prints nothing, so use `rop.api_plan` instead.

```text
sc.api_plan(target, badchars?)
```
