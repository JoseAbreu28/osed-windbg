# SEH commands

Use these commands for structured exception handler (SEH) overwrites on x86.

Run each command as `dx @$osed().<command>` in WinDbg. The [command index](../COMMANDS.md#conventions) explains byte lists, addresses, and optional arguments. `dx @$osed().help("<command>", "full")` prints the built-in help.

| Command | What it does |
| --- | --- |
| [`seh.visualize`](#sehvisualize) | Walk the SEH chain of the current thread and show each `Next` and `Handler` value. |
| [`seh_ppr`](#seh_ppr) | Find and rank `pop r32 ; pop r32 ; ret` gadgets for an SEH overwrite. |

### seh.visualize

**[fork: changed]**

Walk the SEH chain of the current thread and show each `Next` and `Handler` value.

```text
seh.visualize()
```

```text
dx @$osed().seh.visualize()
```

Run it after the first-chance exception. If `Handler` shows your pattern, pass that value to `pattern_offset`. In this fork the lookup reads the TEB from the engine's `$teb`, so it works without symbols, the same way `!exchain` does. On WOW64 it uses the 32-bit TEB at the native TEB + `0x2000` and accepts it only when the self pointer at TEB + `0x18` matches. The help catalog lists this command as `seh`. Call it as `seh.visualize()`, because `@$osed().seh()` is not callable.

### seh_ppr

Find and rank `pop r32 ; pop r32 ; ret` gadgets for an SEH overwrite.

```text
seh_ppr(module?, exclude?, maxResults?, executableOnly?, mode?)
```

```text
dx @$osed().seh_ppr()
dx @$osed().seh_ppr("libspp.dll", "00 0A 0D", 100, true, "thorough")
dx @$osed().seh_ppr("libspp.dll", "00 0A 0D")
```

The `SEH PPR Candidates` table skips addresses that contain any byte in `exclude`. Use a module without SafeSEH and without ASLR. `mode` is `fast` (default) or `thorough`.
