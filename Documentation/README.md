# Documentation

The [project README](../README.md) explains how to load the script and walks through the exam workflow.

## Command reference

[COMMANDS.md](COMMANDS.md) lists every command from A to Z and explains the argument conventions. Each category has its own file:

- [Pattern and bad characters](commands/payload.md)
- [Crash triage](commands/crash.md)
- [Target and memory](commands/target.md)
- [SEH](commands/seh.md)
- [ROP and DEP](commands/rop.md)
- [Format strings](commands/format.md)
- [Shellcode](commands/shellcode.md)
- [Strings](commands/strings.md)
- [PE and API](commands/pe-api.md)
- [Leak, math, and session](commands/tools.md)

## Design notes

These upstream documents explain how the toolkit works inside:

- [ANALYSIS_ARCHITECTURE.md](ANALYSIS_ARCHITECTURE.md) sets the dependency and evidence rules for `src/analysis/`.
- [SEMANTIC_ROP_DESIGN.md](SEMANTIC_ROP_DESIGN.md) describes how gadget parsing, semantics, and ROP policy are separated.
- [GADGET_DISCOVERY.md](GADGET_DISCOVERY.md) explains how to find a specific gadget in the corpus and how to spot one that breaks the stack layout.
- [ROP_WORKFLOW.md](ROP_WORKFLOW.md) walks through the semantic ROP pipeline.
- [CHAIN_COMMANDS.md](CHAIN_COMMANDS.md) compares the chain builders for each API.
- [ROP_API_REFERENCE.md](ROP_API_REFERENCE.md) documents the ROP API and its register conventions.
- [ROP_PROVE_IMPLEMENTATION_SPEC.md](ROP_PROVE_IMPLEMENTATION_SPEC.md), [ROP_PROVE_IMPLEMENTATION_PLAN.md](ROP_PROVE_IMPLEMENTATION_PLAN.md), and [ROP_PROVE_WINDOWS_VALIDATION.md](ROP_PROVE_WINDOWS_VALIDATION.md) cover `rop.prove`.
- [ROP_CORPUS_PERSISTENCE_DESIGN.md](ROP_CORPUS_PERSISTENCE_DESIGN.md) and [ROP_CORPUS_PERSISTENCE_IMPLEMENTATION_PLAN.md](ROP_CORPUS_PERSISTENCE_IMPLEMENTATION_PLAN.md) cover `rop.corpus.*`.
- [HELP_SYSTEM.md](HELP_SYSTEM.md) describes the `help` command.
- [DEVELOPMENT.md](DEVELOPMENT.md) explains how to add a command.

## Troubleshooting

- If `.scriptload` fails on classic WinDbg, load `dist/osed-legacy.js` instead of `dist/osed.js`.
- If `@$osed` is missing after the load, run `.scriptload` again. If the load reports that `functionAlias` registration failed, call the global object directly, as in `dx osed.help()`.
- If the load banner or `version()` shows `dev` or `unknown`, you loaded a file that is not a built bundle. Load the file from `dist/`.
- If a command reports a validation error, run `dx @$osed().help("<command>")` and match its signature.
- If memory reads fail, check that the target is stopped and that the address is valid in the current context.
