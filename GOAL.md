# Goal: one command, any target, evidence you can screenshot

A standing goal for `osed-windbg`, set by Bruno on 2026-11-22. Every agent working on the
DEP path reads this before starting and reports against it.

## What this is for

Bruno is sitting an OffSec OSED exam. In it he gets an unfamiliar binary, a few hours, and
has to produce both a working exploit and a report that shows how he got there. This tool
exists to carry the discovery work so his time goes on the parts only he can do.

## The goal, stated so it can be failed

**One invocation produces a working exploit on a target the tool has never seen, without the
user knowing which argument to change.**

Bruno set that bar on 2026-11-22: the baseline is the exploit running, not a plausible
looking chain. A chain is a claim; a shell is evidence.

The exception, and it has to be earned: where no exploit is possible, the run ends on a
named reason. Which layer failed, module, API or method, and what single missing piece would
have unlocked it, each backed by what was searched. That exit exists for targets that really
are closed, not as a comfortable place to stop. A tool that always produces a chain is lying;
a tool that reaches for the exception when it could have found a path is lying more quietly.

Passing does not count if the answer was remembered. Every target is re-derived from the live
process on each run, with no stored addresses, no target-specific branch in the code and no
argument that names the target.

## Who decides it is ready, and on what

Claude makes that call, and will not make it on corpus results alone. Every target used to
fix the tool has been taught to it, so passing on those proves only that the lessons stuck.

The call needs a **holdout**: a target the tool has never been run against, exploited cold,
one invocation, nobody adjusting anything. Until that has happened at least once, the honest
answer to "is it ready" is no, however green the corpus is.

## The two rules, and they pull against each other

**Automatic.** No conclusion may depend on a default the user would have to know to change.
If a limit hides a gadget, the limit is the bug. If a guessed parameter produces a wrong
answer, the parameter is the bug. The user supplies what only he can know: the bad chars,
which come from his own hunt, and the stage number, because the tool cannot see his file.
Everything else the tool works out.

**Evidence you can screenshot.** Every automatic decision prints what it chose, why, and the
command that reproduces it. The report needs a picture per claim, so:

- each section's evidence fits a screen at the guide's font size; a three thousand row table
  is not evidence, it is a dump
- the echoed first line is the call with every choice written out, so a screenshot never
  hides a decision the tool made silently
- the copy block sits below a separator, so the screenshot above it stays clean and the code
  below it is one drag to select

A decision the tool cannot show is worse than one it does not make.

## The target corpus

Generality is measured, not asserted. The tool is run against every target below on each
iteration, and a change that fixes one must not regress another.

| Target | Module | Shape it exercises |
|---|---|---|
| `vuln_dep.exe` | `libbkup` | the API is imported directly; skeleton style completes |
| Sync Breeze 10.0.28 `syncbrs.exe` | `libspp` | no fixed module imports any DEP API; the route is a kernel32 neighbour plus a distance; only one of four fixed modules is usable; pushad is the only viable style |
| T06 | one exe | no register copy anywhere in the module and no `pushad ; ret` either, so neither stack-frame style can be built: the frame has to be staged at a fixed writable address |
| T07 | one dll, one exe | no saved EIP takes the overwrite: the overflow faults on a pointer it replaced inside a `__try` and the chain arrives through the SEH handler the dispatcher calls next. The delivery, not the style, is what the target picks |
| T11 | one dll, one exe | every address in the exe carries the first bad char, and the one usable module has no `pushad`, no `jmp esp`, no `call esp` and no `push esp ; ret` at all, so the frame must be staged and ESP pivoted onto it. Adds what T06 does not: a staged frame whose section is too small for what the call returns into, so the sled has to put ESP back on the thread's stack before the shellcode runs. T06 has 0x3dfd bytes under its frame and got away with it; T11 has 0x1fec and its shellcode wanted 0x2210 in one WinExec. Its crash also dereferences the dword just past the saved return address before the function returns, so a payload must keep that dword a readable pointer |

Add a target whenever one teaches a shape the corpus does not already hold. Record what
shape it adds, not just that it was added.

**T14 was removed from the corpus on 2026-11-23.** It was a class B target, the same shape T13
and T15 exercise: nothing at a fixed base, so `dep_plan` must refuse with a named reason and send
the user to the leak. Its lab was never written. The folder holds only a `lab.json` naming two
sources and four guest files, none of which exists anywhere in the tree, so there is no build, no
reference exploit, no offset and no marker. It was never attempted on any run, and counting it in
the denominator made every score read worse than it was. The manifest keeps its entry under
`removed`, and it returns to `targets` the moment the lab is written, built and given a reference.
Nothing about the tool can be learned from it before that. The denominator is 14.

## How an iteration goes

1. Run the harness over the whole corpus and record what each target produced.
2. Pick the largest honest failure. A wrong verdict beats a slow one; a silent wrong answer
   beats both.
3. Fix the cause, not the symptom.
4. Re-run the whole corpus. No regressions.
5. Append what was learned, with the evidence, so the next agent does not rediscover it.

## The harness

`tools/harness/run_corpus.py` does step 1. The manifest it reads, the per-target protocol adapters
and every result live outside this repository, because they name course labs; the runner takes the
manifest path as its argument:

    py -3.12 tools/harness/run_corpus.py <manifest.json> [--only ID|NAME ...] [--ref] [--out DIR]

Per target it starts the program on the lab clone (and refuses any other VM), attaches cdb x86 by PID,
loads `dist/osed-legacy.js`, sends the target's own crash input, and runs `dep_plan(badchars, 1)` with
nothing else. The transcript is kept verbatim. It then pastes the copy blocks of `[1/7]` to `[7/7]`
under `OFFSET` and `BADCHARS` into one file, puts a marker shellcode where `[7/7]` leaves its shellcode
hole, runs the file, and fires the payload at a fresh copy of the target under cdb with a breakpoint on
each DEP API. Pass is observed, never read off the chain: the marker file appeared. Short of that it
records whether the chain reached an API and where the process faulted. `--ref` fires the lab's own
reference exploit instead, which grades the target rather than the tool.

The manifest's `holdout` list names the targets kept back for the readiness call. The runner refuses
them by that list, and refuses a manifest without one, so their names never enter this public repo.
`--only` takes a target id as well as a lab name, so a run command written down anywhere, here included,
uses ids; a selection that matches no target stops the run rather than producing an empty one.

`tools/harness/replay.ts` is the same run without a VM, for the questions a module's bytes can answer on
their own: which modules can give gadgets, the corpus, the IAT slot, the caves, the job picks and every
register route. It maps a PE the way the loader would, headers and then each section at its VirtualAddress,
answers `!vprot` from the section characteristics so `code_caves` behaves as it does live, and runs the real
command through the same host shim the fixture tests use. It takes the module paths as arguments, so no lab
name reaches this repo:

    node node_modules/esbuild/bin/esbuild tools/harness/replay.ts --bundle --platform=node --format=cjs --outfile=replay.cjs
    node replay.cjs <module.pe> [more.pe ...] --bad "<bad chars>" [--cmd palette|code_caves|dep_candidates]

Verified against a captured clone transcript: same API, same module, same slot, same job picks, same holes.
What it cannot reproduce is a route that dereferences an IAT slot to measure a distance, because an on-disk
image's slots hold their unbound values. A direct import is faithful, since only the slot address is used.
It says whether a chain was built, never whether one runs: only the clone can say that.

The screenshot rule is `src/core/screenshot_rule.ts`. `tests/screenshot_rule.test.ts` pins one check
per clause and a ratchet over the fixture output; the harness runs the same module on every real
capture. The budget is 40 rows and 130 columns per section. The guides draw the command pane in 15 px
Consolas with a 7 px gap, 22 px a row (`lab/v2/guides/Workflows/headless.py`), and a 1080 px screen
leaves about 880 px of pane under the title bar, the ribbon and the input line. The same renderer
clamps a figure to 130 columns and cuts every longer line there, so a character past 130 never reaches
a guide. Rows count the evidence above the separator; columns count every line, the copy block too,
because the editor figures photograph it at the same font.

## Corpus run, 2026-11-23, measured at `6b0a8ef`

`dist/osed-legacy.js` sha256 `607b9550f1349a7690e983923af2cf7f21ec595919dffbf9fb8d5aa5b84c7902`, on the
lab clone. Targets are listed by id; the manifest outside this repo maps each id to its lab. The three
holdout targets were not run, opened or read. Every class A target was given only its bad chars and stage
1. Nothing passed.

Ranked by size of honest failure: a silent wrong answer first, then a wrong verdict, then an incomplete
exit. Nothing was slow: `dep_plan` finished in 30 to 70 seconds per target in the engine, and Sync Breeze's
368 seconds are service restarts and a second fire.

| Rank | Target | Shape | What happened | Where it stopped | Whose |
|---|---|---|---|---|---|
| 1 | T01, T02, T04, T09 | skeleton style, VirtualAlloc, exe or dll at a fixed base | `[7/7]` says the only hole is the shellcode. The file runs and the payload carries `0x00000014`, which is three `00` bytes, from `c.rop(POP_ECX, neg(-20))` in the pivot. The value is static and never checked against the bad chars. The string copy stops there. | payload: bad char, then a fault in the cut chain | tool. T02's own reference also fails on the clone, so T02 alone does not separate tool from target |
| 2 | Sync Breeze (T12) | pushad, VirtualAlloc by a kernel32 distance | `[7/7]` says the only hole is the shellcode. The vulnerable function returns with `ret 4`, so ESP lands at OFFSET + 8, and the chain assumes OFFSET + 4: every value is popped one dword late. Even so it reached the pushad with dwSize, flAllocationType and flProtect right and ESI wrong (`QueryDosDeviceA+4`). With 4 junk bytes after the EIP dword and nothing else changed, **the marker landed**. A diagnostic, not a pass: nothing told the user to add them. The crash state shows the gap, so the tool could. | chain, misaligned by the target's `ret 4` | tool |
| 3 | T07 | pushad, VirtualAlloc; the overwrite is a job pointer, not a saved EIP | `[7/7]` says the only hole is the shellcode. The payload puts the chain where the pointer is, so it faults at `0x0040126C` before any gadget runs. | chain, never reached | tool. The reference also fails on the clone, so the target is unverified |
| 4 | T03, T05 | exe only (T03); two fixed modules (T05) | Refuses at the method layer: "the skeleton style lacks negate, and the pushad style lacks pop eax. Each was searched for in every byte of it." The gadgets exist at clean addresses and the reference uses them: `neg eax ; ret` and `xchg ecx, eax ; ret` at `0x6C91164C` and `0x6C911649` in T03, and `pop eax ; pop ebp ; ret` and `neg eax ; pop ebp ; ret` at `0x6E2C85F9` and `0x6E2D47E6` in T05. `[4/7]` itself lists `neg eax ; pop ebp ; ret` and rejects it because EAX still holds the field address in that recipe. The absence claimed is the recipe's register order, not the module. | dep_plan, method layer | tool |
| 5 | T06, T08, T10 | WriteProcessMemory in the reference; eight bad chars (T06), a short offset (T08), three offsets in play (T10) | Refuses at the method layer: the skeleton style lacks "copy a register" and the pushad style lacks several pops and `pushad ; ret`. Each reference exploits the target on the clone with a chain that needs no register copy, so a chain exists that the tool's one skeleton recipe cannot express. | dep_plan, method layer | tool |
| 6 | T13, T15 | class B: nothing at a fixed base | Refuses correctly ("the module layer fails: no loaded module can give gadgets: every one has ASLR") but never names the leak as the next step. | dep_plan, module layer | tool: the exit is honest but incomplete |
| - | T11 | two fixed modules, unfinished lab | Not attempted. A 1200 byte cyclic pattern faults inside its dll at `0x63C80D80` before any return reads the pattern (`findmsp`: EIP does not hold pattern bytes), and the lab has no solution to say where EIP is reachable. | no offset | target |
| - | T14 | class B | Not attempted: not built, no reference. | no build | target |

The reference exploits, fired by `--ref` on the same clone, land their marker on T01, T03, T04, T05, T06,
T08, T09, T10, T13 and T15, and fail on T02 and T07. Sync Breeze, T11 and T14 have no reference.

Every route the tool chose, against the API each reference used. T05 matched (VirtualProtect), and so did T07
(VirtualAlloc). T06 and T10 matched (WriteProcessMemory) and still refused. T02, T04, T08 and T09 got
VirtualAlloc where their references used VirtualProtect or WriteProcessMemory. T01, T03 and Sync Breeze are
open to all three.

The screenshot rule on the 13 real transcripts. `[5/7]` is past 40 rows in 9 of them, and prints Python
above the separator in 10. `[6/7]` prints Python above the separator in 8, all of them skeleton runs.
Those are the two violations already recorded below, and the harness flags both. It also found ones this
file did not list. `[4/7]` is past 40 rows in 11 (79 on Sync Breeze). `[1/7]` is 58 rows and has 53 lines
past 130 columns on Sync Breeze. The echoed first line says `"auto"` for the style in all 6 runs that
built a chain: it prints before the style is chosen. Every run has a line past 130 columns somewhere, the
widest 368 characters (T05).

## Corpus run, 2026-11-23, measured at `0c58ee2`

`dist/osed-legacy.js` sha256 `e89d94e2448a47f3ec6d29c3c74e13df7f6879913482475ac88329ebf98c1dbd`.
The agent that made these changes was stopped by a model safeguard before it could write this
section or commit the rebuilt bundle; both were finished by the parent, which rebuilt `dist` from
the committed source, re-ran the suite and read the measured run rather than the agent's account
of it.

**Eight of fifteen pass, from zero.** Six class A targets land the marker, among them the only
real application in the corpus. Two class B targets now refuse correctly *and* name the leak, which
is what `GOAL.md` asks a refusal to do, so they count.

| Result | Targets |
|---|---|
| marker landed | T01, T02, T03, T04, T09, T12 |
| refused correctly, leak named | T13, T15 |
| still failing | T05, T06, T07, T08, T10 |
| not attempted, the target's fault | T11, T14 |

What moved, against the previous run:

| # | Targets | Then | Now |
|---|---|---|---|
| 1 | T01, T02, T04, T09 | the payload carried `0x00000014`, three `00` bytes, from a static `neg(-20)` in the pivot | every dword the planner sends is now built rather than written raw, so the bad char check is a property of emitting a dword at all. All four land the marker |
| 2 | T12, Sync Breeze | the target returns with `ret 4`, ESP lands at OFFSET + 8, and the chain assumed OFFSET + 4, so every value popped one dword late | the gap is read from the crash instead of assumed. The marker lands. Two independent measurements agreed on it beforehand: a 1200 byte cyclic pattern put EIP at 780 with ESP pointing into the pattern at 788, and the harness found that four bytes of padding after EIP fixed the chain with nothing else changed |
| 3 | T13, T15 | refused correctly and left the user standing there | the refusal names the leak as the missing piece. Both count as passes now |
| 4 | T03 | refused at the method layer although the gadgets existed at clean addresses | a job is satisfied by a path, not by one named gadget. T03 lands the marker |

What did not move, and why each is a different problem:

- **T05** no longer refuses; it reaches the payload and stops on an unfilled hole,
  `virtualprotect_value`. One layer further than before, and a different bug.
- **T06, T08** still refuse at the method layer, for "copy a register" and for pops the pushad
  style wants. Their references exploit them with chains that need neither, so the job list is
  still too rigid per style and per API. This is the largest remaining item.
- **T07** still faults at `0x0040126C`: its overwrite is a job pointer, not a saved EIP, and the
  tool puts the chain where the pointer is. Its own reference also fails on the clone, so the
  target is unverified and tool and target are not yet separated.
- **T10** failed in the harness, not in the tool: the marker shellcode generator raised. That is
  harness noise and must be fixed before T10 says anything about the tool.

The build is reproducible apart from one stamp: `__OSED_BUILD_TIME__` differs between two builds of
the same source and nothing else does, five bytes in 1.3 MB. So a published sha256 identifies the
exact file shipped, not the source it came from.

## Corpus run, 2026-11-23, measured at `ef5d741`

`dist/osed-legacy.js` sha256 `77c7c177e5889d7b7cd5976444226e7921c453f406b6f5629ac802018a3e4e61 (the file the corpus ran against). The build shipped to the VMs and to Notion is 37b9ac92d121b784cf571372c2605ef28c597c3494883f100ccb25bb010846f5, rebuilt by the parent from the same committed source and verified by it; the two differ only in the `__OSED_BUILD_TIME__` stamp. Targets are listed by id; the manifest outside this repo maps each
id to its lab. The three holdout targets were not run, opened or read. Every class A target was given
only its bad chars and stage 1.

**Ten of fifteen pass, from eight.** Seven class A targets land the marker and two class B targets refuse
correctly and name the leak. The two that moved are T05, whose chain was complete at the last run and died
on a junk dword, and T06, which the last run refused at the method layer and which now takes its target
with a third chain style.

| Result | Targets |
|---|---|
| marker landed | T01, T02, T03, T04, T05, T06, T09, T12 |
| refused correctly, leak named | T13, T15 |
| still failing | T07, T08, T10 |
| not attempted, the target's fault | T11, T14 |

What moved, against the previous run:

| # | Targets | Then | Now |
|---|---|---|---|
| 1 | T05 | reached the payload and stopped on `still to fill: virtualprotect_value` | the write gadget is weighed against the frame it has to fill, so the chain carries the field address and the value in registers the corpus can actually load. The chain completed, then died at `0x41414141`: one `COST` row served a gadget used with one value in one place and two in another. A row now counts the gadget's own appetite. The marker lands |
| 2 | T06 | refused at the method layer: no register copy in the module, and no `pushad ; ret` either, both true | a third style lays the call frame at a fixed writable address, so every field address is a constant the chain pops and no copy is needed. It reached WriteProcessMemory with every argument right and faulted inside the call, because the pivot puts ESP on the frame and the frame sat near the bottom of its writable run. Laid at the top of the run instead, with 0x3DFD bytes under it, the marker lands |
| 3 | T10 | the harness raised before the tool was asked anything: the marker shellcode generator could not avoid `5e`, the opcode of `pop esi` | `sc_builder` chooses the form of a pop against the bad chars, so T10 is graded. It now finds its executable cave, which it could not while `nSize` was hard coded at 0x210 and the module's largest clean cave is 0x180, and stops on the shellcode's address on the stack |
| 4 | T11 | refused at the method layer | builds a complete chain in the staged style. Its lab has no measured offset, so the harness still cannot fire it: this is visible only in the replay |

What did not move, and why each is a different problem:

- **T07** still faults at `0x0040126C`, where it faulted before. Its overwrite is a job pointer rather than
  a saved EIP, so the chain goes where the pointer is. Its own reference also fails on the clone, so target
  and tool are still not separated. Out of scope by instruction, and unchanged.
- **T08** no longer refuses. It builds in the staged style and names three holes, and the module owns two of
  them: its only ESP capture leaves the address in EBP and nothing in it moves EBP anywhere, so no stack
  address can reach the register the frame is built in. The third is the tool's: its only memory read is
  `xchg dword [ecx], eax`, which `effectOf` refuses as a transition because it stores through an address
  the search cannot pin, although the dword it clobbers is the slot the chain has just read.
- **T10** stops on `lpbuffer_value`, the shellcode's address on the stack. The emitted script works that
  distance out, so no static search owns it, and subtracted it pops as `0xFFFFFExx` while added it pops as
  `0x000001xx`, which `00` rules out. The module has `add eax, edx` and no `sub` at all.

The screenshot rule on the 13 real transcripts, scored by the harness with the same module the tests use.
**Two violations in all, both in `[1/7]` of one target**, where the last run had a height or a width
violation in nearly every section of every target and a widest line of 368 characters. What is left is the
module table of the only target with four loaded modules: 60 rows against 40, and 51 lines at up to 135
columns. It is `modules()`, a listing of every module the process has, printed whole; it is the one
section whose size follows the target rather than the chain, and it is the next thing to cut. Every other
section of every other target is inside 40 rows and 130 columns.

## Corpus run, 2026-11-23, measured at `2038a47`

`dist/osed-legacy.js` sha256 `1e914b42d519975984619edb3c4b767fab907d6c708e8c0d9cd2225f4e97cdc2 (the file the corpus ran against). The build shipped to the VMs and to Notion is bfe1a9df88b8340bab898df7f0dc65e533a4cde648c04db940e76de9be6742b0, rebuilt by the parent from the same committed source and verified by it; the two differ only in the build stamp` (the file the
corpus ran against), on the lab clone. The three holdout targets were not run, opened or read. Every class A target
was given only its bad chars and stage 1. A run at `482ab7a` gave the same eleven passes and one width violation,
which `2038a47` fixes; this table is the second run.

**Eleven of fifteen pass, from ten.** Eight class A targets land the marker and two class B targets refuse correctly
and name the leak. T10 is the one that moved. Nothing regressed.

| Result | Targets |
|---|---|
| marker landed | T01, T02, T03, T04, T05, T06, T09, T10, T12 |
| refused correctly, leak named | T13, T15 |
| still failing | T07, T08 |
| not attempted, the target's fault | T11, T14 |

What moved, against the previous run:

| # | Targets | Then | Now |
|---|---|---|---|
| 1 | T10 | stopped on `lpbuffer_value`: "no gadget adds a popped distance to eax" | the shellcode's address comes from a second capture of ESP, as the reference does it, and the distance is popped negated into EDX and negated back by `neg edx`, which the module had all along. The marker lands |
| 2 | T08 | built in the staged style with four holes, one of them a read the tool should have allowed | the read it was asked to allow, `xchg dword [ecx], eax` on the IAT slot, faults: the slot's page is `PAGE_READONLY` on the clone. Both layers now refuse it and the run stops at the method layer naming "read a pointer". Still a fail, now an honest one |
| 3 | T12 | `[1/7]` 60 rows, 51 lines past 130 columns | inside the budget: the table holds the four modules without ASLR and counts the rest |

The screenshot rule on the 13 real transcripts: **no violation in any section of any target.**

## Corpus run, 2026-11-23, measured at `9d27618`

`dist/osed-legacy.js` sha256 `1887cfcac0964cd41bad6c02290b709ea3074da42851b4e7a2c2e3fbc5c009c2`, the file the
corpus ran against, on the lab clone. The bundle committed and left on disk is
`a16adf2434b3db23753ac80e3e29d215d96fbf5bb0c4c092b29f8ab8b6934bad, rebuilt and verified by the parent and shipped to the VMs and to Notion (the agent left 7a4320c25e30265e9acbce2520f59513e790451b3e511c09cba42a6b4db4c7f1, the same source with a different build stamp)`. The two are the same source and differ in
five bytes, the `__OSED_BUILD_TIME__` stamp, verified here by building twice and diffing: same length, five
differing bytes, all inside that one string. So a published sha256 identifies the exact file, not the source. The three holdout targets were not run, opened or read. Every class A
target was given only its bad chars and stage 1. T14 was removed from the corpus before this run, so the
denominator is 14 and the previous run's eleven of fifteen is eleven of fourteen for comparison.

**Twelve of fourteen pass, from eleven.** Ten class A targets land the marker and two class B targets refuse
correctly and name the leak. T07 is the one that moved. Nothing regressed: every other target kept the API,
the module and the style it had, and the whole run took 1333 seconds, 599 of them Sync Breeze's service
restarts and second fire.

| Result | Targets |
|---|---|
| marker landed | T01, T02, T03, T04, T05, T06, T07, T09, T10, T12 |
| refused correctly, leak named | T13, T15 |
| still failing | T08 |
| not attempted, the target's fault | T11 |

What moved, against the previous run:

| # | Targets | Then | Now |
|---|---|---|---|
| 1 | T07 | faulted at `0x0040126C` before any gadget ran: its overwrite is a job pointer rather than a saved EIP, and the chain was laid where the pointer is | the chain arrives through the SEH handler the dispatcher calls once that fault happens. `add esp, 0xD10 ; ret` from its dll, with the record measured 0x1410 above the ESP the handler is called with, lands it at `OFFSET - 0x700`. VirtualAlloc is reached from the chain and returns into `jmp esp`. The marker lands |
| 2 | T08 | refused with nine missing jobs across three style lists, one of them "read a pointer: absent, no hit at all" and "this is the module, not the scan" | still refuses, and says the module is "1 job(s) short of the staged style, the closest of the 3: read a pointer". `[4/7]` names the gadget the search had been hiding: `0x63101ED5  mov eax, dword [eax] ; mov esp, ebp ; ret 0x12`, which is the one its own reference reads the slot with |

What did not move:

- **T08** is the only class A failure left. The refusal is honest and the shape that would close it is written
  down under "Known gaps": a pivot that reads while it pivots, a frame whose entry slot pushes a register, and
  a frame base shifted to stay aligned under the pivot's `ret 0x12`. Three things, not one, and none of them
  is a search tweak.
- **T11** is still not attempted and still the target's fault: its lab has no measured offset, so the harness
  cannot aim the crash input. The replay shows it builds a complete chain in the staged style.

The screenshot rule on the 14 real transcripts, scored by the harness with the same module the tests use:
**no violation in any section of any target.** The SEH delivery adds between four and eleven lines to `[6/7]`
and every one of them fits.

Two things this run is not. No `--ref` pass was made at this commit, so every statement here about what a
reference does rests on the earlier runs recorded above and, for T08 and T07, on reading the reference
sources. And four of the thirteen crashes that reached a corpus look like SEH deliveries by the first test
applied to them, so four of them let an exception through once to measure the handler's ESP: T07, where the
delivery is taken, and T01, T03 and T06, where no handler lands in the buffer and the saved EIP stands. The
other nine never reach a record. That measurement restores the handler, the SEH head and every register, and
it disturbed nothing in this run, but it runs the program.

## Corpus run, 2026-11-23, measured at `636a034`

`dist/osed-legacy.js` sha256 `4c40bfeb5bfb1beb55bd815cf7f5abd8e9f5d1d37a4cceb52231e36fae65b33a`, the file the corpus ran
against on the lab clone and the file committed in `dist/`. The three holdout targets were not run, opened or read. Every
class A target was given only its bad chars and stage 1.

**Twelve of fourteen pass, as before.** Nothing moved and nothing regressed: every target kept the API, the module and the
style it had at `9d27618`, and the screenshot rule found no violation in any section of any target. This run measured four
defects in the printed evidence, found while the Workflows pages were captured from the shipped build, not the chain.

| Result | Targets |
|---|---|
| marker landed | T01, T02, T03, T04, T05, T06, T07, T09, T10, T12 |
| refused correctly, leak named | T13, T15 |
| still failing | T08 |
| not attempted, the target's fault | T11 |

What changed on the screen, measured on the transcripts of both runs:

| # | Where | Then | Now |
|---|---|---|---|
| 1 | `[4/7]` | 15 of the `>` picks on 7 transcripts named a gadget the chain never calls: `read a pointer` in every style and the pushad pops, whose values the `[5/7]` route search loads, and T05's `add`, which the build did through another register | the build reports what its `c.rop` lines call and runs before the ranking prints. All 66 `>` picks on the 13 transcripts that reach `[4/7]` are called. The 15 that were false keep their row without the `>` and say where the chain does the job |
| 2 | `.explain` of `seh_ppr` | the report line said a pop-pop-ret was selected for the SEH handler, nothing about DEP | it ranks them for a target without DEP and says so in every field; a catalog test fails any field that offers a pop pop ret without naming DEP |
| 3 | `[5/7]` | `not searched: built from the frame, not searched for` | `not searched: built from the frame` |
| 4 | `[4/7]` | the commands the section repeats spelled the bad chars upper case under an echo that spelled them as typed | one spelling per target, the echo's |

Two things found and not done:

- ~~`[4/7]`'s copy block still names gadgets the chain never calls.~~ Fixed at `132fb13`: see that corpus run.
- No `--ref` pass was made at this commit, as at the last one.

## Corpus run, 2026-11-23, measured at `132fb13`

`dist/osed-legacy.js` sha256 `a469f1bef699504a40b2f7dedb2fb5bd695909fb0f7ec2c9a33ecbf08f8e522e`, the file the corpus ran
against on the lab clone and the file committed in `dist/` after it. The one holdout left was not run, opened or read. Every
class A target was given only its bad chars and stage 1.

**Twelve of fourteen pass, as before, and both spent holdouts pass again.** Nothing moved and nothing regressed: all
sixteen targets the manifest now runs, T16 and T17 included, kept the status and the full echoed call they had on their
last run, and the screenshot rule found no violation in any section of any target. This change was about the evidence,
not reach: two defects in what the run prints, both found by the second holdout's agent and left unfixed there.

| Result | Targets |
|---|---|
| marker landed | T01, T02, T03, T04, T05, T06, T07, T09, T10, T12, and the spent holdouts T16, T17 |
| refused correctly, leak named | T13, T15 |
| still failing | T08 |
| not attempted, the target's fault | T11 |

| # | Where | Then | Now |
|---|---|---|---|
| 1 | `[6/7]` | on every crash with EIP inside a module, six targets (T01, T03, T05, T06, T16, T17), it described a crashing ret, then told the reader to run `dep_plan` at the crash it was at and to find an EIP dword it had just reported absent | `No return gap to read: EIP … faulted inside <module>, so no ret ran`, and the one line that still applies: a `ret N` in the function means `RET_GAP = N`. The `RET_GAP` comment in the block says the same. Each other unmeasured case carries its own advice |
| 2 | `[4/7]` copy block | 9 to 11 names per skeleton target, 1 on T10 and 3 on T17, that no line of the file calls or sends, and their `COST` entries | none on any target: the block and `COST` hold what the chain calls or sends |

**Why the fault is checked before the stack.** EIP inside a module means the crash is the program faulting, not a ret
through the overflow. Checking the stack first would be wrong in a quiet way: a `call` just before the faulting
instruction leaves its return address, which is that same EIP, below ESP, and the search would read it as the dword the
ret popped and print a gap measured from a ret that never ran.

**Why the uncalled gadgets were deleted and not relabelled.** He wants alternatives where swapping one in is moving a
comment marker. A gadget from a route the search dropped is not that: using it means writing another loader, so a
commented line for it would promise a swap the file cannot make. The swaps that are real stay, as `#` lines beside the
gadget they replace with their cost in `COST`. The dropped ones stay in the ranking above the separator, without the
`>`, with the `dep_candidates` command that lists them all. `Build.called` alone was not the filter: the pushad tail
sends `RET` and `JMP_ESP` as values and never calls them, so the block keeps what the chain calls or sends.

**T17 crashed differently on this run.** The same crash input that faulted on `mov dword ptr [edi], edx` inside the
executable on the holdout run returned into `0x42424242` here, and `[6/7]` measured a plain ret. The store goes through a
pointer the overflow replaced, and whether that pointer is mapped differs from one start to the next of a relocated image
(an inference, not measured). The chain landed both times, and both crash shapes now print a true line.

Figures: only step 8 on the three DEP Workflows pages showed the old line, and only those were recaptured, from this run.
No `--ref` pass was made at this commit.

## Corpus run, 2026-11-23, measured at `4a2eb50`

`dist/osed-legacy.js` sha256 `82d8412e1d047107f601f55f3a73cc5993b444b4433eb8fd2267a0ed860fdfbe`, the file the corpus
ran against on the lab clone and the file committed in `dist/` after it: one sha256 for the measured file, the committed
file and the one shipped to the VMs and to Notion, because the bundle was built from this source before the run and not
rebuilt after it. The run directory is `harness/runs/corpus-4a2eb50`; its `results.json` carries the stamp `21a05d5`,
which was this same tree `034102fb` under a commit message corrected before anything was published. The one holdout
left was not run, opened, read or grepped. Every class A target was given only its bad chars and stage 1.

**Thirteen of fourteen pass, from twelve, and both spent holdouts pass again.** T11 is the one that moved, and it moved
from the far side of the line: it was the only target the harness had never been able to fire. Nothing regressed. Every
one of the other fifteen targets the manifest runs reproduced its previous echoed call byte for byte, API, module and
style included, and the screenshot rule found no violation in any section of any target. The whole run took 1544
seconds, 604 of them Sync Breeze's service restarts and second fire.

| Result | Targets |
|---|---|
| marker landed | T01, T02, T03, T04, T05, T06, T07, T09, T10, T11, T12, and the spent holdouts T16, T17 |
| refused correctly, leak named | T13, T15 |
| still failing | T08 |

**On the denominator.** The brief for this change put the score at twelve of fourteen and said T11 becoming scoreable
makes it fifteen. It does not: T11 was already inside the fourteen, counted as a failure under "not attempted, the
target's fault" at `9d27618`, `636a034` and `132fb13`. The denominator is what the manifest runs minus the holdouts,
and spending a holdout is the only thing that has ever moved it. So twelve of fourteen before and thirteen of fourteen
after, comparable as they stand.

| # | Target | Then | Now |
|---|---|---|---|
| 1 | T11 | built a complete chain in the staged style, reached VirtualAlloc with every argument right, and faulted on a `push` inside `ntdll` at `esp=63c97df0`, a page below the module's writable section in read-only `.rdata` | the sled puts ESP back on the thread's stack before the shellcode runs, out of the frame field that already holds its own stack address. The marker lands |
| 2 | T11 | the run printed `never reached a DEP API` beside an `api_hits` entry recording that call | the grader counts a hit whose return address no loaded image holds, so the staged style's return into the sled reads as the chain's. `return_is` says `not in any loaded module` |

**The cause was not the one the brief named, and the measurements are in "Known gaps" above.** The API returned. The
room under a staged frame bounds the call, which spends hundreds of bytes; it cannot bound what the call returns into,
which spent `0x2210` in one `WinExec`. Before and after, on the same target and the same build, the API's entry ESP is
the same `63c99fec` and only the shellcode's stack moved: `WinExec` at `esp=63c99e9c` inside T11's dll `.data`, then
at `esp=0019ebf0` on the thread's stack.

**What did not move.** T08 is still the only class A failure and still refuses at the method layer for "read a pointer",
with the same echoed call as at `132fb13`. Its shape is written down under "Known gaps" and none of it is a search
tweak. The holdout that measures the honest class B exit is still held back, so the readiness answer is unchanged.

No `--ref` pass was made at this commit. Figures: the staged style's own two figures on the WriteProcessMemory page are
the only published ones this change alters, step 8 and the editor shot, and only those were recaptured.

## Target or tool: T07 and T14, 2026-11-23

Asked to separate, not to fix. Both answers are measured.

**T07 is a working lab that the harness grades wrongly, and its tool failure is the tool's.** The vulnerable
function copies into a 2048 byte buffer inside `__try`. The overflow reaches its pointer argument, and the
store through it faults at `0x0040126C` on the planted pointer. That fault is the trigger: the exploit is the SEH handler the same
overflow replaces. The harness's fire step runs `g` and, on the first break, records the registers and quits,
and cdb breaks on a first-chance access violation by default. So nothing that needs the exception to reach
its handler can pass there, which is why the reference and the tool failed at the same address. Fired again
with `sxd av` and nothing else changed, the reference lands the marker: VirtualAlloc is reached and returns
into `jmp esp`. The tool's own payload from the same run, fired the same way, ends in `c00001a5`, an invalid
exception handler: it lays a saved-EIP chain at `JOB_OFFSET` and leaves the SEH record as padding. A DEP
chain delivered through an overwritten SEH handler is a shape `dep_plan` does not model. Two pieces of work
follow, neither started: the harness should let first-chance exceptions through, and the tool needs an SEH
delivery. Changing the harness changes how every target's fault is recorded, so it is a decision, not a fix.

**Both were done on 2026-11-23, and T07 passes.** The harness rule is per target and not global: a target
whose exploit path runs through an exception carries `"through_exception": true` in the manifest, and only
then does the fire step pass first-chance access violations on with `sxd av`. A second chance still stops
it, and every other target keeps the default, because one that faults and never recovers is dead and
forgiving that fault would hide it.

**The SEH route is a delivery any style can be wrapped in, not a fourth style.** The handler overwrite
changes two things and no others: where in the payload the chain starts, and what sits around it. It
changes nothing about how the call frame is built or which register carries which argument, which is all a
style is. So `Delivery` is one value on the build input, `deliveryLines` writes the placement block, and
each of the three styles asks it for the same thing with one parameter: how much of the buffer below the
chain the style keeps for itself. The skeleton keeps `len(frame)`, because it lays the frame under the
chain; pushad and staged keep nothing. A fourth style would have duplicated all three job lists to change
an offset.

**The premise that the handler is a `pop pop ret` is wrong under DEP, and the tool says so on the screen.**
A `pop pop ret` pops the return address and the exception-record pointer and returns through the dword at
ESP+8, which is `EstablisherFrame`: the address of the SEH record itself, on the stack. That is the whole
technique without DEP, where nSEH holds a short jump into the buffer. With DEP the stack does not execute,
so it faults there. The handler has to be a gadget that adds a large constant to ESP and returns, so that
its own `ret` reads a dword the overflow wrote and takes the chain the way the vulnerable function's `ret`
would have. T07's own reference does exactly that: `add esp, imm ; ret` from its dll, chosen for the
smallest `imm` that lands inside the copied text.

The tool does not special-case the `pop pop ret` away. `handlerCandidates` asks for a fixed stack move and
a plain return and nothing but the stack touched, and `pop eax ; pop ecx ; ret` satisfies that with a
landing of 8 bytes: it is the smallest member of the same family. What rules it out is the landing filter,
which keeps only the handlers whose `ret` reads a dword the overflow wrote, above the ESP the target
faulted with and below the record. Eight bytes above the handler's ESP is inside the dispatcher's own
frames. `[6/7]` prints that as a sentence with the `!vprot` of the record behind it, so the reader sees the
reason rather than a missing option.

What the run measures, in this order. That the crash is an SEH delivery at all: EIP is still inside a
module, so no saved EIP took the overwrite, and the first record's handler is in no module, so the overflow
wrote it. Then the ESP the dispatcher calls the handler with, which no static search can give: a candidate
handler is written over the record's handler field with a breakpoint on it, the exception is let through
once, ESP is read where it hits, and the handler, the SEH head and every register are put back, so the
process is at the crash again and a second run measures the same thing. The crash's own handler cannot be
used for this, because the dispatcher refuses an address in no image before it calls it. Then how far past
the handler field the crash wrote, so the payload overwrites as far and faults the same way. On T07 the
record sits 0x1410 above that ESP and `add esp, 0xD10 ; ret` lands the chain at `OFFSET - 0x700`. The
reference's own constant agrees: its `HANDLER_ESP_TO_TEXT` is 0xC00 and the text starts at `OFFSET` 2064
below the record, and 0xC00 + 2064 is 0x1410.

**T14 is a lab that was never written.** Its folder holds only `lab.json`, which names two source files and
four guest files. None of them exists anywhere in the tree outside the holdout and the guides. Nothing
about the tool can be learned from it until it is written, built and given a reference.

## First holdout, spent 2026-11-23

**T16 passed cold. The marker landed.**

Three targets were held back from the start and never run, opened, read or grepped, because
corpus results cannot answer "is it ready": every target used to fix the tool has been taught to
it. One of the three was spent on the build shipped at `ba01d86`, `dist/osed-legacy.js` sha256
`4c40bfeb5bfb1beb55bd815cf7f5abd8e9f5d1d37a4cceb52231e36fae65b33a`. **Two remain.**

The agent running it was stopped by a model safeguard before it could write this section. The run
itself had completed, and what follows was read from the run directory and verified by the parent,
not taken from a report.

**What it was given.** The offset and the bad chars, which `GOAL.md` has always put out of scope
because they come from the crash and from the user's own hunt. Nothing else: no module, no API,
no style, no hint.

**The call, as it appears first in the transcript:**

```
dx @$osed().dep_plan("00 0a 0d 3b 23 24 a0", 1)
```

That is the short form. The long form that appears later in the same log is the tool echoing the
choices it made, which the harness then re-runs to reproduce the sections.

**What it worked out on its own:**

| Decision | What it chose |
|---|---|
| DEP | on, by system policy OptIn and the program's own NX_COMPAT |
| module | the main image; six others rejected for ASLR, counted not listed |
| API | VirtualAlloc |
| the API address | an import slot in that module, read with `mov eax, [eax]` |
| style | skeleton |
| delivery | a saved return address |
| holes left | one, the shellcode |

The chain reached `VirtualAlloc` under the harness breakpoint and the marker appeared. The
screenshot rule found **no violation in any section**, which matters as much as the pass: the
evidence it printed on a target nobody had prepared for it still fitted a picture.

**What this does and does not settle.** `GOAL.md` says the honest answer to "is it ready" stays no
until a holdout has been exploited cold at least once. That has now happened. It does not make the
answer an unqualified yes: this target is class A with gadgets in its own image, which is the
shape the corpus holds most of, so it is the easiest of the three. The two held back are a harder
class A, where only a DLL is at a fixed base, and a class B, where nothing is fixed and the right
answer is a refusal that names the leak.

## Second holdout, spent 2026-11-23

**T17 passed cold. The marker landed.**

The second of the three held-back targets, spent on the build shipped at `c31e21b`,
`dist/osed-legacy.js` sha256 `4c40bfeb5bfb1beb55bd815cf7f5abd8e9f5d1d37a4cceb52231e36fae65b33a`,
the same build T16 was measured on. The sha256 of the file on the clone was checked before the run
and matched. **One holdout remains, not two.**

Run once. Nothing was adjusted, retried or re-fired. The run took 67 seconds.

**Why this one is harder than T16.** T17 is class A, but the executable is relocated and only its
DLL sits at a fixed base, so the module choice is forced and the gadgets have to come from the
smaller image. The manifest already recorded that shape, so it was not a secret. T16 was the easy
shape: gadgets in the main image, which is what most of the corpus holds.

**What it was given.** The offset and the bad chars, both out of scope by this document. The tool
itself was given neither: it got the bad chars and the stage number. No module, no API, no style,
no hint.

**The call, as cdb received it:**

```
dx @$osed().dep_plan("00 09 0a 0d 20", 1)
```

That is the short form, and the first `dep_plan` line in the raw log. The long form is the tool
echoing back the choices it made, and it appears twice later in the same log, as the first section
title and again under `=== Verdict ===`. The module name is redacted here and nowhere else, because
this file is public and the fourth argument is the lab's own DLL:

```
dx @$osed().dep_plan("VirtualProtect", "<the dll>", "00 09 0a 0d 20", "skeleton", 1)
```

**What it worked out on its own:**

| Decision | What it chose |
|---|---|
| DEP | on, by system policy OptIn and the program's own NX_COMPAT |
| module | the DLL, the only image not relocated; eight others rejected for ASLR, counted not listed |
| API | VirtualProtect |
| the API address | the DLL's own import slot for it, read with `mov eax, [eax]` |
| style | skeleton, because the module holds no `pushad ; ret` |
| delivery | a saved return address, after the SEH route was measured and ruled out |
| holes left | one, the shellcode |

**The module choice was a discrimination, not a default.** `[2/7]` listed five import slots for
VirtualProtect, two of them in the lab's own images. It took the one in the fixed DLL and left the
one in the relocated executable, whose address changes on every start. Nothing told it which image
was relocated except its own `[1/7]` scan.

**The delivery was decided from a crash that is not a clean EIP overwrite.** The crash input faults
inside the executable on `mov dword ptr [edi],edx`, a store through a pointer the overflow replaced,
before the function ever returns. `[6/7]` read that correctly: it found the SEH record the same
overflow reached, measured the ESP the dispatcher would call a handler with by writing a candidate
handler over the record, breaking on it and putting the state back, then said no handler lands
between the faulting ESP and the record and sent the chain to the saved EIP instead. It also printed
the single missing piece for the SEH route, a gadget adding between 0xBF4 and 0x1088 to ESP, as a
conditional, not a claim. The saved-EIP route is the one that landed the marker.

**At the API breakpoint the frame was exactly what `[5/7]` and `[6/7]` promised**: lpAddress and the
return address equal, dwSize 0x201, flNewProtect 0x40, lpflOldProtect the writable cave `[5/7]`
named. The payload carried no bad char. Every value the chain patches at run time arrived right.

**The screenshot rule found no violation in any section.** The budget is 40 rows and 130 columns.
The tightest section is `[4/7]` at 35 rows, five short of the limit, and six sections touch 129 or
130 columns without passing them. The row counts are 2, 11, 12, 15, 35, 13, 14, 2 and 8.

**One defect, and it is the wrong kind.** Nothing the chain does not support is claimed about the
chain. But `[6/7]` prints two lines about the crash that the crash contradicts:

```
[!] ESP after the crashing ret: not measured, EIP 0x009448E9 is not on the stack below ESP: assumed 0, a plain ret.
[!] Run dep_plan at the crash, or find the EIP dword with dds esp-10 L8 and set RET_GAP.
```

There was no crashing ret. The process faulted on a store, which the same section says two lines
above. And the advice tells the reader to run `dep_plan` at the crash and to read the EIP dword off
the stack, when `dep_plan` was running at the crash and the line directly above it says that dword
is not on the stack. `src/index.ts:4045` prints that string whenever the landing is unmeasured, with
no test for whether the session is already at a live crash or for why the measurement failed. The
first half is unreachable advice and the second half asks for something the tool just reported
absent. It cost nothing here: `RET_GAP = 0` was right, which the marker proves. It is recorded, not
fixed, because this run was a measurement.

Fixed at `132fb13`, and it was not one target: six print it, every one whose crash faults inside a
module. See that corpus run.

**An exposure in the measurement, not in the tool.** The manifest's `api` field for this target
already held the reference exploit's two APIs, written on 2026-11-22 when the manifest was built
from every lab's reference, before the holdout rule existed. The agent spending the holdout saw it
while moving the entry out of the `holdout` list, so that agent knew one plausible API before the
run. The tool did not: `run_corpus.py` passes only the bad chars and the stage to `dep_plan` and
records the field as `ground_truth_api` in the result afterwards. The field was left in place rather
than deleted, so the next reader can weigh it. T16's was cleared because it was never read.

**What this does and does not settle.** Two holdouts have now been exploited cold, on two different
shapes, one invocation each, nothing adjusted. The second needed the forced module, the import slot
in the fixed image and a crash that gives no clean saved-EIP overwrite, and it got all three right
with no help. The one still held back is the class B shape, where nothing is fixed and the correct
answer is a refusal that names the leak. That one measures the honest exit rather than the chain, so
no pass on a class A target can stand in for it.

## Known gaps, newest first

- ~~**The staged style pivots ESP onto its frame and never puts it back, so the API it just reached dies
  on its own stack.**~~ Closed on 2026-11-23 at `2757bb1`, and **the cause written down here was wrong.**
  The API did not die. It returned, and the shellcode it returned into died.

  What the entry got right. T11 is the hardest supply in the corpus: its main image is based where the
  first bad char rules out every address in it, and the one usable module has no `pushad`, no `jmp esp`,
  no `call esp` and no `push esp ; ret` anywhere in its `.text`, so the frame has to be built in writable
  memory at a fixed address and ESP pivoted onto it. `dep_plan` got all of that right with nothing but the
  bad chars and stage 1, and reached the API with arguments correct on their face:

      HARNESS_API VirtualAlloc
      63c99fec  0019ed54     <- return, into the shellcode on the stack
      63c99ff0  0019ed54     <- lpAddress
      63c99ff4  0000013e     <- dwSize
      63c99ff8  00001000     <- MEM_COMMIT
      63c99ffc  00000040     <- PAGE_EXECUTE_READWRITE

  What it got wrong, and how. The run then faulted on a `push` inside `ntdll` at `esp=63c97df0`, a page
  below the section in read-only `.rdata`, and that was read as VirtualAlloc spending about 8 KB of stack
  and walking off the bottom. Three measurements say otherwise. The lab's own reference, which lands its
  marker, enters the same VirtualAlloc with **less** room under its frame, `0x140c` against the tool's
  `0x1fec`, so more room was what failed. Dumping the section before and after a reference run and diffing
  it dword by dword puts the call's whole footprint below its entry ESP at `0x2c` bytes. And firing the
  tool's own failing payload again with a breakpoint on `kernel32!WinExec`, which the marker shellcode
  calls, **hits it**, at `esp=63c99e9c`: the API returned, the shellcode ran, and `CreateProcess` inside
  it spent `0x2210` bytes and fell off the section. The first attempt to measure the depth read the lowest
  changed dword in the whole section and got the same answer at every frame base, because what it had
  found was a global the program writes on every run. That number had to be thrown away.

  So the step that was missing is a pivot on the **return**, not before the call, and the brief that
  described it as "before the API runs" could not have been built on T11 anyway: nothing in that module
  puts a stack address in the store's address register, which is why the frame is in `.data` in the first
  place. The reference pivots back on the return too, through four more frame dwords and a `jmp eax`.

  What shipped is smaller, and it needs no gadget and nothing kept across the call. The frame already
  holds the sled's own stack address, in a field at a fixed address, for the call's own sake; the sled's
  first instruction loads ESP out of that field. Six bytes, `mov esp, dword [FIELD]`, or
  `mov eax, dword [FIELD] ; xchg eax, esp` where the first form's bytes are bad chars, and a named hole
  where neither is clean. `stagedPops` carries that field's address now so one function still decides
  where a frame may go; it bites only where the write gadget's displacement lifts every popped address off
  the field, which is T11's `mov [ecx+0x20], eax`. Same run, after: `WinExec` at `esp=0019ebf0`, on the
  thread's stack, with the API's entry ESP unchanged at `63c99fec`. The marker landed.

  **The room under the frame is still worth printing, and it is no longer load-bearing.** It bounds the
  call, which wants hundreds of bytes, not what the call returns into, which wanted `0x2210`. No module's
  writable section holds a shellcode's stack, and what a shellcode spends is not a number this tool can
  bound, so "guarantee the room" was never implementable. `[6/7]` says both facts now.

- ~~A staged API hit read as never having happened.~~ Closed at `4a2eb50`. The run printed
  `never reached a DEP API` beside an `api_hits` entry recording that VirtualAlloc call. The grader decided
  `from_chain` by whether the return address is a chain gadget or sits within `0x10000` of ESP, and in the
  staged style it is neither: the frame is in the module and the return address is the sled on the stack. A
  return address in no image the process loaded was pushed by no code the process loaded, which is read off
  the `ModLoad` lines the fire log already carries. Replayed over every `cdb_fire.log` recorded before the
  change, 150 hits across 132 runs, it flips exactly one and leaves every program call alone. The repo has
  no Python test harness, so that replay is the regression check rather than a unit test.

- ~~**A DEP chain delivered through an overwritten SEH handler is a shape `dep_plan` does not model.**~~
  Closed on 2026-11-23, as a delivery rather than a style: see "Target or tool: T07 and T14" above for
  what was chosen and why, and what the run measures. T07 lands the marker.

  Two things fell out of it that are not obvious. **A crash that looks like an SEH delivery usually is
  not one.** The test is EIP still inside a module, so no saved EIP took the overwrite, and the first
  record's handler in no module, so the overflow wrote it; every overflow long enough to fault inside the
  program while reaching a record up the stack satisfies both, and most of the corpus does. T01 regressed
  to an unfillable hole on exactly that. What separates the two is not the crash but whether the delivery
  can be completed: a handler whose `ret` lands above the ESP the target faulted with and below the
  record reads a dword the overflow wrote. Where none does, the saved EIP stands and `[6/7]` names the
  window a gadget would have to add to ESP. And **the `pop pop ret` needs no special case.** It is the
  smallest member of the same family, a fixed stack move of 8 with a plain return, and the landing filter
  is what rules it out, because 8 bytes above the handler's ESP is inside the dispatcher's own frames.

  What this costs, and it is a real cost. The ESP the dispatcher calls a handler with cannot be read
  statically, so it is measured by letting the exception through once with a chosen handler and a
  breakpoint on it, then putting the handler, the SEH head and every register back. That happens on every
  crash that looks like an SEH delivery, which was four of the thirteen measured on 2026-11-23, and no
  cheap pre-filter rules the useless three out: the window a usable pivot has to fall in is itself a
  function of the ESP being measured.
  `measureLanding` runs before it, so the gap for the saved-EIP delivery is read off the untouched stack,
  and nothing after it reads the stack below the faulting ESP. On the corpus it disturbed nothing
  measurable, but it runs the program, and that is worth knowing before a target where it matters.

- ~~**A job was searched for only as its own instruction followed immediately by a `ret`.**~~ Closed on
  2026-11-23, and it had been reporting the scan's reach as a fact about the module. `encodingsFor` built
  `[body, ret]` and `[body, ret N]` and nothing longer, so a module holding the job and one more
  instruction read as holding none, and the run said "absent: no hit at all" and "this is the module, not
  the scan". Up to four bytes of anything may now stand between the two, which is one or two more
  instructions, and `findEncodings` drops any span that does not decode. A hit the ranking never judged
  is printed with its disassembly, so the second instruction is on the screenshot, and the summary line
  no longer claims the module is empty over a hit it has just listed. The wider search exposed two
  counting bugs: one address is matched by several encodings once a tail is allowed, so clean hits are
  deduplicated by address and dirty hits are collected as addresses rather than summed per encoding.

- **T08 refuses, and the two gadgets that would complete it are both rejected for reasons the message
  does not give.** Measured on 2026-11-23 against its own reference, which exploits it on the clone.

  The refusal is right that no chain the tool can express exists, and wrong about why. Every memory read
  in that module either writes the slot back or moves ESP:

  | Address | Gadget | Why the chain cannot take it |
  |---|---|---|
  | `0x631023EE` | `xchg dword [ecx], eax ; pop ebp ; ret` | writes the slot as it reads it, and the slot's page is `PAGE_READONLY` |
  | `0x63102553`-ish | `mov ecx, [eax+4] ; or dword [eax], 2 ; mov [eax+4], ecx ; ret` | writes through the same address twice, same fault |
  | `0x63101ED5` | `mov eax, dword [eax] ; mov esp, ebp ; ret 0x12` | reads the slot and leaves it alone, and sets ESP from EBP |
  | `0x63101E84` | `mov eax, [ebp-8] ; mov esp, ebp ; pop ebp ; ret` | the same |

  The reference reads the `WriteProcessMemory` slot with `0x63101ED5`, as the chain's **last** gadget: it
  loads the API address into EAX and pivots ESP onto the frame in one step, and the frame's first dword is
  `push eax ; adc byte [ebx+0x5d], ah ; ret`, which enters the call through the register the read just
  filled. Nothing in the tool can express that. Its staged pivot is `pop ebp, STAGING` then
  `mov esp, ebp`, and the API address is a value written into a frame field, never carried in a register
  into the call. That is the one missing shape, and it is three things, not one: a pivot that reads while
  it pivots, a frame whose entry slot pushes a register, and a frame base shifted to keep the fields
  aligned under the pivot's `ret 0x12` (the reference picks `pad % 4 == 2` for exactly that).

  **The premise that nothing in that module takes anything out of EBP is wrong.** `lea eax, [ebp - 4] ;
  mov dword ptr fs:[0], eax ; ret` sits at `0x63101EE6` at a clean address and the reference uses it.
  `effectOf` already models `lea <dst>, [<src> + disp]` as a transition; what it rejects is the second
  instruction, a store through a segment-prefixed absolute address, which `memOperand` cannot pin and the
  model therefore calls a write somewhere nobody chose. `fs:[0]` is the thread's SEH head, which is a
  perfectly chooseable address, and writing `ebp - 4` there costs the chain nothing on its success path.
  Allowing it was left undone deliberately: it moves no target, because the read above is the binding
  constraint, and `effectOf` is the one function the eleven passing targets depend on. The address and the
  reason are written down here so the next agent does not have to re-derive them.

  **ESP is genuinely needed, not demanded out of habit.** The staged style's field addresses are indeed
  constants, but `WriteProcessMemory`'s `lpBuffer` has to point at the source bytes, and the only copy of
  the shellcode is the one the overflow put on the stack. The reference computes exactly that address from
  a captured ESP. `VirtualProtect` needs one too, for the page it makes executable and for the return into
  it. No route for this target avoids a stack address.

- ~~**Both chain styles build the frame where only a run can know the address.**~~ The skeleton lays it in
  the stack buffer and PUSHAD keeps it in registers until one gadget writes it, which is why the skeleton
  needs six jobs to compute one address: capture ESP, add a distance, copy the result into the write
  gadget's address register, and walk that pointer field by field. A module with no register copy and no
  `pushad ; ret` was therefore refused outright, although a chain existed.

  A third style lays the frame at a fixed writable address in the module, so every field address is a
  constant the chain pops: per field, `pop <addr>, FRAME + n` then the write. No copy, no advance, and the
  pivot targets a constant. Its job list comes off `FRAMES` like the other two. Two things fell out of
  building it that are not obvious. The field job comes **after** the value jobs, because a constant can be
  popped again at any point while a captured pointer has to stay live, so a staged chain's value loads keep
  nothing and a gadget the skeleton refuses for clobbering the field address is usable here. And where the
  frame can go is not a property of the frame: the chain pops `field - writeOffset`, so a write through
  `[reg+4]` pops the dword below the frame too, and the pivot's own pops shift its dword as well.
  `stagingBase` walks a writable run a dword at a time until a base makes every popped address clean; one
  clean address at the head of a long cave proves nothing.

  `chooseStyle` takes fewest jobs left open, then `skeleton`, `pushad`, `staged`. That order is a
  preference and not a gadget count: nothing outside the process can touch a frame in the payload or in
  registers, while a staged frame sits in memory the program owns and nothing here proves the program
  leaves those bytes alone between the write and the call. `[6/7]` says so rather than hiding it. The
  order is also what protects the targets that already pass: staged can at best tie them, and a tie keeps
  the style they had.

- ~~**The job list is per style but not per API.**~~ `jobsFor` reads the list off `FRAMES` and
  `PUSHAD_FRAMES` in `src/commands/dep_frames.ts`, so a job can only be required by a slot that exists.
  The skeleton asks for a negate only when the frame computes a size, and the PUSHAD frame for
  WriteProcessMemory asks for five pops rather than seven, because its five arguments do not fit the four
  spare registers and two of them are never loaded. `tests/dep_plan_registers.test.ts` holds both lists.

  It moved no target. T06 and T08 were the two it was meant to free and their refusals turned out to be
  honest: a register copy is absent from both modules outright, every byte searched for all 222 plain
  encodings, and `pushad ; ret` with it. Neither existing style can be built there whatever the API.

- ~~**The write gadget's two operands are chosen without reference to the frame.**~~ A skeleton chain
  carries the field address in one register and the value in the other, and the write gadget decides
  which. The old ranking chose it for its side effects alone, so a module whose cheapest write is
  `mov [eax+4], ecx` forced every value into ECX with EAX held, and a value reachable only in EAX was
  reported out of reach although a lower-ranked write would have taken it. `planWrites` tries each
  usable candidate, re-plans the job list around it, and keeps the one whose frame the corpus can fill.
  `[4/7]` prints what each candidate could fill, so the choice is on the screenshot.

  The copy had the same blindness: it runs before the write, so nothing had bound the field and it landed
  wherever was cheapest. It is picked again once the write's register is known, and only if no single
  gadget lands there is the path search asked.

- ~~**A cost row was a leftover measured at one call site.**~~ The emitted chain pads junk for the stack
  dwords a gadget takes past the values handed to it, and read the count from one `COST` row per gadget.
  The row held the leftover from wherever the gadget was first used, so a gadget used once with one value
  and once with two could only be right in one place; and because a drop-in swap is written into `COST`
  by address, and an address can be another gadget's chain row, Python let a swap's leftover define the
  chain gadget's padding. A row now counts the dwords the gadget itself takes and the emitted `rop` pads
  `max(0, pops - len(values))`. `tests/dep_build_cost.test.ts` goes red with either half reverted.

  This is what killed T05 on the clone after its chain became complete: `pop ecx ; pop esi ; ret` was a
  chain gadget called with both its dwords and also a swap of `pop ecx ; ret` with a leftover of one, so
  the file padded one junk dword too many and the next `ret` took `0x41414141`.

- ~~**`nSize` was 0x210 in four places, so a narrower cave read as no cave.**~~ WriteProcessMemory copies
  into an executable cave, and how many bytes it copies is a fact about that cave. The cave search takes
  the largest clean one rather than the first and reports its size; the slot's value, the printed recipe
  and the loaders all read it from there. A copy smaller than the design size prints one line saying so
  and saying the shellcode has to fit. Below `WPM_MIN_COPY` the cave is still the missing piece.

- ~~Register loading follows one recipe, compute in EAX then move, instead of searching for a path.~~
  **Closed on 2026-11-22.** A register is now loaded by `ReachIndex.reach` in `src/rop/reach.ts`, a
  backward search over gadgets as register transitions. One mechanism covers every route, so a shape
  nobody wrote a recipe for is still found.

  What it covers, each with the test in `tests/reach.test.ts` that proves it:
  - a direct pop of a value the chain can send ("a clean value is one pop")
  - building in place when it cannot: pop a clean seed, then `neg`, `not`, `add`, `sub`, `inc` or `lea`
    ("a value every pop would send as a bad byte is built in place instead")
  - a move into the target by `mov`, by `xchg`, or through the stack with `push <scratch> ; pop <target>`
    ("with no mov into the target, the value goes through the stack"). The push-and-pop form is the one
    that was missing, and it is the one Sync Breeze had.
  - a hop through any register the chain does not need at that point
  - a deref chain for a value only a run can give, with the gadget's offset folded into the address the
    chain pops rather than left for the reader ("the deref offset is taken off the address the chain pops")
  - a dword written to and reloaded from a clean writable cave, when no register route exists at all
  - up to `MAX_HOPS` (8) gadgets, cheapest first by registers clobbered, junk dwords, `ret N` and length

  Evidence, both runs reproduced as fixtures in `tests/dep_plan_layers.test.ts` (`libspp.dll`, bad chars
  `00 0A 0D 25 26 2B 3D`, pushad style, no `mov esi, eax` in the module, a `push eax ; pop esi ; ret`
  present). Before, which is what his run gave him:

      def load_virtualalloc(c):          # esi = VirtualAlloc
          # virtualalloc_value: no gadget moves eax into esi
          virtualalloc_value = hole("virtualalloc_value")

  After:

      def load_virtualalloc(c):                # esi = VirtualAlloc
          # esi = [IAT_SLOT] + API_DELTA, read at run time: pop, pop, add, read, move, pop, add
          c.rop(POP_ECX, 0x01010101)              # ecx = 0x01010101
          c.rop(POP_EAX, IAT_SLOT - 0x01010101)   # eax = IAT_SLOT - 0x01010101
          c.rop(ADD_EAX_ECX)                      # eax = eax + ecx, now IAT_SLOT
          c.rop(MOV_EAX_MEM_EAX)                  # eax = [eax], now [IAT_SLOT]
          c.rop(PUSH_EAX_POP_ESI)                 # esi = eax, now [IAT_SLOT]
          c.rop(POP_ECX, API_DELTA)               # ecx = API_DELTA
          c.rop(ADD_ESI_ECX)                      # esi = esi + ecx, now [IAT_SLOT] + API_DELTA

  Cost, measured on a synthetic corpus of 1771 deduplicated gadgets in Node: 8 ms to build the index,
  350 ms for all seven registers. The pushad order is settled before any loader is written and every
  loader then asks again, which took 4816 ms until `dep_build` memoised the answers; it is 302 ms now, and
  `tests/dep_plan_layers.test.ts` guards it by asserting no question is asked of one corpus twice.
  WinDbg's engine is slower than Node, so treat these as a floor, not what Bruno sees.

- ~~The helper block emits `clean()`, which calls `p32`, without emitting `p32`.~~ Closed by `3b340a0`.

### What the register search still does not cover

Written down so the next agent does not look for it.

- **`dwSize` in the skeleton style.** Its value is chosen at run time by the emitted script
  (`while not clean(neg(size)): size += 1`), so no static search can own it: there is no number to test
  against the bad chars. It keeps the older pop-and-neg path, which needs the `[4/7]` negate pick to
  target that exact register.
- **The shellcode address slot.** A stack address patched after the chain is laid out, so it is frame
  arithmetic, not a value to reach.
- **The skeleton style's pointer plumbing** (capture ESP, add the distance, copy, advance, write, pivot).
  Those still go through `moveOps` and `arithmetic` in `dep_build.ts`, which is the one-recipe shape the
  search replaced for values. A skeleton target whose pointer cannot move between the registers those jobs
  picked still dies, with the older `no way to move ...` wording and no named unlocking gadget.
- **Two registers at once.** `reach` solves one target register per call, so a value reachable only by
  setting two together is out. `src/rop/register_setup.ts` holds a packing planner, still not wired in.
- **The memory route needs a cave.** The write-and-reload hop is offered only when `code_caves` found a
  writable dword with a clean address. Without one that whole class of route is off, and silently.
- **The search can run out of budget.** `MAX_NODES` is 40000 states. When it truncates, the message says
  so in those words instead of claiming no path exists: a truncated verdict is not proof of absence.
- **`cdq ; ret` and the one-operand `imul`, `mul`, `div`, `idiv` are rejected, not modelled.** Safe, and it
  costs real routes in a module whose only spare gadget is one of those.
- ~~**A memory read that also writes memory is not a transition.**~~ Closed on 2026-11-23, and the premise
  it was recorded under was wrong. `xchg dword [ecx], eax` reads the dword and stores the old EAX over it.
  That was written down as harmless, because the chain never needs the slot again. On the clone T08's IAT
  page is `PAGE_READONLY` (`!vprot 0x63103018`, `.rdata`), and on most modules it is, so the store half
  faults. The search now models the swap as a read, gated on the run's own `!vprot` of the slot
  (`FrameFacts.slotWritable`), and only where the swap is the gadget's sole memory access. The method layer
  refuses it for the read job on a read-only slot, with that reason on the screen, so the two layers agree.
  On T08 this moved the run from four holes in the staged style to a method-layer `STOP` naming "read a
  pointer". That is the honest exit: the module has no memory read that leaves the slot alone.
- **The captured ESP can land in a register nothing moves out of.** `[4/7]` judges the capture on its own
  and the move out of it is the build's business, so a module whose only capture is `mov ebp, esp` and
  which has no `mov <reg>, ebp`, `xchg ebp, <reg>`, `push ebp ; pop <reg>` or `add <reg>, ebp` reaches
  `[7/7]` and leaves every stack-address slot a hole. T08 again. The hole names the cause, which is one
  layer better than a refusal, and a job that tested the move would have said it at the method layer.

- ~~**The distance to the sled is one popped dword, so its sign decides whether a target is reachable.**~~
  Closed on 2026-11-23. The diagnosis recorded here missed two things in T10's module. It has
  `neg edx ; ret`, so the distance could always be popped negated and negated back. And the real blocker
  was elsewhere: the skeleton worked the shellcode's address out from the field address in ECX, and the
  only way out of ECX is `xchg eax, ecx`, which takes the field address with it. T10's reference never
  copies the field address. It captures ESP a second time in the value register and adds the distance to
  that. The skeleton now does the same when the field route fails, through the loader the staged style
  already used. The distance itself has three shapes, cheapest first: one dword the op takes as it is, one
  popped negated and negated back, or two dwords the script picks free of bad chars and adds in turn. Each
  patch carries its dwords, the payload offset its register held and its sign, so one `to_sled` serves both
  styles. T10 lands the marker on the clone. The two-dword shape is exercised by a fixture with no negate
  of the distance register, whose emitted Python is run and lands both values on the first NOP.

### What an adversarial review of the search found, and what it cost

Two reviewers were run over the finished search on 2026-11-22. Four defects came back, three of them
silent, and all four were invisible to the 949 tests that were green at the time. They are fixed, and each
fix now has a test that goes red without it, verified by reverting the fixes one at a time.

- A gadget that reads a stack dword it never steps past was taken as a transition. `mov eax, [esp] ; ret`
  loads EAX from the chain's next address and then returns into it, so the chain died at the first loader
  while the route printed "one gadget, a direct pop". `effectOf` now rejects any gadget whose deepest
  stack read sits at or above its final ESP.
- `xadd`, a sub-register `xchg` such as `xchg al, bl`, and the one-operand `imul` changed a register that
  `Effect.writes` never named, so the pool handed them out as gadgets that keep a register they destroy.
- A SIB memory source such as `mov eax, [ecx+edx*4]` recorded no read, so the gadget was usable while
  dereferencing whatever the index register happened to hold. It now records a read no expression can pin,
  which makes it unusable rather than faulting. `lea` is exempt: it reads nothing.
- A gadget wanting its value in its second dword left a hole in `Hop.values`, which rendered as
  `c.rop(ADD_ESP_4, , JMP_ESP)` and failed to parse the whole pasted file.

The lesson, and the reason those tests are shaped as they are: a corpus built from a handful of ideal
gadgets always contains a plain `pop <reg> ; ret`, which always wins on cost, so the awkward shapes are
never exercised at all. The tests under "over a generated corpus" build every shape over every register
pair and drop the lone pops, and they check the model against the disassembly rather than against itself.

### Evidence gaps found in the same review, closed on 2026-11-23

Every gap this section listed is closed. `dep_plan` scores zero violations against
`src/core/screenshot_rule.ts` on both fixture runs and on three real captures replayed through
`tools/harness/replay.ts`, and the ratchet in `tests/screenshot_rule.test.ts` is now an assertion that the
list is empty. No decision changed: the picked gadgets, the routes, the holes, the verdict and every line
of pasted code are identical to what the same runs printed before.

What each gap cost and what was done:

- **`[5/7]` was 128 lines.** `rop.construct` ran per constant and printed a recipe block and then a
  `Value Construction` table of the same facts. Both are gone; each constant keeps its value and the
  `rop.construct` call that builds it by hand. 81 rows to 15 on a real target, 91 to 17 on the fixture.
  That also closed the contradiction: the recipes targeted EAX whatever register the frame wanted, so the
  section could print a clean EAX recipe above a loader saying the register that needs it cannot be
  reached. The route list, which is what the chain does, is what the section now shows.
- **`[4/7]` was over 40 rows on 11 of 13 captures.** Two cuts. The usable candidates ranked after the pick
  were two lines each and are already commented drop-in swaps in the same section's copy block, so they
  are no longer printed above the separator; the candidates ranked *above* the pick stay, because they are
  the evidence it was not taken blind. And `find_bytes` runs quietly behind its echo, which removed the
  two-column table whose columns held the same value and the five lines of boilerplate for `call esp:
  none without bad bytes`. 57 to 37, 61 to 29, 58 to 34 on the three real targets.
- **The echo said `"auto"` for the style on every run that built a chain.** The style is the last choice
  made, so the scan and the solve now run before the header with their output held back by
  `output.capture` and replayed under `[3/7]`. A run with no corpus still echoes `"auto"`, because it
  chose nothing, and the rule's exemption for a stopped run covers it.
- **Python above the separator in `[5/7]` and `[6/7]`.** Gone with the `rop.construct` output, and the
  skeleton `[6/7]` no longer invokes `dep_function`: it was printing the call frame a second time, in
  `pack` with six names nothing defines, directly above the same frame built correctly with `p32`.
- **Width, everywhere, the widest 493 characters.** `out.info`, `out.warn` and `out.error` break a message
  at spaces before 130 columns, reading the budget from the rule itself. A `dx` call is one token, so a
  command never breaks where nobody could paste it. Copy blocks go through `output.fitted`, which breaks a
  pasted line inside its Python comment. Two lines needed their source changed instead: `COST` breaks
  after a comma inside its braces, and `settledLines` is two sentences rather than one that named the
  module twice. `[2/7]`'s 351-character conclusion is three `out.info` lines, one per fact.

What this did not touch, and is the next evidence work:

- The `[4/7]` ranking is not wrapped, because its rows are aligned in columns and a continuation of one
  could not be told from the `PICK` line under it. A module whose gadget disassembly is long enough can
  still put a row past 130. Nothing in the corpus does today.
- `[4/7]`'s height fits by how much was cut, not by construction: nine pushad jobs each with four
  candidates ranked above the pick would still exceed 40 rows. A budget that spends the rejected
  candidates against the rows left is the structural fix, and it needs the section's lines counted before
  any of them is printed.
- ~~A run with DEP off has no chain and so no style, and its echo still reads `"auto"`.~~ Closed on
  2026-11-23. That run decided something: no chain is needed. The echo writes it as the style `"none"`,
  `dep_plan` accepts `"none"` only for a process without DEP and says why otherwise, and the screenshot
  rule takes `"none"` only after the `DEP is OFF` exit.
- ~~`[1/7]` printed every module in the process.~~ Closed on 2026-11-23. It was the one section whose size
  followed the target: 60 rows on T12, 51 of them past 130 columns for their full paths. `modules("", true)`
  lists the modules without ASLR, the ones a chain can come from, names each by its file, and counts the
  rest in one line that carries the command for the whole list.

## Out of scope

The offset and the bad chars stay the user's work: they come from the crash and from his own
hunt, and a tool that guessed them would be guessing.

Nothing here licenses touching his study VM beyond `dist/osed-legacy.js` and `GUIA.pdf`, or
his own exploit files anywhere.
