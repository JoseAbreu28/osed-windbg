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

Add a target whenever one teaches a shape the corpus does not already hold. Record what
shape it adds, not just that it was added.

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

    py -3.12 tools/harness/run_corpus.py <manifest.json> [--only NAME ...] [--ref] [--out DIR]

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

## Known gaps, newest first

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
- **A memory read that also writes memory is not a transition.** `effectOf` refuses any gadget that stores
  through an address the search cannot pin, so `xchg dword [ecx], eax` is unusable as a deref although the
  dword it clobbers is the one the chain just read and never needs again. Measured on T08 with the replay
  lever at `e596453`: it is that module's only memory read, `[4/7]` picks it for the read job, and
  `load_virtualalloc` is still a hole. The method layer and the value search disagree about one gadget.
- **The captured ESP can land in a register nothing moves out of.** `[4/7]` judges the capture on its own
  and the move out of it is the build's business, so a module whose only capture is `mov ebp, esp` and
  which has no `mov <reg>, ebp`, `xchg ebp, <reg>`, `push ebp ; pop <reg>` or `add <reg>, ebp` reaches
  `[7/7]` and leaves every stack-address slot a hole. T08 again. The hole names the cause, which is one
  layer better than a refusal, and a job that tested the move would have said it at the method layer.

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
- A run with DEP off has no chain and so no style, and it prints no `STOP`, so the rule's echo exemption
  does not cover it and its echo still reads `"auto"`. Either the run should say it stopped, or the rule
  should know that a run needing no chain made no choice. Not in the measured set, so not yet decided.

## Out of scope

The offset and the bad chars stay the user's work: they come from the crash and from his own
hunt, and a tool that guessed them would be guessing.

Nothing here licenses touching his study VM beyond `dist/osed-legacy.js` and `GUIA.pdf`, or
his own exploit files anywhere.
