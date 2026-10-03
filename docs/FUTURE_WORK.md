# Future Work

> This file collects ideas that are speculative, not started, or only loosely sketched — things
> that extend an implemented system rather than describe it. Topic docs (`LLIL_DSL.md`,
> `HLIL_GUIDE.md`, etc.) describe what's actually built; this file is where "someday" ideas live
> instead of accumulating as a growing tail on top of those docs. Each entry links back to the
> concrete doc/code it extends. LLIL-level ideas (the LLIL DSL, the writer) live in
> `docs/FUTURE_WORK_LLIL.md`.

## VM-Accurate DIV/MOD and Float Folding (`docs/MLIL_DESIGN.md`)

SCCP (`ir/mlil/passes/pass_ssa_sccp.py`) deliberately does not fold `MLIL_DIV`/`MLIL_MOD`, or any
op with a float operand, and no pass decides a branch from a float (LLIL DSL neatening plan, Step
3b) - see the Optimization Passes section of `docs/MLIL_DESIGN.md`. The one live, corpus-confirmed
bad fold the DIV/MOD part closed: `sora2_1.0/script_en/scena/mp0000_ev.dat`'s `MayaEvented_22_test`
used to print `13.0` for `400 / 30.0` (Python floor-division), which is wrong for VM float division
no matter what the VM's exact answer turns out to be. The float part closed `chr0000`'s
`AniBtlCraft01Main` printing `0.4 * 0.8` as `0.32` (a double-precision fold).

**Not started** - a real fix needs more than not-folding:
- `ScpValue` (`falcom/ed9/parser/types_scp.py`) describes the *constant encoding* (30-bit int
  payload, float32-with-2-bits-dropped), not proof of the runtime arithmetic width - whether the
  VM actually computes int ops at 30 or 32 bits is unverified.
- MOD's sign convention (Python's `%` vs. C-style truncating remainder) is unverified.
- Overflow/wrap behavior on both int and float paths is unverified.
- Float32 rounding and int/float mixing are unverified too; a verified fold would compute in
  float32, not Python doubles.
- decompiler2 may only be read **to verify** hypotheses already derived from this repo's own
  source (`ScpValue`'s encoding), never as the source of the rules. Per `CLAUDE.md` -0.1, this
  needs the user's explicit go-ahead in whatever future request actually does it - a past
  planning session having scoped this permission for Step B doesn't carry forward as standing
  authorization; ask again before reading anything under `decompiler2/`.
- None of the above can be *proven* by static analysis or corpus diffing alone - the only real
  oracle is running an affected script in-game and comparing (e.g. `MayaEvented_22_test`'s
  `camera_rotate` duration against the actual animation timing it drives). Whoever picks this up
  needs that ability, or the result stays "derived and cross-checked, not proven" like the
  analysis already done.
- If/when this lands, `pass_ssa_expression_simplification.py`'s `_apply_algebraic_identity`
  should also be audited: its identities skip float constants, but `x * 0 → 0` is still wrong for a
  float `x` (inf/NaN, `-0.0`), and the `0xFFFFFFFF` bitwise identities assume a 32-bit int against
  the VM's 30-bit constant encoding - both predate this idea and are independent of it, but a
  natural pass to make at the same time.
- Mixed int/float arithmetic is typed `int`: `SSATypeInferencePass._infer_expr_type`
  (`ir/mlil/passes/pass_ssa_type_inference.py`) falls back to `int` when `unify_types` gives
  `variant<int, float>`, which `is_numeric()` rejects. Since Step 3b leaves such expressions
  unfolded, it shows in 2 places: `chr0125` `AniFieldAttack`'s `arg1 = 0.0333 * 5` makes the
  `.mlil.asm` type `int` (was `variant<int, float>`), and `sound_ani` `SeBattleWaitingVoice`'s
  `var_s10` went from `any` to `number` in the `.ts`. Not fixed: this pass goes with the SSA layer
  in the IR rewrite, and typing resumes as its own plan; a fix would change types wherever an int
  and a float meet (e.g. `400 / 30.0`).

## HLIL Nesting Depth (`docs/HLIL_GUIDE.md`)

A call whose result is read on the right side of the VM's eager `&&`/`||` stays its own statement,
since HLIL `&&`/`||` short-circuit (`CallResultFolder` in `ir/hlil/mlil_to_hlil.py`). Inside an
`else if` chain that statement sits between `else` and the next test, so the chain can no longer
print flat and nests one level per such test: `sound.dat` `InitBGM` went from 53 to 230 indent
levels on 2026-09-24 (only 3 files in the corpus got deeper). Accepted for now as faithful output.

**Not started:**
- **Check indent levels** across the corpus: report each function's maximum nesting depth and flag
  outliers, so a readability regression like this shows up in a dump diff instead of being noticed
  by hand.
- **Keep chains flat where it's safe:** when the left operand is side-effect free and reads nothing
  the call could change (no call, deref or `REG[]`/`GLOBAL[]` load), swapping the operands puts the
  call on the always-evaluated side, so it can stay folded: `var_s2 == 102 && flag(16002) == 0`
  becomes `flag(16002) == 0 && var_s2 == 102`. It reorders operands the script author wrote, and the
  folder and the converter would have to agree on when the swap applies. A separate eager-logic node
  (HLIL, TypeScript Output) would keep every chain flat without reordering.
- **Iterative tree walkers.** The MLIL->HLIL converter, the HLIL passes and the TS generator recurse
  once or twice per nesting level, and an `else if` cascade nests one level per test (TS prints it
  flat): `InitBGM`'s ~490-level cascade needs 989 frames in the converter, just under Python's default
  limit of 1000. `falcom/ed9/scena2py.py` and `tools/ir_semantic_validator.py` raise the limit to
  10,000 for now; building cascades in a loop and walking the tree with explicit stacks would remove
  the dependence on it.

## Recompilation Pipeline (`docs/LLIL_DSL.md`)

### 1. HLIL DSL — a Python `.py` output generated from HLIL

**Planned, not started.** A second output beside `.ts`: a Python DSL file generated from HLIL (not
from bytecode) that compiles back to game bytecode. No reference to `ScpWriter`, `handle_opcode`, or
any bytecode-emission path exists anywhere in `ir/mlil/`, `ir/hlil/`, or `codegen/` today. The form,
the lowering and the hooks were worked out on 2026-09-30 (HLIL, below).
Decisions already made (2026-09-23):

```
HLIL → HLIL DSL (.py) → exec() → lower → LLIL DSL (.py, exists today) → ScpWriter → bytecode
```

- **Executed, like the LLIL DSL.** The `.py` is run against a lowering writer, so control flow is
  DSL-defined (`If`/`Elif`/`Else`, `While`/`DoWhile`, `Switch`/`Case`, `Break`/`Continue` with an
  optional loop label, `Return`) rather than native Python syntax.
- **Lowers straight to the LLIL DSL** and through today's `ScpWriter` path — the backend that already
  passes the logic round trip on the full corpus (`docs/LLIL_DSL.md` §2). No intermediate MLIL DSL; an
  MLIL-level DSL stays a separate idea, only worth building if MLIL output is wanted for its own sake.
- **No renderer shared with the TypeScript generator.** Different syntax, and a different contract:
  `codegen/typescript.py` is readable pseudocode (it folds constant comparisons and rewrites boolean
  comparisons); this output must be exact. Its natural sibling is the LLIL `.py` formatter
  (`falcom/ed9/disasm/`): exact float literals (`ScpValue.float_literal`),
  `Formatter.format_param` signatures, decorators, common-function library conventions. With TS it
  shares only HLIL-level structure helpers and language-neutral operator tables. Once it exists,
  retire `HLILFormatter` / `.hlil.ts` (an unused debug dump) — this output is the faithful HLIL view.

Design rules for an executed DSL:
- Every DSL expression's `__bool__` raises, so an accidental Python `if`/`while`/`and`/`or`/`not` or
  chained comparison fails loudly instead of being decided once, at build time.
- Logical operators are functions (`And`/`Or`/`Not`): Python can't overload `and`/`or`/`not`, and
  `&`/`|` are the VM's bitwise ops.
- Never emit an operator applied only to Python literals — Python computes `7 / 2` as `3.5` while the
  file runs, where the VM's integer DIV gives `3`. Wrap one side in a DSL constant.
- Assignments and statement-level calls need DSL forms, since `x = ...` only rebinds a Python name
  (e.g. `Set(x, e)`, or a namespace: `v.x = e`, `GLOBALS[n] = e`). A bare call statement is recorded
  explicitly, or tracked as an unconsumed call node (guarding against one node used twice). Build
  function bodies after all functions are registered, so calls to later functions resolve.
- The VM's eager logical ops and short-circuit logic recovered from jumps are separate nodes: `And`/`Or`
  lower to the VM's `LOGICAL_AND`/`LOGICAL_OR`, `AndThen`/`OrElse` to jumps (HLIL, HLIL DSL: Form). This
  replaces the earlier rule of lowering every HLIL `&&`/`||` as short-circuit and using the eager op only
  when the right side has no side effects.

**Correctness** is the logic round trip of `docs/LLIL_DSL.md` §2 (game logic unchanged, fixed point
within a few rounds), but its per-function fingerprint check can't transfer — an HLIL recompile is
not opcode-identical to its source — and a fixed point alone can't catch a decompiler bug that loses
logic in the first decompilation (the loss repeats every round). The check is the static game-logic
comparison (see "Static Game-Logic Check" below) in cross-program mode. An execution-based oracle (a
bytecode emulator) was considered and deliberately not pursued.

**Prerequisites.** Once HLIL compiles back, every HLIL pass must preserve game logic exactly, not just
readability. Before starting: calls never folded under a native VM logical op (met 2026-09-24 - see
`docs/HLIL_DESIGN.md`, Call Results as Expressions); copy propagation never
forwarding a register/global past a redefinition (met 2026-09-24 - including clobbering calls whose
record dead-code elimination drops; see `docs/MLIL_DESIGN.md`, Optimization Passes); HLIL never silently dropping a path (met
2026-09-28 - a jump the tree cannot express is an `HLILUnstructured` node, which the DSL must refuse
to compile, and `tools/hlil_path_check.py` finds 0 of 80,571 sora2_1.0 functions losing or inventing a
path; see `docs/HLIL_DESIGN.md`, Open Items); common-return extraction only hoisting from an
exhaustive switch (met 2026-09-24 - see `docs/HLIL_GUIDE.md`, Passes).

### 2. Mixed-IR-Level Compilation, Per Function

The idea: because jump opcodes don't cross function boundaries (an assumption this leans on —
worth confirming explicitly, not just assuming), a single output `.py` file could hold some
functions written at the LLIL DSL level and others at HLIL DSL level (or MLIL DSL level, if one is
ever built), each lowered independently down to LLIL DSL / bytecode.

**This needs more than independent per-function lowering to actually work**, though — even once
the jump-boundary assumption is confirmed, functions still participate in several script-wide
concerns that a per-function compile can't resolve alone: `CALL` operands and
`PUSH_CURRENT_FUNC_ID` depend on the final function table; common-function source order affects
byte layout; function offsets are assigned during whole-script compilation; labels/xrefs and
string-pool relocation are writer-global; debug records and global-variable resolution are
script-wide; per-function labels need collision-safe namespacing. A real version of this idea needs
an explicit per-function intermediate object plus a separate link/finalization phase that stitches
independently-lowered functions back into one script — not merely "lower each function on its own."

The HLIL DSL design (HLIL, HLIL DSL: Mixing LLIL and HLIL) mixes LLIL and HLIL functions without that
phase: each function lowers in place during the one `ScpWriter` run.

### 3. Knowledge-Driven Typing for Common Functions

The common-function library (`docs/LLIL_DSL.md` §3) currently derives everything purely from raw
bytecode — params are always `arg1: Value32`, `arg2: Value32`, etc. There's a real precedent in
this codebase for annotating that kind of gap externally instead of by hand-editing generated
output: `falcom/ed9/signatures/format_signatures.py` + a YAML file, which does exactly this for
TypeScript codegen (`FormatSignatureDB` supplies per-function param names/types/enum formats,
consulted by `codegen/typescript.py`).

**The idea:** once a common function's arguments and their real meaning are identified (by hand,
or by future analysis), that knowledge can be patched into the generated library the same way — a
YAML-backed `CommonFunctionKnowledgeDB`, consulted by `scp_writer_gen_common_funcs.py` between
extraction and rendering. Every generator run does a full rewrite of the output directory, so this
has to be a hook inside the generator, not a post-process edit of generated files (which would
just be overwritten on the next regeneration).

Groundwork this would need, not yet done:
- Knowledge entries keyed by the function's fingerprint digest (`docs/LLIL_DSL.md` §1), not just
  its name — the digest *is* the function's identity in this system, so a name-only key (unlike
  `FormatSignatureDB`'s today) could silently apply stale knowledge after a corpus change.
  Generation should fail loudly if a knowledge entry's expected digest no longer matches.
- The renderer's intermediate operand representation would need to preserve raw values alongside
  formatted text (it currently flattens straight to source text), if the knowledge layer should
  ever reformat a value (enum names, hex vs. decimal) rather than just rename a parameter.
- A possible `scp_writer_types.py` for named parameter types the knowledge DB introduces (e.g. an
  `ItemID` alias), distinct from the generic `Value32`/`NullableStr` aliases in
  `falcom/ed9/parser/types_scp.py`, which stay tied to raw parsed value shape, not identified
  meaning. Whether this is a new file or an extension of `types_scp.py` is an open call to make
  when this is actually built.

**Sequencing note:** this is independent of items 1-2 above — it applies to the LLIL DSL library
that exists today and doesn't need the MLIL/HLIL DSL lowering work at all.

### 4. Common-Function Library at MLIL/HLIL DSL Level

Item 1 describes lowering an entire script from a higher IR level down to LLIL DSL; a natural
extension, once that lowering exists and HLIL output is trusted, is generating a *second* common
library at that level — canonical HLIL (or MLIL) bodies for shared functions, lowered to LLIL DSL
only at the final compile step, mirroring `docs/LLIL_DSL.md` §3's design. The fingerprint/match/
render approach there doesn't assume LLIL specifically, so the concept should carry over with only
the operand-normalization details needing rework for the higher IR's shape.

This has no independent risk or design work of its own beyond what item 1 already carries — it's
gated entirely on item 1 landing and HLIL quality being trusted enough to compile back to bytecode,
not a separate open question.

## HLIL (`docs/HLIL_GUIDE.md`, Recompilation Pipeline §1)

Ideas from a review of the TypeScript output and a design discussion of the HLIL DSL (2026-09-30).
Nothing here is started. The DSL work follows the IR rewrite, which already plans eager vs
short-circuit nodes, a ternary node and a per-function fallback
(`notes/rewrite/08_decision_and_checklist.md`). LLIL-level ideas from the same discussion (the LLIL
DSL, the writer, the hook callbacks) are in `docs/FUTURE_WORK_LLIL.md`.

### TypeScript Output

The output was correct in every function traced; what it costs is readability.

- **Line markers:** print one trailing annotation per statement, or make them optional. Multi-line
  source calls produce reversed runs of `// line(N)`, and markers land between `}` and `else if`.
- **Eager logic:** give the VM's eager `&&`/`||` its own HLIL node that calls may fold into (both sides
  always run, in order). Today those calls are hoisted into temporaries, which breaks `else if` chains
  into deep nesting (HLIL Nesting Depth) and leaves wait loops as
  `while (1) { temps; if (c) break; else { wait; continue; } }`. With the node, loop recovery also
  needs `if (c) { break; } else { X; continue; }` → `if (c) break; X;`.
- **Unnamed syscalls:** a handful of syscall IDs cover most raw `syscall(...)` sites, dialogue
  `(5, 19)` first. Name them in the one naming table the DSL uses (below), and merge the `10` newline
  codes into the dialogue strings.
- **Locals:** machine names, mostly typed `any`, one stack slot reused for unrelated values, and copy
  chains such as `reg0 = f(); var_s1 = reg0; var_s0 = reg0;`.
- **Constants:** named pseudo-IDs for `65534` and the like, hex for bit flags, and float32 constants as
  the shortest decimal that encodes to the same value.
- **Calls:** print script calls as `module.f()`, as the MLIL does, not `extern_call('module:f')`, and
  leave out trailing arguments equal to the callee's declared defaults.
- **Structure:** don't split an `else if` chain into `switch` fragments when it has conditional arms
  (`var0 == N && !flag(M)` can't be a `case`: a set flag must reach later arms and the final `else`);
  don't invert an empty arm into `!= N` and nest the rest under it; drop a `break;` after arms that all
  return; don't let common-return extraction turn early-return guards into empty arms.
- **Fidelity:** keep what the bytecode distinguishes: `return;` (raw zero) vs `return 0`, and locals the
  source declared but never read (dead-code elimination drops them today).

### HLIL DSL: Recompile Path

- **Lower into the LLIL DSL.** HLIL lowers into the LLIL DSL's opcode API and `ScpWriter` writes the
  file; it already owns operand encoding, labels, the function table, the string pool, globals, debug
  records and library linking. No second bytecode emitter and no MLIL DSL. Lower in-process;
  optionally dump the lowered stream as LLIL DSL text for debugging.
- **Exactness first.** The primary check is that an unedited function recompiles to its original
  opcodes (the per-function fingerprint, ignoring line markers); the static game-logic comparator
  (Static Game-Logic Check, below) covers the rest. Measure the exact-match rate.
- **Stack checks.** The lowering tracks the stack pointer itself; re-lifting the compiled output with
  the LLIL lifter checks stack discipline (`docs/FUTURE_WORK_LLIL.md`, Writer).
- **What HLIL must keep for exact recompiles:** raw vs typed constants (`is_raw` exists only in LLIL
  today); which jump opcode was used (a "true arm is the fall-through" bit); block-scoped locals,
  including never-read ones and unused stores; stack temporaries rather than named locals; `reg0` as a
  register; constant expressions unfolded (`1 | 32768`); bare truth tests vs `!= 0`; eager vs
  short-circuit logic; a tail-call node; the compiler's switch pattern. Loop rotation, switch recovery,
  return hoisting and region cloning are not worth inverting; the comparator covers those functions.
- **Shared stack model.** One stack-effect table shared by the parser, the LLIL lifter and the
  lowering, and the lowering designed as a pair with the rewrite's translator.
- **Two layers.** Structured statements lower to labels and jumps; the bottom layer lowers expressions,
  assignments, calls, labels and jumps. The bottom layer can compile the rewrite's MLIL directly: a
  round-trip test that isolates translator bugs from structuring bugs.
- **Small blockers:** `CALL` resolves functions by their Python `__name__`; `debug_argc` cannot be
  rebuilt from HLIL (it only affects debug records); `HLILSyscall.subsystem`/`cmd` are annotated `str`;
  `ScpWriter.run2` always writes to disk, while exactness checks want an in-memory compile.

### HLIL DSL: Form

Executed Python in the style of decompiler2's ED8.x output: every statement is a call that builds a
node, and blocks are Python lists. Chosen over `with` blocks, def/lambda bodies, decorator blocks,
begin/end markers, parsing native Python syntax, and `Block(...)` objects. `CheckSBreak`, traced
against its original opcodes, lowers to exactly them:

```python
@scena.HLILCode()
def CheckSBreak(arg1: Value32, arg2: Nullable32 = 2):
    v = Locals('var_s2', 'var_s3')
    If(arg1 == 3, [
        Let(v.var_s2, chr_info(65534, 0)),
        If(btl_check_condition(v.var_s2, 26, 0), [
            If(btl_get_chr_info(v.var_s2, 18), [Return(0)]),
            Let(v.var_s3, 0),
            btl_chr_list_init(v.var_s2, Int(1) | 32768),
            While(btl_chr_list_get_remain(v.var_s2) > 0, [
                Set(v.var_s3, v.var_s3 + 1),
                btl_chr_list_next(v.var_s2),
            ]),
            If(v.var_s3 == 0, [Return(0)]),
            If(chr_info(v.var_s2, 35), [Return(0)]),
            If(btl_get_sys_info(4) != v.var_s2, [Return(1)]),
            If(btl_get_condition_remain_turn(v.var_s2, 26) == arg2 - 1, [Return(1)]),
        ]),
    ])
    Return(0)
```

- **Ownership:** every node registers when it is created, and a parent (`If`, `While`, `Set`, a call's
  arguments) claims what is passed to it; unclaimed statements are the function's top level, in order.
  A statement and everything it claims must be one unbroken run of creation order, so a node kept in a
  Python variable and used later (which would move a call), a node claimed twice, and an unclaimed
  non-statement (`arg1 = arg1 + 1`) all raise. Build each function in isolation, validate it, then
  lower it; record each node's file and line for error messages.
- **Locals:** `Let` declares (where the source's declaring push is) and `Set` assigns. `Locals(...)`
  makes a typo an `AttributeError`; `Set` on an undeclared local and a second `Let` in one scope raise.
  The end of a block frees the locals declared in it; `Scope([...])` covers a lifetime that is not a
  control block. Script globals are `this.x`.
- **Calls:** `f()` is a `CALL` by table index, `script.<module>.f()` a `CALL_SCRIPT` (`script['']` for
  the empty module name the bytecode also uses), `TailCall(...)` the tail-call sequence. Generated
  scripts star-import the shared library, whose functions are LLIL bodies that emit opcodes when
  called, so a bare call must never run one. Wrap each library function in a stub
  (`@library_function`): the body is unchanged, and the one name builds a call node in an HLIL body,
  still works as `CALL(f)` in LLIL code (it keeps `__name__`), and tells the writer to compile the body
  when listed in `@scena.CommonImports()` (`functools.update_wrapper` keeps the writer's signature
  handling working). The script's own decorators return stubs too. While an HLIL body is being built,
  an opcode call only builds a node that `EmitLLIL` must claim (Mixing LLIL and HLIL, below), so a
  leftover raw body fails loudly.
- **Jumps:** `JumpIfFalse`/`JumpIfTrue` (`POP_JMP_ZERO`/`POP_JMP_NOT_ZERO`), `Label` and `Jump` mix with
  blocks in one function: structure what is clean, jump elsewhere. Labels are per function and named by
  order, not address. A jump must arrive with the same live locals; `Break`/`Continue` free inner
  locals first.
- **Switch:** `Switch(value, [Case(k, [...]), ...], default = [...])` lowers to the compiler's own
  pattern: `SET_REG 0`; per case `GET_REG 0; PUSH_INT k; EQ; POP_JMP_NOT_ZERO`; a jump past the cases;
  the bodies in order, each ending in a jump to the end. A list rather than a dict keeps `1` and `1.0`
  apart.
- **Operators:** `And`/`Or`/`Not` are the VM's eager `LOGICAL_AND`/`LOGICAL_OR`/`EZ` and may contain
  calls, so eager chains print flat; `~` is bitwise `NOT`; `x == 0` is a real comparison; `/` is `DIV`
  and `%` is `MOD`; operators the VM lacks raise; a bare value as a condition emits no comparison.
  `AndThen`/`OrElse` are short-circuit logic recovered from jumps, allowed only in conditions and
  lowered to jumps. Operands evaluate left to right, call arguments right to left (last pushed first);
  warn when an edit puts two calls in one argument list.
- **Other statements:** `Return(n)` computes its `POP` from the live locals and parameters; `Return()`
  is the raw-zero return. Out-parameters are `Ref(x)` (`PUSH_STACK_OFFSET`), `Deref(p)` and
  `Set(Deref(p), value)`, only on `Pointer` parameters. `Syscall(subsystem, cmd, ...)` covers unnamed
  syscalls, and `EmitLLIL(...)` places LLIL opcodes for a region no HLIL node expresses (Mixing LLIL
  and HLIL, below). `do … while` and labelled `break` are deferred: the sora2 output has neither.
- **Python traps:**
  - a missing comma before a line starting with `[` or `(` parses as a subscript or a call, so nodes'
    `__getitem__` and `__call__` raise "missing comma?";
  - defining `__eq__` makes nodes unhashable, so the registry keys by `id()`; forbid
    `__int__`/`__float__`/`__index__`;
  - reject Python `bool` and `None` (`ScpValue(True)` fails with a bare `KeyError` today);
  - print with Python's operator precedence, not C's (`a == b & c` is `a == (b & c)`), and make chained
    comparisons raise;
  - Python folds an operation between two literals before the DSL sees it (`1 | 32768`, `7 / 2`), so
    the printer wraps one side (`Int(1) | 32768`) and an optional lint flags hand edits;
  - keep `1` and `1.0` distinct, and emit `# fmt: off` so formatters don't reflow the lists;
  - warn when a function's last statement is not a return or a jump (a bare Python `return` stopped
    the build early); `return Return()` stays a deliberate early exit.
- **Line numbers:** none in the DSL; re-emitting them from per-statement data is future work.
- **Printer:** one statement per line, a trailing comma on every list item, comments allowed inside
  brackets; named pseudo-IDs, hex bit flags, the shortest float that encodes identically.
- **Python limits:** nesting stops at 99 levels (200 nested brackets; `with`/`if` hit the same limit
  through indentation), and very long method chains overflow the compiler (an `.Elif` chain of 3,000
  arms compiles on Python 3.14, 10,000 does not). Past about 90 levels the printer falls back to
  jumps; tree walkers should be iterative.
- **Tooling:** generated `.pyi` stubs and explicit imports; keyword arguments for wide calls once the
  knowledge DB (Recompilation Pipeline §3) names parameters; one syscall naming table used by both the
  printers and the writer (the raw ED9 syscalls have no name anywhere in the game data).

### HLIL DSL: Mixing LLIL and HLIL

One `.py` can hold functions at both levels: `@scena.HLILCode()` and `@scena.HLILCommonCode()` beside
today's `@scena.LLILCode()` and `@scena.LLILCommonCode()`. The decompiler prints HLIL and keeps a
function at LLIL level only when it has to.

- **One writer run, no link phase.** `ScpWriter.run2` builds the function table from every registered
  function before it runs any body, then runs the bodies in file order into one code buffer; labels,
  strings and globals are writer-wide. An HLIL function lowers in place, at its turn, so `CALL` and
  `PUSH_CURRENT_FUNC_ID` resolve across levels without the link phase Recompilation Pipeline §2
  expected. HLIL labels are per function (Form), so the lowering prefixes them unless the writer gets
  per-function label namespaces (`docs/FUTURE_WORK_LLIL.md`, Writer).
- **HLIL functions** register like LLIL ones (parameters, flags and defaults from the signature). At
  its turn the body runs with parameter nodes to build the tree, which is validated, passed to the tree
  hooks and lowered onto the writer. Both kinds of decorator return stubs, so the levels call each
  other by name: `f()` in HLIL, `CALL(f)` in LLIL.
- **`EmitLLIL`** places LLIL opcodes in an HLIL body, for an opcode no HLIL node expresses or a patch
  that needs exact opcodes. It takes one opcode or a list, like the other blocks. The list holds opcode
  calls and `label('x')` items (the `def _x(): pass` line can't sit in a list), and is emitted in order
  where it stands, never folded, reordered or dropped. While an HLIL body is built, `handle_opcode`
  (which every opcode function calls) and `label()` return nodes instead of writing, and only
  `EmitLLIL` may claim them. Chosen over `ExactLLIL`, since "exact" already names the exact recompile
  check.
- **Stack contract.** The HLIL compiler owns the stack layout and addresses every parameter and local
  from it, so a list that disturbs it compiles silently into reads and writes of the wrong slots, a
  `RETURN` that pops the wrong frame, or a loop that grows the stack each pass. A list therefore:
  - pops only what it pushed, and ends at the depth it started at or in a `JMP`;
  - reaches parameters and locals only by name (`LOAD_STACK(v.var_s5)`), with the offset worked out at
    that item, counting the list's earlier pushes. Numeric offsets reach only values the list pushed.
    The five stack-offset opcodes (`LOAD_STACK`, `LOAD_STACK_DEREF`, `PUSH_STACK_OFFSET`, `POP_TO`,
    `POP_TO_DEREF`) accept a name as well as a number;
  - holds no `RETURN` or tail call, whose `POP` needs the frame size only the compiler knows; `Return`
    and `TailCall` follow the list instead;
  - jumps only where depths agree: the depth at a label equals the depth at every jump to it, across
    the list's edge too.
- **Checked when built.** The lowering checks each list with the shared stack model (Recompile Path),
  and its errors name the variable to use ("`LOAD_STACK(-8)` here is `v.var_s5`"). Re-lifting the
  output would catch an imbalance, but not a numeric offset that lands on the wrong variable.
- **Fallback.** A function is printed with `@scena.LLILCode()` when structuring leaves an
  `HLILUnstructured` node, when it uses a construct the DSL has no form for, or, in an exact mode, when
  it does not compile back to its original opcodes. The decompiler runs that check while writing the
  file, so an exact-mode file recompiles exactly by construction.
- **File names.** The mixed file is `<stem>.py`, and the pure LLIL listing becomes `<stem>_llil.py`
  (named in `falcom/ed9/scena2py.py`). Both compile to `<stem>.dat` and import the same
  `<stem>_hook.py`, whose name comes from the `.dat` name (`gen_hook_import`,
  `falcom/ed9/parser/scp.py`). The round-trip validator's `{stem}.py` and `{stem}_out.py` are internal
  run files and can keep their names.

The debug print in `ai_chr5122_e00`'s `CheckAlgoUse`, written as opcodes to show a list (the printer
would use a statement for it, as the TypeScript output does with `debug.log`):

```python
If(btl_check_resist_condition(65507, 50, 0) == 0, [
    EmitLLIL(DEBUG_SET_LINENO(192)),
    EmitLLIL([
        LOAD_STACK(v.var_s5),     # +1, compiles to LOAD_STACK(-8)
        PUSH_STR("駆動解除レジストできないやつ発見：chrid："),   # +1
        DEBUG_LOG(2),             # -2, pops both
    ]),
    Return(1),
]),
```

### HLIL DSL: Hooks and Patching

Hook files keep decompiler2's ED8.x layout: each script `<stem>.py` imports the `<stem>_hook.py` next
to it, and a build script runs each `.py` (which compiles it) and moves the `.dat` into the game's
patch folder. The writer callbacks the hooks register with are an LLIL-level change
(`docs/FUTURE_WORK_LLIL.md`, Writer).

- **Two styles, mixable in one file:** decompiler2's raw callbacks (`registerFuncCallback`,
  `registerRunCallback`, `registerOpCodeCallback`) and decorator shorthand over the same calls:
  `@replace_function('Name')`, `@add_function`, and `Original()`, which inlines the replaced body (in
  the executed list form, calling the original body inlines it; the replacement then shares its
  locals). Raw callbacks remain for pattern-based logic, such as every function named `AniBtl*`. The
  writer checks that every target a hook names exists and warns when two hooks replace the same
  function.
- **Tree hooks for HLIL functions:** `@edit_function('Name')` edits the built tree anchored by content
  (`f.find_call('btl_chr_list_init').insert_after(...)`), and `@on_call('set_flag')` rewrites a call
  across the script. Inside callbacks, nodes are inspected with plain accessors (`.name`, `.args`,
  `.value`), since DSL operators build nodes.
- **Text patches:** keep addresses out of the printed text (labels by order), make the printer
  deterministic, and test that decompile → compile → decompile reproduces the file. After one recompile
  the LLIL round trip already differs only in `loc_` label lines (`docs/LLIL_DSL.md` §2), so an
  ordinary unified diff made against a decompiled script also applies to a recompiled one. Record the
  decompiler version a patch was made against. Anchoring patches to original bytecode addresses was
  rejected: it ties a patch to one `.dat`. Original source line numbers could later serve as anchors
  that survive decompiler changes.

```python
# chr0000_hook.py
from ed9_hlil import *

@replace_function('AniBtlCraft05Main')
def AniBtlCraft05Main(arg1: Value32 = 0):
    effect_load(65534, 5040, "battle/cr0000_50_9", 1)
    Original()

@add_function
def GiveAllItems():
    for item in range(0x80, 0xFF):
        item_add(item, 1, 0)
    Return()

def funcCallBack(name, func):
    if name.startswith('AniBtl'):
        ...

get_scena().registerFuncCallback(funcCallBack)
```

### Open Questions

- **Calls:** stubs (bare names, above) or namespaces (`lib.chr_info(...)`, `this.Foo(...)`). Leaning
  stubs: namespaces can't collide with anything, but they put a prefix on most statements.
- **Literals:** wrap only operations between two literals, or every literal operand in generated
  output.
- **Very long `else if` chains:** keep `.Elif` with the printer guard, or print a flat form
  (`c = If(...)` followed by one `c.Elif(...)` statement per arm, or one call holding every arm).
- **Switch order:** whether the compiler ever lays case bodies out in a different order from its
  tests; if it does, `Switch` needs a way to record both (for example `tests = [...]`).
- **Hooks across levels:** whether a replacement is written at the replaced function's level, and what
  `Original()` does when the levels differ (an LLIL body can't go in an `EmitLLIL` list: it pops its
  own frame and returns).

## Structuring the Remaining Reducible Shapes (`docs/HLIL_DESIGN.md`)

Since 2026-09-28 a jump the HLIL tree cannot express becomes an `HLILUnstructured` node: loud, but the
path is lost to the reader (and to a future HLIL DSL). None remains on the sora2_1.0 corpus. On random
CFGs (`tests/test_hlil_structuring_fuzz.py`'s generator) 96 of 6,000 are reducible yet get a reachable
node - a reducible CFG can always be structured, so these are converter gaps; the 14 among the test's
1,000 seeds are pinned, so a new one fails the suite. Two causes (nodes counted over those 96):

- 57 fall-outs to a merge that a loop lies in front of: a loop with several non-returning exits keeps
  one as its `break` target, and a path leaving through another one cannot reach the enclosing merge
  by falling out of the loop body.
- 46 re-emissions refused because the region reaches the active loop's header, where
  `_reconstruct_control_flow` would in fact emit `continue` (or at an exit, `break`).

Options, cheapest first: let `_clone_region_blocks` treat the active loops' headers and exits as
region boundaries instead of refusing; express a loop with several exits with a labelled block
(`label: { ... break label; }` is valid TypeScript) or an exit flag; keep goto emulation
(`while (true) switch (state)`) for irreducible regions only. Measure each change with the fuzz test
(no wrong run, fewer pinned seeds) and with `tools/hlil_path_check.py` over the corpus.

## Static Game-Logic Check (`tools/ir_semantic_validator.py`)

The validator already tracks game logic as *effect events* — engine/script calls, global writes,
returns — plus branch conditions, and matches them LLIL → MLIL → HLIL on the in-memory IR that the
`.llil.asm`/`.mlil.asm` dumps are printed from (it should keep reading the IR objects; parsing the dump
text back would be fragile). Its known-noise and real-signal categories are documented in
`notes/validator_guide.md`, including its current limitations: it builds no LLIL/MLIL control-flow edges
and links only some HLIL ones (edges feed block matching only, never a pass/fail gate - fix all three
builders together, since fixing one side alone makes block matching worse), and branch conditions
carry no expression, so a changed condition is not detected. Global writes are matched on all three
layers (a dropped one shows as `missing_write_anchor`). For MLIL -> HLIL, `tools/hlil_path_check.py`
already checks control paths: every reachable call and store appears, and each HLIL occurrence of a
statement is followed by exactly what MLIL runs next - but it cannot see which way a condition sends
control either, so a negated condition passes both tools. **Not started:**

- **Compare effect arguments and values**, resolved to layer-neutral expressions over inputs
  (parameters, global reads, earlier call results). Today events are keyed `family:target` only, so a
  call with changed arguments, or a return with a changed value, still matches.
- **Compare each effect's guard** — the branch conditions it runs under (control dependence, which needs
  real CFG edges, condition expressions and a post-dominator analysis - none of which the validator has
  today), treating the right side of HLIL `&&`/`||` as
  conditional. This catches an always-run call becoming conditional, and should also remove two
  known-noise categories (matches paired across mutually exclusive branches; duplicated calls counted
  as "added").
- **Provenance for HLIL `if`/`while`/`switch`** (deferred from the Codex IR review plan's Step E,
  2026-09-27). No HLIL `if`/`while`/`switch` carries an `mlil_index` (17,673 of them in a 500-file
  sample), so no branch condition is ever provenance-matched MLIL -> HLIL. A prototype that stamped
  them from their MLIL branch (the `mlil_to_hlil.py` construction sites and the control-flow pass's
  rebuilt `if`/new `switch`) changed no HARD_FAIL on 7 files, since conditions compare no operands; it
  only moved per-operation statuses (`mp2000`: 55 MLIL `IF` vs HLIL `SWITCH` and 17 `IF` vs `WHILE`
  newly "different", for lack of a transformation rule). Do it together with comparing condition
  expressions and add `IF` -> `WHILE` / `IF` -> `SWITCH` rules (a call folded into a condition already
  keeps its own MLIL call's index, since 2026-09-28). With it, and a note of which arm is the
  condition's true side, `tools/hlil_path_check.py` could check condition polarity as well.
- **Cross-program mode** for compile-back: source `.dat` vs recompiled `.dat`, both at LLIL — the
  least-transformed level, so decompiler bugs and lowering bugs both show. There are no provenance
  links across two programs, so matching leans on order, guards and arguments; legitimate
  restructuring (a switch vs an if-chain, duplicated regions) needs normalizing.

**Limits:** it flags differences but can't prove equivalence; heuristic matching can pair the wrong
events; loops are approximate. With arguments and guards compared it is a strong regression net —
both live bugs found by the 2026-09-23 review (a deleted global restore; an always-run call folded
under a short-circuiting `&&`) would have been flagged. Useful for the decompiler today (within one
decompilation), and the correctness gate for the HLIL DSL (Recompilation Pipeline §1).

## Generic/Falcom Boundary (`docs/ARCHITECTURE.md`)

`ir/` and `common/` are meant to be generic, with game code under `falcom/`, and nothing generic imports
`falcom/`. `codegen/` is game output (user, 2026-10-02): it reads only HLIL and nothing in `ir/` depends on it, so
game knowledge there can't spread back into the IR. An audit (2026-10-02, Fable and Codex, read-only) found ED9
knowledge in generic code anyway. None of it is a bug, and with one VM it costs nothing today. Decided with the user:

- **Removed by the IR rewrite:** the Falcom type names in the SSA type pass
  (`ir/mlil/passes/pass_ssa_type_inference.py:307`), the parameter-slot mapping in
  `ir/mlil/llil_to_mlil.py:101`, `MLILCallScript`, and the generic `RegStore`/`RegLoad`/`Syscall` translation
  that only the Falcom translator has. The rules for the new translator are in
  `notes/rewrite/08_decision_and_checklist.md` (Checklist, "Boundary rules").
- **Small moves that change no output (for the opcode-table plan):**
  - `LLIL_PUSH_CALLER_FRAME`/`LLIL_CALL_SCRIPT`/`LLIL_CALL_SCRIPT_NO_RETURN` leave the generic enum
    (`ir/llil/llil.py:74-77`) for `LowLevelILFalcomOperation`, numbered after `LLIL_DEBUG_LOG` like the global ops.
  - `LLILFormatter`'s ED9 shapes (`REG[n] = STACK[--sp]`, `if (STACK[--sp] ...)`, `ir/llil/llil_builder.py:786-805`)
    move to `FalcomLLILFormatter`.
  - "Parameters are on the stack at entry" (`_seed_entry_state`, `ir/llil/llil_builder.py:117-123`) becomes a
    `FalcomVMBuilder` override; the generic default starts with an empty stack.
- **Game-specific by design:** all of `codegen/` - the TypeScript header (`generate_typescript_header`: `GLOBALS`,
  `REGS`, `debug.log`, `extern_call`, `syscall`), the syscall and extern-call rendering, and its use of the signature
  database; no change planned. If a second game ever needs different output, that is the time to move or split it.
- **Noted as game-specific, no fix scheduled:** the `(subsystem, cmd)` syscall pair that runs through LLIL, MLIL
  and HLIL (`ir/llil/llil.py:558`, `ir/mlil/mlil.py:561`, `ir/hlil/hlil.py:383`) and the signature lookup by that
  pair (`ir/mlil/mlil_types.py:153`).
- **Left as is:** `is_raw` on constants, 4-byte slots (`WORD_SIZE`), 32-bit ints, the call-clobber model, and
  comments that say "ED9"/"SCP" (reword when touched). `is_common_func` on the generic function containers is read
  only by a `codegen/` path that never runs (nothing calls `set_signature_db`); decide when the signature database
  is wired in.
- **Floats:** generic code prints floats without knowing their width - the Falcom lifter attaches the display text
  as a `SourceFloat` (`ir/core/il_literals.py`; LLIL DSL neatening plan, Step 4, done).
