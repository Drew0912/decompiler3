# Future Work

> This file collects ideas that are speculative, not started, or only loosely sketched — things
> that extend an implemented system rather than describe it. Topic docs (`docs/dsl/LLIL_DSL.md`,
> `docs/hlil/HLIL_GUIDE.md`, etc.) describe what's actually built; this file is where "someday" ideas live
> instead of accumulating as a growing tail on top of those docs. Each entry links back to the
> concrete doc/code it extends.

## Index

| File | Open items |
|---|---|
| `docs/dsl/DSL_FUTURE_WORK.md` | LLIL DSL, writer and listing ideas (most done; a Not Doing list); Recompilation Pipeline: the HLIL DSL overview and decisions, mixed-IR-level compilation, knowledge-driven typing for common functions, the common-function library at MLIL / HLIL DSL level |
| `docs/dsl/HLIL_DSL.md` | the HLIL DSL design: recompile path, form, mixing LLIL and HLIL, script-facing modules, open questions |
| `docs/dsl/HOOKS.md` | HLIL DSL hooks and line-anchored patches (after the HLIL DSL writer) |
| `docs/mlil/MLIL_FUTURE_WORK.md` | VM-accurate DIV/MOD and float folding (needs an in-game oracle) |
| `docs/hlil/HLIL_FUTURE_WORK.md` | HLIL nesting depth, TypeScript output readability, the remaining reducible shapes |
| this file | the static game-logic check, generic / Falcom boundary leftovers, ED8 support, `kuro1` byte-exact debug records |

## Static Game-Logic Check (`tools/ir_semantic_validator.py`)

The validator already tracks game logic as *effect events* — engine/script calls, global writes,
returns — plus branch conditions, and matches them LLIL → MLIL → HLIL on the in-memory IR that the
`.llil.asm`/`.mlil.asm` dumps are printed from (it should keep reading the IR objects; parsing the dump
text back would be fragile). Its known-noise and real-signal categories are documented in
`docs/VALIDATOR_GUIDE.md`, including its current limitations: it builds no LLIL/MLIL control-flow edges
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
- **Provenance for HLIL `if`/`switch`** (deferred from the Codex IR review plan's Step E,
  2026-09-27; loops carry their header's last instruction since the IR rewrite's part 1, Step 4,
  which the logic check names them by). No HLIL `if`/`switch` carries an `mlil_index`, so no branch
  condition is ever provenance-matched MLIL -> HLIL by the validator. A prototype that stamped
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
decompilation), and the correctness gate for the HLIL DSL (`docs/dsl/DSL_FUTURE_WORK.md`, Recompilation Pipeline §1).

## Generic/Falcom Boundary (`docs/ARCHITECTURE.md`)

An audit (2026-10-02, Fable and Codex, read-only) found ED9
knowledge in generic code anyway. None of it is a bug, and with one VM it costs nothing today. Decided with the user:

- **Removed by the IR rewrite:** the Falcom type names in the SSA type pass
  (`ir/mlil/passes/pass_ssa_type_inference.py:307`), the parameter-slot mapping in
  `ir/mlil/llil_to_mlil.py:101`, `MLILCallScript`, and the generic `RegStore`/`RegLoad`/`Syscall` translation
  that only the Falcom translator has. The rules for the new translator are in
  `notes/rewrite/08_decision_and_checklist.md` (Checklist, "Boundary rules").
- **Small moves, done by the opcode-table plan** (Step 7 `89063e4`, no output change; Step 7b `f8f4682` changed only
  the `POP_TO_DEREF` lines of `.llil.asm`):
  - `LLIL_CALL_SCRIPT`/`LLIL_CALL_SCRIPT_NO_RETURN` live only in `LowLevelILFalcomOperation`
    (`falcom/ed9/ir/llil/llil_ext.py`) with the global ops, numbered after `LLIL_DEBUG_LOG` (`LLIL_PUSH_CALLER_FRAME`,
    moved with them, was later removed with its node, which no block ever held).
  - The pop shapes are `FalcomLLILFormatter`'s: a shape is Falcom's when the pop it shows is done by a
    `FalcomVMBuilder` method that hides it (`set_reg`, `pop_jmp_zero`/`pop_jmp_not_zero`, `pop_to`, `pop_to_deref`:
    `REG[n] = STACK[--sp]`, `if (STACK[--sp] ...)`, two `= STACK[--sp]` stores, `*ptr = STACK[--sp]`; `set_global`'s
    `GLOBAL[n] = STACK[--sp]` already was). The generic `LLILFormatter` prints the IR's own text; the binary/unary
    expansion (`rhs = STACK[--sp]` ...) stays generic, since the generic builder's binary and unary operations pop
    their operands.
  - Kept generic: "parameters are on the stack at entry" (`_seed_entry_state`, `ir/llil/llil_builder.py`) - the
    generic slot rule (`_holds_parameter`) and `tests/llil_tests/test_llil_slot_lifetime.py` assume parameters at the
    frame base.
- **Game-specific by design:** all of `codegen/` - the TypeScript header (`generate_typescript_header`: `GLOBALS`,
  `REGS`, `debug.log`, `extern_call`, `syscall`) and the syscall and extern-call rendering; no change planned. If a
  second game ever needs different output, that is the time to move or split it.
- **Noted as game-specific, no fix scheduled:** the `(subsystem, cmd)` syscall pair that runs through LLIL, MLIL
  and HLIL (`LowLevelILSyscall`, `MLILSyscall`, `HLILSyscall`).
- **Left as is:** `is_raw` on constants, 4-byte slots (`WORD_SIZE`), 32-bit ints, the call-clobber model, and
  comments that say "ED9"/"SCP" (reword when touched).
- **Floats:** generic code prints floats without knowing their width - the Falcom lifter attaches the display text
  as a `SourceFloat` (`ir/core/il_literals.py`; LLIL DSL neatening plan, Step 4, done).

## ED8 Support (`dc3/fileio.py`, `falcom/ed9/disasm/ed9_optable.py`)

**Planned, not started** (user, 2026-10-12); unscheduled, much later (user, 2026-10-15). Notes for when it starts,
from decompiler2's ED8.x support:
- **Wider reads:** `FileStream` reads only 8/16/32-bit integers and float32. decompiler2's operand tables also have
  64-bit integers (`q`, `Q`) and float64 (`d`), so ED8 adds `ReadLong64`/`ReadULong64`/`ReadDouble` (their letters
  in `STRUCT_FORMATS`), tested against ED8 scripts, once it is known which ED8 instructions use them.
- **Game-metadata operands:** `N` (ChrId), `t` (Item) and `R` (CraftId) are operand-table letters, the layer of
  `ED9_FORMAT_TABLE`, not stream formats. Each reads a plain integer (`ReadUShort`); only printing looks the name up in
  a two-way table (`ChrTable[id]`), and the generated script writes `ChrTable['name']`, evaluated back to the integer
  when it runs (decompiler2 `Falcom/ED83/InstructionTable/types.py`, `Falcom/ED83/Parser/scena_writer_helper.py`).
  decompiler2's ED9 table has these descriptors too, with the letters commented out: no ED9 instruction uses them.
- **Feasibility study** (2026-10-15, user asked; report and scripts in `notes/ed85_mlil_feasibility/`; the only sample
  is `decompiler2/Decompiler2/Falcom/ED85/btlcom.dat`): lifting ED85 straight into the generic MLIL, with no LLIL,
  needs no `ir/` change. A hand-built ED85-shaped MLIL function went through `optimize_mlil`, the HLIL passes and the
  TypeScript output with its loop and switch recovered. A whole-file prototype then lifted all 133 code functions of
  `btlcom.dat` with no failures and no `goto` left (`btlcom_proto.py`). Its front end reads decompiler2's decoded
  `btlcom.py` with `ast`, so a real ED85 decoder is still to be written.
  - **Bytecode:** command-based; every operand is self-contained, with no operand stack across instructions.
    Conditions are RPN programs ending in `Return`, and `Eval` embeds a command whose result the expression uses.
    ED85 adds a debug word to each instruction (24-bit source line, size byte). A stdlib walker decodes all 133 code
    functions (3,765 instructions, 830 branch targets).
  - **Families:** ED83 -> ED84 -> ED85 are one engine, each game's opcode table the previous one plus changes
    (decompiler2's `update()`). ED81 / ED82 (Cold Steel 1-2, not in decompiler2) are believed to be the same engine
    with other opcodes (user, unverified). ED6 / ED62 are another engine that shares the RPN operator numbering.
    Layout: one package per engine (`falcom/ed8/`, `falcom/ed6/`).
  - **Registers:** built-in commands touch registers only through explicit register-index operands
    (`BattleTargetsIterReset(regIndex, ..)` writes it), so they can be lifted with `clobbers_registers = False`. A
    script `Call` can change registers: `AniCheckDeadTarget` sets reg 7, and four callers branch on reg 7 right after
    calling it. Calls between script functions keep the clobbering default, or get a per-callee summary of the
    registers they write (41 of the 133 functions write one, directly or through a call). Registers must be MLIL
    globals, whose writes outlive the function: as register variables, the SSA dead-code pass deletes a write the
    function never reads again, which lost `AniCheckDeadTarget`'s `reg7` in the prototype's first run.
  - **SSA optimizer:** no stack slots to turn into variables, but across the whole file it propagates copies and
    constants: `KISIN_SET_FIRST_CP` sets `reg2 = 0`, then tests `reg2 >= 3`, `reg2 == 2`, ..., which print as
    `if (false)` - branches the script itself never reaches.
  - **Risks:** 161 of the 214 ED85 opcodes are unnamed in decompiler2, some affecting data flow (`OP_0C` / `OP_0D` /
    `OP_0E`, likely frame slots; `Expr24` / `Expr25`); one sample, with no dialogue text; the validators assume an
    LLIL layer.

## kuro1 Byte-Exact Debug Records (`falcom/ed9/structs/call_debug_records.py`, `falcom/ed9/writer/`)

**Planned, not started; much later, after the HLIL DSL is done** (user, 2026-10-18). A three-game census
(2026-10-18, every file, `tools/scp_roundtrip_validator.py` checks plus `--round-trip`) found `sora2_1.0`, `sora1` and
`kuro1` share one format: the same 45 instructions, header, value encoding and table field values; 2,505 of 2,506
files parse (the one failure, `kuro1` `ani/mon9996_c00.dat`, is a broken script, never to be supported). Only the
call debug records differ: `kuro1` rebuilds byte-identical in 26 of 634 files (`sora2_1.0` 1,076 of 1,082, `sora1`
783 of 789). Its older compiler leaves two patterns the record tracker does not reproduce:
- **Records written twice:** a function's whole record list appears again after itself (`ani/chrx001.dat`
  `AniAttachE07kmo05`: 5 calls, 10 records, the second five a repeat of the first).
- **Records for calls without a line marker,** where the `sora` compilers write none (`ai/ai_chr0002.dat`
  `btl_ai_algo`: no line marker, one record, for its `SYSCALL`).

Records are debug data, so this is a byte-exact gap, not a logic one (the census did not run the logic round trip on
`kuro1`).
