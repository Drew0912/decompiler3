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
| this file | the static game-logic check, generic / Falcom boundary leftovers, ED8 support, older-compiler byte-exact debug records |

## Static Game-Logic Check (`tools/logic_check/`, `tools/ir_semantic_validator.py`)

**Step A, the structural check, is built** (the IR rewrite's part 1, 2026-10-27/28): per function, the logic check
compares the LLIL against the MLIL and the MLIL against the HLIL on the in-memory IR - the effects with their argument
values, the conditions they run under, branches, the order of effects and the values loops carry - and
`tools/ir_semantic_validator.py` runs it per script, with a regression export and compare (`docs/VALIDATOR_GUIDE.md`:
its categories, the known findings, its limits). It replaced the block matcher the validator had. Over the five games'
full corpus it reports only the paths `TestEmotion`'s unstructured jumps lose (2026-10-29). **Not started:**

- **Step B, the value layer:** values computed, not compared as trees, so an equal value written another way
  (`1 + 1` for `2`) and an ordering inverted (`!(a < b)` for `a >= b`, which differs only for NaN) are decided.
  The VM's arithmetic and comparisons are known statically, from the game exe (`docs/falcom/ed9/ED9_VM.md`); it
  waits for those rules to be traced in the running game.
- **Cross-program mode** for compile-back: source `.dat` vs recompiled `.dat`, both at LLIL - the
  least-transformed level, so decompiler bugs and lowering bugs both show. There are no provenance
  links across two programs, so matching leans on order, guards and arguments; legitimate
  restructuring (a switch vs an if-chain, duplicated regions) needs normalizing.

**Limits:** it flags differences but proves equivalence only up to its normal form. With arguments and guards
compared it is a strong regression net - both live bugs found by the 2026-09-23 review (a deleted global restore; an
always-run call folded under a short-circuiting `&&`) are the kinds it reports. Useful for the decompiler today
(within one decompilation), and the correctness gate for the HLIL DSL (`docs/dsl/DSL_FUTURE_WORK.md`, Recompilation
Pipeline §1).

## Generic/Falcom Boundary (`docs/ARCHITECTURE.md`)

An audit (2026-10-02, Fable and Codex, read-only) found ED9
knowledge in generic code anyway. None of it is a bug, and with one VM it costs nothing today. Decided with the user:

- **Left with the SSA path by the IR rewrite** (part 2: kept in `ir/mlil_ssa/`, never called by the decompile
  path): the parameter-slot mapping in its generic translator (`ir/mlil_ssa/llil_to_mlil.py`,
  `_frame_offset_to_param_index`) and the generic `RegStore`/`RegLoad`/`Syscall` translation that only its Falcom
  translator has. The decompile path's stack translator meets the rules (`notes/rewrite/08_decision_and_checklist.md`,
  Checklist, "Boundary rules"; `docs/ARCHITECTURE.md`, "Generic/Falcom Boundary"); `MLILCallScript` ->
  `MLILExternCall` is deferred (IR rewrite part 2, D2).
- **Small moves, done by the opcode-table plan** (Step 7 `89063e4`, no output change; Step 7b `f8f4682` changed only
  the `POP_TO_DEREF` lines of `.llil.asm`):
  - `LLIL_CALL_SCRIPT`/`LLIL_CALL_SCRIPT_NO_RETURN` live only in `LowLevelILFalcomOperation`
    (`falcom/ed9/ir/llil/llil_ext.py`) with the global ops, numbered after `LLIL_POPN` (`LLIL_PUSH_CALLER_FRAME`,
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
  `REGS`, `POPN`, `DEBUG_INT`, `extern_call`, `syscall`) and the syscall and extern-call rendering; no change
  planned. If a second game ever needs different output, that is the time to move or split it.
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
    (`BattleTargetsIterReset(regIndex, ..)` writes it), so they can be lifted as calls that write no register. A
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
  - **Logic check** (`tools/logic_check/`, `docs/VALIDATOR_GUIDE.md`): ED85 support brings the logic check with it.
    Its MLIL -> HLIL half runs on the generic IR and carries over, given ED85's own register facts (ED9's 16
    registers and result register 0 are `falcom/ed9/disasm/stack_effects.py`'s, which the check's `VMEffects` in
    `vm_effects.py` takes; an ED85 layer names its own in `VM_EFFECTS`). With no LLIL, the passes' reference is the
    MLIL as lifted, before `optimize_mlil`, compared with the optimized MLIL as LLIL is with MLIL today; ED9's LLIL
    side (`llil_layer.py`) and driver (`scripts.py`) get ED85 counterparts. The lifter stays outside the check, as
    ED9's bytecode -> LLIL lifter does.

## Older-Compiler Byte-Exact Debug Records (`falcom/ed9/structs/call_debug_records.py`, `falcom/ed9/writer/`)

**Planned, not started; much later** (user, 2026-11-06). `kuro1`, `kuro2`, `kai1` and `sora`'s older-built `chr` files
come from the older compiler (`docs/falcom/ed9/ED9_FORMAT.md`, Call-Site Debug Records). `Kuro1ScpWriter` writes two of
its three differences, records on common functions and each record's own debug-only Strings, so `kuro1` rebuilds
byte-identical in 397 of 634 files (2026-11-07; 26 without them). The third is doubling, which needs the transitive
simulation of rule 8: each of the other 237 rebuilds fewer records than its original. `sora`'s older-built files get
neither of the two, since `sora`'s writer is the newer compiler's.

Whether those engines read the records isn't known, since their exes are unread. The logic round trip passed on a
30-file sample of each of `kuro1`, `kuro2` and `kai1` (2026-11-07).
