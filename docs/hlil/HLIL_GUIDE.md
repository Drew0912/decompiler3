# High Level IL (HLIL) Guide

> Status: Implemented, active development. Unlike MLIL (see `docs/mlil/MLIL_GUIDE.md`), HLIL's structure —
> which passes run, in what order, how arm-ordering and loop recovery are decided — is still being
> tuned against real corpus output. Treat this document as accurate to current code, not as a
> stable, finished spec.

## Role in the Pipeline

```
SCP → Parser → Disassembler → Lifter → LLIL → MLIL → HLIL → Codegen (TypeScript)
```

HLIL is the final IR layer before generated output. It takes MLIL's variable-based, stack-free
representation and recovers high-level structure: `if`/`else`, `while`/`do-while`, `switch`,
`break`/`continue`, and calls with folded results — the shape a human-readable decompilation
needs, as opposed to MLIL's flatter statement list. It does not itself recognize these structures
from raw VM semantics; that recovery work is entirely HLIL's — the Lifter/LLIL layer below only
deals with VM-level calls, branches, and CFG shape.

## Module Layout

| Path | Responsibility |
| --- | --- |
| `ir/hlil/__init__.py` | Public API surface — re-exports node types, formatter, converter, passes. |
| `ir/hlil/hlil.py` | Core node/instruction class definitions (statements, expressions, variables). |
| `ir/hlil/statement_printer.py` | The statement printer (`HLILStatementPrinter`) the `.hlil.ts` formatter and `codegen/typescript.py` share; each prints expressions itself. |
| `ir/hlil/hlil_formatter.py` | Debug text pretty-printer (`HLILFormatter`) — tree dump, not codegen. |
| `ir/hlil/mlil_to_hlil.py` | The MLIL → HLIL converter: CFG build, structural reconstruction. |
| `ir/hlil/call_result_folder.py` | `CallResultFolder`: which call results fold into the instruction reading them. |
| `ir/hlil/structural_analysis.py` | Dominator / natural-loop / region-reduction CFG analysis (`StructuralAnalyzer`), used by the converter. |
| `tools/logic_check/` | Checks the final HLIL against its MLIL: the effects, the conditions each runs under, the values they pass, their order, every reachable unstructured jump (`docs/VALIDATOR_GUIDE.md`); not part of the pipeline. |
| `ir/hlil/passes/*.py` | Seven pass modules (below) — one is the conversion wrapper itself, six are post-conversion transformations (line-marker removal only with `line_markers` off). |
| `falcom/ed9/ir/hlil/hlil_converter.py` | Falcom's concrete pipeline wiring — this, not anything in `ir/hlil/` directly, is what the real driver calls. Mirrors the same generic/project-specific split MLIL uses (`ir/mlil/*` + `falcom/ed9/ir/mlil/`). |
| `codegen/typescript.py` | HLIL → TypeScript pseudocode emitter (`TypeScriptGenerator`) — the actual human-readable output. |

## Node / Instruction Model

All nodes derive from `HLILInstruction`, split into `HLILStatement` (side effects) and
`HLILExpression` (produces a value); both have `address`/`mlil_index` back-references to the
source MLIL. A statement converted from an MLIL statement fills them in, and so does a call
expression - its own MLIL call's, also where the call folded into another statement or a
condition. A loop (`while`, and the `do`-`while` `LoopRecoveryPass` makes of one) carries its
MLIL header block's last instruction, the test or the jump into the body: the logic check
(`tools/logic_check/`) names a loop by it on both layers. The `if`/`switch` nodes structuring
builds carry none (`docs/FUTURE_WORK.md`, "Static Game-Logic Check").

**Control flow statements:** `HLILIf`, `HLILWhile` (optional label), `HLILDoWhile` (optional
label), `HLILSwitch`/`HLILSwitchCase` (supports multi-value case labels for merged `||` tests),
`HLILBreak`/`HLILContinue` (optional label), `HLILReturn`. `HLILFor` existed in the node model but
was removed (Step H, 2026-09-22) — nothing ever constructed one, and its renderers were already
wrong for the shape.

**Other statements:** `HLILBlock`, `HLILAssign`, `HLILExprStmt`, `HLILIntrinsic` (a VM instruction kept as a
statement of its own, `POPN(...)` / `DEBUG_INT(n)`), `HLILComment` (carries `line(N)`
markers that the branch-order pass reads to recover original source ordering; with `line_markers` off
(`ScpDecompileConfig.line_markers`) they are dropped after every pass that reads them), `HLILUnstructured`
(a jump the tree cannot express - HLIL has no goto; terminal: the path ends there visibly instead
of falling through. TypeScript renders it as a comment plus `throw new Error("unstructured: loc_X")`,
the `.hlil.ts` listing as `goto loc_X;`. `falcom/ed9/scp2py_base.py` warns about every one on a path that
can run (`reachable_statements`), and the logic check (`tools/logic_check/`, run by `tools/ir_semantic_validator.py`)
reports it as the difference `unstructured_jump`; none occurs in the sora2 corpus, two in `TestEmotion` of
`scena/a0000.dat` in kuro1, kuro2 and kai1).

**Expressions:** `HLILVar`/`HLILConst`, `HLILBinaryOp`/`HLILUnaryOp`, `HLILAddressOf`, `HLILDeref`
(`*ptr`, from `MLILDeref` - a runtime-computed address, e.g. an out-parameter; not a subclass of
`HLILUnaryOp`, same as `HLILAddressOf`), `HLILCall` (name + args), `HLILSyscall` (subsystem + cmd +
args), `HLILExternCall` (`"module:func"`, a call by module and function name).

**Register model:** there is no dedicated register IL node. `VariableKind` is
`LOCAL`/`PARAM`/`GLOBAL`/`REG`; a `REG`/`GLOBAL` variable simply prints as `REGS[index]`/
`GLOBALS[index]`. Registers are ordinary `HLILVar`s with a different `VariableKind`. Separately,
`CallResultFolder` decides when an MLIL call's `output` can be inlined straight into its single
reader instead of materializing as a `REG` assignment — turning `reg0 = f(); use(reg0)` into
`use(f())` wherever safe, under the VM's eager logical ops too, which evaluate both sides (see
`docs/hlil/HLIL_DESIGN.md`).

## Conversion Pipeline

`MLILToHLILConverter.convert()` (`ir/hlil/mlil_to_hlil.py`) runs 5 phases:
1. Build the CFG and detect loops (via `StructuralAnalyzer`).
2. Fold call results (`CallResultFolder`).
3. Convert parameters.
4. Recursively reconstruct control flow starting from block 0.
5. Declare used variables.

The real production entry point is `convert_falcom_mlil_to_hlil()`
(`falcom/ed9/ir/hlil/hlil_converter.py`), which builds a `Pipeline` and runs, in order:

```
MLILToHLILPass → SwitchRecoveryPass → LoopRecoveryPass → CommonReturnExtractionPass →
DeadCodeEliminationPass → BranchOrderNormalizationPass (default on) →
LineMarkerRemovalPass (only with line_markers off)
```

For `.ts`, the file-level stage (`write_ts`, `falcom/ed9/scp2py_base.py`) runs after every function is converted
and the other outputs are written: `FalcomTypeInferencePass` (`falcom/ed9/ir/hlil/hlil_passes.py`) over the
converted functions, then each function's TypeScript. The pass sets each parameter's type from the flag the script
declares for it (`Value32`/`Nullable32` -> `number`, `str`/`NullableStr` -> `string`, `Pointer` -> `Pointer`), so
signatures don't depend on MLIL inference. Local variables have no type on the decompile path (`any` until the HLIL
type plan: its stack translator runs no type pass); on the SSA path they take the MLIL SSA types. With the game's
syscall rows (`falcom/ed9/games/<game>/metadata/syscall_args.py`, `SyscallArgs` in
`falcom/ed9/assembler/ed9_syscalls.py`), the pass also marks the character-ID parameters: a parameter whose every
read is a pass to an ID slot (a syscall's ID slot, or a marked parameter of a call to a function of the same file,
so a forwarder marks too), with no other read anywhere in the reachable body, and no write or address taken
anywhere in the body, dead code included
(`HLILVariable.id_kind`). Then it tags each int constant written in decimal that is exactly the argument at an ID
slot, of a syscall by its row or of a call to a marked parameter (`HLILConst.id_kind`); not inside an expression,
not an `extern_call`'s, not a bool, a Raw word, a float, a string or a hex constant.

HLIL has no copy-propagation pass: the decompile path's stack translator folds each push into its consumer, and the
SSA path propagates copies earlier, at the MLIL-SSA layer. An HLIL
`CopyPropagationPass`, disabled since 2025-12, was removed on 2026-09-27. Re-enabled on the full
corpus, it changed 27 functions, and 24 of those changes were wrong: it deleted `GLOBALS[n]` writes
(a wait loop became `while (1)`) and assignments whose value was still read after the enclosing
branch or on the next loop iteration. The other 3 only replaced a variable with its constant value,
so none of the 27 improved the output.

## Passes

| Pass | What it does |
| --- | --- |
| `pass_mlil_to_hlil.py` | Thin wrapper invoking `MLILToHLILConverter.convert()` — the conversion step itself, not a post-conversion cleanup pass. |
| `pass_switch_recovery.py` | Folds `==`/`!=`/`\|\|` chains on one variable into an `HLILSwitch` - a link also under a truth test (`(x == k) == 0`, as the stack translator keeps the LLIL's jump test; `strip_truth_test`), each later test's leading comments starting its case (the first test's stay before the switch; a comment after a chain's tail keeps it an if) - absorbing a switch already built from the rest of the chain. |
| `pass_loop_recovery.py` | Rewrites `while(1) { if (c) break; ... }` into a real `while(!c)` or `do...while`; hoists a leading `if (c) return` out of the loop. A body ending in the bottom test structuring writes, `if (c) continue; else break;` (each arm that statement alone), becomes `do { ... } while (c)` too (45 loops in the five games, menu loops most; 2026-10-28); a body that is only that test (line markers aside) stays `while (c) { }`, an empty `do` being the harder read. The `do...while` rewrite refuses when the body has a `continue` targeting this loop (`continue` means something different in the two shapes - always jumps to the top in `while(1)`, can exit in `do...while`) and carries a labelled loop's label through (`HLILDoWhile.label`), instead of silently dropping it. |
| `pass_common_return_extraction.py` | Hoists a `return` shared by every arm of an `if`/`switch` to after the construct - only when no path can leave the construct without one of those returns: an `if` needs both arms, a `switch` needs a `default` and no case holding a bare `break` (`contains_bare_break`, `ir/hlil/hlil.py`), since an unmatched value or that `break` would otherwise run the hoisted return instead of the code after the switch. Constants compare with `constant_values_equal` (`ir/core/il_literals.py`): `1` and `1.0` are different returns, so are `0.0` and `-0.0`; NaN matches NaN. |
| `pass_dead_code_elimination.py` | Truncates a block immediately after `return`/`break`/`continue`. |
| `pass_branch_order_normalization.py` | The sole if/else arm-order decision point: swaps arms and negates the condition (De Morgan) to match the original source's `line(N)` order, with if-nesting depth as a tiebreak. Also decides which of two structurally-similar else-if chains to flatten, via "same-head" matching — this is where cascade-flattening behavior actually lives; there is no separate cascade-flattening pass. |
| `pass_line_marker_removal.py` | Only with `line_markers` off: drops the `line(N)` comments after every pass that reads them, then tidies the if arms left empty - an empty else goes, an empty then takes the else, its condition negated. |

A separate, smaller mechanism worth knowing about: `_collapse_funnel_chain` (in the converter, not
a pass) merges same-target tests - a switch case's labels, a short-circuit `||` written with jumps -
into one `||` (`BinaryOp.OR_ELSE`). It's unrelated to MLIL-SSA critical-edge splitting, which is deconstruction machinery
living in `ir/mlil_ssa/mlil_ssa.py`, entirely outside `ir/hlil/`.

## Codegen

`codegen/typescript.py` is a real TypeScript emitter, not generic pseudocode: typed signatures and
`let` declarations, a generated header with `GLOBALS`/`REGS` arrays, a `Pointer` type for
out-parameters (`type Pointer = number;`, so a `Pointer` takes the same `int(...)` coercion as a
number) and `addr_of`/`deref`/`deref_set`/`int`/`and_`/`or_`/`extern_call`/`syscall` intrinsics, and `POPN`/`DEBUG_INT`
placeholders for the VM's intrinsic statements.
TypeScript has no `*ptr` syntax, so a pointer read is a `deref(ptr)` call and a store through one
(`HLILAssign` whose `dest` is `HLILDeref`) becomes a `deref_set(ptr, value)` call instead of an
assignment - matching the existing `addr_of(x)` convention for `&x`. It
also does its own peephole simplification at print time (constant-folds
comparisons of two plain int constants via `constant_truth` - never floats, strings or a frontend's own int, whose VM
comparisons are known
only statically, not traced (`docs/falcom/ed9/ED9_VM.md`, Comparisons) - `(bool) != 0` → `bool` for an int `0`
only, double-negation elimination) — some optimization happens here, not only in `ir/hlil/passes/`.

**Trailing default arguments.** A local call pushes every argument, so HLIL holds them all; `.ts` leaves
out a call's longest tail of literal constants equal to the callee's declared defaults - the original
compiler's own rule, and the signature prints the defaults: `camera_lookat(63.153, 29.174, -63.103, 0, 3,
-1)` prints `camera_lookat(63.153, 29.174, -63.103, 0)`. Equal is `constant_values_equal`, as the HLIL
passes compare constants: the same type (an Integer `0` is not a Raw `0` or `0.0`), floats by bits and
spelling. `scp2py` passes `generate_typescript` every function's defaults as the lifter converts them
(`ED9VMLifter.source_value`), from the whole function table. In a round trip (`ScpParser.round_trip`) it
also passes the function's `call_written_argc` - each paired local call's debug-record count by CALL offset -
and a call never drops an argument its author wrote: it prints the larger of the two counts, found by
`HLILCall.address` (`camera_lookat(63.153, 29.174, -63.103, 0, 3)`, the `3` written out). The larger, not the
record's: a record that keeps fewer passes an address-taken local HLIL shows as a variable
(`btl_check_condition(arg1, 3, *&var_s4)`). A call with no count (an unpaired function, a call without a
record, an everyday decompile) prints the rule's. Syscalls, script calls and `.hlil.ts` print every argument.

**Address-taken locals fold back to a plain variable, not a `deref` call.** The stack translator writes every
address-taken local/parameter `x` in explicit `*(&x)` memory form, as MLIL SSA construction lowers it on the SSA path
(see `docs/mlil/MLIL_DESIGN.md`'s Variable Model & SSA section); that form survives SSA deconstruction and MLIL-
to-HLIL conversion unchanged, so it also reaches HLIL as `HLILDeref(HLILAddressOf(HLILVar(x)))` /
an `HLILAssign` whose `dest` is that same shape. `*(&x) ≡ x` always holds for exactly this shape
(never for a genuine runtime-computed pointer), so both printers special-case it before falling
through to the generic `deref(...)`/`deref_set(...)` handling: `codegen/typescript.py` prints plain
`x` / `x = v` (reusing the ordinary assignment branch's `int(...)` boolean coercion, not a second
copy of it - the shared `unwrap_address_taken_var`/its own `_format_var_assignment`), and
`ir/hlil/hlil_formatter.py` prints `x` the same way, via the same shared `unwrap_address_taken_var`
(`ir/hlil/hlil.py`).
Real output therefore reads naturally - `chr_set_pos(65533, var_s5, var_s6, var_s7, var_s8)` - with
no visible trace of the underlying memory-form representation.

**Character IDs by name.** A tagged constant, and a marked parameter's default when it is an exact `int`, print
by name from plain data `generate_typescript` takes (`id_hints`: ID kind -> `IdFormatHint`, from
`falcom/ed9/formatter/format_hints.py`; `codegen/` imports nothing from `falcom/`): the table's name
(`ChrIdTable['Estelle']`, from the game's generated `chr_table.py`), else the pseudo enum's (`PseudoChrId.Self`,
`PseudoChrId.Nothing`, the VM's), else the number. The header then declares `ChrIdTable` and `enum PseudoChrId`.
Only `.ts` reads the tags: `.hlil.ts` and the logic check print and compare the values.
`ScpDecompileConfig.id_names` (on by default) turns it off, as does a game without `syscall_args.py`; a game
without `chr_table.py` names only the pseudo IDs.

Two outputs exist side by side, printed from the same tree. A fact about the bytecode goes in HLIL and
shows in both; a TypeScript concern goes in `.ts` only.
- **`.ts`** — `generate_typescript()`'s readable TypeScript pseudocode. The VM's eager `&&`/`||` print
  as `and_(a, b)`/`or_(a, b)` where TypeScript's would differ: as a value (theirs gives an operand, the
  VM 0 or 1) and with a call under them (theirs could skip it).
- **`.hlil.ts`** — `HLILFormatter`'s high-level form of the bytecode. It is not TypeScript (the
  suffix is only for editor highlighting) and not recompilable, and it follows the VM's evaluation
  rules, not TypeScript's. `&&`/`||` are the VM's eager `LOGICAL_AND`/`LOGICAL_OR`, both sides always
  run; `andThen(a, b)`/`orElse(a, b)` are logic recovered from jumps, the right side conditional, a
  chain of one reading as one (`orElse(a, b, c)`). A truth test of a boolean is read off
  (`x == 0 != 0` prints `x == 0`, `(x > 0) == 0` prints `!(x > 0)`, never `x <= 0`, which differs for
  NaN); a plain value's test stays (`x != 0`).

They share the operator symbols, precedence parentheses and case `break`s, from the tables in
`ir/hlil/hlil.py`, the string literals (`dc3.utils.quote_string`) and hex constants (`0xFFFFFFFF`, not
`-1`). In both, a minus over an operand that already starts with one keeps its parentheses (`-(-a)`,
never `--a`, a decrement).

## Known Gaps / Active Work

- Arm-ordering and chain-flattening (`pass_branch_order_normalization.py`) is the newest, most
  actively-changing part of this layer — expect this document's pipeline order/pass list to drift
  fastest here.

## Testing

Several dedicated test files: `tests/hlil_tests/test_hlil_branch_order_normalization.py`,
`tests/hlil_tests/test_hlil_switch_recovery.py`, `tests/hlil_tests/test_hlil_loop_recovery.py`,
`tests/hlil_tests/test_hlil_loop_traversal.py`, `tests/hlil_tests/test_hlil_call_fold_short_circuit.py`,
`tests/hlil_tests/test_hlil_long_functions.py`, `tests/hlil_tests/test_hlil_common_return_extraction.py`,
`tests/hlil_tests/test_hlil_operators.py`, `tests/hlil_tests/test_hlil_traversal.py`,
`tests/hlil_tests/test_hlil_structuring.py`, `tests/hlil_tests/test_hlil_structuring_fuzz.py`,
`tests/hlil_tests/test_falcom_param_types.py`, `tests/hlil_tests/test_hlil_line_marker_removal.py` (see
`HLIL_DESIGN.md`'s Testing section for what each covers).
