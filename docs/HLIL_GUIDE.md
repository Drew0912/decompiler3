# High Level IL (HLIL) Guide

> Status: Implemented, active development. Unlike MLIL (see `MLIL_GUIDE.md`), HLIL's structure —
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
| `ir/hlil/hlil_formatter.py` | Debug text pretty-printer (`HLILFormatter`) — tree dump, not codegen. |
| `ir/hlil/mlil_to_hlil.py` | The MLIL → HLIL converter: CFG build, call-result folding, structural reconstruction. |
| `ir/hlil/structural_analysis.py` | Dominator / natural-loop / region-reduction CFG analysis (`StructuralAnalyzer`), used by the converter. |
| `tools/hlil_path_check.py` | Checks that the final HLIL keeps every MLIL control path (lost or invented paths, missing calls/stores, each repeated region on its own); not part of the pipeline. |
| `ir/hlil/hlil_passes.py` | Re-export shim (`from .passes import *`) — no logic of its own. |
| `ir/hlil/passes/*.py` | Six pass modules (below) — one is the conversion wrapper itself, five are active post-conversion transformations. |
| `falcom/ed9/ir/hlil/hlil_converter.py` | Falcom's concrete pipeline wiring — this, not anything in `ir/hlil/` directly, is what the real driver calls. Mirrors the same generic/project-specific split MLIL uses (`ir/mlil/*` + `falcom/ed9/ir/mlil/`). |
| `codegen/typescript.py` | HLIL → TypeScript pseudocode emitter (`TypeScriptGenerator`) — the actual human-readable output. |

## Node / Instruction Model

All nodes derive from `HLILInstruction`, split into `HLILStatement` (side effects) and
`HLILExpression` (produces a value); both have `address`/`mlil_index` back-references to the
source MLIL. A statement converted from an MLIL statement fills them in, and so does a call
expression - its own MLIL call's, also where the call folded into another statement or a
condition; the `if`/`while`/`switch` nodes structuring builds do not (`docs/FUTURE_WORK.md`,
"Static Game-Logic Check").

**Control flow statements:** `HLILIf`, `HLILWhile` (optional label), `HLILDoWhile` (optional
label), `HLILSwitch`/`HLILSwitchCase` (supports multi-value case labels for merged `||` tests),
`HLILBreak`/`HLILContinue` (optional label), `HLILReturn`. `HLILFor` existed in the node model but
was removed (Step H, 2026-09-22) — nothing ever constructed one, and its renderers were already
wrong for the shape.

**Other statements:** `HLILBlock`, `HLILAssign`, `HLILExprStmt`, `HLILComment` (carries `line(N)`
markers that the branch-order pass reads to recover original source ordering), `HLILUnstructured`
(a jump the tree cannot express - HLIL has no goto; terminal: the path ends there visibly instead
of falling through. TypeScript renders it as a comment plus `throw new Error("unstructured: loc_X")`,
the `.hlil.ts` listing as `goto loc_X;`. `falcom/ed9/scena2py.py` warns about every one on a path that
can run (`reachable_statements`), and `tools/ir_semantic_validator.py` reports it as the hard fail
`unstructured_jump`; none occurs in the sora2_1.0 corpus).

**Expressions:** `HLILVar`/`HLILConst`, `HLILBinaryOp`/`HLILUnaryOp`, `HLILAddressOf`, `HLILDeref`
(`*ptr`, from `MLILDeref` - a runtime-computed address, e.g. an out-parameter; not a subclass of
`HLILUnaryOp`, same as `HLILAddressOf`), `HLILCall` (name + args), `HLILSyscall` (subsystem + cmd +
args), `HLILExternCall` (`"module:func"` cross-script calls).

**Register model:** there is no dedicated register IL node. `VariableKind` is
`LOCAL`/`PARAM`/`GLOBAL`/`REG`; a `REG`/`GLOBAL` variable simply prints as `REGS[index]`/
`GLOBALS[index]`. Registers are ordinary `HLILVar`s with a different `VariableKind`. Separately,
`CallResultFolder` decides when an MLIL call's `output` can be inlined straight into its single
reader instead of materializing as a `REG` assignment — turning `reg0 = f(); use(reg0)` into
`use(f())` wherever safe. It never folds a call under the right side of a native VM logical op:
the VM evaluates both sides, HLIL `&&`/`||` short-circuit (see `docs/HLIL_DESIGN.md`).

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
MLILToHLILPass → ControlFlowOptimizationPass → LoopRecoveryPass →
CommonReturnExtractionPass → DeadCodeEliminationPass → BranchOrderNormalizationPass (default on)
```

`FalcomTypeInferencePass` exists in the codebase but is currently **wired off** in this pipeline
(disabled, marked "testing").

HLIL has no copy-propagation pass: copy propagation happens earlier, at the MLIL-SSA layer. An HLIL
`CopyPropagationPass`, disabled since 2025-12, was removed on 2026-09-27. Re-enabled on the full
corpus, it changed 27 functions, and 24 of those changes were wrong: it deleted `GLOBALS[n]` writes
(a wait loop became `while (1)`) and assignments whose value was still read after the enclosing
branch or on the next loop iteration. The other 3 only replaced a variable with its constant value,
so none of the 27 improved the output.

## Passes

| Pass | What it does |
| --- | --- |
| `pass_mlil_to_hlil.py` | Thin wrapper invoking `MLILToHLILConverter.convert()` — the conversion step itself, not a post-conversion cleanup pass. |
| `pass_control_flow_optimization.py` | Inlines `var = bool_expr; if (var)` into `if (bool_expr)`; folds `==`/`!=`/`\|\|` chains on one variable into an `HLILSwitch`, absorbing a switch already built from the rest of the chain; inverts empty-then `if`s. |
| `pass_loop_recovery.py` | Rewrites `while(1) { if (c) break; ... }` into a real `while(!c)` or `do...while`; hoists a leading `if (c) return` out of the loop. The `do...while` rewrite refuses when the body has a `continue` targeting this loop (`continue` means something different in the two shapes - always jumps to the top in `while(1)`, can exit in `do...while`) and carries a labelled loop's label through (`HLILDoWhile.label`), instead of silently dropping it. |
| `pass_common_return_extraction.py` | Hoists a `return` shared by every arm of an `if`/`switch` to after the construct - only when no path can leave the construct without one of those returns: an `if` needs both arms, a `switch` needs a `default` and no case holding a bare `break` (`contains_bare_break`, `ir/hlil/hlil.py`), since an unmatched value or that `break` would otherwise run the hoisted return instead of the code after the switch. Constants compare with `constant_values_equal` (`ir/core/il_base.py`): `1` and `1.0` are different returns, NaN matches NaN. |
| `pass_dead_code_elimination.py` | Truncates a block immediately after `return`/`break`/`continue`. |
| `pass_branch_order_normalization.py` | The sole if/else arm-order decision point: swaps arms and negates the condition (De Morgan) to match the original source's `line(N)` order, with block depth as a tiebreak. Also decides which of two structurally-similar else-if chains to flatten, via "same-head" matching — this is where cascade-flattening behavior actually lives; there is no separate cascade-flattening pass. |

A separate, smaller mechanism worth knowing about: `_collapse_funnel_chain` (in the converter, not
a pass) merges same-target equality tests into one `||`. It's unrelated to MLIL-SSA critical-edge
splitting, which is deconstruction machinery living in `ir/mlil/mlil_ssa.py`, entirely outside
`ir/hlil/`.

## Codegen

`codegen/typescript.py` is a real TypeScript emitter, not generic pseudocode: typed signatures and
`let` declarations, a generated header with `GLOBALS`/`REGS` arrays, a `Pointer` type for
out-parameters (`type Pointer = number;`, so a `Pointer` takes the same `int(...)` coercion as a
number) and `addr_of`/`deref`/`deref_set`/`int`/`extern_call`/`syscall`/`debug.log` intrinsics, and
per-syscall wrapper functions from a signature database. TypeScript has no `*ptr` syntax, so a pointer read is a `deref(ptr)`
call and a store through one (`HLILAssign` whose `dest` is `HLILDeref`) becomes a `deref_set(ptr,
value)` call instead of an assignment - matching the existing `addr_of(x)` convention for `&x`. It
also does its own peephole simplification at print time (constant-folds
constant-vs-constant comparisons, `(bool) != 0` → `bool`, double-negation elimination) — some
optimization happens here, not only in `ir/hlil/passes/`.

**Address-taken locals fold back to a plain variable, not a `deref` call.** MLIL SSA construction
lowers every address-taken local/parameter `x` to explicit `*(&x)` memory form (see
`MLIL_DESIGN.md`'s Variable Model & SSA section); that form survives SSA deconstruction and MLIL-
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

Two output modes exist side by side:
- **`.ts`** — `generate_typescript()`'s real pseudocode output.
- **`.hlil.ts`** — a raw `HLILFormatter` tree dump, explicitly documented in-repo as
  "not recompilable code." Useful for debugging the IR, not as generated output. It prints the
  same operator symbols, precedence parentheses and case `break`s as `.ts`, from the shared
  tables in `ir/hlil/hlil.py`.

## Known Gaps / Active Work

- Arm-ordering and chain-flattening (`pass_branch_order_normalization.py`) is the newest, most
  actively-changing part of this layer — expect this document's pipeline order/pass list to drift
  fastest here.

## Testing

Several dedicated test files: `tests/test_hlil_branch_order_normalization.py`,
`tests/test_hlil_control_flow_optimization.py`, `tests/test_hlil_loop_recovery.py`,
`tests/test_hlil_loop_traversal.py`, `tests/test_hlil_call_fold_short_circuit.py`,
`tests/test_hlil_long_functions.py`, `tests/test_hlil_common_return_extraction.py`,
`tests/test_hlil_operators.py`, `tests/test_hlil_traversal.py`.
