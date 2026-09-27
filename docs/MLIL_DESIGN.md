# Medium Level IL (MLIL) Design

> Status: Implemented. This document originally described a pre-implementation target
> architecture; it has been rewritten against the real implementation (2026-09-20), including a
> full SSA optimizer pipeline that predates this revision but was never documented. See
> `docs/MLIL_GUIDE.md` for a practical usage guide; this document focuses on the node model and
> pipeline shape.

## Role in the Pipeline

```
SCP → Parser → Disassembler → Lifter → LLIL → MLIL → HLIL → Codegen (TypeScript)
```

MLIL is the bridge between the Falcom-specific stack-based LLIL and HLIL. It:

1. **Erases the explicit operand stack** — every temporary becomes a named variable.
2. **Exposes control/data flow** suitable for SSA and optimizer passes.
3. **Retains Falcom semantics** (syscall IDs, `CALL_SCRIPT` metadata, etc.) so later passes still
   understand VM behavior.

## Module Layout

| Path | Responsibility |
| --- | --- |
| `ir/mlil/mlil.py` | Core non-SSA data structures: `MediumLevelILInstruction` base, the `MediumLevelILExpr`/`MediumLevelILStatement` split, `MLILVariable`, `MediumLevelILBasicBlock`, `MediumLevelILFunction`. |
| `ir/mlil/mlil_ssa.py` | The SSA layer: `MLILVariableSSA`/`MLILVarSSA`/`MLILSetVarSSA`/`MLILPhi`, `DominanceAnalysis`, `SSAConstructor`, `SSADeconstructor` (including critical-edge splitting), and the public `convert_to_ssa`/`convert_from_ssa` entry points. |
| `ir/mlil/mlil_ssa_optimizer.py` | `SSAOptimizer` — orchestrates the optimization passes below. |
| `ir/mlil/mlil_optimizer.py` | `mlil_optimization_passes()`, the one list of passes that runs after LLIL→MLIL translation (see "LLIL → MLIL Pipeline"), and `optimize_mlil()`, which runs that list on an already translated function. |
| `ir/mlil/passes/` | The actual pass implementations (14 files): `pass_llil_to_mlil.py`, `pass_ssa.py`, `pass_ssa_sccp.py`, `pass_ssa_constant_propagation.py`, `pass_ssa_copy_propagation.py`, `pass_ssa_expression_simplification.py`, `pass_ssa_condition_simplification.py`, `pass_ssa_nnf.py`, `pass_ssa_expression_inlining.py`, `pass_ssa_dead_code.py`, `pass_ssa_dead_phi.py`, `pass_ssa_type_inference.py`, `pass_reg_global_propagation.py`, `pass_block_merge.py`. |
| `ir/mlil/mlil_passes.py` | Re-export shim over `ir/mlil/passes/` — mirrors HLIL's `hlil_passes.py`. |
| `ir/mlil/mlil_builder.py` | Builder API for constructing MLIL directly. |
| `ir/mlil/mlil_formatter.py` | Pretty printer for MLIL functions (text dump used in tests/debugging). |
| `ir/mlil/mlil_types.py` | Type-kind/unification support, `FunctionSignatureDB`. |
| `ir/mlil/llil_to_mlil.py` | Generic `LLILToMLILTranslator`/`translate_llil_to_mlil` (not Falcom-specific). |
| `falcom/ed9/ir/mlil/mlil_converter.py` | Falcom's concrete pipeline wiring — the real production entry point, `convert_falcom_llil_to_mlil()`. Mirrors `falcom/ed9/ir/hlil/hlil_converter.py`'s structure exactly. |
| `falcom/ed9/ir/mlil/mlil_translator.py` | Falcom-specific LLIL → MLIL translation (syscall IDs, `CALL_SCRIPT` metadata, etc.). |
| `falcom/ed9/ir/mlil/type_signatures.py` | Type signature data used by Falcom-specific passes. |
| `tests/test_mlil_metadata.py` | One of several dedicated MLIL test files today — see Testing below. |

Note: `falcom/ed9/lifters/mlil_lifter.py`, previously listed here, does not exist anywhere in the
tree. This table now reflects the real path.

## Operations & Node Types

All MLIL nodes derive from a common `MediumLevelILInstruction` base carrying an
`operation` enum value, an optional source `address`, and an `inst_index` inherited from LLIL for
cross-layer traceability. Nodes are split into `MediumLevelILExpr` (produces a value) and
`MediumLevelILStatement` (side effects only) — roughly 32 concrete instruction classes exist across
these two categories, covering:

| Category | Examples |
| --- | --- |
| Constants | `MLIL_CONST_INT`, `MLIL_CONST_FLOAT`, `MLIL_CONST_STR` |
| Variable read/write | `MLIL_VAR`, `MLIL_SET_VAR`, `MLIL_PHI` (SSA form) |
| Arithmetic / logical | `MLIL_ADD`, `MLIL_SUB`, `MLIL_MUL`, `MLIL_DIV`, `MLIL_MOD`, `MLIL_AND`, `MLIL_OR`, `MLIL_NOT`, `MLIL_CMP_*` |
| Memory / stack artifacts | Explicit address expressions, for the cases where a raw stack address is referenced directly rather than eliminated. |
| Pointer dereference | `MLILDeref` (`*ptr`, a unary expression) / `MLILStoreDeref` (`*dest = value`, modelled on `MLILStoreGlobal` but with an expression target instead of a static index) — for `LOAD_STACK_DEREF`/`POP_TO_DEREF`, where the address is a runtime value (e.g. a caller-supplied out-parameter) rather than a statically known stack/frame slot. Unlike `MLILAddressOf`, a `MLILDeref`'s operand is an ordinary value and safe to copy-propagate through; a `MLILStoreDeref` is always kept (never DCE'd) since its target isn't a tracked SSA variable. |
| Control flow | `MLIL_GOTO`, `MLIL_IF`, `MLIL_RET` |
| Calls | `MLIL_CALL`, `MLIL_CALL_SCRIPT`, `MLIL_SYSCALL` |
| Falcom specific | Derived metadata on top of generic ops — stack-setup helpers like `PUSH_CALLER_FRAME`/`PUSH_FUNC_ID`/`PUSH_RET_ADDR` are fully lowered to regular variables/arguments, with no dedicated MLIL opcode. |

When a pass replaces an expression's operands and keeps its operation, it calls the node's own
`rebuild()`, which keeps the source metadata (address, indices): `MLILBinaryOp.rebuild()` and
`MLILUnaryOp.rebuild()` (one method each, since every subclass constructor takes only its operands),
and the call and `MLILStoreDeref` rebuilds. There is no per-pass reconstruction table. A rewrite
that produces a different operation (NNF's De Morgan, comparison inversion) builds the new node
directly.

Reading is shared the same way. Every node's `operands()` returns the expressions it holds, in
evaluation order; `walk()` (`ir/mlil/mlil.py`) visits a node and everything below it, and
`iter_ssa_reads()` (`ir/mlil/mlil_ssa.py`) yields each SSA variable it reads with the node that
reads it (the `MLILVarSSA`, or the phi for a phi source). Every use collector - SSA construction's
address-taken scan, de-SSA liveness, SCCP, dead code, dead phis, copy propagation, inlining - is
built on these, so a new node type needs only its own `operands()`. Copy propagation passes
`skip = (MLILAddressOf,)`: it never rewrites the operand of `&`, so a read there is not one of its
uses.

## Variable Model & SSA

Two coexisting representations, not a single evolving one:

- **Non-SSA** (`ir/mlil/mlil.py`): `MLILVariable`, read via `MLILVar` and written via
  `MLILSetVar`. This is the "on the wire" default form — a `MediumLevelILFunction` starts and ends
  in this form both before and after the optimizer runs.
- **SSA** (`ir/mlil/mlil_ssa.py`): `MLILVariableSSA`, `MLILVarSSA`, `MLILSetVarSSA`, and `MLILPhi`.
  SSA construction is dominance-based (`SSAConstructor`) and includes critical-edge splitting;
  deconstruction (`SSADeconstructor`) converts back to non-SSA form afterward.

Stack slots are named `var_sN` and parameters `argN`. Which one an access gets is decided by the
LLIL builder from the slot's current lifetime (`LowLevelILBuilder._holds_parameter`): a parameter
slot is `argN` only while it still holds the caller's value, and a value pushed there after the
function popped the parameter is a `var_sN`, like any other push.

SSA is not optional or a future addition — it's where essentially all real optimization work
happens. The shared pass list (`mlil_optimization_passes()` in `ir/mlil/mlil_optimizer.py`) merges
call-split blocks, converts to SSA, runs the full `SSAOptimizer` pass suite plus optional type
inference, deconstructs back to non-SSA, then propagates register/global values. HLIL's converter (`falcom/ed9/ir/hlil/hlil_converter.py`) imports and consumes
non-SSA `MediumLevelILFunction` — it does not read SSA form directly; by the time HLIL sees a
function, SSA construction/optimization/deconstruction has already happened upstream in the MLIL
pipeline.

Falcom-specific stack-setup helpers (`PUSH_CALLER_FRAME`, `PUSH_FUNC_ID`, `PUSH_RET_ADDR`) are
fully lowered to regular variables/arguments in MLIL — there is no dedicated MLIL opcode for them
once the stack layout is eliminated.

**Address-taken locals/parameters are memory, not scalar SSA values.** A variable whose address is
taken anywhere in the function (`SSAConstructor._collect_address_taken_vars`) cannot be versioned
like an ordinary scalar: doing so would version the *address* itself (`&x#1`, `&x#2`, ...),
conflating one stable storage location with a chain of immutable SSA values — the root cause of a
real bug where a call's actual effect on an out-parameter was silently replaced by its pre-call
value (`chr_set_pos(65533, 0, 0, 0, 0)` instead of the real post-call coordinates). Instead,
`SSAConstructor._lower_address_taken_vars` rewrites every read/write of such a variable to explicit
`*(&x)` deref/store form (`MLILDeref(MLILAddressOf(MLILVar(x)))` / `MLILStoreDeref(MLILAddressOf(...), v)`)
before renaming, so `x` itself never advances past its seeded version (`x#0`) — it renames to one
stable address identity throughout, and every existing deref-safety mechanism (SCCP evaluates a
deref to BOTTOM, copy/expression-inlining never moves an impure deref read across a call, DCE never
drops a `MLILStoreDeref`, `RegGlobalValuePropagator` never caches a deref read or a variable read at
all — only a fully closed-form constant expression is ever cached under a REG/GLOBAL slot, so a
pointer write has nothing stale to invalidate in the first place) applies to it unchanged. A call whose own `output` would alias an address-taken variable is redirected through
a fresh temporary first (`SSAConstructor._decompose_address_taken_call_outputs`), so the general
rewrite never has to special-case call outputs. The memory form is kept through every IR layer and
raised back to a plain variable only at print time (`x` / `x = v`, never `deref(addr_of(x))`) — see
`HLIL_GUIDE.md`'s printing-convention section.

## Basic Blocks & Functions

```
class MediumLevelILBasicBlock:
    index: int
    instructions: list[MediumLevelILStatement]
    incoming_edges: list[MediumLevelILBasicBlock]
    outgoing_edges: list[MediumLevelILBasicBlock]

class MediumLevelILFunction:
    name: str
    start_addr: int
    basic_blocks: list[MediumLevelILBasicBlock]
```

(Simplified for illustration — see `ir/mlil/mlil.py:632` and `:672` for the real class
definitions.) Predecessor/successor edges are `incoming_edges`/`outgoing_edges`, not `preds`/
`succs`. Each MLIL block mirrors an LLIL block when `optimize=False` - the `BlockMergePass` (part
of the SSA optimization pipeline, so it does not run when `optimize=False`) collapses call-return
and other single-predecessor goto chains when optimization is enabled, so this 1:1 property does
not hold for `optimize=True` output. The LLIL `inst_index` carried on each instruction is how
debugging tools jump between layers, rather than a separate `llil_inst_to_mlil` map.

## LLIL → MLIL Pipeline

The real production entry point is `convert_falcom_llil_to_mlil()`
(`falcom/ed9/ir/mlil/mlil_converter.py`), which builds a `Pipeline` and runs, in order:

```
ED9LLILToMLILPass → BlockMergePass (optimize only) → SSAConversionPass → SSAOptimizationPass →
SSATypeInferencePass (optional) → SSADeconstructionPass → RegGlobalValuePropagationPass
```

Every pass after `ED9LLILToMLILPass` comes from `mlil_optimization_passes()`
(`ir/mlil/mlil_optimizer.py`); `optimize_mlil()` runs the same list on an already translated
function, so tests that call it run what production runs. No dead-code pass runs after SSA
deconstruction: a census of production output found no unread local assignment (500-file sample,
2026-09-26).

### Optimization Passes (inside `SSAOptimizer`)

Run on SSA form, in `ir/mlil/mlil_ssa_optimizer.py`'s configured order: sparse conditional constant
propagation (SCCP), constant propagation, copy propagation, expression inlining, expression/
condition simplification, negation normal form, dead-code elimination, and dead-`Phi` elimination.
Register/global value propagation (`pass_reg_global_propagation.py`) runs as its own pipeline stage
in the Falcom entry point, after SSA deconstruction.

Copy propagation and expression inlining never move a register/global read past anything that may
redefine that storage: an explicit definition, a call's own output, or any call that may clobber it
(`MediumLevelILFunction.call_may_clobber`, the same rule SSA construction uses for its `<undef>`
pseudo-definitions). Both passes share one check, `reaches_without_redefinition`
(`pass_ssa_copy_propagation.py`), which also scans the use block's own instructions before the use.
The call itself is the barrier, not its pseudo-definitions or output: dead-code elimination drops an
unread call output and dead register pseudo-definitions while the call - and its clobber - stays,
so a later optimizer round must still see it (without this, a saved `reg0` value was forwarded past
the next call in ~1,800 places across the corpus). Dead-code elimination refuses to drop a call
output that is a global (it raises): call results only ever land in the result register, and
dropping a global output would silently lose a global write.

SCCP folds constant `+ - * & | ^ << >>`, `&&`/`||`, and comparisons, but deliberately never
evaluates `MLIL_DIV`/`MLIL_MOD` to a lattice constant (`pass_ssa_sccp.py`'s `_eval_binary_op`) -
Python's arithmetic doesn't match the VM's actual number format (`ScpValue`'s 30-bit-int/float32
shape describes the constant *encoding*, not the runtime arithmetic width), and the real semantics
(float rounding, int truncation, overflow, MOD's sign) can't be verified without running the game.
Folding with an unverified formula risks silently replacing one wrong constant with another. Note
this is narrower than "DIV/MOD always print unfolded" - a separate pass
(`ExpressionSimplificationPass`'s `x / 1 → x` identity) can still simplify a DIV whose divisor is
literally 1, including a fully-constant one like `10 / 1 → 10`, since that identity holds
regardless of numeric semantics. See `docs/FUTURE_WORK.md` for what a verified SCCP fix would need.

## Testing

Several dedicated MLIL test files exist today (`test_mlil_metadata.py`,
`test_mlil_ssa_optimizer.py`, `test_mlil_sccp_folding.py`, `test_mlil_address_taken.py`,
`test_mlil_reg_global_propagation.py`, and others) covering SSA construction/deconstruction, the
SSA optimizer's passes, and register/global propagation - a closed gap from when this line last
said only one existed.

## Open Items

- Four SSA optimizer passes have no test of their own: negation normal form, expression
  simplification, constant propagation and dead-`Phi` elimination.
- This document and `docs/MLIL_GUIDE.md` should be kept in sync with `ir/mlil/passes/` as passes
  are added, removed, or reordered — that directory is the actual source of truth for what runs.
