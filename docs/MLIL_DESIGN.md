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
| `ir/mlil/mlil_optimizer.py` | Top-level `optimize_mlil()`: SSA-convert → run `SSAOptimizer` → type inference → de-SSA → a post-de-SSA dead-code pass. |
| `ir/mlil/mlil_type_inference.py` | `MLILTypeInference`, operating on SSA variables/`Phi` nodes. |
| `ir/mlil/passes/` | The actual pass implementations (~16 files): `pass_llil_to_mlil.py`, `pass_ssa.py`, `pass_ssa_sccp.py`, `pass_ssa_constant_propagation.py`, `pass_ssa_copy_propagation.py`, `pass_ssa_expression_simplification.py`, `pass_ssa_condition_simplification.py`, `pass_ssa_nnf.py`, `pass_ssa_expression_inlining.py`, `pass_ssa_dead_code.py`, `pass_ssa_dead_phi.py`, `pass_ssa_type_inference.py`, `pass_reg_global_propagation.py`, `pass_dead_code.py`, and others. |
| `ir/mlil/mlil_passes.py` | Re-export shim over `ir/mlil/passes/` — mirrors HLIL's `hlil_passes.py`. |
| `ir/mlil/mlil_builder.py` | Builder API for constructing MLIL directly. |
| `ir/mlil/mlil_formatter.py` | Pretty printer for MLIL functions (text dump used in tests/debugging). |
| `ir/mlil/mlil_types.py` | Type-kind/unification support, `FunctionSignatureDB`. |
| `ir/mlil/llil_to_mlil.py` | Generic `LLILToMLILTranslator`/`translate_llil_to_mlil` (not Falcom-specific). |
| `falcom/ed9/ir/mlil/mlil_converter.py` | Falcom's concrete pipeline wiring — the real production entry point, `convert_falcom_llil_to_mlil()`. Mirrors `falcom/ed9/ir/hlil/hlil_converter.py`'s structure exactly. |
| `falcom/ed9/ir/mlil/mlil_translator.py` | Falcom-specific LLIL → MLIL translation (syscall IDs, `CALL_SCRIPT` metadata, etc.). |
| `falcom/ed9/ir/mlil/type_signatures.py` | Type signature data used by Falcom-specific passes. |
| `tests/test_mlil_metadata.py` | The only dedicated MLIL test file currently — see Testing below. |

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

## Variable Model & SSA

Two coexisting representations, not a single evolving one:

- **Non-SSA** (`ir/mlil/mlil.py`): `MLILVariable`, read via `MLILVar` and written via
  `MLILSetVar`. This is the "on the wire" default form — a `MediumLevelILFunction` starts and ends
  in this form both before and after the optimizer runs.
- **SSA** (`ir/mlil/mlil_ssa.py`): `MLILVariableSSA`, `MLILVarSSA`, `MLILSetVarSSA`, and `MLILPhi`.
  SSA construction is dominance-based (`SSAConstructor`) and includes critical-edge splitting;
  deconstruction (`SSADeconstructor`) converts back to non-SSA form afterward.

SSA is not optional or a future addition — it's where essentially all real optimization work
happens. `optimize_mlil()` (`ir/mlil/mlil_optimizer.py`) converts non-SSA MLIL to SSA, runs the
full `SSAOptimizer` pass suite plus type inference, then deconstructs back to non-SSA before
returning. HLIL's converter (`falcom/ed9/ir/hlil/hlil_converter.py`) imports and consumes
non-SSA `MediumLevelILFunction` — it does not read SSA form directly; by the time HLIL sees a
function, SSA construction/optimization/deconstruction has already happened upstream in the MLIL
pipeline.

Falcom-specific stack-setup helpers (`PUSH_CALLER_FRAME`, `PUSH_FUNC_ID`, `PUSH_RET_ADDR`) are
fully lowered to regular variables/arguments in MLIL — there is no dedicated MLIL opcode for them
once the stack layout is eliminated.

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
`succs`. Each MLIL block mirrors an LLIL block; the LLIL `inst_index` carried on each instruction
is how debugging tools jump between layers, rather than a separate `llil_inst_to_mlil` map.

## LLIL → MLIL Pipeline

The real production entry point is `convert_falcom_llil_to_mlil()`
(`falcom/ed9/ir/mlil/mlil_converter.py`), which builds a `Pipeline` and runs, in order:

```
ED9LLILToMLILPass → SSAConversionPass → SSAOptimizationPass →
SSATypeInferencePass (optional) → SSADeconstructionPass → RegGlobalValuePropagationPass
```

One pass is explicitly disabled in this pipeline: `DeadCodeEliminationPass()` is commented out
with a `# TODO: check if needed` note. This doesn't mean dead-code elimination is actually missing
from the live path — other DCE passes still run: `pass_ssa_dead_code.py` and
`pass_ssa_dead_phi.py` inside `SSAOptimizer`, plus a separate post-de-SSA dead-code step inlined in
`ir/mlil/mlil_optimizer.py`. Only this one specific pass instance is unused.

### Optimization Passes (inside `SSAOptimizer`)

Run on SSA form, in `ir/mlil/mlil_ssa_optimizer.py`'s configured order: sparse conditional constant
propagation (SCCP), constant propagation, copy propagation, expression inlining, expression/
condition simplification, negation normal form, dead-code elimination, and dead-`Phi` elimination.
Register/global value propagation (`pass_reg_global_propagation.py`) runs as its own pipeline stage
in the Falcom entry point, after SSA deconstruction.

## Testing

Only one dedicated MLIL test file currently exists: `tests/test_mlil_metadata.py`. This is
noticeably thinner than HLIL's three dedicated test files — worth treating as a gap given how much
of the real optimization work (SSA construction/deconstruction, the ~10 SSA passes, register/
global propagation) has no direct test coverage of its own.

## Open Items

- `DeadCodeEliminationPass()` in the Falcom pipeline is commented out with an unresolved
  "check if needed" note — worth actually resolving given other DCE passes already cover most of
  the same ground.
- Dedicated MLIL-SSA test coverage (construction, deconstruction, critical-edge splitting, each of
  the ~10 optimizer passes) doesn't exist yet, unlike HLIL's per-pass test files.
- This document and `docs/MLIL_GUIDE.md` should be kept in sync with `ir/mlil/passes/` as passes
  are added, removed, or reordered — that directory is the actual source of truth for what runs.
