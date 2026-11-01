# Medium Level IL (MLIL) Design

> Status: Implemented. This document originally described a pre-implementation target
> architecture; it has been rewritten against the real implementation (2026-09-20), including a
> full SSA optimizer pipeline that predates this revision but was never documented. See
> `docs/mlil/MLIL_GUIDE.md` for a practical usage guide; this document focuses on the node model and
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
| `ir/mlil/passes/` | The actual pass implementations (15 files): `pass_llil_to_mlil.py`, `pass_ssa.py`, `pass_ssa_sccp.py`, `pass_ssa_constant_propagation.py`, `pass_ssa_copy_propagation.py`, `pass_ssa_expression_simplification.py`, `pass_ssa_condition_simplification.py`, `pass_ssa_nnf.py`, `pass_ssa_expression_inlining.py`, `pass_ssa_dead_code.py`, `pass_ssa_dead_phi.py`, `pass_ssa_type_inference.py`, `pass_reg_global_propagation.py`, `pass_block_merge.py`, `pass_bitwise_hex.py`; SCCP, expression simplification and register/global propagation are out of the pipeline (see "LLIL → MLIL Pipeline"). |
| `ir/mlil/mlil_builder.py` | `MLILBuilder`: builds a function's blocks, variables and statements; expressions are built with the node classes. |
| `ir/mlil/mlil_formatter.py` | Pretty printer for MLIL functions (text dump used in tests/debugging) and the `.mlil.dot` graphs, with the DOT writer LLIL's formatter shares (`CFGDotFormatter`, `ir/core/il_cfg.py`). |
| `ir/mlil/mlil_types.py` | Type-kind/unification support. |
| `ir/mlil/llil_to_mlil.py` | Generic `LLILToMLILTranslator` (not Falcom-specific). |
| `ir/mlil/llil_ops.py` | The LLIL operations that map one to one onto MLIL ones (`BINARY_OP_TYPES`, `UNARY_OP_TYPES`), for both translators. |
| `ir/mlil/stack_translator.py` | The generic symbolic-stack translator, `StackTranslator`, and `StackTranslatorPass` (see "The stack translator"). |
| `falcom/ed9/ir/mlil/mlil_converter.py` | Falcom's concrete pipeline wiring — the real production entry point, `convert_falcom_llil_to_mlil()`, and the stack translator's, `convert_falcom_llil_to_mlil_stack()`, not yet production. Mirrors `falcom/ed9/ir/hlil/hlil_converter.py`'s structure exactly. |
| `falcom/ed9/ir/mlil/stack_translator.py` | `FalcomStackTranslator`: ED9's result register, calling convention, globals, script calls and `DEBUG_LOG` on the stack translator. |
| `falcom/ed9/ir/mlil/mlil_passes.py` | `ED9LLILToMLILPass`, the pipeline's first pass: the generic `LLILToMLILPass` run with the Falcom translator. |
| `falcom/ed9/ir/mlil/mlil_translator.py` | Falcom-specific LLIL → MLIL translation (syscall IDs, `CALL_SCRIPT` metadata, etc.). |
| `tests/mlil_tests/test_mlil_metadata.py` | One of several dedicated MLIL test files today — see Testing below. |

Note: `falcom/ed9/lifters/mlil_lifter.py`, previously listed here, does not exist anywhere in the
tree. This table now reflects the real path.

## Operations & Node Types

All MLIL nodes derive from a common `MediumLevelILInstruction` base carrying an
`operation` enum value and source tracking: `address` (the SCP offset), `llil_index` (the LLIL
instruction the statement comes from - every statement one LLIL instruction produces shares it, and a
statement de-SSA places on a CFG edge, a phi copy or a split-edge goto, takes the branch that leaves
along that edge) and `inst_index` (the statement's own number: `convert_falcom_llil_to_mlil()` and
`optimize_mlil()` end by numbering every statement 0..N-1 in block order, and HLIL copies it as
`mlil_index`). On the SSA path only statements carry them, expressions keeping the defaults; the stack translator
stamps every expression node too, with the LLIL statement it comes from (`MLILBuilder.stamp`). A pass that replaces a
statement copies all three with `copy_metadata_from()`. Nodes are split into `MediumLevelILExpr` (produces a value) and
`MediumLevelILStatement` (side effects only); the concrete instruction classes in both cover:

| Category | Examples |
| --- | --- |
| Constants | `MLIL_CONST_INT`, `MLIL_CONST_FLOAT`, `MLIL_CONST_STR` |
| Variable read/write | `MLIL_VAR`, `MLIL_SET_VAR`, `MLIL_PHI` (SSA form) |
| Arithmetic / logical | `MLIL_ADD`, `MLIL_SUB`, `MLIL_MUL`, `MLIL_DIV`, `MLIL_MOD`, `MLIL_AND`, `MLIL_OR`, `MLIL_NOT`, `MLIL_CMP_*` |
| Memory / stack artifacts | Explicit address expressions, for the cases where a raw stack address is referenced directly rather than eliminated. |
| Pointer dereference | `MLILDeref` (`*ptr`, a unary expression) / `MLILStoreDeref` (`*dest = value`, modelled on `MLILStoreGlobal` but with an expression target instead of a static index) — for `LOAD_STACK_DEREF`/`POP_TO_DEREF`, where the address is a runtime value (e.g. a caller-supplied out-parameter) rather than a statically known stack/frame slot. Unlike `MLILAddressOf`, a `MLILDeref`'s operand is an ordinary value and safe to copy-propagate through; a `MLILStoreDeref` is always kept (never DCE'd) since its target isn't a tracked SSA variable. |
| Control flow | `MLIL_GOTO`, `MLIL_IF`, `MLIL_RET` |
| Calls | `MLIL_CALL`, `MLIL_CALL_SCRIPT`, `MLIL_SYSCALL` |
| Falcom specific | Derived metadata on top of generic ops — stack-setup helpers like `PUSH_CALLER_FRAME`/`PUSH_CURRENT_FUNC_ID`/`PUSH_RET_ADDR` are fully lowered to regular variables/arguments, with no dedicated MLIL opcode. |

When a pass replaces a node's operands and keeps its operation, it calls `map_operands(node,
transform)` (`ir/mlil/mlil.py`): transform runs on each direct operand in evaluation order, and the
node comes back as it is when nothing changed, else through its own `rebuild(*operands)`, which keeps
the source metadata (address, indices) and every other field. `MLILBinaryOp.rebuild()` and
`MLILUnaryOp.rebuild()` are one method each, since every subclass sets only its `OPERATION` and
keeps its base's constructor, which takes only the operands; every statement holding an expression
has its own, so a new node type with operands needs one too. SSA construction and deconstruction,
copy propagation, inlining, constant propagation, SCCP and register/global propagation rewrite this
way: each handles its own leaves and names what it does not enter (copy propagation, inlining, SCCP
and the address-taken lowering stop at `&`; constant propagation also at `TestZero`). There is no
per-pass reconstruction table. A rewrite that produces a different operation (NNF's De Morgan,
comparison inversion) builds the new node directly.

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
  deconstruction (`SSADeconstructor`) converts back to non-SSA form afterward. An entry block a back
  edge enters (a loop at the function's very start) first gets an empty block in front of it
  (`SSAConstructor._add_entry_preheader`): the dominance frontier counts only real predecessors, so
  without one the loop header had no phi and the loop's writes to a parameter or register were lost.

Stack slots are named `var_sN` and parameters `argN`. Which one an access gets is decided by the
LLIL builder from the slot's current lifetime (`LowLevelILBuilder._holds_parameter`): a parameter
slot is `argN` only while it still holds the caller's value, and a value pushed there after the
function popped the parameter is a `var_sN`, like any other push.

SSA is not optional or a future addition — it's where essentially all real optimization work
happens. The shared pass list (`mlil_optimization_passes()` in `ir/mlil/mlil_optimizer.py`) merges
call-split blocks, converts to SSA, runs the full `SSAOptimizer` pass suite plus optional type
inference, deconstructs back to non-SSA, then marks bitwise constants for hex display (`BitwiseHexPass`). HLIL's
converter (`falcom/ed9/ir/hlil/hlil_converter.py`) imports and consumes
non-SSA `MediumLevelILFunction` — it does not read SSA form directly; by the time HLIL sees a
function, SSA construction/optimization/deconstruction has already happened upstream in the MLIL
pipeline.

Falcom-specific stack-setup helpers (`PUSH_CALLER_FRAME`, `PUSH_CURRENT_FUNC_ID`, `PUSH_RET_ADDR`) are
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
`docs/hlil/HLIL_GUIDE.md`'s printing-convention section.

**A register a return leaves is the caller's.** A caller can read a register after the call, as it
reads a global, while a register variable prints as a local. So SSA construction ends by storing,
before each return, every register whose version there is the function's own write
(`SSAConstructor._store_registers_left_by_returns`, `registers_left_by_returns`): `REGS[n] = v`,
an `MLILStoreReg`, an ordinary read no pass drops, which HLIL prints as the register. Left out: the
result register (`MediumLevelILFunction.result_register`, from the translator's `RESULT_REGISTER`),
which the return passes as its value; a version a call may have clobbered, the callee's; a phi
over only incoming and callees' values. Each store stores what the registers held before any of
them: an `MLILStoreReg` redefines its register for copy propagation and inlining (below), so a
read of a register another store overwrites stays before that store. Real bytecode has none: its
registers do not cross a call boundary but through the result register.

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

(Simplified for illustration — the real classes are `MediumLevelILBasicBlock` and
`MediumLevelILFunction` in `ir/mlil/mlil.py`.) Predecessor/successor edges are `incoming_edges`/`outgoing_edges`, not `preds`/
`succs`. Both layers' blocks derive from `ILBasicBlock` (`ir/core/il_cfg.py`): the instructions, the edges kept on
both ends (`add_outgoing_edge`) and `has_terminal`.
Each MLIL block mirrors an LLIL block when `optimize=False` - the `BlockMergePass` (part
of the SSA optimization pipeline, so it does not run when `optimize=False`) collapses call-return
and other single-predecessor goto chains when optimization is enabled, so this 1:1 property does
not hold for `optimize=True` output. A statement's `llil_index` is how tools get back to LLIL
(`MediumLevelILFunction.llil_function` is the LLIL function it was translated from); there is no
separate LLIL-to-MLIL map.

## LLIL → MLIL Pipeline

The real production entry point is `convert_falcom_llil_to_mlil()`
(`falcom/ed9/ir/mlil/mlil_converter.py`), which builds a `Pipeline` and runs, in order:

```
ED9LLILToMLILPass → BlockMergePass (optimize only) → SSAConversionPass → SSAOptimizationPass →
SSATypeInferencePass (optional) → SSADeconstructionPass → BitwiseHexPass
```

Every pass after `ED9LLILToMLILPass` comes from `mlil_optimization_passes()`
(`ir/mlil/mlil_optimizer.py`); `optimize_mlil()` runs the same list on an already translated
function, so tests that call it run what production runs. No dead-code pass runs after SSA
deconstruction: a census of production output found no unread local assignment (500-file sample,
2026-09-26).

Since 2026-10-27 no pass computes a value the bytecode does not hold, so MLIL keeps the LLIL's values as
written: SCCP, `ExpressionSimplificationPass` and `RegGlobalValuePropagationPass` (constant folding, algebraic
identities, a register's or global's value carried forward) are out of the pipeline, their code and direct tests
kept. A constant expression prints as written (`1 | 32768`, `40000 + 200`), a branch on one keeps both arms
(`if ((1024 & 1024) != 0)`), and a register read stays `REG[n]`.

`BitwiseHexPass` (`pass_bitwise_hex.py`) runs last and only marks constants for display: a bitwise operation
(`& | ^ << >>`) whose other operand is not constant prints its int constant operand in hex, under a `~` too
(`arg3 & 0x00000800`, `x & ~0x00000010`), and a union of single-bit flags there as well (`x & (0x00000001 |
0x00000008)`); any other expression made only of constants prints as written (`1 | 32768`). It sets only
`MLILConst.is_hex`, which the HLIL converter copies, so `.mlil.asm`, `.hlil.ts` and `.ts` agree.

### Optimization Passes (inside `SSAOptimizer`)

Run on SSA form, in `ir/mlil/mlil_ssa_optimizer.py`'s configured order: constant propagation (a
variable's one constant definition substituted into its reads), condition simplification, negation
normal form, copy propagation, expression inlining, dead-code elimination, and dead-`Phi` elimination.
They repeat until a round changes nothing, for at most `SSA_OPTIMIZER_MAX_ITERATIONS` (10) rounds -
hitting the cap prints a "did not converge" warning.
Dead-code elimination repeats its own sweep until nothing more is removed, so a dead chain goes in
one round rather than one link per round. A removed string assignment stays as a `debug.string`
comment unless constant propagation put the string into its uses: both dead-code passes read the
variables it substituted (`ConstantPropagationPass.replaced_vars`, `string_debug_comment`).

Condition simplification and negation normal form negate only `==` / `!=` (`negate_comparison`): an
ordering keeps its NOT (`!(a < b)`), since `!(a < b)` and `a >= b` differ when an operand is NaN.
HLIL's structuring still inverts orderings (`negate_condition`, `ir/hlil/hlil.py`).

Copy propagation and expression inlining never move a register/global read past anything that may
redefine that storage: an explicit definition, a store to the register (`MLILStoreReg`), a call's
own output, or any call that may clobber it
(`MediumLevelILFunction.call_may_clobber`, the same rule SSA construction uses for its `<undef>`
pseudo-definitions). Both passes share one check, `reaches_without_redefinition`
(`pass_ssa_copy_propagation.py`), which also scans the use block's own instructions before the use.
The call itself is the barrier, not its pseudo-definitions or output: dead-code elimination drops an
unread call output and dead register pseudo-definitions while the call - and its clobber - stays,
so a later optimizer round must still see it (without this, a saved `reg0` value was forwarded past
the next call in ~1,800 places across the corpus). Call results only ever land in the result
register, so dropping an unread call output never loses a global write.

SCCP (out of the pipeline, above) folds constant `+ - * & | ^ << >>`, unary `- ! ~`, `&&`/`||`, and
comparisons on ints, but deliberately never evaluates `MLIL_DIV`/`MLIL_MOD`, or any op with a float operand,
to a lattice constant (`pass_ssa_sccp.py`'s `_eval_binary_op`/`_eval_unary_op`), and a float constant decides no
branch (`_visit_branch`) - Python's arithmetic doesn't match the VM's actual number format
(`ScpValue`'s 30-bit-int/float32 shape describes the constant *encoding*, not the runtime arithmetic
width), and the real semantics (float32 rounding, int/float mixing, a float's truth, int truncation,
overflow, MOD's sign) can't be verified without running the game. Folding with an unverified formula
risks silently replacing one wrong constant with another: `0.4 * 0.8` used to print as `0.32`. The
same holds downstream: HLIL's `constant_truth` and loop recovery decide nothing from a float, the
TypeScript printer folds a comparison of two constants only for ints, and the rewrites that turn a
comparison with zero into a truth test (condition simplification, boolean-temp inlining, the TypeScript
printer) accept only the int `0` (`is_int_zero`, `ir/core/il_literals.py`). `ExpressionSimplificationPass`'s
identities likewise fire only on int constants (`0.0 * x` used to become the int `0`), but they still
simplify an int DIV by 1, even a constant one (`10 / 1 → 10`), since that identity holds regardless of
numeric semantics. See `docs/mlil/MLIL_FUTURE_WORK.md` for what a verified SCCP fix would need.

In SCCP, a phi of constants folds to a constant only when `constant_values_equal` (`ir/core/il_literals.py`)
says they are equal: same type (`1`, `1.0` and a `SourceFloat` all differ) and, for floats, same bits
and same printed text (`0.0` and `-0.0` differ, NaN equals NaN).

### Type Inference

`SSATypeInferencePass` types parameters from their declared kinds, `SetVar`/`Phi` targets, and
address-taken locals through their `*(&x) = v` stores, takes backward hints from the top level of
each `if` condition (a comparison with a constant, arithmetic, a bare truth test), then unifies every
SSA version into one type
per variable name (`func.var_types`, printed as the `.mlil.asm` "Inferred Types" list). Conflicting
kinds unify to an `MLILVariantType`, which is identified by its members (`mlil_types.py`), so a
member that arrives after the variable is already a variant is still recorded.

## The stack translator (not yet production)

`convert_falcom_llil_to_mlil_stack()` runs `ED9StackTranslatorPass`, `BlockMergePass` and `BitwiseHexPass`. It will
replace the SSA path at parity (IR rewrite part 2), and the decompile path does not call it yet.

The translator (`StackTranslator`, `ir/mlil/stack_translator.py`; `FalcomStackTranslator` for ED9) reads only the
LLIL and its stack layout: each block's `sp_in`, each stack access's `slot_index`, the `SpAdd`s. A function-wide
pre-pass finds which push each slot holds and how each push is read. Translation then works on that:
- **Pending values:** a pushed value stays a pending expression and folds into the statement or expression that
  consumes it.
- **Locals:** a push becomes a local when it is read by offset, written in place or address-taken, when it is never
  read and is no call's setup (a declared slot, kept), or when it is read twice. Locals are named per declaring
  push: `var_s<slot>`, then `var_s<slot>_<n>` for sibling scopes in one slot.
- **Address-taken variables:** an address-taken local (per declaring push: a sibling local in its slot, or a value
  pushed there, stays plain) or parameter (for the whole function) is read and written in memory form, through its
  address: `*(&v)` and `*(&v) = value`, the SSA path's shapes, which the printers fold back to `v`. A call's result
  goes to a fresh temporary, so no call output is one.
- **Copies before a write:** before a statement that writes storage, every pending leaf the write may change is
  copied into a fresh temporary `t<n>` (one conservative rule, `may_change`). A call may change every register,
  global and dereference, `*(&v)` included; a store to `v` changes `v` and `*(&v)`; a store through a pointer changes
  every dereference, `*(&v)` included (the function may have stored `&v` in the pointer parameter).
- **Calls:** a call's continuation (its return target, reached from the call alone) is translated into the call's
  own block, the pending values carried over.

**The canonical form:**
- every register is storage, `REG[n]` (`MLILLoadReg` / `MLILStoreReg`), and no register variables;
- a call with a result writes it to the result register through a temporary (`t1 = f(); REG[0] = t1`), so a later
  read of the register sees a write the output prints;
- a return reads the result register (`return REG[0]`), and `result_register` is set;
- a tail call is `t = module.func(args)` marked `tail_call`, then `REG[0] = t; return REG[0]`;
- a condition stays as the LLIL has it (`(x == 0)`); HLIL's switch recognizer reads a chain link through it
  (`strip_truth_test`, `docs/hlil/HLIL_DESIGN.md`).

Shaping passes (dropping a dead result store, returning a stored value directly) come after the translator, each
exact and removable.

**Not translated yet:** a function with a value pending where control reaches a block other than its call's
continuation, a block entry slot two pushes may hold, or an address of a slot no push holds (ED9's lifter refuses
such an address first). These raise
`UnsupportedStackShape`, as does, on ED9, a call frame value read as data (a hand edit reading a slot of a call's
setup, `PUSH_CALLER_FRAME`'s or `PUSH_CURRENT_FUNC_ID`'s: no MLIL node holds the VM's frame values).

**Counts:** the translator records the shapes it meets in the function's `translation_counts` (a `Counter`, empty
from the SSA path), which the corpus runs of IR rewrite part 2 compare with the side-effect census. Nothing prints
them, and the rewrite removes them after its last such run. The keys:
- `pending at <S>`: a statement that writes (or ED9's `DEBUG_LOG`) with a value pending below its own operands, once
  per statement. `<S>` is its LLIL operation name, a register store's with its register (`REG_STORE 1`);
- `copy at <S>: <leaf>`: each temporary made before a write, the leaf `register <n>`, `global`, `dereference` or
  `variable` (an address-taken one's `*(&v)` too);
- `push never read` (no consumer, no read or write by offset, no address taken, no call's setup) and
  `push read twice`, both locals;
- `store above sp`: a store into a dead slot (a `POP_TO` above `sp`);
- `sibling slots` and `sibling locals`: the slots holding two or more locals, and those locals;
- `unwritten register read`: a register read that some way reaches with no store to the register since the entry
  or since a call that clobbers (a dataflow over the translator's MLIL).

## Testing

Several dedicated MLIL test files exist today (`test_mlil_metadata.py`,
`test_mlil_ssa_optimizer.py`, `test_mlil_sccp_folding.py`, `test_mlil_address_taken.py`,
`test_mlil_reg_global_propagation.py`, `test_mlil_types.py`, and others) covering SSA construction/deconstruction, the
SSA optimizer's passes, and register/global propagation - a closed gap from when this line last
said only one existed. `test_mlil_stack_translator.py` covers the stack translator on assembled functions, each case
also compared clean by the logic check on both pairs.

## Open Items

- Four SSA optimizer passes have no behaviour test of their own: negation normal form, expression
  simplification, constant propagation and dead-`Phi` elimination (three appear only in metadata
  checks: `test_mlil_rebuild.py`, `test_mlil_provenance.py`).
- SCCP's edge reachability is coarse, and kept that way on purpose: a statement it does not model (a
  call, a store) marks every edge out of its block reachable, and so does an `if` whose condition is
  not known yet. This only loses folding - SCCP never removes blocks - and tighter
  reachability would fold more constants, moving output further from the bytecode.
- Rendered parameter types no longer come from this pass: since 2026-09-29 HLIL's
  `FalcomTypeInferencePass` takes them from the declared flags, so `Value32`/`Nullable32` - which this
  pass still calls `int` - reach a signature as `number` (int or float). Locals still use this pass's
  types. An HLIL type pass for locals (CX Step F's follow-up plan) is parked until the tool is nearly
  done. Known gaps until then: call results are never typed (a call is a statement with an `output`,
  which the pass never reads); use hints come only from the top level of an `if` condition, so a
  comparison nested under `&&`/`||` gives none; and types are keyed by pre-deconstruction names, so a
  split variable (`var_s11_v0`) finds no type (78 locals in the corpus).
- This document and `docs/mlil/MLIL_GUIDE.md` should be kept in sync with `ir/mlil/passes/` as passes
  are added, removed, or reordered — that directory is the actual source of truth for what runs.
