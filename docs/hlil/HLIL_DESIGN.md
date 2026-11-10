# High Level IL (HLIL) Design

> Status: Implemented, active development. This document was rewritten against the real
> implementation on 2026-09-20 and is kept current by each change's doc correction (last full
> review 2026-09-29). See `docs/hlil/HLIL_GUIDE.md` for practical usage and the current pass-by-pass behavior;
> this document focuses on the node model, structural-analysis boundary, and architectural reasons
> behind the MLIL-to-HLIL conversion.

## Role in the Pipeline

```
SCP → Parser → Disassembler → Lifter → LLIL → MLIL → HLIL → Codegen (TypeScript)
```

HLIL is the final intermediate representation before code generation. MLIL has already removed the
VM operand stack and recovered named values, but it still expresses control flow as basic blocks,
conditional branches, and gotos. HLIL replaces that graph-oriented representation with a nested
statement tree suitable for source-like output.

That boundary gives HLIL three main responsibilities:

1. **Recover structured control flow** — represent branches and natural loops as `if`, `while`,
   `do-while`, `switch`, `break`, and `continue` nodes.
2. **Recover expression shape** — translate MLIL operators and calls, and fold safe single-use call
   results into their reader.
3. **Normalize source-like structure** — simplify recovered control flow without reintroducing CFG
   edges or an SSA variable model.

HLIL is intentionally not a general replacement for MLIL analysis. Data-flow work happens upstream (the stack
translator; on the SSA path, its optimizer); HLIL favors explicit tree ownership and straightforward code generation.

## Module Layout

| Path | Responsibility |
| --- | --- |
| `ir/hlil/hlil.py` | Core enums and tree nodes: expressions, statements, variables, switch cases, and `HighLevelILFunction`. |
| `ir/hlil/mlil_to_hlil.py` | Generic MLIL → HLIL conversion, including CFG construction, loop/branch reconstruction, shared-region cloning, and variable declaration. |
| `ir/hlil/call_result_folder.py` | `CallResultFolder`: which call results fold into the instruction reading them, decided on the MLIL before the converter emits anything. |
| `ir/hlil/structural_analysis.py` | Dominator calculation, natural-loop discovery, iterative region reduction, and merge-point queries used by the converter. |
| `ir/hlil/statement_printer.py` | `HLILStatementPrinter`, the statement printer the `.hlil.ts` formatter and the TypeScript code generator share: each prints expressions its own way and overrides the hooks where its statements differ (assignments, unstructured jumps, an if's arms, switch case blocks). |
| `ir/hlil/hlil_formatter.py` | The `.hlil.ts` formatter, on the shared statement printer: the bytecode's high-level form, not TypeScript. It is separate from the TypeScript code generator. |
| `ir/hlil/passes/` | Conversion wrapper and post-conversion tree transformations: switch recovery, loop recovery, common-return extraction, dead-code elimination, branch-order normalization, and line-marker removal. |
| `ir/hlil/__init__.py` | Public re-exports for the node model, the statement printer, the formatter and the passes (the conversion pass `MLILToHLILPass` among them). |
| `falcom/ed9/ir/hlil/hlil_converter.py` | Production Falcom pipeline entry point, `convert_falcom_mlil_to_hlil()`, and its pass ordering/configuration. |
| `tests/hlil_tests/test_hlil_branch_order_normalization.py` | Unit tests for source-order arm normalization and its pipeline flag. |
| `tests/hlil_tests/test_hlil_switch_recovery.py` | Unit tests for equality-chain and grouped-label switch recovery. |
| `tests/hlil_tests/test_hlil_loop_recovery.py` | Unit tests for guarded-loop recovery and its safety checks. |

The generic/project-specific split is deliberate. The core converter understands MLIL nodes and
structured control flow; the Falcom entry point chooses the production pass sequence. `FalcomTypeInferencePass`
(`falcom/ed9/ir/hlil/hlil_passes.py`) runs after it, once over the file's converted functions (the file-level stage,
`write_ts` in `falcom/ed9/scp2py_base.py`): it types parameters from the flags the script declares and, with the game's
syscall rows, tags character IDs.

## Operations & Node Types

Every tree node derives from `HLILInstruction`, which stores an `HLILOperation`, a source bytecode
`address`, and an `mlil_index`. `HLILStatement` and `HLILExpression` are marker subclasses that
separate side-effecting tree positions from value-producing ones. Directly translated statements
receive source metadata from their MLIL instruction, a loop its header block's last instruction's;
the other synthesized control-flow nodes and expressions can retain the base defaults.

The concrete model is small and source-oriented:

| Category | Nodes and purpose |
| --- | --- |
| Containers | `HLILBlock` owns an ordered list of statements. `HighLevelILFunction` owns one root block. |
| Structured control flow | `HLILIf`, `HLILWhile`, `HLILDoWhile`, `HLILSwitch`, `HLILBreak`, `HLILContinue`, `HLILReturn`. |
| Unexpressible jump | `HLILUnstructured` - a jump the tree cannot express; the path ends there (see Basic Blocks & Functions). |
| Ordinary statements | `HLILAssign`, `HLILExprStmt`, `HLILComment`, `HLILIntrinsic` (a VM instruction with no HLIL form of its own, its name and args: `POPN`, `DEBUG_INT`; never skipped by a pass that skips comments). |
| Leaf expressions | `HLILVar`, `HLILConst`. Constants retain an `is_hex` display hint, and an `id_kind` tag a project's stage sets (`.ts` prints the value by name). |
| Operators | `HLILBinaryOp`, `HLILUnaryOp`, `HLILAddressOf`, using `BinaryOp` and `UnaryOp`. |
| Pointer dereference | `HLILDeref` (`*ptr`, from `MLILDeref`) - like `HLILAddressOf`, not a subclass of `HLILUnaryOp`. A store through one (`MLILStoreDeref`) lowers to an ordinary `HLILAssign` whose `dest` is an `HLILDeref` - no dedicated store node. |
| Calls | `HLILCall`, `HLILSyscall`, and `HLILExternCall`. |

`BinaryOp` distinguishes arithmetic, comparison, logical, and bitwise operations. This distinction
matters because MLIL `AND`/`OR` become bitwise operators, while MLIL `LOGICAL_AND`/`LOGICAL_OR`
become boolean operators. MLIL logical-not and test-zero operations are represented as equality
with zero; other unary operations map to negation or bitwise-not.

The boolean operators come in two kinds. `AND`/`OR` are the VM's eager `LOGICAL_AND`/`LOGICAL_OR`: both
operands always run. `AND_THEN`/`OR_ELSE` are logic recovered from jumps (`_collapse_funnel_chain`,
`if (C || true)`, and what `negate_condition` makes of those): the right operand runs only when the left
leaves the answer open. `.ts` prints both as `&&`/`||`, `.hlil.ts` the recovered ones as `andThen`/`orElse`.
`DE_MORGAN_OP` keeps the kind, `OR_OPS` is either `||`, and the logic check (`tools/logic_check/`) tests an
eager op whole and a recovered one operand by operand.

Operator knowledge lives once, in `ir/hlil/hlil.py`, in two groups. The language-neutral group -
`COMPARISON_OPS`, `BOOLEAN_BINARY_OPS`/`is_boolean_expr`, `NEGATED_COMPARISON_OP`, `DE_MORGAN_OP`,
`negate_condition` (negation distributed through `&&`/`||`) and `strip_truth_test` (a boolean's truth
tests, `(c) != 0`, `(c) == 0` and `!c`, read off without changing the tree) - is what any output language
needs, including the planned HLIL DSL. The C-family syntax group - the `BINARY_OP_STR`/`UNARY_OP_STR`
symbols, `BINARY_OP_PRECEDENCE` and `needs_parentheses` - serves only the
TypeScript generator and the `.hlil.ts` formatter; a non-C output needs its own. `TERMINAL_STATEMENTS`
(return, break, continue, `HLILUnstructured`) is the one list of statements that never fall through.
`SwitchRecoveryPass` reads each chain link through `strip_truth_test`: the stack translator keeps the
LLIL's jump test, so a link arrives as `(x == k) == 0`, or `(x == k) != 0` once negated.

Tree walking is shared the same way. `sub_blocks` gives the blocks a structured statement owns;
`node_children` gives every child of a node in source order (a switch contributes each case's
labels, then its body), and `iter_tree` walks a whole subtree without recursion. `statement_expressions` gives a
statement's own expressions, not those of the blocks it owns, so a walk of each reachable statement visits each once.
`contains_escaping_exit` says whether a `break`/`continue` leaves a block (a loop owns both, a switch
only a `break`), and `sole_statement`
finds a block's one non-comment statement. The passes, the converter's variable declaration and
the renderers are built on these, so a new node type needs a sample in
`tests/hlil_tests/test_hlil_traversal.py` and an entry in `node_children` (a statement) or `expr_children` (an
expression), plus `sub_blocks` if it owns a block - that test fails until both exist.

`HLILSwitchCase` is a helper owned by `HLILSwitch`, not an `HLILInstruction`. Its `values` field is
either a list of expressions or `None` for the default case. A list permits several case labels to
share one body, which preserves a recovered chain such as `x == A || x == B` without duplicating
the body.

`HLILExternCall` also has no distinct `HLILOperation`; it uses `HLIL_CALL` while preserving the
external `target` string separately. Consumers that care about the call form therefore dispatch on
the concrete class, as the formatter and optimization passes do.

`HLILFor` previously existed in the node model but was removed (Step H, Codex IR review plan,
2026-09-22): nothing ever constructed one, and both renderers passed its statement-typed
`init`/`update` fields to the expression formatter, so its output was already wrong for a shape
nothing produced. Current loop output is `HLILWhile` or `HLILDoWhile` only. If a for-loop
recognizer is ever built, design it (and its rendering) from scratch rather than reviving the old
node.

`HLILDoWhile` carries an optional `label`, the same as `HLILWhile` - needed so a `while(1)` loop
recovered into `do-while` form (`HLIL_GUIDE.md`'s loop recovery section) keeps working
`continue`/`break` targets for anything that names it from a nested construct.

Comments are first-class statements rather than formatter-only annotations. In particular,
`line(N)` comments carry source-order evidence used by `BranchOrderNormalizationPass`; every reader
that needs a marker's line number (that pass, `tools/ir_line_order_report.py`) takes it from
`line_marker_number()`. The shared `split_else_if_arm()` helper also treats comments before a lone
nested `HLILIf` as annotations for the next test, allowing both renderers to agree on `else if` shape.

## Variable Model

HLIL has one non-SSA variable object, `HLILVariable`. It carries:

- `name` for locals and parameters;
- `type_hint` and `default_value` metadata;
- `id_kind`, a parameter's ID kind (e.g. `'ChrId'`): a tag a project's stage sets, read by `.ts` only (not in equality
  or hashing);
- a `VariableKind` of `LOCAL`, `PARAM`, `GLOBAL`, or `REG`;
- `index` for global and register slots.

`HLILVar` is the expression that reads one of these objects. Locals and parameters render by name;
globals and registers render as `GLOBALS[index]` and `REGS[index]`. Stores to MLIL register/global
slots become assignments to those same explicit storage expressions. There is no separate HLIL
register instruction family.

Equality compares a variable's name, kind, and index. This prevents a named local from being
treated as the same storage location as a register or global slot. Parameters are collected from
MLIL before reconstruction, while locals are declared afterward by walking the emitted tree in
first-use order. Unused MLIL temporaries consequently do not become HLIL declarations.

HLIL does not have variable versions, phi nodes, or SSA construction/deconstruction. It consumes
the non-SSA `MediumLevelILFunction` produced by the upstream MLIL pipeline. This keeps the final IR
close to a source-language variable model and avoids exposing optimizer machinery to codegen.

Type information is deliberately lightweight. `HLILTypeKind` contains `INT`, `FLOAT`, `STRING`,
`BOOL`, `VOID`, `POINTER` and `NUMBER` (int or float), but types are hints on variables rather than
types attached to every expression. During conversion, MLIL booleans map to `INT`, MLIL pointers
(`Pointer` out-parameters) to `POINTER`, and unknown and variant MLIL types to no hint. Parameter default
values are copied from MLIL source-parameter metadata when available. The file-level stage's
`FalcomTypeInferencePass` then sets each parameter's type from its declared flag -
`Value32`/`Nullable32` -> `NUMBER`, `str`/`NullableStr` -> `STRING`, `Pointer` -> `POINTER` - so a
signature never depends on MLIL inference. Locals have no type on the decompile path (its stack translator runs no
type pass: `any` until the HLIL type plan); on the SSA path they take the MLIL SSA types.

### Call Results as Expressions

MLIL calls are statements with an optional output variable; HLIL calls are expressions. The
`CallResultFolder` bridges that mismatch using non-SSA liveness over variable names. A call result
is folded only when the converter can identify one reader, the value is dead afterward, and no
intervening control-flow or evaluation-order constraint makes substitution unsafe.

The folder can look through a run of other calls that will fold into the same reader, but only when
the reader's operand order matches call execution order. It can cross into a single-successor block
only when that block has one predecessor. Calls without outputs remain expression statements so
their side effects are preserved; calls with non-foldable outputs remain assignments.

The fold moves the call to the read's position, so that position must run exactly when the
statement did (`CallResultFolder._read_unsafe_to_fold`). A fold is refused when an impure read (a
deref or a `REG[]`/`GLOBAL[]` load) comes earlier in the reader's evaluation order, and when the read
sits under `&x`. A read under the VM's eager `AND`/`OR` folds on either side: both operands always
run, in order. `.ts` keeps that true where TypeScript's `&&`/`||` would not, with `and_`/`or_`. The
converter's `OR_ELSE` chains (funnel collapse) take in a later test, calls folded into it included,
only when that test is entered from the previous one alone, so its calls run only when the earlier
tests failed: a call on the right of `AND_THEN`/`OR_ELSE` really is conditional.

This specialized folding belongs in conversion rather than a post-conversion tree pass: it
uses MLIL instruction positions, CFG predecessor information, and call evaluation order before the
graph is discarded.

## Basic Blocks & Functions

HLIL has no basic-block class and stores no predecessor/successor edges. Its structural unit is the
nested `HLILBlock`:

```
class HLILBlock(HLILStatement):
    statements: list[HLILStatement]


class HighLevelILFunction:
    name: str
    start_addr: int
    body: HLILBlock
    variables: list[HLILVariable]
    parameters: list[HLILVariable]
```

(Simplified field view; the real definitions are in `ir/hlil/hlil.py`.) An `HLILIf` owns its true
and optional false blocks; loops own their bodies; a switch owns cases, and each case owns a body.
This exclusive nesting is what makes recursive optimization and code generation simple.

Removing CFG edges creates a representational constraint: HLIL has no goto node. Most shared tails
become code after an enclosing construct, but a body reached independently from several conditions
cannot always be expressed that way. The converter may reconstruct that region again (a loop
entered again is rebuilt whole), bounded by `CLONE_STATEMENT_BUDGET` statements per function -
nested statements counted, comments not (a line marker never decides what is repeated), a region
repeated inside another charged once - and `CLONE_MAX_REGION_BLOCKS` blocks per region (both
overridable in the converter's constructor, for tests). A merge that falling out of a branch would
not reach (a loop entered since, or a nearer merge in between) is repeated the same way. A jump it
cannot express - a region it may not repeat - becomes an `HLILUnstructured` node rather than a
fallthrough to whatever follows: the path ends there, visibly.

Nested loop exits are represented with optional labels. The converter maintains a loop stack; a
jump to an active loop header becomes `continue`, and a jump to its selected exit becomes `break` -
also through goto-only blocks, since the exit is compared after skipping them, while a loop header
is never skipped. A skipped block's line markers print where its code runs, once per copy; those of
the goto-only blocks after a loop's chosen exit follow the loop, for every way out. When an edge
targets an outer rather than the innermost loop, the outer loop and transfer receive a generated
label.

## MLIL → HLIL Pipeline

The generic conversion begins by deriving a CFG from each MLIL block's terminal `MLILIf`,
`MLILGoto`, `MLILRet`, or implicit fallthrough. `StructuralAnalyzer` then computes dominators on the
original graph (`ir.core`'s `immediate_dominators`, which the logic check shares), identifies natural
loops from back edges whose targets dominate their sources, and
performs iterative region reduction in this priority order: loops, conditionals, then linear
sequences.

The converter uses that analysis as decision support rather than asking it to emit the HLIL tree.
It queries loop membership and exits, merge points, and whether a branch looks like an
inverted continuation chain. A merge point is where both arms of an if continue once they fall out
of it, so it has to be a real merge: `find_merge_point` keeps the heuristic's answer (a reduction
region, else reachability on the original graph) only when, within the innermost loop around the if
and before the converter's enclosing stop, no path gets around it into the code after it or reaches
the enclosing stop first; otherwise the nearest real merge both arms reach is used, and with none
the arms run up to the enclosing stop. A self-loop's natural loop is just its header. Recursive reconstruction remains responsible for owning blocks,
emitting branch arms, recognizing active-loop transfers, and processing merge blocks exactly once.
This separation keeps graph algorithms isolated from MLIL-to-HLIL node translation. It recurses into
branch arms and loop bodies only: the code after an if or a loop (its merge block or exit) is
returned as a `FollowOn` and continued in `_reconstruct_control_flow`'s loop, so recursion depth
grows with nesting, not with function length. Deep nesting still recurses - a long `else if`
cascade nests one level per test - so `falcom/ed9/scp2py_base.py` and `tools/ir_semantic_validator.py`
raise Python's recursion limit to 10,000.

Before reconstruction, `CallResultFolder` computes its folding decisions. The converter then
translates parameters, reconstructs from MLIL block zero, and finally declares the local variables
actually present in the result. Funnel-shaped runs of tests that share a target - each later one
holding only its test and the calls folded into it - are collapsed inside the converter into one
logical-OR condition so the shared body need not be emitted for every test; a later test with a line
marker of its own (a nested `if` in the source) is left out.

The production entry point is `convert_falcom_mlil_to_hlil()` in
`falcom/ed9/ir/hlil/hlil_converter.py`. Its configured pipeline is:

```
MLILToHLILPass → SwitchRecoveryPass → LoopRecoveryPass → CommonReturnExtractionPass →
DeadCodeEliminationPass → BranchOrderNormalizationPass (enabled by default) →
LineMarkerRemovalPass (only with line_markers off)
```

For `.ts`, the file-level stage follows, once every function is converted and `.llil.asm`, `.mlil.asm` and `.hlil.ts`
are written: `FalcomTypeInferencePass` over the converted functions (a function the output leaves out, or whose
conversion failed, gives it nothing), then each function's TypeScript.

The post-conversion passes operate on the tree, not on the original CFG. In architectural terms,
they divide into shape recovery (`SwitchRecoveryPass`, `LoopRecoveryPass`), cleanup
(`CommonReturnExtractionPass`, `DeadCodeEliminationPass`), and presentation-preserving ordering
(`BranchOrderNormalizationPass`), which is optional through `normalize_branch_order` because it
deliberately prefers recovered source-line order over bytecode emission order.
`LineMarkerRemovalPass` runs after all of them and only with `line_markers` off: it drops the
`line(N)` comments, then tidies the if arms left empty without changing what runs (a negated
condition, swapped or nested arms); the code statements and their order are unchanged.

HLIL has no copy-propagation pass (the disabled HLIL `CopyPropagationPass` was removed on 2026-09-27): the decompile
path's stack translator folds each push into its consumer, and the SSA path propagates copies in its optimizer.
`FalcomTypeInferencePass` is the home of Falcom semantic types: the parameter types (see Variable Model), and the
character IDs. With the game's syscall rows (`falcom/ed9/games/<game>/metadata/syscall_args.py`), a parameter is marked
as an ID (`HLILVariable.id_kind`) when every read of it is a pass to an ID slot: a syscall's ID slot, or a marked
parameter of a call to a function of the same file, which chains (least fixpoint, a worklist from the syscall passes).
A read anywhere else blocks the mark (a comparison, arithmetic, a non-ID slot, a row-less syscall, an `extern_call`,
an unmarked callee), as does a write or an address taken anywhere in the body, and a read in unreachable code counts
for nothing. Passes of two kinds leave it unmarked. Then each int constant written in decimal that is exactly the
argument at an ID slot, of a syscall by its row or of a call to a marked parameter, is tagged (`HLILConst.id_kind`).
Each function's part runs on its own: one whose facts or whose rows lookup raises is logged and gets no marks or tags.
See `docs/hlil/HLIL_GUIDE.md` for the detailed transformations performed by each active pass and why the
copy-propagation pass was removed.

## Testing

Several dedicated HLIL unit-test files exist today:

- `tests/hlil_tests/test_hlil_branch_order_normalization.py` covers line-based swaps, nesting-depth fallback,
  chain preservation, De Morgan negation, nested ordering, and the production enable/disable flag.
- `tests/hlil_tests/test_hlil_switch_recovery.py` covers switch conversion thresholds, mixed
  equality/inequality chains, grouped labels, duplicate rejection, scrutinee consistency, where the line
  comments before each later test end up, and links under a truth test (each form, `||` groups, label 0, a
  register scrutinee, and the tests that are no link).
- `tests/hlil_tests/test_hlil_switch_on_stack_path.py` runs dispatch chains as the compiler writes them through
  the stack translator: the expected switch, and the logic check's MLIL -> HLIL pair clean;
  `tests/mlil_ssa_tests/test_mlil_ssa_switch.py` runs the same chains through the SSA path.
- `tests/hlil_tests/test_hlil_loop_recovery.py` covers leading break/return guards, unsafe rotations, nested
  switch breaks, preservation of already-tested loops, the while(1)->do-while rotation (from a trailing
  `if (c) break;` and, since 2026-10-28, from a trailing `if (c) continue; else break;`), and its
  continue-safety/label-preservation guards (Step H, 2026-09-22).
- `tests/hlil_tests/test_hlil_loop_traversal.py` (Step H, 2026-09-22) covers `DeadCodeEliminationPass`,
  `CommonReturnExtractionPass`, and `TypeScriptGenerator._infer_return_type` each correctly seeing
  into a do-while body via the shared `sub_blocks` helper.
- `tests/hlil_tests/test_hlil_call_fold_short_circuit.py` covers calls folding under the VM's eager logic and
  into funnel tests.
- `tests/hlil_tests/test_hlil_long_functions.py` checks that long runs of sequential ifs and loops convert
  without recursing once per statement.
- `tests/hlil_tests/test_hlil_common_return_extraction.py` covers when `CommonReturnExtractionPass` may hoist a
  shared return (switch default and bare-break guards, `if` without `else`, int/float and NaN
  constants) plus the shared `constant_values_equal` and `contains_bare_break` helpers.
- `tests/hlil_tests/test_hlil_operators.py` covers the shared operator tables (comparison negation is the
  complement), `negate_condition`, `strip_truth_test`, `needs_parentheses`, and the `.hlil.ts` formatter's operator
  symbols, recovered logic, truth tests and switch-case `break`s.
- `tests/hlil_tests/test_hlil_traversal.py` covers the shared tree walkers: every node type's children, source
  order, the escaping-exit rules, `sole_statement`, declaration order, and
  switch recovery reaching into a do-while body.
- `tests/hlil_tests/test_hlil_structuring.py` (CX Step G, 2026-09-28) runs small CFGs through structuring
  against their MLIL for every parameter assignment: merge points, loop exits and headers, the
  region-repeat limits, and the `HLILUnstructured` node (reachability, passes, rendering, validator
  report).
- `tests/hlil_tests/test_hlil_structuring_fuzz.py` does the same for 1,000 random CFGs, and checks no statement
  sits in two places, with markers or without.
- `tests/tools_tests/test_logic_check_mlil_hlil.py` checks HLIL against its MLIL with the logic check
  (`tools/logic_check/`): each way of losing or inventing a path, deleting an effect, or changing what a repeated
  region does is reported (`TestPlantedHLILBugs`), and the structures HLIL builds otherwise than MLIL compare clean
  (`TestHLILStructures`).
- `tests/hlil_tests/test_falcom_param_types.py` covers `FalcomTypeInferencePass`: the type each declared
  parameter flag gives, the declared flag winning over an inferred int/float variant, and default
  values still printed once; which parameters a syscall or a forwarding chain marks, each read that blocks,
  reachability, recursion, the names a body may change, which constants are tagged, a function that raises,
  and the propagation's kinds.
- `tests/hlil_tests/test_hlil_line_marker_removal.py` covers `line_marker_number`, `LineMarkerRemovalPass` (markers
  go from every block, other comments stay, the arms left empty are tidied) and the `line_markers` flag (on by
  default; off, it runs after branch-order normalization).

These tests directly exercise important tree rewrites and structuring, but not every part of HLIL
construction. `StructuralAnalyzer`'s own analyses (dominators, natural loops, region reduction),
source metadata propagation, variable declaration, and the rest of formatting (`hlil_formatter.py`)
still have no dedicated test file of their own.

## Open Items

- Parameter types come from the declared flags (`FalcomTypeInferencePass`, since 2026-09-29). Locals are
  `any` since the decompile path moved to the stack translator (IR rewrite part 2, 2026-11-01), which runs
  no type pass, until the HLIL type plan for locals; the SSA path's type pass never typed call results
  either (`any` in TypeScript), which were most of its untyped locals.
- **Resolved (Step H, 2026-09-22):** `HLILFor` (no construction site, and already-wrong rendering)
  was deleted rather than fixed. Tree-walking passes that only recursed into simple nested blocks -
  `DeadCodeEliminationPass`, `CommonReturnExtractionPass`, `TypeScriptGenerator._infer_return_type`
  - used to skip `HLILDoWhile` entirely; all three now share one traversal helper (`sub_blocks` in
    `ir/hlil/hlil.py`) covering every structured node that owns a nested block, so a future node
  type needs one edit there instead of one per walker. Since PR Step 6b (2026-09-27) the
  general-purpose walkers in branch-order normalization, loop recovery and
  the converter's variable declaration use the shared tree helpers too (see Operations & Node Types);
  since PR Step 10c (2026-09-28) so does branch order's `_if_depth`, the arm-order tie-break for
  arms without distinct line numbers: it counts ifs inside loops and switches too, and only an if
  adds a level.
  Separately, `LoopRecoveryPass`'s `while(1)` -> `do-while`
  rewrite was unsound when the body held a `continue` targeting the loop (different exit-target
  semantics between the two shapes) and silently dropped a labelled loop's label (`HLILDoWhile` had
  no `label` field); both fixed - see `HLIL_GUIDE.md`'s loop recovery section.
- **Resolved (Codex IR review plan Step G, 2026-09-28):** structuring used to lose or invent paths
  in some `sora2` functions - half of them behind `[hlil] dropped path` warnings, half with no warning at
  all (loops that never exited, a case's code run twice). The causes were merge points that were not
  merges and loop exits through goto-only blocks, not the clone limits. `tests/hlil_tests/test_hlil_structuring.py`
  pins each shape and the node's handling; `tests/hlil_tests/test_hlil_structuring_fuzz.py` runs 1,000 random
  CFGs through the pipeline against their MLIL for every parameter assignment; the logic check
  (`tools/logic_check/`, `docs/VALIDATOR_GUIDE.md`) checks real scripts (2026-10-29: of the 351,245 functions of the
  five games, only `TestEmotion` in `scena/a0000.dat` of kuro1, kuro2 and kai1 loses paths, at its two unstructured
  jumps). Still open: 6 of the 1,000 random CFGs are reducible yet need a node (pinned in the fuzz test;
  `docs/hlil/HLIL_FUTURE_WORK.md`, Structuring the Remaining Reducible Shapes).
- HLIL is the planned input of a Python DSL that compiles back to bytecode (`docs/dsl/DSL_FUTURE_WORK.md`,
  Recompilation Pipeline §1). Once that exists, every HLIL pass must preserve game logic exactly -
  readable-but-approximate rendering is only acceptable in the TypeScript generator.
