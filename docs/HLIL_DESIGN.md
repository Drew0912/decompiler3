# High Level IL (HLIL) Design

> Status: Implemented, active development. This document describes the real implementation as of
> 2026-09-20. See `docs/HLIL_GUIDE.md` for practical usage and the current pass-by-pass behavior;
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

HLIL is intentionally not a general replacement for MLIL analysis. Data-flow optimization and SSA
work happen upstream; HLIL favors explicit tree ownership and straightforward code generation.

## Module Layout

| Path | Responsibility |
| --- | --- |
| `ir/hlil/hlil.py` | Core enums and tree nodes: expressions, statements, variables, switch cases, and `HighLevelILFunction`. |
| `ir/hlil/mlil_to_hlil.py` | Generic MLIL → HLIL conversion, including CFG construction, call-result folding, loop/branch reconstruction, shared-region cloning, and variable declaration. |
| `ir/hlil/structural_analysis.py` | Dominator calculation, natural-loop discovery, iterative region reduction, and merge-point queries used by the converter. |
| `ir/hlil/hlil_formatter.py` | Debug formatter for rendering an HLIL tree. It is separate from the TypeScript code generator. |
| `ir/hlil/passes/` | Conversion wrapper and post-conversion tree transformations: control-flow optimization, loop recovery, common-return extraction, dead-code elimination, branch-order normalization, and the currently disabled copy-propagation pass. |
| `ir/hlil/hlil_passes.py` | Compatibility re-export of `ir/hlil/passes/`. |
| `ir/hlil/__init__.py` | Public re-exports for the node model, formatter, converter, and passes. |
| `falcom/ed9/ir/hlil/hlil_converter.py` | Production Falcom pipeline entry point, `convert_falcom_mlil_to_hlil()`, and its pass ordering/configuration. |
| `tests/test_hlil_branch_order_normalization.py` | Unit tests for source-order arm normalization and its pipeline flag. |
| `tests/test_hlil_control_flow_optimization.py` | Unit tests for equality-chain and grouped-label switch recovery. |
| `tests/test_hlil_loop_recovery.py` | Unit tests for guarded-loop recovery and its safety checks. |

The generic/project-specific split is deliberate. The core converter understands MLIL nodes and
structured control flow; the Falcom entry point chooses the production pass sequence and owns the
optional Falcom type-inference hook.

## Operations & Node Types

Every tree node derives from `HLILInstruction`, which stores an `HLILOperation`, a source bytecode
`address`, and an `mlil_index`. `HLILStatement` and `HLILExpression` are marker subclasses that
separate side-effecting tree positions from value-producing ones. Directly translated statements
receive source metadata from their MLIL instruction; synthesized control-flow nodes and expressions
can retain the base defaults.

The concrete model is small and source-oriented:

| Category | Nodes and purpose |
| --- | --- |
| Containers | `HLILBlock` owns an ordered list of statements. `HighLevelILFunction` owns one root block. |
| Structured control flow | `HLILIf`, `HLILWhile`, `HLILDoWhile`, `HLILFor`, `HLILSwitch`, `HLILBreak`, `HLILContinue`, `HLILReturn`. |
| Ordinary statements | `HLILAssign`, `HLILExprStmt`, `HLILComment`. |
| Leaf expressions | `HLILVar`, `HLILConst`. Constants retain an `is_hex` display hint. |
| Operators | `HLILBinaryOp`, `HLILUnaryOp`, `HLILAddressOf`, using `BinaryOp` and `UnaryOp`. |
| Calls | `HLILCall`, `HLILSyscall`, and `HLILExternCall`. |

`BinaryOp` distinguishes arithmetic, comparison, logical, and bitwise operations. This distinction
matters because MLIL `AND`/`OR` become bitwise operators, while MLIL `LOGICAL_AND`/`LOGICAL_OR`
become boolean operators. MLIL logical-not and test-zero operations are represented as equality
with zero; other unary operations map to negation or bitwise-not.

`HLILSwitchCase` is a helper owned by `HLILSwitch`, not an `HLILInstruction`. Its `values` field is
either a list of expressions or `None` for the default case. A list permits several case labels to
share one body, which preserves a recovered chain such as `x == A || x == B` without duplicating
the body.

`HLILExternCall` also has no distinct `HLILOperation`; it uses `HLIL_CALL` while preserving the
external `target` string separately. Consumers that care about the call form therefore dispatch on
the concrete class, as the formatter and optimization passes do.

`HLILFor` is part of the node model and supported by the formatter and branch-order traversal, but
the converter and active recovery passes do not currently construct it. Current loop output is
therefore `HLILWhile` or `HLILDoWhile`.

Comments are first-class statements rather than formatter-only annotations. In particular,
`line(N)` comments carry source-order evidence used by `BranchOrderNormalizationPass`. The shared
`split_else_if_arm()` helper also treats comments before a lone nested `HLILIf` as annotations for
the next test, allowing both renderers to agree on `else if` shape.

## Variable Model

HLIL has one non-SSA variable object, `HLILVariable`. It carries:

- `name` for locals and parameters;
- `type_hint` and `default_value` metadata;
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

Type information is deliberately lightweight. `HLILTypeKind` contains `UNKNOWN`, `INT`, `FLOAT`,
`STRING`, `BOOL`, and `VOID`, but types are hints on variables rather than types attached to every
expression. During conversion, MLIL booleans and pointers currently map to `INT`, and MLIL variants
map to unknown. Parameter default values are copied from MLIL source-parameter metadata when
available.

### Call Results as Expressions

MLIL calls are statements with an optional output variable; HLIL calls are expressions. The
`CallResultFolder` bridges that mismatch using non-SSA liveness over variable names. A call result
is folded only when the converter can identify one reader, the value is dead afterward, and no
intervening control-flow or evaluation-order constraint makes substitution unsafe.

The folder can look through a run of other calls that will fold into the same reader, but only when
the reader's operand order matches call execution order. It can cross into a single-successor block
only when that block has one predecessor. Calls without outputs remain expression statements so
their side effects are preserved; calls with non-foldable outputs remain assignments.

This specialized folding belongs in conversion rather than the general copy-propagation pass: it
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
    is_common_func: bool
```

(Simplified field view; the real definitions are in `ir/hlil/hlil.py`.) An `HLILIf` owns its true
and optional false blocks; loops own their bodies; a switch owns cases, and each case owns a body.
This exclusive nesting is what makes recursive optimization and code generation simple.

Removing CFG edges creates a representational constraint: HLIL has no goto node. Most shared tails
become code after an enclosing construct, but a body reached independently from several conditions
cannot always be expressed that way. The converter may reconstruct that region again, bounded by
`CLONE_STATEMENT_BUDGET` per function and `CLONE_MAX_REGION_BLOCKS` per region. It warns when a
region is unsafe or too large to repeat rather than silently treating the second path as ordinary
fallthrough.

Nested loop exits are represented with optional labels. The converter maintains a loop stack; a
jump to an active loop header becomes `continue`, and a jump to its selected exit becomes `break`.
When an edge targets an outer rather than the innermost loop, the outer loop and transfer receive a
generated label.

## MLIL → HLIL Pipeline

The generic conversion begins by deriving a CFG from each MLIL block's terminal `MLILIf`,
`MLILGoto`, `MLILRet`, or implicit fallthrough. `StructuralAnalyzer` then computes dominators on the
original graph, identifies natural loops from back edges whose targets dominate their sources, and
performs iterative region reduction in this priority order: loops, conditionals, then linear
sequences.

The converter uses that analysis as decision support rather than asking it to emit the HLIL tree.
It queries loop membership and exits, merge points, back edges, and whether a branch looks like an
inverted continuation chain. Recursive reconstruction remains responsible for owning blocks,
emitting branch arms, recognizing active-loop transfers, and processing merge blocks exactly once.
This separation keeps graph algorithms isolated from MLIL-to-HLIL node translation.

Before reconstruction, `CallResultFolder` computes its folding decisions. The converter then
translates parameters, reconstructs from MLIL block zero, and finally declares the local variables
actually present in the result. Funnel-shaped runs of bare tests that share a target are collapsed
inside the converter into one logical-OR condition so the shared body need not be emitted for every
test.

The production entry point is `convert_falcom_mlil_to_hlil()` in
`falcom/ed9/ir/hlil/hlil_converter.py`. Its configured pipeline is:

```
MLILToHLILPass → ControlFlowOptimizationPass → LoopRecoveryPass →
CommonReturnExtractionPass → DeadCodeEliminationPass →
BranchOrderNormalizationPass (enabled by default)
```

The post-conversion passes operate on the tree, not on the original CFG. In architectural terms,
they divide into shape recovery (`ControlFlowOptimizationPass`, `LoopRecoveryPass`), cleanup
(`CommonReturnExtractionPass`, `DeadCodeEliminationPass`), and presentation-preserving ordering
(`BranchOrderNormalizationPass`). The last pass is optional through `normalize_branch_order`
because it deliberately prefers recovered source-line order over bytecode emission order.

`CopyPropagationPass` is implemented but not added to the production pipeline; its role moved to
MLIL SSA optimization. The imported `FalcomTypeInferencePass` hook is also disabled and marked as
testing. See `docs/HLIL_GUIDE.md` for the detailed transformations performed by each active pass.

## Testing

There are three dedicated HLIL unit-test files, totaling 605 lines and 25 test methods:

- `tests/test_hlil_branch_order_normalization.py` covers line-based swaps, nesting-depth fallback,
  chain preservation, De Morgan negation, nested ordering, and the production enable/disable flag.
- `tests/test_hlil_control_flow_optimization.py` covers switch conversion thresholds, mixed
  equality/inequality chains, grouped labels, duplicate rejection, and scrutinee consistency.
- `tests/test_hlil_loop_recovery.py` covers leading break/return guards, unsafe rotations, nested
  switch breaks, and preservation of already-tested loops.

These tests directly exercise important tree rewrites, but they do not constitute end-to-end
coverage of HLIL construction. `StructuralAnalyzer`, `CallResultFolder`, shared-region cloning,
source metadata propagation, variable declaration, common-return extraction, dead-code
elimination, formatting, and the disabled copy-propagation pass have no dedicated HLIL test files.

## Open Items

- `HLILFor` is defined and partially supported by consumers but has no construction site. Either
  loop recovery should gain a sound for-loop recognizer or the node should remain explicitly
  documented as reserved.
- `FalcomTypeInferencePass` is wired off as "testing," leaving the intended ownership of final HLIL
  type refinement unresolved.
- `CopyPropagationPass` remains implemented and exported despite being disabled in favor of MLIL
  SSA propagation. Its long-term API/maintenance status should be decided.
- Tree-walking passes are not uniform about `HLILDoWhile` and `HLILFor`. Each pass should be audited
  when new structured node kinds become constructible so nested cleanup is not silently skipped.
- Direct tests for irreducible/shared CFG regions and the clone-budget warning paths are still
  needed; these are the cases where a goto-free tree representation is under the most pressure.
