# MLIL Implementation Guide

> Status: Implemented, including a full SSA-based optimizer pipeline. This guide was previously
> mostly in Chinese and described MLIL as intentionally non-SSA with SSA/optimization/HLIL
> integration listed as future work — all superseded by the real implementation. Rewritten in
> English against current code (2026-09-20). See `docs/MLIL_DESIGN.md` for the node model and
> pipeline shape in more detail; this guide focuses on what MLIL actually does and how the pieces
> fit together.

## What MLIL Is

MLIL (Medium Level IL) removes LLIL's explicit stack semantics, turning stack push/pop/load/store
operations into ordinary variable reads and writes. Conceptually:

**LLIL (stack semantics):**
```
STACK[0] = 10                 ; StackStore(Const(10), offset=0, slot_index=0)
sp = sp + 1
STACK[1] = 5                  ; StackStore(Const(5), offset=0, slot_index=1)
sp = sp + 1
sp = sp - 1
rhs = STACK[1]
sp = sp - 1
lhs = STACK[0]
result = lhs + rhs
STACK[0] = result
sp = sp + 1
```

**MLIL (variable semantics):**
```
var_s0 = 10
var_s1 = 5
var_s0 = var_s0 + var_s1
```

Seven LLIL instructions collapse to three MLIL statements that directly operate on variables
instead of tracking a stack pointer — easier to read and to run further analysis on.

## Module Layout

See `docs/MLIL_DESIGN.md`'s Module Layout table for the full file-by-file breakdown. In short:
`ir/mlil/` holds the generic engine (non-SSA node types, the SSA layer, the optimizer, the
builder/formatter), `ir/mlil/passes/` holds the ~16 actual pass implementations, and
`falcom/ed9/ir/mlil/` holds Falcom-specific wiring — `mlil_converter.py` is the real production
entry point (`convert_falcom_llil_to_mlil()`), mirroring how `falcom/ed9/ir/hlil/hlil_converter.py`
wires HLIL.

## Variable Model

Two representations coexist rather than one replacing the other:

- **Non-SSA** — the default, on-the-wire form. Stack slots become named variables
  (`var_s0`, `var_s1`, ...), parameters become `arg1` ... `argN` (`arg1` is the highest
  parameter slot), and translation introduces temporaries as needed. A parameter slot is `argN`
  only while it still holds the caller's value: once the function pops the parameter and pushes a
  new value into its slot (the usual tail-call pattern), every access to that slot uses the push's
  `var_sN`, like any other push. The LLIL builder decides this (`_holds_parameter`); MLIL maps
  frame accesses to `argN` and stack accesses to `var_sN`.
- **SSA** — used internally during optimization. Every assignment gets a fresh version, and
  control-flow joins get explicit `Phi` nodes. A function is converted to SSA, optimized, and
  converted back to non-SSA before anything downstream (including HLIL) ever sees it.

## Instruction Categories

**Constants:** integer/float/string literals.

**Variable operations:** load a variable's value; store a value to a variable (SSA and non-SSA
variants of each).

**Arithmetic / logical:** add, sub, mul, div, mod; bitwise and/or/xor/shift; logical and/or.

**Comparisons:** eq, ne, lt, le, gt, ge.

**Unary:** negate, logical-not, test-zero.

**Control flow:** unconditional goto; conditional branch; return (with optional value).

**Calls:** ordinary function call, syscall, Falcom script call (`CALL_SCRIPT`).

**Globals/registers:** load/store global variable; load/store VM register.

**Pointer dereference:** `MLILDeref`/`MLILStoreDeref` (`*ptr` / `*dest = value`) for
`LOAD_STACK_DEREF`/`POP_TO_DEREF` - a runtime-computed address (e.g. a caller-supplied
out-parameter), not a statically known slot. Always impure (never assumed constant, never
inlined across a call) and a deref store is never dead-code-eliminated.

The same `MLILDeref`/`MLILStoreDeref`/`MLILAddressOf` shape also carries a second, distinct use:
during SSA construction, every local or parameter whose address is taken anywhere in the function
(`&x`) is rewritten to explicit `*(&x)` memory form - `MLILDeref(MLILAddressOf(MLILVar(x)))` reads,
`MLILStoreDeref(MLILAddressOf(MLILVar(x)), v)` writes - instead of being versioned like an ordinary
scalar (see `MLIL_DESIGN.md`'s Variable Model & SSA section for why). This is purely an SSA-layer
representation choice, not a new opcode: outside SSA form (before construction, after
deconstruction), `x` still prints and behaves like any other local. `*(&x) ≡ x` always holds for
this shape, so every printer folds it back to plain `x` / `x = v` - see `HLIL_GUIDE.md`'s printing
convention.

## The Pipeline

`convert_falcom_llil_to_mlil()` (`falcom/ed9/ir/mlil/mlil_converter.py`) is what real code paths
call. It builds a `Pipeline` and runs:

```
ED9LLILToMLILPass → BlockMergePass (optimize only) → SSAConversionPass → SSAOptimizationPass →
SSATypeInferencePass (optional) → SSADeconstructionPass → RegGlobalValuePropagationPass
```

Every pass after `ED9LLILToMLILPass` comes from `mlil_optimization_passes()`
(`ir/mlil/mlil_optimizer.py`), and `optimize_mlil()` runs that same list on an already translated
function - there is one MLIL pipeline, not a production one and a test one.

`BlockMergePass` splices any block whose only way in is another block's unconditional goto into
that block - mainly undoing the call-return split every `LowLevelILCall` forces (it is a block
terminator), but it also removes real bytecode `JMP`s that happen to land on a single-predecessor
target. Only runs when `optimize=True`; `optimize=False` keeps the untouched, block-per-LLIL-
boundary translation.

`SSAOptimizationPass` internally runs the `SSAOptimizer` (`ir/mlil/mlil_ssa_optimizer.py`), which
chains together sparse conditional constant propagation, constant propagation, copy propagation,
expression inlining, expression/condition simplification, negation normal form conversion, and two
flavors of dead-code elimination (dead statements, dead `Phi` nodes) — all defined under
`ir/mlil/passes/`.

No dead-code pass runs after SSA deconstruction: a census of production output found no unread
local assignment (500-file sample, 2026-09-26).

## Formatting

`ir/mlil/mlil_formatter.py` pretty-prints MLIL functions as text, used for test snapshots and
debug dumps — analogous to `HLILFormatter` on the HLIL side.

## Known Gaps

- Four SSA optimizer passes have no test of their own: negation normal form, expression
  simplification, constant propagation and dead-`Phi` elimination.

## Testing

`tests/test_mlil_*.py` (and `tests/test_llil_deref.py`) - see `docs/MLIL_DESIGN.md`'s Testing
section.
