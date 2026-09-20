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
  (`var_s0`, `var_s1`, ...), parameters become `param_0`, `param_1`, ..., and translation
  introduces temporaries as needed.
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

## The Pipeline

`convert_falcom_llil_to_mlil()` (`falcom/ed9/ir/mlil/mlil_converter.py`) is what real code paths
call. It builds a `Pipeline` and runs:

```
ED9LLILToMLILPass → SSAConversionPass → SSAOptimizationPass →
SSATypeInferencePass (optional) → SSADeconstructionPass → RegGlobalValuePropagationPass
```

`SSAOptimizationPass` internally runs the `SSAOptimizer` (`ir/mlil/mlil_ssa_optimizer.py`), which
chains together sparse conditional constant propagation, constant propagation, copy propagation,
expression inlining, expression/condition simplification, negation normal form conversion, and two
flavors of dead-code elimination (dead statements, dead `Phi` nodes) — all defined under
`ir/mlil/passes/`.

One pass instance, a standalone `DeadCodeEliminationPass()`, is present in the code but commented
out in the Falcom pipeline with a `# TODO: check if needed` note. This doesn't leave dead-code
elimination actually missing — the SSA-level DCE passes above still run, plus a further
post-de-SSA dead-code pass inside `ir/mlil/mlil_optimizer.py`'s `optimize_mlil()`. It's one
specific, seemingly redundant pass instance sitting unused, not a gap in DCE coverage overall.

## Formatting

`ir/mlil/mlil_formatter.py` pretty-prints MLIL functions as text, used for test snapshots and
debug dumps — analogous to `HLILFormatter` on the HLIL side.

## Known Gaps

- The disabled `DeadCodeEliminationPass()` in the Falcom pipeline has an open "check if needed"
  TODO rather than a resolved decision either way.
- Dedicated test coverage for the MLIL-SSA machinery (construction, deconstruction, critical-edge
  splitting, and the individual optimizer passes) doesn't exist yet — see `docs/MLIL_DESIGN.md`'s
  Testing section. `tests/test_mlil_metadata.py` is currently the only dedicated MLIL test file.

## Testing

`tests/test_mlil_metadata.py` — the only dedicated MLIL test file at present.
