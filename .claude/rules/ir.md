---
paths:
  - "ir/**"
  - "falcom/ed9/ir/**"
---

# Working in `ir/` and `falcom/ed9/ir/`

## Shared Walkers
HLIL and MLIL each have one set of shared walkers, named in `docs/hlil/HLIL_DESIGN.md` and `docs/mlil/MLIL_DESIGN.md`
(under "Operations & Node Types": "Tree walking is shared the same way", "Reading is shared the same way"). Build every
search, predicate and collector on them: a new node type is then one edit in the walkers, and no copy of a walker
misses it. A new hand-rolled walker needs a stated reason. Tests use the same walkers: `docs/TESTS_GUIDE.md`, "Adding
tests". A new HLIL node type also needs its case in the printers: a statement in the statement printer both share
(`ir/hlil/statement_printer.py`, with a hook where their text differs), an expression in each one's `_format_expr`
(`ir/hlil/hlil_formatter.py`, `codegen/typescript.py`); they print an unknown node as text instead of failing.

## Root-Cause Fixes
When a bug turns up while editing `ir/` (LLIL / MLIL / HLIL structures and passes), fix its root cause, not the
reported symptom. If a root-cause fix is out of reach, fix the widest form of the gap you can (every case it can
produce), never a guard scoped to the one reported instance. Hand-rolled tree traversal produces two recurring
shapes: a walker that misses a node type, a class of bug that recurs in every hand-rolled walker in the file, so
close the class by moving it onto the shared walkers; and two walkers that must agree on traversal shape (a detector
and its rewriter) but are maintained apart, so make them share the traversal shape, not only the answer for one
input, or the asymmetry returns the next time either is edited alone. Some `ir/` bugs are plain logic gaps (a wrong
equality check, a missing case) that a shared walker would not catch; for those too, name the underlying gap before
patching. A root-cause fix bigger than the current step is proposed and asked about, not added silently.

## Also
- The generic / Falcom boundary: `docs/ARCHITECTURE.md`, "Generic/Falcom Boundary".
- Layer docs follow the code that runs: `docs/llil/`, `docs/mlil/`, `docs/hlil/` (`docs/mlil/MLIL_DESIGN.md` names
  the passes it must match).
- A change here gets the Codex IR change review (`CLAUDE.md`, Codex).
