---
paths:
  - "ir/**"
  - "falcom/ed9/ir/**"
---

# Working in `ir/` and `falcom/ed9/ir/`

## Root-Cause Fixes
When a bug turns up while editing `ir/` (LLIL / MLIL / HLIL structures and passes), fix its root cause, not the
reported symptom. If a root-cause fix is out of reach, fix the widest form of the gap you can (every case it can
produce), never a guard scoped to the one reported instance. Hand-rolled tree traversal produces two recurring
shapes: a walker that misses a node type, a class of bug that recurs in every hand-rolled walker in the file, so
close the class (e.g. a shared traversal helper every predicate and collector is built on); and two walkers that must
agree on traversal shape (a detector and its rewriter) but are maintained apart, so make them share the traversal
shape, not only the answer for one input, or the asymmetry returns the next time either is edited alone. Some `ir/`
bugs are plain logic gaps (a wrong equality check, a missing case) that a shared walker would not catch; for those
too, name the underlying gap before patching.

## Also
- The generic / Falcom boundary: `docs/ARCHITECTURE.md`, "Generic/Falcom Boundary".
- Layer docs follow the code that runs: `docs/llil/`, `docs/mlil/`, `docs/hlil/` (`docs/mlil/MLIL_DESIGN.md` names
  the passes it must match).
- A change here gets the Codex IR change review (`CLAUDE.md`, Codex).
