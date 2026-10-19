---
paths:
  - "ir/**"
  - "falcom/ed9/ir/**"
---

# Working in `ir/` and `falcom/ed9/ir/`

## Root-Cause Fixes
When a bug is found while editing `ir/` (LLIL/MLIL/HLIL structures and passes), prioritize fixing the root cause over patching just the reported symptom. If a genuine root-cause fix isn't achievable, fix the version that catches the most cases the underlying gap can produce — never the narrowest guard clause scoped to the one reported instance; that's the outcome to avoid even as a fallback, not a shortcut to take. This directory's passes tend to hand-roll their own tree traversal, and that produces two recurring shapes of the same problem: a walker missing a node type — not a one-off mistake at that call site, but a class of bug that recurs across every hand-rolled walker in the file, so prefer closing the class (e.g. a shared traversal helper every predicate/collector is built on) over a narrow guard clause that only fixes the specific finding; and two related walkers (a detector and a rewriter, e.g.) that must agree on traversal shape but are maintained independently — fixing one to produce the right output for the reported case without making it structurally match the other leaves the same asymmetry free to resurface the next time either is edited alone, so prefer making them share the same traversal shape, not just the same answer for one input. Not every `ir/` bug is a traversal-coverage bug — some are genuine logic gaps (wrong equality check, missing case) that a shared walker would not have caught either; for those, still ask what the underlying gap is before patching, rather than defaulting to the narrowest possible fix.

## Also
- The generic / Falcom boundary: `docs/ARCHITECTURE.md`, "Generic/Falcom Boundary".
- Layer docs follow the code that runs: `docs/llil/`, `docs/mlil/`, `docs/hlil/` (`docs/mlil/MLIL_DESIGN.md` names
  the passes it must match).
- A change here gets the Codex IR change review (`CLAUDE.md`, Codex).
