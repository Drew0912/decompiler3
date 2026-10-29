# `tools/ir_semantic_validator.py` — reading its output

**Purpose of this doc:** what the validator checks, what each of its categories means, which findings are already
known, and what a clean run does not prove. Read this before treating a validator FAIL as a regression.

**Since 2026-10-28** (IR rewrite part 1, Step 5b) the validator runs the logic check (`tools/logic_check/`); before,
it matched operations block by block. The block matcher's categories (`missing_write_anchor`, `local_order_violation`
and the rest), its statistics and its regression files (version `2.0`) are gone and not comparable with today's; a
version `2.0` file given to `--compare-regression` is refused.

## What it checks

Per function, decompiled as the decompiler decompiles it (`round_trip` off, unreachable code left out, its pass lists),
the logic check compares two layer pairs: the LLIL against the MLIL (the LLIL is the trust root) and the MLIL against
the HLIL. Each layer is evaluated over storage that means the same on every layer, and compared are:

- the effects - calls, syscalls, script calls, `debug.log`, global stores, stores through a pointer, returns (with the
  registers a return leaves) - with their argument values;
- the conditions each effect runs under (its guard): LLIL -> MLIL by the branches it depends on, MLIL -> HLIL as a
  formula over conditions, compared exactly (a truth table, then a decision diagram);
- LLIL -> MLIL also each branch's condition and targets; MLIL -> HLIL sees a branch through the guards of what it
  leads to, and a loop through its stamp: whether it runs and whether it goes round again;
- which effect can run next (the order), and the values a loop carries round its back edges.

Values are compared as trees, not computed (Step A of `docs/FUTURE_WORK.md`, "Static Game-Logic Check"); conditions
in a small normal form (`!c`, `c == 0` and `EZ c` one tree; an ordering pair by one representative).

## Categories

Every category is a finding until checked, except the two marked.

| Category | What differs |
|---|---|
| `missing_effect` / `added_effect` | an effect of the reference absent from the layer checked, or one it lacks (LLIL -> MLIL: or fewer / more times) |
| `target_differs`, `argc_differs` | an effect's target, its argument count |
| `arg_differs` | an argument's value, or a local an argument points to |
| `return_differs` | the returned value, or another register a return leaves |
| `guard_differs` | the conditions an effect runs under, or their polarity |
| `condition_differs`, `branch_targets_differ` | LLIL -> MLIL: a branch's condition (or a branch on one side only), its targets |
| `order_differs` | the effects that can run next after an effect |
| `loop_value_differs` | a value a loop carries round a back edge |
| `unstructured_jump` | a jump HLIL could not express, on a path that can run: the path is lost from the output |
| `condition_ordering_inverted` | not a finding: equal once orderings are read as one representative (`!(a < b)` and `a >= b`, which differ only for NaN); HLIL's own inversions, counted for the HLIL slice |
| `guard_unchecked` | not compared: formulas past the decision diagram's node cap, as written and with orderings read as one representative, or a mismatch left where a choice, lifted, passed the lifting cap of 1,024 alternatives (`LIFTED_CHOICES`; Limitations). Not a finding, but a clean run has none |

A difference's key names where it is: `(address, kind)` for an effect (the address is the bytecode offset of its
instruction, as in the `.llil.asm` / `.mlil.asm` listings), `(address, 'branch')`, `(header, 'loop')` /
`(header, 'loop continue')` for a loop, `(None, 'return')` for the function's returns. Its detail shows what each side
has there, cut.

## Known findings (the full corpus, 2026-10-29)

Every parseable script of the five games (4,828 scripts, 351,245 functions; IR rewrite part 1, Step 5e; per function
in `notes/ir_rewrite_plan/baselines/{llil_mlil,mlil_hlil}_full_5e.json`): no decompile or internal error; LLIL -> MLIL
clean; MLIL -> HLIL 3 functions, all real. The 8 scripts left out are the parser's: it rejects their `POP 255` (`ani/`
of `kuro2` and `kai1`).

- **Real:** `TestEmotion` in `scena/a0000.dat` of `kuro1`, `kuro2` and `kai1`: two unstructured jumps lose paths
  (`unstructured_jump`, and the `guard_differs`, `loop_value_differs` and `order_differs` the lost paths bring).
- **The check's own artifacts:** Step 5a's run (2026-10-28) found 35 more functions, the check's own artifacts of five
  kinds (no HLIL bug among them); all are gone since Step 5c, and the limitations below give the assumptions the fixes
  rest on.

## How to use it

- One file: `python tools/ir_semantic_validator.py <dat>` (both pairs, function by function), `--compare llil mlil`
  or `--compare mlil hlil` (one pair), `--function NAME`, `--failed-only`, `--json`, `--output-dir <scratch folder>`
  (a file per pair).
- A pair after a decompile or internal error is `not compared` (in the JSON `[]`, as a clean pair: the error says
  where the check stopped); a pair before it is reported as usual.
- Before and after an IR change: `--export-regression <scratch folder>/before.json` first, `--compare-regression
  <scratch folder>/before.json` after. A regression is a difference new since the export, by category and key, or a
  new decompile or internal error; an improvement one gone; functions added or gone are listed.
- Exit codes: a report exits 0 when no function has a difference or an internal error (a decompile error is shown,
  not failed), else 1; `--compare-regression` exits 1 on a regression, 2 for a baseline of another version.
- A finding: `--function NAME` for its differences in full, then the function's `.mlil.asm` and `.hlil.ts` at the
  key's address.

## Limitations (what a clean run does not prove)

- Values are trees, not computed: an equal value written another way (`1 + 1` for `2`) is a difference. Computing
  them is Step B, after the user's own analysis of the game executable.
- MLIL -> HLIL compares no branch on its own: a branch shows only through the guards of the effects after it.
- An effect HLIL repeats is compared by the disjunction of its copies' guards, so a copy on a path another copy
  already covers adds nothing the check sees (the full corpus has 445 calls HLIL repeats, in 26 functions).
- A loop is a place in the order of effects even where it makes no effect of its own: an effect moved past one is
  `order_differs` (6 such loops on the full corpus).
- A loop that runs is taken to end (a formula's atoms stand for no iteration in particular): where the formulas of an
  effect after a loop differ, they are compared again with each side's premise that every loop before the effect, and
  none it is inside of, takes one of its exits when it runs (before: reached from the loop's exits in the same
  iteration of the loops around it; an enclosing loop's going round again is after it, its header's effects are not).
  So the iterations that go round again are never the last, and HLIL splitting a loop's `&&` exit in two tests, or
  repeating the code after the loop in each exit, is no finding. A loop that never ends is not checked.
- A merged value is a choice over the conditions its paths are taken under, told apart by its digest, which each layer
  builds its own way, and the formulas of a big choice have no key of their own. Where the formulas or values of an
  effect then differ, they are compared again with the choices lifted: a choice anywhere in a value an effect passes or
  a loop copy carries, or in a condition of its guard (split at `&&` and `||` first), becomes its values each under its
  formula, up to 1,024 distinct values at a time. That answer is taken only if it clears the difference. Past the cap,
  or for a choice inside a value a loop carries round (`loop_value_differs`), the difference stays. A value that is a
  choice of choices past the cap, lifted whole, is `guard_unchecked`: a long chain of merges that HLIL merges once more
  (a common return made one) or splits in two (a loop rebuilt in each arm) is unchecked, not clean.
- Only natural loops (a header dominating the edge back to it) have a body. In an irreducible region, which no
  real script has, the formulas of the blocks outside natural loops are those of one pass through the region, so a
  clean result there proves less (the fuzz's irreducible graphs compare without error).
- A formula past a decision diagram's cap is not compared as written: two formulas whose diagram passes 1,000,000
  nodes are compared again with orderings read as one representative, whose answer decides (equal:
  `condition_ordering_inverted`; different: the difference), and are `guard_unchecked` only where that passes the cap
  too; a formula whose key's diagram passes 20,000 has no key, so a choice under it is told apart by the
  formula's digest. Answers are remembered by the formulas' digests, so of two comparisons of formulas equal but for
  the order of their `&&` / `||` items, the first decides whether the cap is passed.

## Keeping this doc current

When a change adds or retires a category or a known finding, update the tables above with how it was measured.
