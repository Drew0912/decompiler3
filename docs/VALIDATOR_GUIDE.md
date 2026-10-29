# `tools/ir_semantic_validator.py` — reading its output

**Purpose of this doc:** what the validator checks, what each of its categories means, which findings are already
known (real ones and the check's own artifacts), and what a clean run does not prove. Read this before treating a
validator FAIL as a regression.

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
| `guard_unchecked` | not compared: formulas past the decision diagram's node cap. Not a finding, but a clean run has none |

A difference's key names where it is: `(address, kind)` for an effect (the address is the bytecode offset of its
instruction, as in the `.llil.asm` / `.mlil.asm` listings), `(address, 'branch')`, `(header, 'loop')` /
`(header, 'loop continue')` for a loop, `(None, 'return')` for the function's returns. Its detail shows what each side
has there, cut.

## Known findings (the full corpus, 2026-10-28)

Every parseable script of the five games (351,245 functions; IR rewrite part 1, Step 5a; per function in
`notes/ir_rewrite_plan/baselines/{llil_mlil,mlil_hlil}_full.json`): LLIL -> MLIL clean; MLIL -> HLIL 38 functions.

- **Real:** `TestEmotion` in `scena/a0000.dat` of `kuro1`, `kuro2` and `kai1`: two unstructured jumps lose paths
  (`unstructured_jump`, and the `guard_differs`, `loop_value_differs` and `order_differs` the lost paths bring).
- **The check's own artifacts** (no HLIL bug among them), all gone since Step 5c, one kind a sub-step: K1, a dead arm
  of `if (x != 0 && 0 != 0)` counted in `AniBtlKnockDown`, `-Loop`, `-End` of sora1 `ani/chr5004.dat` and `TKFront` of
  `scena/a1011.dat` in kuro1, kuro2 and kai1, is gone since 5c-1: MLIL's view folds a condition with a decisive constant
  operand as HLIL does; K3, a value after a loop whose exit HLIL splits in two tests, in `AniBtlChaseAttack` of sora2
  `ani/chr0003`, `chr0125`, `chr5006` and `chr5106`, is gone since 5c-2: a loop that runs ends, see the limitations;
  K2, the registers at a return HLIL merges with another or repeats in two arms, in `MayaEvent*` (sora2 `mp5005`,
  `mp1051`; kai1 `e5000`), `Archive01`, `-02`, `-04`, `Svis00`, `Dlc00`, `Etc00` (kai1, kuro2 `scena/a1018.dat`), is
  gone since 5c-3: a merge cut at the phi depth is opened where the layers cut it at different depths; K4, a gated
  choice inside a condition or an operation compared by its digest, in `FdungeonStartVoicePlay`, `OnQuestEnd` (kai1
  `scena/system.dat`), `PigeonProc` (sora1, sora2 `scena/npc_setting.dat`) and 4 of `TestEmotion`'s `guard_differs`,
  is gone since 5c-4: the choice is lifted, see the limitations; K5, formulas too large, `guard_unchecked` in
  `MapJumpCheck` (kuro1 `system.dat`), `InitBGM` (kuro2 `sound.dat`) and `ChangeEnvSE` (kuro1 `sound.dat`), and checks
  of over two minutes, `MapJumpCallScript` (kai1 `system.dat`) and `InitBGM` (sora1, sora2 `sound.dat`), is gone since
  5c-5: keys and comparisons are remembered, a key is built over the variables its formula depends on, and the caps
  are larger.

## How to use it

- One file: `python tools/ir_semantic_validator.py <dat>` (both pairs, function by function), `--compare llil mlil`
  or `--compare mlil hlil` (one pair), `--function NAME`, `--failed-only`, `--json`, `--output-dir <scratch folder>`
  (a file per pair).
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
  builds its own way: more than three merges deep it is cut to a fingerprint, at a depth each layer reaches on its own,
  and the formulas of a big choice have no key of their own. Where the formulas or values of an effect then differ,
  they are compared again with the choices lifted: a choice anywhere in a value an effect passes or a loop copy
  carries, or in a condition of its guard (split at `&&` and `||` first), becomes its values each under its formula,
  up to 1,024 distinct values at a time. That answer is taken only if it clears the difference. Past the cap, or for a
  choice inside a value a loop carries round (`loop_value_differs`), the difference stays.
- Only natural loops (a header dominating the edge back to it) have a body. In an irreducible region, which no
  real script has, the formulas of the blocks outside natural loops are those of one pass through the region, so a
  clean result there proves less (the fuzz's irreducible graphs compare without error).
- A formula past a decision diagram's cap is not compared: two formulas whose diagram passes 1,000,000 nodes are
  `guard_unchecked`; a formula whose key's diagram passes 20,000 has no key, so a choice under it is told apart by the
  formula's digest. Answers are remembered by the formulas' digests, so of two comparisons of formulas equal but for
  the order of their `&&` / `||` items, the first decides whether the cap is passed.

## Keeping this doc current

When a change adds or retires a category or a known finding, update the tables above with how it was measured; Step
5c removes each K kind from "Known findings" as it fixes it.
