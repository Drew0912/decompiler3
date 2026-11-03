# Future Work: MLIL

> Ideas for MLIL (`ir/mlil/`, `falcom/ed9/ir/mlil/`), not started unless marked. Every future-work file:
> `docs/FUTURE_WORK.md`.

## VM-Accurate DIV/MOD and Float Folding (`docs/mlil/MLIL_DESIGN.md`)

SCCP (`ir/mlil_ssa/passes/pass_ssa_sccp.py`) deliberately does not fold `MLIL_DIV`/`MLIL_MOD`, or any
op with a float operand, and no pass decides a branch from a float (LLIL DSL neatening plan, Step
3b) - see the Optimization Passes section of `docs/mlil/MLIL_DESIGN.md`. The one live, corpus-confirmed
bad fold the DIV/MOD part closed: sora2's `script_en/scena/mp0000_ev.dat`'s `MayaEvented_22_test`
used to print `13.0` for `400 / 30.0` (Python floor-division), which is wrong for VM float division
no matter what the VM's exact answer turns out to be. The float part closed `chr0000`'s
`AniBtlCraft01Main` printing `0.4 * 0.8` as `0.32` (a double-precision fold). Since 2026-10-27 neither SCCP nor
expression simplification runs (`docs/mlil/MLIL_DESIGN.md`, "LLIL → MLIL Pipeline"): no pass folds, so this matters
again only where folding comes back.

**Not started** - a real fix needs more than not-folding. The VM's arithmetic is now known statically, from the
game exe, but not traced (`docs/falcom/ed9/ED9_VM.md`, Arithmetic):
- `ScpValue` (`falcom/ed9/structs/scp_types.py`) describes the *constant encoding* (30-bit int
  payload, float32-with-2-bits-dropped); the VM computes int ops in 32 bits and stores a 30-bit result.
- MOD is C's truncating remainder (the dividend's sign), not Python's `%`.
- Int results wrap modulo 2^30 with no overflow check; floats are float32 only, nothing checks for inf or NaN.
- Every float result has its 2 lowest mantissa bits cut (truncation), and an int operand meeting a float is converted
  to float32; a fold would compute in float32 with that cut, not in Python doubles.
- decompiler2 may only be read **to verify** hypotheses already derived from this repo's own
  source (`ScpValue`'s encoding), never as the source of the rules. Per `CLAUDE.md` (decompiler2 Submodule Access), this
  needs the user's explicit go-ahead in whatever future request actually does it - a past
  planning session having scoped this permission for Step B doesn't carry forward as standing
  authorization; ask again before reading anything under `decompiler2/`.
- The rules above come from a static read of the exe; folding should still wait for a trace in the running game
  (e.g. `MayaEvented_22_test`'s `camera_rotate` duration against the animation timing it drives), as the
  comparator's Step B does (`docs/FUTURE_WORK.md`).
- If/when this lands, `pass_ssa_expression_simplification.py`'s `_apply_algebraic_identity`
  should also be audited: its identities skip float constants, but `x * 0 → 0` is still wrong for a
  float `x` (inf/NaN, `-0.0`); its bitwise identities test all-ones as `-1`, so a constant SCCP folds
  past the int width (`536870911 * 8 + 7` → `0xFFFFFFFF`, which the VM wraps to Integer `-1`) is
  left as it is - both predate this idea and are independent of it, but a natural pass to make at
  the same time.
- Mixed int/float arithmetic is typed `int`: `SSATypeInferencePass._infer_expr_type`
  (`ir/mlil_ssa/passes/pass_ssa_type_inference.py`) falls back to `int` when `unify_types` gives
  `variant<int, float>`, which `is_numeric()` rejects. Since Step 3b leaves such expressions
  unfolded, it shows in 2 places: `chr0125` `AniFieldAttack`'s `arg1 = 0.0333 * 5` makes the
  `.mlil.asm` type `int` (was `variant<int, float>`), and `sound_ani` `SeBattleWaitingVoice`'s
  `var_s10` went from `any` to `number` in the `.ts`. Not fixed: this pass goes with the SSA layer
  in the IR rewrite, and typing resumes as its own plan; a fix would change types wherever an int
  and a float meet (e.g. `400 / 30.0`).
