# Future Work: MLIL

## VM-Accurate DIV/MOD and Float Folding (`docs/mlil/MLIL_DESIGN.md`)

SCCP (`ir/mlil/passes/pass_ssa_sccp.py`) deliberately does not fold `MLIL_DIV`/`MLIL_MOD`, or any
op with a float operand, and no pass decides a branch from a float (LLIL DSL neatening plan, Step
3b) - see the Optimization Passes section of `docs/mlil/MLIL_DESIGN.md`. The one live, corpus-confirmed
bad fold the DIV/MOD part closed: `sora2_1.0/script_en/scena/mp0000_ev.dat`'s `MayaEvented_22_test`
used to print `13.0` for `400 / 30.0` (Python floor-division), which is wrong for VM float division
no matter what the VM's exact answer turns out to be. The float part closed `chr0000`'s
`AniBtlCraft01Main` printing `0.4 * 0.8` as `0.32` (a double-precision fold).

**Not started** - a real fix needs more than not-folding:
- `ScpValue` (`falcom/ed9/parser/types_scp.py`) describes the *constant encoding* (30-bit int
  payload, float32-with-2-bits-dropped), not proof of the runtime arithmetic width - whether the
  VM actually computes int ops at 30 or 32 bits is unverified.
- MOD's sign convention (Python's `%` vs. C-style truncating remainder) is unverified.
- Overflow/wrap behavior on both int and float paths is unverified.
- Float32 rounding and int/float mixing are unverified too; a verified fold would compute in
  float32, not Python doubles.
- decompiler2 may only be read **to verify** hypotheses already derived from this repo's own
  source (`ScpValue`'s encoding), never as the source of the rules. Per `CLAUDE.md` -0.1, this
  needs the user's explicit go-ahead in whatever future request actually does it - a past
  planning session having scoped this permission for Step B doesn't carry forward as standing
  authorization; ask again before reading anything under `decompiler2/`.
- None of the above can be *proven* by static analysis or corpus diffing alone - the only real
  oracle is running an affected script in-game and comparing (e.g. `MayaEvented_22_test`'s
  `camera_rotate` duration against the actual animation timing it drives). Whoever picks this up
  needs that ability, or the result stays "derived and cross-checked, not proven" like the
  analysis already done.
- If/when this lands, `pass_ssa_expression_simplification.py`'s `_apply_algebraic_identity`
  should also be audited: its identities skip float constants, but `x * 0 → 0` is still wrong for a
  float `x` (inf/NaN, `-0.0`); its bitwise identities test all-ones as `-1`, so a constant SCCP folds
  past the int width (`536870911 * 8 + 7` → `0xFFFFFFFF`, which a 32-bit VM would wrap to `-1`) is
  left as it is - both predate this idea and are independent of it, but a natural pass to make at
  the same time.
- Mixed int/float arithmetic is typed `int`: `SSATypeInferencePass._infer_expr_type`
  (`ir/mlil/passes/pass_ssa_type_inference.py`) falls back to `int` when `unify_types` gives
  `variant<int, float>`, which `is_numeric()` rejects. Since Step 3b leaves such expressions
  unfolded, it shows in 2 places: `chr0125` `AniFieldAttack`'s `arg1 = 0.0333 * 5` makes the
  `.mlil.asm` type `int` (was `variant<int, float>`), and `sound_ani` `SeBattleWaitingVoice`'s
  `var_s10` went from `any` to `number` in the `.ts`. Not fixed: this pass goes with the SSA layer
  in the IR rewrite, and typing resumes as its own plan; a fix would change types wherever an int
  and a float meet (e.g. `400 / 30.0`).
