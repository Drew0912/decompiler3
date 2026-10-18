# `tools/ir_semantic_validator.py` — known false-positive categories

**Purpose of this doc:** `ir_semantic_validator.py` compares semantic effects (calls, returns,
writes, branch conditions) across LLIL/MLIL/HLIL layers by matching them at CFG-block
granularity. Several `HARD_FAIL` categories it reports are **known artifacts of how the
comparison works, not real regressions**. This doc exists so anyone — or any agent, human or
not — reviewing validator output doesn't have to rediscover that from scratch. Read this before
treating a validator FAIL count as a regression gate.

Categories are emitted by `_hard_fail_category_for_event` and the `local_order_violation` /
`control_reachability_change` literals in `validate_hard_fail_semantics`
(`tools/ir_semantic_validator.py`). That function works on each layer's operations flattened into
one list - no HARD_FAIL category and no pass/fail result depends on CFG edges (see "Limitations").

**Counts from before 2026-09-24 are not comparable with later ones:** until then every HLIL global
write was reported as a `missing_write_anchor` on MLIL->HLIL (HLIL globals have no name, and the
validator read only the name), a do-while body's effects were not counted at all, and the two
write false-positive sources under `missing_write_anchor` below were live.

## Categories that are known noise (verified false positives)

### `local_order_violation`
**What it flags:** two same-category effect events (e.g. two calls) that the validator matched
between source and target layers, where the matched order looks reversed.

**Why it's noise:** this fires whenever the same effect occurs more than once and the branches
containing them are mutually exclusive (only one ever executes) — the validator's matcher doesn't
model mutual exclusivity, so it can pair occurrences across branches in an order that looks
"reversed" even though nothing actually reordered at runtime. It also spikes when a single call is
legitimately repeated many times (e.g. a 48-way dispatch inlining the same call into every branch)
since the validator sees many same-category events to (mis)pair. Confirmed repeatedly across
unrelated HLIL changes: this count moves up and down as a side effect of *how* branches get
restructured (switch recovery, branch-order normalization, call folding) with zero accompanying
`missing_*` violations each time. Zero `missing_*` supports the noise reading but does not prove no
path was lost: the matcher ignores paths, so a lost path whose effects still appear elsewhere in the
function fires no `missing_*` (checked 2026-09-29 on `LOOP_REENTERED` in
`tests/hlil_tests/test_hlil_structuring.py`: only `local_order_violation` + `unstructured_jump`).
`tools/hlil_path_check.py` is the check that proves paths are kept.

### `added_write_anchor` - no longer known noise (re-characterize before dismissing)
**What it flags:** a global write that appears in the target layer with no matching source-layer
write (only global writes are anchored; local and register writes are expected to fold away).

**History:** this used to be noise because LLIL's global store had no `result`, so it was read as a
register write and dropped from the source side. That is fixed (the LLIL normalizer sets
`result = GLOBALS[n]`), and since 2026-09-24 HLIL global writes also produce events, so global
writes now match on LLIL, MLIL and HLIL. A remaining `added_write_anchor` could be a legitimate
duplicate (a cloned shared region re-emitting a global write, like `added_call_anchor` below) or a
real extra write - treat it as real signal until checked.

**How to check one:** follow the added HLIL write's MLIL provenance (`source_location.mlil_index`).
If it points at an MLIL `STORE_GLOBAL` of the same global, HLIL re-emitted an existing write on a
second path (cloning), not a new write. Verified 2026-09-24 for all 41 MLIL->HLIL ones in the plan
corpus (e.g. `AniFieldAttack` `GLOBALS[1]`: 1 MLIL store, 2 HLIL copies, one before an early
`return`). The 4 LLIL->MLIL ones were global reads misread as writes (fixed - see the
`missing_write_anchor` note below). Whether each copy runs under the right condition is not something this validator
can check (see Limitations).

### `added_call_anchor` / `added_return_anchor`
**What it flags:** a call or return effect present in the target layer with no matching
source-layer counterpart.

**Why it's noise:** fires whenever a transformation legitimately duplicates content instead of
losing it — e.g. call-chain folding inlining one call reader into every arm of a multi-way
condition, or the HLIL funnel-merge clone-and-structure fix re-emitting a shared block once per
incoming path. Much rarer since CX Step G (2026-09-28): merge points are now real merges, so shared
code is no longer repeated in both arms of an if. Full sora2_1.0 census (1,082 files), 2026-09-24 ->
2026-09-29, a span that includes Step G: MLIL->HLIL `added_call_anchor` 11,917 -> 128,
`added_return_anchor` 809 -> 0. What remains is code a case falls through into (all 128: switch
cases repeating another case's code in `mp3000` `TK_KUNO`, `mp5000` `TK_FEY`/`TK_SCHERA`,
`mp8300_01` `TK_RUSSELL`/`TK_SCHERA`), or a region that genuinely has to be repeated. The validator assumes roughly 1:1 correspondence between source and target effect
events; it has no concept of "this call was legitimately re-emitted N times," so every extra
emission counts as "added." Confirmed by re-running before/after on an isolated file: the *only*
new categories introduced were `added_call_anchor`/`added_return_anchor`, with **zero**
`missing_call_anchor`/`missing_return_anchor` at any point — content was duplicated, not lost.

**Second mechanism, LLIL->MLIL only (verified 2026-09-24):** equal `added_call_anchor` and
`added_return_anchor` counts in `ani/` files come from `CALL_SCRIPT_NO_RETURN` tail calls. The
validator's LLIL normalizer does not recognize that operation (it lands in `_unknown_llil_ops`),
while MLIL lifts it to a script call plus a return - one added call and one added return per tail
call (847 of each in the plan corpus, all 217 files in `ani/`).

## Categories that ARE real signal (do not dismiss)

- **Any `missing_*_anchor` category** (`missing_call_anchor`, `missing_return_anchor`,
  `missing_write_anchor`) — these mean semantic content present in the source layer has no
  counterpart in the target layer, i.e. something was actually dropped. Every HLIL change tracked
  in project history has held **zero** missing/dropped effects; a nonzero count here is the
  regression signal that actually matters.

  **Two false-positive sources, fixed 2026-09-24** (counts from before then include them): (1) HLIL
  `GLOBALS[n] = <call>(...)` was normalized as a bare CALL, discarding the write - now a folded call
  followed by the global write (`_is_global_call_assignment`); (2) `_extract_write_signature`
  substring-matched `GLOBAL` in operand text, so a global *read* stored through a pointer/stack slot
  became `write_global:GLOBAL[n]` (singular `GLOBAL`) - now only a global `result` is a global write.
  They caused all 139 MLIL->HLIL `missing_write_anchor` (and 4 LLIL->MLIL `added_write_anchor`) in the
  first plan-corpus census.
- **`unstructured_jump`** (MLIL->HLIL, since 2026-09-28, CX Step G) — the HLIL holds an
  `HLILUnstructured` node on a path that can run: a jump the tree could not express, so the path is
  lost from the output (TS renders it as `throw new Error("unstructured: loc_X")`). One per node;
  nodes inside an arm a constant condition never takes are not reported. Zero on the sora2_1.0
  corpus - any occurrence is a structuring regression. `tools/hlil_path_check.py` checks the same
  function's paths in full.
- **`control_reachability_change`** — a matched branch condition changed *kind* between layers
  (e.g. an MLIL `GOTO` paired with an HLIL `IF`). Not yet characterized as noise in any known case;
  treat as a real finding until specifically investigated and shown otherwise. Much narrower than
  its name - see "Limitations".
- **Any category not listed above.** This doc only covers categories that have been individually
  investigated and confirmed benign. An unfamiliar category is unverified, not safe.

## Limitations (what a clean run does not prove)

Measured 2026-09-24 (`notes/post_review_2026-09-23/step0_assumption_review/`). All are deferred to
the validator upgrade in `docs/FUTURE_WORK.md` ("Static Game-Logic Check"), not bugs to patch alone.

- **No CFG edges.** `build_cfg_from_llil`/`build_cfg_from_mlil` build none, on purpose (their old edge
  loops looked for `edge.target.index` and never added one; replaced by a comment 2026-09-26, CX Step Q).
  `build_cfg_from_hlil` links only condition->arm and loop edges, not consecutive blocks. Edges only feed
  block-similarity matching (per-block results, `stats.different`), never a HARD_FAIL category;
  `stats.different` gates only LLIL->MLIL `passed`, and real edges left LLIL->MLIL unchanged (blocks
  match by address). Fix all three builders together or not at all: real LLIL/MLIL edges alone made
  MLIL->HLIL block matching worse (`mp2000` `different` 136->233, unmatched blocks 999->1,359;
  `btlsys` 44->55, 108->122; passes and HARD_FAILs unchanged; re-measured on `d330e4b`).
- **Conditions carry no expression.** Every `IF`/`WHILE` condition normalizes to the same empty
  signature, so `IF`<->`IF` always counts as equivalent. `control_reachability_change` can only
  fire when a provenance-matched condition changes kind (`GOTO`<->`WHILE` is allowed). It can never
  fire on LLIL->MLIL, where LLIL conditions are `BRANCH` (not compared), nor on MLIL->HLIL, where no
  HLIL `IF`/`WHILE`/`SWITCH` carries an MLIL index (structuring builds them without one - deferred,
  see `docs/FUTURE_WORK.md`). `SWITCH`/`DO_WHILE` conditions are not compared; unmatched conditions
  are ignored.
- **Provenance keys are tagged by layer** (since 2026-09-27, CX Step E). An operation's keys come from
  its source location: `('LLIL', i)` for the LLIL instruction it is or comes from (MLIL statements
  carry `llil_index`), `('MLIL', j)` for the MLIL statement. LLIL->MLIL therefore matches on the LLIL
  index - its quality metrics changed from that date (7 reference files: provenance-matched atoms 0 ->
  all, `unmatched_critical` -> 0; HARD_FAILs unchanged), and `--compare-regression` compares only
  HARD_FAIL counts, so it does not show that. The operation/block similarity score adds its
  provenance bonus before checking that the two operations are the same kind.
- **Effect values are not compared.** Events match by family and target only - a global write or
  call with a different value/arguments still matches. Deletions are caught; wrong values are not.

## How to use this

A validator run is "no real regression" only if every `HARD_FAIL` falls into the known-noise list
above **and** all `missing_*`/`control_reachability_change` counts are zero. Counts within the
known-noise categories are expected to drift (up or down) as unrelated changes reshape branch
structure — they are not a number to hold constant, only a category to keep segregated from real
signal.

## Keeping this doc current

If a new hard-fail category shows up and gets investigated, add it here with the same structure
(what it flags / why it's noise or why it's signal / how it was confirmed) rather than only
recording the conclusion in a one-off memory note — that's the whole point of this doc existing
outside of Claude's own memory.
