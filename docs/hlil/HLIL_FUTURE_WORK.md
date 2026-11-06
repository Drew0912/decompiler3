# Future Work: HLIL

> Ideas for HLIL (`ir/hlil/`, `falcom/ed9/ir/hlil/`, `codegen/`), not started unless marked. Every future-work
> file: `docs/FUTURE_WORK.md`.

## HLIL Nesting Depth (`docs/hlil/HLIL_GUIDE.md`)

Calls fold under the VM's eager `&&`/`||` since 2026-11-06, so `else if` chains print flat again:
`sound.dat` `InitBGM` is back to 53 indent levels from 230, three functions of `sora2` stay over 16.

**Not started:**
- **Check indent levels** across the corpus: report each function's maximum nesting depth and flag
  outliers, so a readability regression like this shows up in a dump diff instead of being noticed
  by hand.
- **Iterative tree walkers.** The MLIL->HLIL converter, the HLIL passes and the TS generator recurse
  once or twice per nesting level, and an `else if` cascade nests one level per test (TS prints it
  flat): `InitBGM`'s ~490-level cascade needs 989 frames in the converter, just under Python's default
  limit of 1000. `falcom/ed9/scp2py_base.py` and `tools/ir_semantic_validator.py` raise the limit to
  10,000 for now; building cascades in a loop and walking the tree with explicit stacks would remove
  the dependence on it.

## HLIL (`docs/hlil/HLIL_GUIDE.md`, `docs/dsl/DSL_FUTURE_WORK.md` Recompilation Pipeline §1)

Ideas from a review of the TypeScript output and a design discussion of the HLIL DSL (2026-09-30; the DSL design is in
`docs/dsl/HLIL_DSL.md`). Nothing here is started. The DSL work follows the IR rewrite, which already plans eager vs
short-circuit nodes, a ternary node and a per-function fallback (`notes/rewrite/08_decision_and_checklist.md`).
LLIL-level ideas from the same discussion (the LLIL DSL, the writer, the hook callbacks) are in
`docs/dsl/DSL_FUTURE_WORK.md`.

### TypeScript Output

The output was correct in every function traced; what it costs is readability.

- **Line markers:** print one trailing annotation per statement, or make them optional. Multi-line
  source calls produce reversed runs of `// line(N)`, and markers land between `}` and `else if`.
- **Wait loops:** with calls folded under the VM's eager logic, loop recovery could also turn
  `if (c) { break; } else { X; continue; }` into `if (c) break; X;`.
- **Unnamed syscalls:** a handful of syscall IDs cover most raw `syscall(...)` sites, dialogue `(5, 19)` first. Name
  them in the one naming table the DSL uses (`docs/dsl/HLIL_DSL.md`, HLIL DSL: Form, Tooling), and merge the `10`
  newline codes into the dialogue strings.
- **Locals:** machine names, mostly typed `any`, one stack slot reused for unrelated values, and copy
  chains such as `reg0 = f(); var_s1 = reg0; var_s0 = reg0;`.
- **Constants:** named pseudo-IDs for `65534` and the like, hex for bit flags, and float32 constants as
  the shortest decimal that encodes to the same value.
- **Calls:** print script calls as `module.f()`, as the MLIL does, not `extern_call('module:f')`
  (trailing default arguments are left out since 2026-10-14: Trailing Default Arguments, below).
- **Structure:** don't split an `else if` chain into `switch` fragments when it has conditional arms
  (`var0 == N && !flag(M)` can't be a `case`: a set flag must reach later arms and the final `else`);
  don't invert an empty arm into `!= N` and nest the rest under it; drop a `break;` after arms that all
  return; don't let common-return extraction turn early-return guards into empty arms.
- **Fidelity:** keep what the bytecode distinguishes: `return;` (raw zero) vs `return 0`, and locals the
  source declared but never read (dead-code elimination drops them today).

### Trailing Default Arguments

**(a) implemented 2026-10-14 in `.ts` only** (`docs/hlil/HLIL_GUIDE.md` Codegen; `.hlil.ts` keeps every argument).
**(b) implemented 2026-10-16** in `.ts`, round trip only (debug-records plan Step 6, `notes/work_order.md` 3c).

Wanted (user, 2026-10-12): print `mes_set_auto(1)`, not `mes_set_auto(1, 0)`. A local call pushes every
argument, defaults included, so both compile to the same bytes and the HLIL holds every call in full;
`.hlil.ts` prints it so, and so did `.ts` before (a) (`mp0000_ev`: 1,172 of 1,181 `camera_lookat` calls end
in its defaults `3, -1`). Local calls
only: their callee's defaults are in this script's function table. Two ways:

- **(a) From the code:** leave out trailing constant arguments equal to the callee's declared defaults
  (the TypeScript signatures already print them). This is the original compiler's own rule: no call-site
  debug record drops an argument that differs from its default (none in `sora2` or `sora1`;
  `notes/debug_records_handoff.md`). Needs no records. It differs from the author where they wrote a default out
  anyway, about one call in seven: `mp0000_ev`'s `camera_lookat` calls all keep the `3`, written
  `camera_lookat(63.153, 29.174, -63.103, 0, 3)`, which (a) prints as `camera_lookat(63.153, 29.174, -63.103, 0)`;
  its `mes_set_auto` calls match (a) exactly.
- **(b) As written:** a local call's debug record keeps the arguments the author wrote. In a round trip
  (`ScpParser.round_trip`; the parser reads records only then) `.ts` prints `max(written, (a))`, the
  written count found by `HLILCall.address` in the parser's `call_written_argc` (every paired local call,
  not only the `.py`'s `debug_argc` exceptions: 138 calls fold an argument to a default-equal constant in
  HLIL, so the bytecode rule and (a) differ there). `max`, not the written count: 232 records keep fewer
  than (a), each passing an address-taken local HLIL shows as a variable (`btl_check_condition(arg1, 3,
  *&var_s4)` after `var_s4 = -1`) - printing the record's count would leave the assignment dangling; the
  cause, a call argument in a reused stack slot, is a work-order follow-up. A call with no written count
  prints (a): functions without records (common functions), unpaired functions (the 4 differently built
  `chr*` files, `chr5110`), calls before the first `DEBUG_SET_LINENO`, `debug_record=False` calls, and
  every everyday decompile. In `sora2` about one recorded call in seven prints more than (a). Dead code isn't in
  `.ts`.

Either way only the HLIL/TypeScript side changes; the LLIL DSL keeps one line per push, and the HLIL
DSL's lowering pushes the omitted defaults back, as Falcom's compiler did. Drop only constants, compared
by `constant_values_equal` (type, float bits and spelling): an expression that happens to equal the default
stays.

## Structuring the Remaining Reducible Shapes (`docs/hlil/HLIL_DESIGN.md`)

Since 2026-09-28 a jump the HLIL tree cannot express becomes an `HLILUnstructured` node: loud, but the
path is lost to the reader (and to a future HLIL DSL). None remains on the sora2 corpus. On random
CFGs (`tests/hlil_tests/test_hlil_structuring_fuzz.py`'s generator) 48 of 6,000 are reducible yet get a reachable
node - a reducible CFG can always be structured, so these are converter gaps; the 6 among the test's
1,000 seeds are pinned, so a new one fails the suite. One cause is left (51 nodes over those 48): re-emissions
refused because the region reaches the active loop's header, where `_reconstruct_control_flow` would in fact
emit `continue` (or at an exit, `break`). The other, a path leaving a loop with several exits that could not
fall out to the enclosing merge (57 nodes over 96 CFGs), was fixed 2026-10-10: such a merge is now repeated
like any other block emitted elsewhere, and a `while (1)` whose first `if` stays in the body picks a `break`
target as the goto-header loop does.

Options, cheapest first: let `_clone_region_blocks` treat the active loops' headers and exits as
region boundaries instead of refusing; express a loop with several exits with a labelled block
(`label: { ... break label; }` is valid TypeScript) or an exit flag; keep goto emulation
(`while (true) switch (state)`) for irreducible regions only. Measure each change with the fuzz test
(no wrong run, fewer pinned seeds) and with the logic check over the corpus (`tools/logic_check/`,
`docs/VALIDATOR_GUIDE.md`).
