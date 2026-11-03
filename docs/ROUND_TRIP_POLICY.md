# Round-Trip Policy

> Status: current. What every change to the parser, the writer, an IR pass or an output must keep. How the round
> trip is generated, run and measured: `docs/dsl/LLIL_DSL.md` §2.

Two tiers, in priority order:

1. **Logic round trip — required, high priority.** `source.dat → out1.py → c1.dat → out2.py → c2.dat → …`, with
   every decompile using `round_trip=False, keep_unreachable_code=False` (the everyday
   `scena2py_config.py` defaults). Every function in each recompiled `.dat` must match its source
   counterpart: normalized body + signature (position-independent fingerprint, keyed by name —
   `falcom/ed9/metadata/fingerprint.py`), `is_common_func`, the global table as ordered
   `(name, type)` tuples, and header `dword_14`. Function order and label names may differ.
   Dropping unreachable code only counts as logic-preserving where the reachability audit
   (`tools/scp_roundtrip_validator.py`'s `check_reachability`) confirms the dropped bytes are
   provably dead. Repeating decompile → recompile must reach a fixed point within a few rounds:
   `outN.py == outN+1.py` and `cN.dat == cN+1.dat`. Checked by `tools/scp_roundtrip_validator.py
   --logic-round-trip`.
2. **Byte-exact round trip — medium priority.** `source.dat → out.py → c.dat` with `c.dat == source.dat`. Needs
   `round_trip=True, keep_unreachable_code=True` — this also disables the common-function library
   (`docs/dsl/LLIL_DSL.md` §3), so this path behaves exactly as it did before the library existed. The script it writes
   keeps the original's dead code, which its compile warns about (`docs/dsl/LLIL_DSL.md` §1). Checked by
   `tools/scp_roundtrip_validator.py --round-trip`.
   More files round-tripping byte-exact is wanted: a step takes a byte-exact fix on the side when it is small and in
   code the step already touches, and when a step has design options, it says how each affects the byte-exact round
   trip. A review may raise a byte-exact mismatch as a finding. It never outranks the logic round trip, never blocks a
   step or a logic fix, and adds no byte-exact gate to a plan. When a file that matched before no longer matches,
   report it.

## Fidelity behind `round_trip` flags

Behaviour that exists only to reproduce the original bytes (the string pool's section order and duplicate entries, the
call-site debug records and their pairing) is optional, on by default, behind the `round_trip` flag of the class doing
it (`ScpParser.round_trip`, `ScpWriter.round_trip`), so it can be turned off, e.g. for another game's scripts where the
fidelity rules may not hold. A change to the generated `.py` text alone needs no flag. Format-correctness fixes are
always on (the function table sorted by name, the `PUSH_CURRENT_FUNC_ID` index, default-parameter order, header
offsets, functions kept in source order); say why it is not gated when adding one. The table's order is the
compiler's: the VM's lookup by name ignores it (`docs/falcom/ed9/ED9_VM.md`, Calls by name).

## Every function stays

Every function-table entry stays in every output (the LLIL DSL `.py`, the recompiled `.dat`, the `.ts`, a future HLIL
DSL), even when its only reachable body is a `return` and the real body is dead code behind it (`chr5110.dat`
`AniBackhairDinamicJointOff`, `chr0110.dat` `AniBtlCraft01`): the game looks functions up by name (script calls,
the engine's own calls: `docs/falcom/ed9/ED9_VM.md`, Engine-called names), and a missing one only logs "function not
found", so dropping it fails silently in game. Dead-code elimination removes unreachable code inside a function,
never the function; a design that would drop one is a finding. The exceptions are opt-in inspection settings in
`scena2py_config.py` (`include_common_functions = False`, `filter_func`): their output is partial on purpose and its
`.py` is not meant to recompile.
