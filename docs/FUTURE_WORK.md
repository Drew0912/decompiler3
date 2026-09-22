# Future Work

> This file collects ideas that are speculative, not started, or only loosely sketched — things
> that extend an implemented system rather than describe it. Topic docs (`LLIL_DSL.md`,
> `HLIL_GUIDE.md`, etc.) describe what's actually built; this file is where "someday" ideas live
> instead of accumulating as a growing tail on top of those docs. Each entry links back to the
> concrete doc/code it extends.

## VM-Accurate DIV/MOD Folding (`docs/MLIL_DESIGN.md`)

SCCP (`ir/mlil/passes/pass_ssa_sccp.py`) deliberately does not fold `MLIL_DIV`/`MLIL_MOD` - see
the Optimization Passes section of `docs/MLIL_DESIGN.md`. The one live, corpus-confirmed bad fold
this closed: `sora2_1.0/script_en/scena/mp0000_ev.dat`'s `MayaEvented_22_test` used to print
`13.0` for `400 / 30.0` (Python floor-division), which is wrong for VM float division no matter
what the VM's exact answer turns out to be.

**Not started** - a real fix needs more than not-folding:
- `ScpValue` (`falcom/ed9/parser/types_scp.py`) describes the *constant encoding* (30-bit int
  payload, float32-with-2-bits-dropped), not proof of the runtime arithmetic width - whether the
  VM actually computes int ops at 30 or 32 bits is unverified.
- MOD's sign convention (Python's `%` vs. C-style truncating remainder) is unverified.
- Overflow/wrap behavior on both int and float paths is unverified.
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
  should also be audited: today's `x * 0 → 0` identity is wrong for a float `x`, and the
  `0xFFFFFFFF` bitwise identities assume a 32-bit int against the VM's 30-bit constant encoding -
  both predate this idea and are independent of it, but a natural pass to make at the same time.

## Recompilation Pipeline (`docs/LLIL_DSL.md`)

### 1. MLIL DSL and HLIL DSL

Extend the same pattern upward, one IR level at a time:

```
HLIL DSL (.py) → lower → MLIL DSL (.py) → lower → LLIL DSL (.py, exists today) → ScpWriter → bytecode
```

A future MLIL-level writer takes a `.py` MLIL DSL file and lowers it to a `.py` LLIL DSL file
(reusing today's real LLIL DSL → `ScpWriter` path unchanged), rather than talking to `ScpWriter`
directly. HLIL would lower to MLIL DSL the same way. **Not started** — no reference to
`ScpWriter`, `handle_opcode`, or any bytecode-emission path exists anywhere in `ir/mlil/`,
`ir/hlil/`, or `codegen/` today.

### 2. Mixed-IR-Level Compilation, Per Function

The idea: because jump opcodes don't cross function boundaries (an assumption this leans on —
worth confirming explicitly, not just assuming), a single output `.py` file could hold some
functions written at the LLIL DSL level, others at MLIL DSL level, others at HLIL DSL level, each
lowered independently down to LLIL DSL / bytecode.

**This needs more than independent per-function lowering to actually work**, though — even once
the jump-boundary assumption is confirmed, functions still participate in several script-wide
concerns that a per-function compile can't resolve alone: `CALL` operands and
`PUSH_CURRENT_FUNC_ID` depend on the final function table; common-function source order affects
byte layout; function offsets are assigned during whole-script compilation; labels/xrefs and
string-pool relocation are writer-global; debug records and global-variable resolution are
script-wide; per-function labels need collision-safe namespacing. A real version of this idea needs
an explicit per-function intermediate object plus a separate link/finalization phase that stitches
independently-lowered functions back into one script — not merely "lower each function on its own."

### 3. Knowledge-Driven Typing for Common Functions

The common-function library (`docs/LLIL_DSL.md` §3) currently derives everything purely from raw
bytecode — params are always `arg1: Value32`, `arg2: Value32`, etc. There's a real precedent in
this codebase for annotating that kind of gap externally instead of by hand-editing generated
output: `falcom/ed9/signatures/format_signatures.py` + a YAML file, which does exactly this for
TypeScript codegen (`FormatSignatureDB` supplies per-function param names/types/enum formats,
consulted by `codegen/typescript.py`).

**The idea:** once a common function's arguments and their real meaning are identified (by hand,
or by future analysis), that knowledge can be patched into the generated library the same way — a
YAML-backed `CommonFunctionKnowledgeDB`, consulted by `scp_writer_gen_common_funcs.py` between
extraction and rendering. Every generator run does a full rewrite of the output directory, so this
has to be a hook inside the generator, not a post-process edit of generated files (which would
just be overwritten on the next regeneration).

Groundwork this would need, not yet done:
- Knowledge entries keyed by the function's fingerprint digest (`docs/LLIL_DSL.md` §1), not just
  its name — the digest *is* the function's identity in this system, so a name-only key (unlike
  `FormatSignatureDB`'s today) could silently apply stale knowledge after a corpus change.
  Generation should fail loudly if a knowledge entry's expected digest no longer matches.
- The renderer's intermediate operand representation would need to preserve raw values alongside
  formatted text (it currently flattens straight to source text), if the knowledge layer should
  ever reformat a value (enum names, hex vs. decimal) rather than just rename a parameter.
- A possible `scp_writer_types.py` for named parameter types the knowledge DB introduces (e.g. an
  `ItemID` alias), distinct from the generic `Value32`/`NullableStr` aliases in
  `falcom/ed9/parser/types_scp.py`, which stay tied to raw parsed value shape, not identified
  meaning. Whether this is a new file or an extension of `types_scp.py` is an open call to make
  when this is actually built.

**Sequencing note:** this is independent of items 1-2 above — it applies to the LLIL DSL library
that exists today and doesn't need the MLIL/HLIL DSL lowering work at all.

### 4. Common-Function Library at MLIL/HLIL DSL Level

Item 1 describes lowering an entire script from a higher IR level down to LLIL DSL; a natural
extension, once that lowering exists and HLIL output is trusted, is generating a *second* common
library at that level — canonical HLIL (or MLIL) bodies for shared functions, lowered to LLIL DSL
only at the final compile step, mirroring `docs/LLIL_DSL.md` §3's design. The fingerprint/match/
render approach there doesn't assume LLIL specifically, so the concept should carry over with only
the operand-normalization details needing rework for the higher IR's shape.

This has no independent risk or design work of its own beyond what item 1 already carries — it's
gated entirely on item 1 landing and HLIL quality being trusted enough to compile back to bytecode,
not a separate open question.
