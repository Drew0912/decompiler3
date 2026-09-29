# LLIL DSL — Recompilation Pipeline

> Status: Core mechanism implemented (a `.py` file can be executed to produce byte-exact
> bytecode, and an automated round-trip check exists). Fidelity is opt-in, not default — see §2
> for the round-trip policy this whole pipeline follows. The common-function shared library (§3)
> is implemented and active by default. Ideas beyond what's implemented here — multi-IR-level
> compilation, knowledge-driven typing for common functions — live in `docs/FUTURE_WORK.md`, not
> in this document.

## Role in the Pipeline

The decompilation pipeline goes forward (bytecode → readable code). This document covers the
reverse: turning a Python source file back into game bytecode.

**Naming note:** "LLIL DSL" in this document refers to this `.py` output — generated from the
disassembly IR (`falcom/ed9/disasm/`), not from `ir/llil`'s `LowLevelILFunction`. The real LLIL
pipeline (`ED9VMLifter`, `FalcomLLILFormatter`) is a separate, disjoint path that only feeds
`.llil.asm`/`.llil.dot` debug dumps and MLIL→HLIL→TypeScript. The two are close enough in shape
(one opcode, one function call, stack-machine semantics), and the disassembly-sourced version is
already correct and round-trip-capable, that there's no plan to switch its source — treat "LLIL
DSL" as this level everywhere it's mentioned below, including in the MLIL/HLIL lowering chain
sketched in `docs/FUTURE_WORK.md`.

**Compilation itself does not involve the Parser or Disassembler at all.** Those two layers only
come into play when *generating* a `.py` DSL file from an existing `.dat` (either for inspection,
or as the first half of a round-trip check). Compiling a `.py` DSL file — however it was produced —
needs only `ScpWriter`:

```
DSL extraction (optional, only needed to round-trip-check an existing script):
    SCP File → Parser → Disassembler → LLIL DSL (.py)

Compilation (the actual recompilation direction):
    LLIL DSL (.py) → exec() → ScpWriter → SCP bytecode
```

## 1. The DSL Itself

`falcom/ed9/writer/scp_writer_opcode_handler.py` defines one Python function per VM opcode
(`PUSH`, `LOAD_STACK`, `JMP`, `CALL_SCRIPT`, `DEBUG_LOG`, etc.), each calling
`get_scp_writer().handle_opcode(...)`. `falcom/ed9/writer/scp_writer_helper.py` layers
user-facing utilities over that (currently just `genLabel()`, a fresh label name for a
hand-written or generated function body) and re-exports the opcode primitives via
`from .scp_writer_opcode_handler import *`, so every generated `.py` only ever needs to import
the helper module. A "DSL file" is a `.py` file that calls these functions in sequence, at the
same granularity as the disassembly — one opcode, one call. It is opcode-level Python assembly,
not the TypeScript/HLIL-level output a person would read to understand a script.

## 2. Round-Trip Policy

Two tiers, in priority order:

1. **Logic round trip — required.** `source.dat → out1.py → c1.dat → out2.py → c2.dat → …`, with
   every decompile using `round_trip=False, keep_unreachable_code=False` (the everyday
   `scena2py_config.py` defaults). Every function in each recompiled `.dat` must match its source
   counterpart: normalized body + signature (position-independent fingerprint, keyed by name —
   `falcom/ed9/writer/metadata/signature.py`), `is_common_func`, the global table as ordered
   `(name, type)` tuples, and header `dword_14`. Function order and label names may differ.
   Dropping unreachable code only counts as logic-preserving where the reachability audit
   (`tools/scp_roundtrip_validator.py`'s `check_reachability`) confirms the dropped bytes are
   provably dead. Repeating decompile → recompile must reach a fixed point within a few rounds:
   `outN.py == outN+1.py` and `cN.dat == cN+1.dat`.
2. **Byte-exact round trip — nice to have, low priority.** `source.dat → out.py → c.dat` with
   `c.dat == source.dat`. Needs `round_trip=True, keep_unreachable_code=True` — this also disables
   the common-function library (§3), so this path behaves exactly as it did before the library
   existed.

**Measured on the full sora2_1.0 corpus** (1082 files, `tools/scp_roundtrip_validator.py
--logic-round-trip`, before the common-function library existed): all 1082 files reach the fixed
point at round 2 (`c1 == c2`, `out2 == out3`); all preserve game logic against the source;
`out1`/`out2` differ only in `loc_` label lines. Re-checked after the library landed (§3) on a
132-file subset (`sora2_1.0/script_en/battle/`, chosen for subsystem diversity) plus the two
previously-broken edge cases (`common.dat`, `mon5078+.dat`): identical result, 100% converge at
round 2, no logic regressions. **Full 1082-file re-run with the library active, completed
2026-09-22:** 0 logic round-trip failures and 0 errors — every file's `logic round trip` check
(fingerprint match against source, per function) passes. 234/1082 files additionally show a
**structural**-only difference (function order and/or rebuilt debug records, 7 also string-pool
counts) against source when checked with `validate_file`'s format checks: common functions are now
always registered before source functions (`@scena.CommonImports()` runs eagerly, ahead of the
inline definitions), which reorders them relative to source and shifts debug-record layout — both
explicitly excluded from the "game logic" definition above (function order, debug records,
string-pool layout). This is the expected, designed consequence of pulling matched functions out of
their original source position into the shared-library import path, not a regression. 127 files'
worst status was an informational WARN (mostly pre-existing "N unreachable ranges" notes, same
category as the pre-library baseline).

**Generation** (bytecode → `.py`): `Formatter.format_function`/`format_block`
(`falcom/ed9/disasm/formatter.py`) → `ScpParser.format_function` (`falcom/ed9/parser/scp.py`) →
`scena2py.write_python_dsl` (`falcom/ed9/scena2py.py`).

**Compilation** (`.py` → bytecode): the `.py` file is executed (`runpy.run_path(...)['main']()`)
against a `ScpWriter`, which emits bytecode via the same per-opcode calls.

**Validation**: `tools/scp_roundtrip_validator.py` automates a full loop — decompile a script,
delete the temporary *copy* of the source `.dat` it made for the run (the original input file is
never touched), exec the generated `.py` in a subprocess, byte-compare the result against the
original. This mechanism — the automated byte-exact comparison itself — is real and implemented.
Inputs must be named `<name>.dat`: the generated header names the compiled output after the whole
file name, so a two-suffix input (`X.original.dat`) compiles to `X.original.dat`, and
`--logic-round-trip` reports its round as a failed compile. No script in the corpora has such a
name.

**What's opt-in, not default:** round-trip fidelity depends on
`ScpParser(round_trip=True, keep_unreachable_code=True)`. `scena2py_config.py` — the everyday CLI
config — sets both to `False`. The validator passes both explicitly (`decompile_to_python`: `True`
for `--round-trip`, `False` for `--logic-round-trip`), so it does not depend on `ScpParser`'s class
defaults. Anyone using `scena2py.py` directly for byte-exact recompilation needs to set both flags
to `True`.

**What's actually verified, and what isn't:** `--round-trip` is byte-identical on the validator's 5
baseline samples (`script_en/scena/e0000.dat`, `e2000.dat`, `mp0000_ev.dat`,
`script_en/ai/ai_chr0100_e00.dat`, and `sora2_1.0/script_en/scena/system.dat`, which replaced a
deleted `system.original.dat`), and `--logic-round-trip` converges at round 2 on all 5 (re-run
2026-09-29; results in the gitignored `notes/post_review_2026-09-23/step11_findings/11b/`). The
logic round trip is also measured corpus-wide (above); the byte-exact one is not. Of 5 sampled `ani/`
scripts, all recompile but none is byte-identical: debug records around `ScriptNoReturn` tail calls
do not pair with their call sites, so the rebuilt records differ.

## 3. Common-Function Shared Library — Implemented

**Problem (confirmed):** output `.py` files used to embed a full copy of every shared game
function they used. Across the 1082-file sora2_1.0 corpus: 953 distinct common-function names,
43,185 total copies, up to 290 in a single script (`mp2000.py`).

**Design:** `falcom/ed9/writer/scp_writer_gen_common_funcs.py` walks the corpus once and generates
`falcom/ed9/writer/metadata/common/scp_writer_common_{N}.py` (one module per first-syscall
subsystem, or `scp_writer_common_no_syscall.py`), plus `falcom/ed9/writer/metadata/common_index.py`
(pure data: `name -> (module, fingerprint digest)`) and `falcom/ed9/writer/metadata/common_all.py`
(re-exports every generated module via `import *`, see Gating below for its `try`/`except`). At
decompile time, `ScpParser` (`scp.py`) matches each of a script's own common functions against the
index by name *and* fingerprint (`match_library_functions`) — a name whose body diverges from the
canonical library variant is left inline, unchanged. **Every generated script unconditionally
imports the whole library** (`gen_python_header` emits `from
falcom.ed9.writer.metadata.common_all import *`) — every mode, every script, whether or not its
own source used any common functions — so a human editing the script has every common function in
scope for `CALL()`/autocomplete even when adding one the original bytecode never used. Only the
matched subset is declared in a `@scena.CommonImports()` manifest, in the script's own code order,
since that (not the import) is what actually gets baked into the compiled bytecode; the import
itself has zero effect on compiled output; it's inert until the manifest (or, in strict mode, this
script's own inline definitions, which always take precedence) actually references a name.
Everything else — non-matching commons and this script's own functions — is still emitted inline
as today.

**Gating:** the *import* is unconditional (see above) and needs no `try`/`except` of its own in the
generated script's header — `common_all.py` is a tracked project file (always present) that wraps
its *own* internal imports of the gitignored, locally-generated `common/` package in
`try`/`except ModuleNotFoundError`, logging a hint to run the generator and setting
`COMMON_LIBRARY_GENERATED = False` if that package doesn't exist yet, `True` otherwise. The
*manifest* — i.e. what actually gets matched and baked into bytecode — stays gated on two things
in `match_library_functions`: `not (self.round_trip or self.keep_unreachable_code)` (the everyday
`scena2py_config.py` default; the library was generated with unreachable code already stripped, so
either fidelity flag falls back to inlining everything, exactly as before this existed), and
`common_all.COMMON_LIBRARY_GENERATED` (needed because `common_index.py` is tracked in git and would
otherwise claim matches that don't actually exist on a fresh checkout, leaving the manifest
referencing an undefined name). That second check is a **deferred import inside the method, not at
module level** — `common_all` transitively imports `scp_writer`, which imports names from this same
module (`parser/scp.py`), so importing it at module load time would be circular; by the time
`match_library_functions` actually runs, `parser.scp` has already finished loading, so the deferred
import is safe (CLAUDE.md rule 2's explicit circular-dependency exception). When the library isn't
generated, matching returns `{}` and every function falls back to fully inline, same as strict mode.

**Regenerating the library:** `python falcom/ed9/writer/scp_writer_gen_common_funcs.py
sora2_1.0` walks the corpus (round_trip=False, keep_unreachable_code=False), fingerprints every
`is_common_func` occurrence, picks the majority fingerprint per name as canonical (ties → first
occurrence in sorted order), excludes any function touching `LOAD_GLOBAL`/`SET_GLOBAL` plus the
closure of anything calling an excluded function (asserting the closure holds), and does a full
rewrite of the output directory every run — hand edits to generated files don't survive
regeneration.

**`falcom/ed9/writer/metadata/common/` is gitignored, not checked in** — like `sora2_1.0`/
`script_en` themselves, its generated modules are a substantive translation of the game's own
script content (real function bodies, not original project code), so it's treated the same way:
regenerated locally, never committed. `metadata/common_index.py` and `metadata/common_all.py`
(pure data/import-statements — names, module keys, fingerprint digests, `import *` lines, no
translated code) are checked in normally. **This means a fresh checkout needs the generator run
once, against a local copy of the corpus, before the default (`round_trip=False`) `scena2py.py`
path produces working output** — otherwise `common_index.py`/`common_all.py` reference modules
that don't exist on disk yet.

**The four questions this section used to leave open, now closed:**

- *Eager registration on decoration* — the shared-library modules define plain, undecorated
  `def`s. Registration only happens when an output script's own `@scena.CommonImports()` manifest
  imports and returns a specific function, going through the same `functionDecorator` machinery
  `LLILCode`/`LLILCommonCode` use (as an ordinary `is_common_func=True` registration) — so
  importing the library module itself registers nothing.
- *Name collisions* — `functionDecorator` now raises `ValueError` on a duplicate name instead of
  silently overwriting `functions_by_name` (`scp_writer.py`). The generator additionally rejects,
  at generation time, any candidate name that collides with a Python keyword, a star-imported
  helper/opcode name, a cross-module `common_N` alias, or a name every emitted script's own
  header/footer binds (`scena`, `commonImports`, `globalvars`, `main`) — all of which would
  otherwise silently shadow the real one (`validate_names` in the generator).
- *Transitive dependencies* — `CALL` resolves purely by the callee's Python `__name__`
  (`_find_function`, `scp_writer.py`), so a library function calling another library function binds
  correctly whether the caller's script imported it or is using its own diverged inline fallback.
  The generator computes the exclusion closure over `CALL` targets and asserts every included
  function's targets are themselves included, failing generation loudly otherwise.
- *Repeated compilation / module caching* — there is still no reset method; **one compile per
  interpreter remains the supported model**, unchanged from before the library. Tests achieve
  isolation by swapping in a fresh `ScpWriter` instance
  (`scp_writer._gScp = ScpWriter()`) rather than reusing one across compiles. `genLabel()` (used by
  generated bodies for their internal jump targets) is a stateless `uuid.uuid4()`-based helper, so
  it needs no per-compile reset either — the same cached module can be executed against a fresh
  writer any number of times and its labels are re-allocated fresh each time.

## 4. Future Work

Ideas that extend this pipeline but haven't been started — MLIL/HLIL DSL lowering, mixed-IR-level
compilation, knowledge-driven typing for common functions — are collected in
`docs/FUTURE_WORK.md` rather than here, so this document stays a description of what's actually
implemented.
