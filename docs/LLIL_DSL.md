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
`get_scp_writer().handle_opcode(...)`, which rejects a `bool` operand (`True` would otherwise
pass the `int` checks and encode as 1). `falcom/ed9/writer/scp_writer_helper.py` layers the DSL
statements that emit no instruction over that (`label()`, `GLOBAL_VAR`, and `genLabel()`, a fresh
label name for a hand-written or generated function body) and re-exports the opcode primitives via
`from .scp_writer_opcode_handler import *`, so every generated `.py` only ever needs to import
the helper module. A "DSL file" is a `.py` file that calls these functions in sequence, at the
same granularity as the disassembly — one opcode, one call. It is opcode-level Python assembly,
not the TypeScript/HLIL-level output a person would read to understand a script.

**Operand spelling.** A float is stored as float32 bits with the lowest 2 dropped
(`ScpValue.FLOAT_DROPPED_BITS`), so each stored value covers 4 float32 values. The `.py` prints the
shortest float literal that stores the same word (`ScpValue.float_literal`): `PUSH_FLOAT(0.3)`, not the
decoded `PUSH_FLOAT(0.2999999523162842)`, and the same for float parameter defaults (`= 0.2`). It is
always a float literal (`1.0`, `-0.0`), because the writer picks the encoding from the Python type;
`PUSH_FLOAT` itself converts an `int` with `float()`, so a hand-written `PUSH_FLOAT(1)` still pushes a
float. Non-finite floats, which the game can't use, print as `float('inf')`/`float('nan')`: decoding one
logs a warning and compiling it raises. `CALL_SCRIPT`/`CALL_SCRIPT_NO_RETURN` names print as plain
strings, `CALL_SCRIPT("this", "GetCoolClone", 0)` - the writer wraps a bare `str` itself. An `int` must
fit the 30-bit Integer payload (`ScpValue.INTEGER_MIN..INTEGER_MAX`, -0x20000000..0x1FFFFFFF) and a
`RawInt` `0..0x3FFFFFFF`; past that, compiling raises instead of storing a different number or type.

**Comments.** Every trailing comment starts at display column 32 after the indent (a CJK character
takes two columns; a longer line gets 2 spaces), several on one line joined by `, `. Besides
`# global var N` on `LOAD_GLOBAL`/`SET_GLOBAL` and the header's `GLOBAL_VAR` lines, the `.py` shows the
stack the way the `.llil.asm` does, read from the parser's simulated stack (`Function.stack_layout`,
`docs/ARCHITECTURE.md` Layer 2). Each of the 5 offset opcodes gets the absolute slot it addresses and
what it holds, `*` marking a dereference and `&` an address (`POP_TO` and `POP_TO_DEREF` count their
offset from sp after their pop); the instruction that opened a local the code addresses gets
`(local)`; `POP(n)` gets its slot count; each label gets the depth there:
```python
    LOAD_STACK(-16)                 # slot 1 = arg2
    POP(12)                         # 3 slots

    def _loc_3444(): pass
    label('loc_3444')               # sp = 3

    PUSH_RAW(RawInt(0x00000000))    # slot 3 (local)
    PUSH_INT(65535)
    POP_TO(-4)                      # slot 3
```
In `ani/btlcom`, `PUSH_STACK_OFFSET(-12)  # &slot 7` passes a local's address, and
`POP_TO_DEREF(-20)  # *slot 3 = arg5` stores through a pointer parameter. Parameters are numbered as
in every other output (`arg1` is the highest parameter slot); a parameter slot that is popped and
pushed again holds a local from then on. A label that only unreachable code
jumps to adds `jumped to by unreachable code`; unreachable code itself (fidelity mode) has no simulated
stack and gets no stack comments. A slot that holds anything but one parameter or a local prints
everything it may hold (`slot 2 = arg1 or local`, `slot 1 = caller frame`, `slot 0 = call setup`,
`slot -1 (below the stack)`, `slot 5 (above the stack)`), and the parser logs a warning; none occur in
the `sora2_1.0` scripts. `ScenaDecompileConfig.stack_slot_comments` (on by default) turns the stack
comments off in scripts; the common-function library (§3) always has them, labels named `L0`, `L1`, ...
(`label(L0)  # sp = 3`). Comments don't change the compiled bytes.

Three more kinds are opt-in, script `.py` only (`ScenaDecompileConfig`, all off by default):
`call_arg_comments` numbers each push by the argument it becomes (`arg1` is the last push), for `CALL`,
`CALL_SCRIPT`, `CALL_SCRIPT_NO_RETURN` and `SYSCALL` - after an offset opcode's slot reference it reads
`passed as`; `float_bits_comments` adds `PUSH_FLOAT`'s float32 bits and stored word;
`function_id_comments` puts the table index and code offset above each function. All three on
(`AniCatWait`, `scena/npc_setting`):
```python
# id: 0x001C offset: 0x21FF7
@scena.LLILCode()
def AniCatWait():
    DEBUG_SET_LINENO(171)
    PUSH_FLOAT(0.0)                 # arg4, f32 0x00000000, raw 0x80000000
    PUSH_STR("AniEvWait1")          # arg3
    PUSH_INT(2)                     # arg2
    PUSH_INT(65534)                 # arg1
    SYSCALL(1, 0x2F, 0x04)
    POP(16)                         # 4 slots
```
The function id's offset changes after the first recompile, like `loc_` labels; the fixed point holds
from round 2.

**Compiling.** A generated script's `main()` calls `scena.run(globals())`. `ScpWriter.build()` compiles
in memory - the function table, every body in source order, debug records, globals and the string pool -
and returns the bytes; `run()` writes the `.dat` only after `build()` succeeds, so a failed compile writes
nothing and leaves an older `.dat` as it was. Labels are file-wide: a name is defined once in the script
(`B: label 'ret' is already defined in A`), and once every body has compiled each jump operand or return
address resolves against all of them (`Foo: undefined label 'nowhere'`). A reference to a label in
another function compiles, for a deliberate jump between functions, with a warning
(`B: jumps to label 'done' in A (another function)`); generated scripts never have one. DSL statements
must be in their place: an opcode or `label()` outside a function body raises `PUSH_INT is outside a
function body`, and `GLOBAL_VAR` inside a body raises (the header counts the globals before the bodies
run). Operand checks report first: `LOAD_GLOBAL('missing')` at module level reports the unknown name.
Errors raised while a body runs carry the `.py` line in their traceback.

**The compile check** (`ScpWriter.check_compiled`, on by default; a script turns it off with
`scena.check_compiled = False`). At the end of `build()` the bytes are parsed and lifted again in memory
by the decompiler's own `ScpParser` and `ED9VMLifter` (`falcom/ed9/writer/scp_compile_check.py`), so a
stack mistake that compiles - a wrong `POP(n)`, a call with an extra or missing argument, branches that
reach a label with different stacks, a read or write outside the live stack - fails the compile instead
of reaching the game:
```
CompileCheckError: test.py:12: Caller: CALL at 0x77: expects a return address, found PUSH_INT@0x6B
```
The line is the one whose call emitted the failing opcode (a helper called from a body maps to the
body's call); an error with no instruction to blame (an empty last function) points at the function's
`def`, past its decorators. Undefined labels and jumps into another function get the same `file:line:`
prefix. A function without `RETURN` runs on into the next function's code - a `.dat` has no
end-of-function marker, so the VM keeps going - which compiles with a warning while the bytes still
decompile, and adds a note to the error when they don't:
```
WARNING   test.py:38: A: SET_REG at 0x5E: runs past its end into B without RETURN
WARNING   test.py:41: AEmpty: has no code, so it runs on into B without RETURN
```
Nothing follows the last function, so code that runs or jumps past the end of the code fails, in
whichever function's code it is, and so does a call whose return label is its function's very end
(`returns to 0x.., past its end (no RETURN after its return label)`). A failed check is a
failed compile: no `.dat` is written, an older one stays, and the writer is spent like after any failed
compile. Not checked: unreachable code (the parser never simulates it) and a stack that balances but
reads the wrong slot. A read or write outside the live stack fails at once; decompiling a game `.dat`
only warns about it. The check costs about twice the compile itself (`mp0000_ev`, the largest script:
about 4 s on top of 1.7 s); while it is on, each opcode also records where it was emitted.

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
`scena2py.write_python_dsl` (`falcom/ed9/scena2py.py`). `ScpParser.gen_python_script(functions,
comments = CommentOptions(...))` picks the optional comments (`falcom/ed9/disasm/llil_dsl_comments.py`;
`scena2py` builds them from its config); the validator keeps the defaults, so the logic round trip
checks that the stack comments reach the fixed point too. A generated script imports the helper, an
optional `<stem>_hook` module for patches kept outside the generated file (only a missing hook is
ignored; an import error inside the hook stops the compile), and the library (§3). Its footer calls
`main()`, which compiles the script when it is run directly. Every generated text file is written
with `\n` line endings.

**The `.dat` listing** (`.debug.txt`, `ScenaDecompileConfig.write_debug_info`, off by default): the
byte-level companion of the `.py`, read-only and never compiled - the whole file as the VM sees it
(`falcom/ed9/parser/scp_listing.py`). Sections, each switched in `debug_sections = ListingSections(...)`:
the header, the global vars, each function's table entry (parameters as the `.py` declares them), its
code and its call-site debug records, and the string pool with each string's section. A code line has
the offset, the raw bytes, the real opcode with its operands as encoded (every push pseudo-op is the real
`PUSH`: `PUSH 4, Int(1120)`, `Raw(0x342F)`, `Float(0.3)`, `Str(0x3A68)`) and the meaning as a comment
(labels, callees, return addresses, string text, float bits and the `.py`'s slot and argument comments);
labels get their own line with the depth. The listing loads the file itself, unreachable code decoded
(marked `unreachable`), so every byte from the end of the global var table to the string pool is listed
once: under the function whose range holds it (functions starting at the same offset share one range),
or as raw bytes where no instruction covers it (`mp0090`'s 21 bytes before its first function). A call's
debug record is printed under it when every record of the function holds what its call gets
(`call_records.record_mismatch`, content only); otherwise the function notes `records not paired: ...`,
as for the `chr0000`-style files and calls without a record. `filter_func` and `include_common_functions`
pick the functions listed; the listing is written after every other output.

**Compilation** (`.py` → bytecode): the `.py` file is executed (`python e0000.py`, or the
validator's `runpy.run_path(...)['main']()`) against a `ScpWriter`, which emits bytecode via the same
per-opcode calls.

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
baseline samples (`sora2_1.0/script_en/scena/e0000.dat`, `e2000.dat`, `mp0000_ev.dat`, `system.dat`,
and `sora2_1.0/script_en/ai/ai_chr0100_e00.dat`), and `--logic-round-trip` converges at round 2 on
all 5 (2026-10-01). On a 300-file quota sample of `sora2_1.0` that includes them (2026-10-01; list
and results in the gitignored `notes/llil_dsl_neatening/validator300/`), 265 files are byte-identical
and all 300 converge at round 2. The logic round trip is also measured corpus-wide (above), and so is
the byte-exact one: 855 of 1,082 `sora2_1.0` files are byte-identical (2026-10-01,
`notes/debug_records_handoff.md`). Nearly all of the others differ only in their rebuilt debug
records, most of them `ani/` scripts, where records around `ScriptNoReturn` tail calls do not pair
with their call sites.

## 3. Common-Function Shared Library — Implemented

**Problem (confirmed):** output `.py` files used to embed a full copy of every shared game
function they used. Across the 1082-file sora2_1.0 corpus: 953 distinct common-function names,
43,185 total copies, up to 290 in a single script (`mp2000.py`).

**Design:** `falcom/ed9/writer/scp_writer_gen_common_funcs.py` walks the corpus once and generates
`falcom/ed9/writer/metadata/common/scp_writer_common_{N}.py` (one module per first-syscall
subsystem, or `scp_writer_common_no_syscall.py`), plus `falcom/ed9/writer/metadata/common_index.py`
(pure data: `name -> (module, fingerprint digest)`) and `falcom/ed9/writer/metadata/common_all.py`
(re-exports every generated module via `import *`, see Gating below for its `try`/`except`). Each
module lists only its own functions in `__all__`, so `common_all` exports library functions and
`COMMON_LIBRARY_GENERATED` and nothing else: re-exporting the helper's names a second time made type
checkers treat aliases like `Value32` as variables. At
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
`is_common_func` occurrence (noting, once per fingerprint, whether it touches a global, what it
calls and its first syscall), picks the majority fingerprint per name as canonical (ties → first
occurrence in sorted order), excludes any function touching `LOAD_GLOBAL`/`SET_GLOBAL` plus the
closure of anything calling an excluded function (asserting the closure holds) and assigns modules.
Only then does it re-parse the files holding an included function's canonical copy, rendering each
function's final text, stack comments included (§1). Every run is a full rewrite of the output
directory — hand edits to generated files don't survive regeneration.

**`falcom/ed9/writer/metadata/common/` is gitignored, not checked in** — like the `sora2_1.0/`
scripts it is generated from, its generated modules are a substantive translation of the game's own
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
