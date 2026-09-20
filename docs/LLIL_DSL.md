# LLIL DSL — Recompilation Pipeline

> Status: Core mechanism implemented (a `.py` file can be executed to produce byte-exact
> bytecode, and an automated round-trip check exists). Fidelity is opt-in, not default, and no
> corpus-scale round-trip results are currently persisted in the repo — see §2. Common-function
> deduplication and multi-IR-level compilation are future work (§3–§5), several of them only
> loosely sketched — treat those as starting points to refine once someone actually builds them,
> not settled designs.

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
in §4.

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

`falcom/ed9/writer/scp_writer_helper.py` defines one Python function per VM opcode (`PUSH`,
`LOAD_STACK`, `JMP`, `CALL_SCRIPT`, `DEBUG_LOG`, etc.), each calling
`get_scp_writer().handle_opcode(...)`. A "DSL file" is a `.py` file that calls these functions in
sequence, at the same granularity as the disassembly — one opcode, one call. It is opcode-level
Python assembly, not the TypeScript/HLIL-level output a person would read to understand a script.

## 2. Current Round Trip

**Generation** (bytecode → `.py`): `Formatter.format_function`/`format_block`
(`falcom/ed9/disasm/formatter.py`) → `ScpParser.format_function` (`falcom/ed9/parser/scp.py`) →
`scena2py.write_python_dsl` (`falcom/ed9/scena2py.py`).

**Compilation** (`.py` → bytecode): the `.py` file is executed (`runpy.run_path(...)['main']()`)
against a `ScpWriter`, which emits bytecode via the same per-opcode calls.

**Validation**: `tools/scp_roundtrip_validator.py` automates a full loop — decompile a script,
delete the temporary *copy* of the source `.dat` it made for the run (the original input file is
never touched), exec the generated `.py` in a subprocess, byte-compare the result against the
original. This mechanism — the automated byte-exact comparison itself — is real and implemented.

**What's opt-in, not default:** round-trip fidelity depends on
`ScpParser(round_trip=True, keep_unreachable_code=True)`. The validator doesn't set these
explicitly; it relies on `ScpParser`'s class defaults, which currently happen to be `True`.
`scena2py_config.py` — the everyday CLI config — overrides both to `False` by default. So the
validator's correctness currently depends on the parser's class defaults staying `True`; if those
defaults ever changed, the validator would silently stop being round-trip-safe without any config
change of its own. Anyone using `scena2py.py` directly for recompilation needs to know to flip
these two flags explicitly rather than relying on defaults either way.

**What's actually verified, and what isn't:** the validator's documented baseline (5 samples:
`e0000`, `e2000`, `system.original`, `mp0000_ev`, `ai_chr0100_e00`) is a *format-check* baseline
only — it does not run `--round-trip`. There is no persisted "identical (N bytes)" result anywhere
in the repo for any file. Separately, plain (non-fidelity) decompilation has run at much larger
scale (~1090 files via `notes/baseline_step0/dump_set.py`), but that run didn't exercise round-trip
either. In short: the mechanism to verify byte-exact round-trip exists and is automated; actual
corpus-scale confirmation that it currently passes does not yet exist in this repo.

## 3. Future Work: Common-Function Shared Library

**Problem (confirmed):** output `.py` files currently embed full copies of shared game functions
per file. Verified directly — `ai_chr0001_c49_e00`'s and `ai_chr0118_e00`'s output each embed
~12-15 identical `@scena.LLILCommonCode` functions (`global_work`, `chr_info`, `btl_get_chr_info`,
`btl_ai_skill`, `btl_chr_list_init/next/get_remain`, ...); `mp2000.py` embeds 130.
`scena2py_config.py` already documents this.

**Correction on how much precedent already exists for this:** the round-trip validator's
`check_common_order` checks common-function ordering, but more loosely than "a shared include"
implies — it picks whichever observed file has the longest common-function list as an ad hoc
reference, ignores functions absent from that reference, reports order conflicts as warnings (not
failures), and never verifies that same-named functions across files have identical bodies or
signatures. So this is evidence of an informal ordering *convention*, not an enforced canonical
shared-function contract — less of a running start than it first looks like.

**Rough direction, deliberately not fully designed yet:** move common functions into one local
library file (precedent: `scp_writer_helper.py` plays a similar role for opcode primitives) that
output `.py` files import from instead of embedding full bodies. Since the compiled bytecode format
has no cross-file linking — every `.dat` must be fully self-contained, which is why functions are
duplicated today — the compiler still needs to know, per output file, which imported functions to
bake into that file's bytecode. A manifest mechanism (something like an `imported_common_funcs()`
function marked with a decorator) is the shape of the idea, but real open questions need resolving
before it's actually designed, not just sketched — worth revisiting once someone starts building
it rather than trying to settle now:

- `@scena.LLILCommonCode()` registers a function into `ScpWriter.functions` immediately on
  decoration (`falcom/ed9/writer/scp_writer.py`). If shared-library functions keep that decorator,
  importing the library registers everything in it, defeating selective inclusion. If they don't,
  something else needs to reproduce what that decorator currently does (`is_common_func`,
  `debug_argc`, source order, etc.).
- How name collisions between imported and local functions get handled — today,
  `functions_by_name` is silently overwritten while both entries remain in `functions`.
- How transitive dependencies are covered, if one imported common function calls another common
  function that the manifest omits.
- How repeated compilation within one Python process interacts with module caching and the
  singleton writer.

## 4. Future Work: MLIL DSL and HLIL DSL

Extend the same pattern upward, one IR level at a time:

```
HLIL DSL (.py) → lower → MLIL DSL (.py) → lower → LLIL DSL (.py, exists today) → ScpWriter → bytecode
```

A future MLIL-level writer takes a `.py` MLIL DSL file and lowers it to a `.py` LLIL DSL file
(reusing today's real LLIL DSL → `ScpWriter` path unchanged), rather than talking to `ScpWriter`
directly. HLIL would lower to MLIL DSL the same way. **Not started** — no reference to
`ScpWriter`, `handle_opcode`, or any bytecode-emission path exists anywhere in `ir/mlil/`,
`ir/hlil/`, or `codegen/` today.

## 5. Future Work: Mixed-IR-Level Compilation, Per Function

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
