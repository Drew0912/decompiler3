# LLIL DSL — Recompilation Pipeline

> Status: Core mechanism implemented (a `.py` file can be executed to produce byte-exact
> bytecode, and an automated round-trip check exists). Fidelity is opt-in, not default —
> see `docs/ROUND_TRIP_POLICY.md` for the round-trip policy this whole pipeline follows. The common-function
> shared library (§3) is implemented and active by default, and hook files patch a script without editing it
> (`docs/dsl/HOOKS.md`). Ideas beyond what's implemented here — multi-IR-level compilation, knowledge-driven typing for
> common functions — live in `docs/dsl/DSL_FUTURE_WORK.md`, not in this document.

## Role in the Pipeline

The decompilation pipeline goes forward (bytecode → readable code). This document covers the
reverse: turning a Python source file back into game bytecode.

**Naming note:** "LLIL DSL" in this document refers to this `.py` output — generated from the
disassembly IR (`assembler/`, `falcom/ed9/disasm/`), not from `ir/llil`'s `LowLevelILFunction`. The real LLIL
pipeline (`ED9VMLifter`, `FalcomLLILFormatter`) is a separate, disjoint path that only feeds
`.llil.asm`/`.llil.dot` debug dumps and MLIL→HLIL→TypeScript. The two are close enough in shape
(one opcode, one function call, stack-machine semantics), and the disassembly-sourced version is
already correct and round-trip-capable, that there's no plan to switch its source — treat "LLIL
DSL" as this level everywhere it's mentioned below, including in the MLIL/HLIL lowering chain
sketched in `docs/dsl/DSL_FUTURE_WORK.md`.

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
(`PUSH`, `LOAD_STACK`, `JMP`, `CALL_SCRIPT`, `POPN`, etc.), each calling
`get_scp_writer().handle_opcode(...)`, which rejects a `bool` operand (`True` would otherwise
pass the `int` checks and encode as 1). `falcom/ed9/writer/scp_writer_helper.py` layers the DSL
statements that emit no instruction over that (`label()`, `GLOBAL_VAR`, and `genLabel()`, a fresh
label name for a hand-written or generated function body) and re-exports the opcode primitives via
`from .scp_writer_opcode_handler import *`, plus `create_scp_writer` and `WORD_SIZE`, so every
generated `.py` only ever needs to import the helper module. The writer's own classes and
constants stay out of that namespace (the opcode handler imports only `get_scp_writer` from
`scp_writer`); a script or hook that needs one imports it from `falcom.ed9.writer.scp_writer`.
A "DSL file" is a `.py` file that calls these functions in sequence, at the
same granularity as the disassembly — one opcode, one call. It is opcode-level Python assembly,
not the TypeScript/HLIL-level output a person would read to understand a script.

**Operand spelling.** A float is stored as float32 bits with the lowest 2 dropped
(`ScpValue.FLOAT_DROPPED_BITS`), so each stored value covers 4 float32 values. The `.py` prints the
shortest float literal that stores the same word (`ScpValue.float_literal`): `PUSH_FLOAT(0.3)`, not the
decoded `PUSH_FLOAT(0.2999999523162842)`, and the same for float parameter defaults (`= 0.2`). It is
always a float literal (`1.0`, `-0.0`), because the writer picks the encoding from the Python type;
`PUSH_FLOAT` itself converts an `int` with `float()`, so a hand-written `PUSH_FLOAT(1)` still pushes a
float, and `PUSH_INT` a `RawInt` with `int()`, so `PUSH_INT(RawInt(5))` pushes an Integer. An inf prints as
`float('inf')` / `-float('inf')`, and a NaN as its stored word, `FloatWord(0xBFE88D14)`, which keeps its sign and
payload (`float('nan')` stores one word only); both compile as the VM stores its own results, the 2 dropped bits
cut (`docs/falcom/ed9/ED9_VM.md`, Values, Floats). `CALL_SCRIPT`/`CALL_SCRIPT_NO_RETURN` names print as plain
strings, `CALL_SCRIPT("this", "GetCoolClone", 0)` - the writer wraps a bare `str` itself. An `int` must
fit the 30-bit Integer payload (`ScpValue.INTEGER_MIN..INTEGER_MAX`, -0x20000000..0x1FFFFFFF) and a
`RawInt` `0..0x3FFFFFFF`; past that, compiling raises at its line instead of storing a different number
or type (`PUSH_INT Integer 600000000 is outside -536870912..536870911: ..`). An int enum (`IntEnum`,
`IntFlag`: a named constant or a flag mask) pushes its value; `RawInt`, an `int` subclass too, stays Raw.

**Comments.** Every trailing comment starts at display column 32 after the indent (a CJK character
takes two columns; a longer line gets 2 spaces), several on one line joined by `, `. Besides
`# global var N` on `LOAD_GLOBAL`/`SET_GLOBAL` and the header's `GLOBAL_VAR` lines, the `.py` shows the
stack the way the `.llil.asm` does, read from the parser's simulated stack (`Function.stack_layout`,
`docs/falcom/ed9/ED9_FORMAT.md` Layer 2). Each of the 5 offset opcodes gets the absolute slot it addresses and
what it holds, `*` marking a dereference and `&` an address (`POP_TO` and `POP_TO_DEREF` count their
offset from sp after their pop); the instruction that opened a local the code addresses gets
`(local)`; `POP(n)` gets its slot count (in a split pop, the first `POP` also the bytes it leaves for the next:
`POP(255)  # 63 slots + 3 bytes`, `POP(77)  # 20 slots`); each label gets the depth there. Whatever the stack
comments' setting, a `PUSH_FLOAT` of a NaN gets what its word holds: its sign and, unless it is the plain NaN,
`signaling` (its quiet bit clear) and its payload, as in
`PUSH_FLOAT(FloatWord(0xBFE88D14))  # -NaN, signaling, payload 0x223450`. The stack comments look like this:
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
the `sora2` scripts. `ScpDecompileConfig.stack_slot_comments` (on by default) turns the stack
comments off in scripts; the common-function library (§3) always has them, labels named `L0`, `L1`, ...
(`label(L0)  # sp = 3`). Comments don't change the compiled bytes.

Three more kinds are opt-in, script `.py` only (`ScpDecompileConfig`, all off by default):
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
run). `GLOBAL_VAR` belongs in the script's one `@scena.GlobalVars()` block or a hook's run or function
callback (`docs/dsl/HOOKS.md`): anywhere else it raises, and so do a second `@scena.GlobalVars()` and one before
`create_scp_writer()`. Its type is stored as an unsigned word (`GLOBAL_VAR('x') type is -1, outside
0..4294967295`); the games declare only 0 (Integer) and 1 (String), so another type compiles as written,
with a warning (`GLOBAL_VAR('x') type is 2, not 0 (Integer) or 1 (String)`). Operand checks report first: `LOAD_GLOBAL('missing')` at module level reports the
unknown name, and `PUSH_INT(5.0)` there its type. A wrong argument type is a `TypeError` naming the
statement, the argument and the types it takes - `PUSH_INT value is 5.0 (float), not int`, in a body at
its line. `CALL` of a function the script never registered says where one comes from: a library function
listed in `@scena.CommonImports()`, a script function with `@scena.LLILCode()`, a hook function with
`@add_function`. An integer operand must fit what its type reads back, and a global index the declared
table - `SET_REG(16)` fails at its line (`SET_REG operand 1 is 16, outside 0..15`: the VM has 16 registers;
`POP` takes at most 255 bytes) instead of being truncated. A string - pushed, a `CALL_SCRIPT` name, a `str` default or a
global name - can't hold a NUL (the game ends the string there) or a lone surrogate (it can't be encoded):
`PUSH_STR('a\x00b')` fails at its line (`PUSH_STR string 'a\x00b' contains a NUL, ..`), a default at its
`def`. Errors raised while a body runs carry the `.py` line in their traceback.

**Call-site debug records.** Every call of a non-common function gets a debug record of its arguments,
with or without a `DEBUG_SET_LINENO` before it, unless its `CALL` says `debug_record=False` (below); a common
function gets none (`ScpWriter._gets_debug_records`). A local call's record keeps them
up to the last one its author wrote, by the original compiler's rule: trailing constant arguments equal to
the callee's defaults (the same type and stored word, a string by its text; the callee's final signature,
hooks included) are left out. A call whose original record breaks the rule carries its count on the `CALL`
- `CALL(chr_allow_controll, debug_argc=2)` - which the round-trip `.py` (`ScpParser(round_trip=True)`)
writes, dead code included: the parser pairs a function's records with every call the `.py` prints
(`call_debug_records.pair_records`, shared with the listing and the validator; each pair content-checked),
and a function whose records don't pair gets no `debug_argc` and a warning (`records not paired: ...`).
The original compiler leaves a few `btl_ai_skill` calls in `ai/` scripts without a record
(`docs/falcom/ed9/ED9_FORMAT.md`, Call-Site Debug Records, rule 2: `ai_chr5004p`, `ai_chr5106p`); with more
calls than records the parser finds the one order-preserving alignment of records with calls
(`align_records`; none or several: not paired), and
each local call left over carries `CALL(btl_ai_skill, debug_record=False)` - no record, so a `debug_argc`
beside it is unused. `debug_argc` must be an `int` (`CALL debug_argc is True (bool), not int`) and is used
as given, `debug_record` a `bool`; opcode callbacks never see either, and they go with their `CALL` when one
drops it. An everyday `.py` (decompiled with `ScpParser.round_trip` off: neither keyword) gets rule-trimmed
records, and a record for each call the original left without one. `ScpWriter.round_trip` covers the string
pool only: on (the default), it is never deduplicated and is written in section order, as the original
compiler wrote it; off, equal strings share one entry. That doesn't change the logic, and only tests turn it
off. The records do (`docs/ROUND_TRIP_POLICY.md`, Records the engine reads), so no flag touches them. An older
round-trip `.py` with `@scena.LLILCode(debug_argc={...})` stops at Python's `TypeError` there: decompile
the `.dat` again.

**The compile check** (`ScpWriter.check_compiled`, on by default; a script turns it off with
`scena.check_compiled = False`). At the end of `build()` the bytes are parsed and lifted again in memory
by the decompiler's own `ScpParser` and `ED9VMLifter` (`falcom/ed9/writer/scp_compile_check.py`), so a
stack mistake that compiles - a wrong `POP(n)`, a call with an extra or missing argument, branches that
reach a label with different stacks, a read or write outside the live stack, a slot offset that isn't a
multiple of `WORD_SIZE` (offsets count bytes) - fails the compile instead of reaching the game:
```
CompileCheckError: test.py:12: Caller: CALL at 0x77: Callee takes 1 argument, found 2 above its call setup [PUSH_RAW@0x5F (line 8), PUSH_RAW@0x65 (line 9)]
```
A local `CALL` with the wrong number of arguments, as here, is counted from its own setup - the one
returning right after the call; a default doesn't make an argument optional, since defaults apply only
when the engine calls the function by name. The line is the one whose call emitted the failing opcode (a
helper called from a body maps to the body's call); an error with no instruction to blame (an empty last
function) points at the function's `def`, past its decorators. Each stack entry an opcode pushed gets
that opcode's line in the error: `[param_0, PUSH_INT@0x46 (line 23)]`, or `(file:line)` when it is in
another file than the failing opcode (a hook's). Branch arms laid out before the code where they meet
are decoded first, so a value one of them leaves is reported where the arms meet. Undefined labels and
jumps into another function get the same `file:line:` prefix. A function without `RETURN` runs on into
the next function's code - a `.dat` has no end-of-function marker, so the VM keeps going - which
compiles with a warning while the bytes still decompile, and adds a note to the error when they don't:
```
WARNING   test.py:38: A: SET_REG at 0x5E: runs past its end into B without RETURN
WARNING   test.py:41: AEmpty: has no code, so it runs on into B without RETURN
```
Nothing follows the last function, so code that runs or jumps past the end of the code fails, in
whichever function's code it is, and so does a call whose return label is its function's very end
(`returns to 0x.., past its end (no RETURN after its return label)`). The parser's warning for a slot
that is legal but unusual (a caller-frame or call-setup slot) gets its line the same way, and so does its
warning for a call whose return label is at or before the call (`returns to 0x.., at or before the call, so
it loops back there`): valid VM code - a loop that jumps out between the label and the call ends - but
almost always a copied call that kept the old label. A label right at the call fails the stack check
instead, and any failure in a function with such a call carries the warning as a note. A failed check is
a failed compile: no `.dat` is written, an older one stays, and the writer is spent like after any failed
compile. Code no path reaches (code between a call and its return label, or after a `RETURN`) isn't
simulated, so its stack isn't checked, but it compiles with one warning per range, at its first opcode's
line: it never runs, and the everyday decompile drops it.
```
WARNING   test.py:31: A: 2 opcodes at 0x3D..0x45 never run (no path reaches them); the everyday decompile drops them
```
A fidelity decompile keeps the game's own dead code, which warns the same way. A script turns the
warning off with `scena.warn_unreachable_code = False` (`ScpWriter.warn_unreachable_code`, on by
default; turning the compile check off also silences it). Not checked: a stack that balances but reads
the wrong slot. Nor the stack's depth: a script thread has 512 bytes and a push past them stops it
(`docs/falcom/ed9/ED9_VM.md`, The thread and its loop); the deepest `sora2` call chain uses 368. Nor a
String that crosses files, as an argument to another file's function or as its result: it is an offset
into one file's string pool, read in the other's (`ED9_VM.md`, Values); no `sora2` script passes one.
A read or write outside the live stack fails at once; decompiling a game `.dat` only
warns about it. A `SYSCALL` whose argc reaches past the stack fails at once too (`reads 2 entries, the
stack has 1: [..]`); decompiling fails only that function's lift. While the stack balances, nothing checks a
`SYSCALL`'s argc, so it must match its own `POP` right after it, the only form the game's compiler emits:
a `POP` of another count, or none after an argc above 0, warns - a merged or shared `POP` too:
```
WARNING   test.py:12: Main: SYSCALL at 0x3C: reads 2 values, but the POP after it pops 3 (POP(12)) - is its argc stale?
```
A slot offset that isn't a multiple of `WORD_SIZE` fails decompiling too, like a partial `POP`.
An opcode can't use a parameter's slot in place - consume it (`SET_REG`, `ADD`, `POP_TO`, `POPN`, ...),
read it (`SYSCALL`) or forward it to `CALL_SCRIPT_NO_RETURN`: that is valid VM code, but
the decompiler doesn't follow it, so the check fails naming the parameter (`uses the slot of parameter 1
(arg1) in place`). Work on a `LOAD_STACK` copy, which moves every offset below it one slot further:
`POP_TO(-WORD_SIZE)` (`arg1` into `arg2`) becomes `LOAD_STACK(-WORD_SIZE)`, `POP_TO(-2 * WORD_SIZE)`,
then pop both parameters before `RETURN`. A tail call passes the copy through a register:
`LOAD_STACK(-WORD_SIZE)`, `SET_REG(0)`, pop the parameters, `GET_REG(0)`, `CALL_SCRIPT_NO_RETURN`. The
check costs about twice the compile itself (`mp0000_ev`, a 1.6 MB script: about 4 s on top of 1.7 s);
while it is on, each opcode also records where it was emitted.

## 2. Round Trip: Generation, Measurements, Validation

The policy (what must hold) is `docs/ROUND_TRIP_POLICY.md`; this section is how the round trip is generated, run and
measured.

**Measured on the full sora2 corpus** (`tools/scp_roundtrip_validator.py --logic-round-trip`, before the
common-function library existed): every file reaches the fixed point at round 2 (`c1 == c2`, `out2 == out3`); all
preserve game logic against the source; `out1`/`out2` differ only in `loc_` label lines. Re-checked after the
library landed (§3) on a 132-file subset (sora2's `script_en/battle/`, chosen for subsystem diversity) plus the two
previously-broken edge cases (`common.dat`, `mon5078+.dat`): identical result, 100% converge at
round 2, no logic regressions. **Full 1082-file re-run with the library active, completed
2026-09-22:** 0 logic round-trip failures and 0 errors — every file's `logic round trip` check
(fingerprint match against source, per function) passes. 234/1082 files additionally show a
**structural**-only difference (function order and/or rebuilt debug records, 7 also string-pool
counts) against source when checked with `validate_file`'s format checks: common functions are now
always registered before source functions (`@scena.CommonImports()` runs eagerly, ahead of the
inline definitions), which reorders them relative to source and shifts where the records sit in the file:
neither changes a record's content, and function order and string-pool layout are outside the "game logic"
definition in `docs/ROUND_TRIP_POLICY.md`. This is the expected, designed consequence of pulling matched
functions out of their original source position into the shared-library import path, not a regression. 127 files'
worst status was an informational WARN (mostly pre-existing "N unreachable ranges" notes, same
category as the pre-library baseline). **Re-run 2026-10-06** at `ebf2578`, with the compile check
(§1) in every compile: again 0 logic round-trip failures and 0 errors, every file at the fixed point
at round 2, and the same worst-status split (721 PASS, 127 WARN, 234 FAIL on the source's format
checks only).

**Generation** (bytecode → `.py`): `Formatter.format_function`/`format_block`
(`falcom/ed9/disasm/formatter.py`) → `ScpParser.format_function` (`falcom/ed9/parser/scp.py`) →
`scp2py_base.write_python_dsl` (`falcom/ed9/scp2py_base.py`). `ScpParser.gen_python_script(functions,
comments = CommentOptions(...))` picks the optional comments (`falcom/ed9/disasm/llil_dsl_comments.py`;
`scp2py` builds them from its config); the validator keeps the defaults, so the logic round trip
checks that the stack comments reach the fixed point too. A generated script first puts the repo root on `sys.path` (`import sys` and
`sys.path.insert(0, '<root>')`, the root of the checkout that generated it - `SYS_PATH_SETUP_LINES` in
`falcom/ed9/parser/scp.py`, from `dc3.utils.PROJECT_ROOT`), so it runs from any folder without `PYTHONPATH`; moving the
checkout means regenerating the script or editing that line. It then imports the helper, an
optional `<stem>_hook` module for patches kept outside the generated file (only a missing hook is
ignored; an import error inside the hook stops the compile; `docs/dsl/HOOKS.md`, which also covers the opt-in hook template), and the
library (§3). Its footer calls `main()`, which compiles the script when it is run directly. Every generated text file is written
with `\n` line endings.

**The `.dat` listing** (`.debug.txt`, `ScpDecompileConfig.write_debug_info`, off by default): the
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
(`call_debug_records.pair_records`, content only); otherwise the function notes `records not paired: ...`,
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
`ScpParser(round_trip=True, keep_unreachable_code=True)`. `scp2py_config.py` — the everyday CLI
config — sets both to `False`. The validator passes both explicitly (`decompile_to_python`: `True`
for `--round-trip`, `False` for `--logic-round-trip`), so it does not depend on `ScpParser`'s class
defaults. Anyone using `scp2py.py` directly for byte-exact recompilation needs to set both flags
to `True`.

**What's actually verified, and what isn't:** `--round-trip` is byte-identical on the validator's 5
baseline samples (sora2's `script_en/scena/e0000.dat`, `e2000.dat`, `mp0000_ev.dat`, `system.dat`,
and `script_en/ai/ai_chr0100_e00.dat`), and `--logic-round-trip` converges at round 2 on
all 5 (2026-10-01). On a 300-file quota sample of `sora2` that includes them (list and results
in the gitignored `notes/validator300/`), all but 2 files are byte-identical and all converge at round 2.
The logic round trip is also measured corpus-wide (above), and so is the byte-exact one: all but 6 `sora2`
files are byte-identical. The 6 left are known and out of the debug-records plan's scope: 4 `chr*` files from the older
compiler (`chr0000`, `chr5001`, `chr5003`, `chr5007`: `docs/falcom/ed9/ED9_FORMAT.md`, Call-Site Debug Records),
`chr5110` (dead code ranges the decompiler drops) and `mp0090` (bytes before its first function); `notes/debug_records_handoff.md` has the details. When a rebuilt file differs, `--round-trip`
also compares the two files' debug records function by function and reports the first difference in each
(`compare_file_records`, e.g. `AniDamage record 3: 1 args, original 2`).

## 3. Common-Function Shared Library — Implemented

**Problem (confirmed):** output `.py` files used to embed a full copy of every shared game
function they used: across the `sora2` corpus, tens of thousands of copies of the shared functions, hundreds in
the largest scripts (`mp2000.py`).

**Design:** `falcom/ed9/tools/gen_common_library.py` walks one game's scripts once and generates
that game's library in its metadata package `falcom/ed9/games/<game>/metadata/` (tracked, the generated
files in it gitignored; later the game's chr table too): `common/scp_writer_common_{N}.py`
(one module per first-syscall subsystem, or `scp_writer_common_no_syscall.py`), plus
`common_index.py` (pure data: `name -> (module, fingerprint digest)`) and `common_all.py`
(re-exports every generated module via `import *`). Each module lists only its own functions in
`__all__`, so `common_all` exports library functions and nothing else: re-exporting the helper's
names a second time made type checkers treat aliases like `Value32` as variables. A parser knows its
game (`ScpParser.load(..., game=...)`; each game's `scp2py.py` passes its own, `None` means no
library). At decompile time, `ScpParser` (`scp.py`) matches each of a script's own common functions
against its game's index by name *and* fingerprint (`match_library_functions`) — a name whose body
diverges from the canonical library variant is left inline, unchanged. **Every script decompiled for
a game imports that game's whole library** (`gen_library_import`, after the hook import) — every
mode, every script, whether or not its own source used any common functions — so a human editing
the script has every common function in scope for `CALL()`/autocomplete even when adding one the
original bytecode never used:

```python
try:
    from falcom.ed9.games.sora2.metadata.common_all import *
except ModuleNotFoundError as e:
    if e.name != 'falcom.ed9.games.sora2.metadata.common_all':
        raise
```

Only the matched subset is declared in a `@scena.CommonImports()` manifest, in the script's own code
order, since that (not the import) is what actually gets baked into the compiled bytecode; the import
itself has zero effect on compiled output; it's inert until the manifest (or, in strict mode, this
script's own inline definitions, which always take precedence) actually references a name.
Everything else — non-matching commons and this script's own functions — is still emitted inline
as today.

**Gating:** the *import* is a `try`/`except` like the hook import's: only the game's missing
`common_all` is ignored (its library not generated: the script has every common function inline,
below; every game folder has its tracked `metadata/__init__.py`, so a game without a library lacks
only `common_all`, never the package), and any other failure — a module under `common/` missing,
a failed import inside the library — re-raises instead of being swallowed. A script decompiled
without a game (`game=None`: the
round-trip validator without `--game`, most tests) has no library import at all. The *manifest* —
i.e. what actually gets matched and baked into bytecode — is gated in `match_library_functions` on
a game, on `not (self.round_trip or self.keep_unreachable_code)` (the everyday `scp2py_config.py`
default; the library was generated with unreachable code already stripped, so either fidelity flag
falls back to inlining everything, exactly as before this existed), and on the game's index
(`common_library_index` in `parser/scp.py`, loaded once per game per process). It **imports the
index, not `common_all`**: that would load the whole library and the writer, none of which a
decompile uses. The generator writes the index with the modules, so a missing index means no
library: the parser logs a hint to run the generator (once per game), matching returns `{}` and
every function falls back to fully inline, same as strict mode. A manifest naming a function the
script's game doesn't define (a misspelled name, or a library deleted after the decompile) fails
with a `NameError`, to which `CommonImports` adds a note naming both causes and the generator
command.

**Regenerating the library:** `python falcom/ed9/tools/gen_common_library.py
falcom/ed9/games/sora2/extracted/script_en` walks the game's scripts (round_trip=False,
keep_unreachable_code=False), fingerprints every
`is_common_func` occurrence (noting, once per fingerprint, whether it touches a global, what it
calls and its first syscall), picks the majority fingerprint per name as canonical (ties → first
occurrence in sorted order), excludes any function touching `LOAD_GLOBAL`/`SET_GLOBAL` plus the
closure of anything calling an excluded function (asserting the closure holds) and assigns modules.
Only then does it re-parse the files holding an included function's canonical copy, rendering each
function's final text, stack comments included (§1). Every run is a full rewrite of the game's
library — hand edits to generated files don't survive regeneration. The game is the one the path
names, `<game>/extracted/script` or `script_<lang>` wherever the folder is (a copy, a junction's
target) for a game in `falcom/ed9/games/`; else `--game <game>`, for any `script` or `script_<lang>`
folder; both given, they must agree. Anything else stops it before anything is written: a file, a
folder not named `script(_<lang>)` (the game folder, a subfolder like `script_en/ai`), no game, a
path and `--game` naming different games, a folder with no `.dat` scripts.

**A game's library is gitignored, not checked in** (`metadata/common/`, `metadata/common_index.py`,
`metadata/common_all.py`; only the package's `__init__.py` is tracked) — like the game scripts
under `falcom/ed9/games/<game>/extracted/` it is generated from, its generated modules are a substantive translation of the game's own script content (real function
bodies, not original project code), so it's treated the same way: regenerated locally, never
committed. **This means a fresh checkout needs the generator run once per game, against a local
copy of its scripts, before that game's default (`round_trip=False`) decompile imports common
functions from the library** — until then the gate above keeps every function inline and the
scripts skip their library import.

**The four questions this section used to leave open, now closed:**

- *Eager registration on decoration* — the shared-library modules define plain, undecorated
  `def`s. Registration only happens when an output script's own `@scena.CommonImports()` manifest
  imports and returns a specific function, going through the same registration machinery
  `LLILCode`/`LLILCommonCode` use (as an ordinary `is_common_func=True` registration) — so
  importing the library module itself registers nothing.
- *Name collisions* — registration now raises `ValueError` on a duplicate name instead of
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

## 4. Hooks — Implemented

Moved to `docs/dsl/HOOKS.md`.

## 5. Future Work

Ideas that extend this pipeline but haven't been started — MLIL/HLIL DSL lowering, mixed-IR-level
compilation, knowledge-driven typing for common functions — are collected in
`docs/dsl/DSL_FUTURE_WORK.md` rather than here, so this document stays a description of what's actually
implemented.
