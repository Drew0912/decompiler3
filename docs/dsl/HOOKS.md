# Hooks

## LLIL DSL Hooks — Implemented

A hook file `<stem>_hook.py`, next to `<stem>.py`, patches a script without editing the generated file. The script
imports it before `create_scp_writer()` (`docs/dsl/LLIL_DSL.md` §2: only a missing hook is ignored), so what a hook
registers at import time is there when the script compiles (`scena.run(globals())` → `ScpWriter.build`). The hook API is
`falcom/ed9/writer/scp_writer_hooks.py`; the helper star-imports it, so a hook needs only the helper's import. The
example below compiles against `ai_chr5122_e00.py` with the compile check on:

```python
# pyright: basic
# ai_chr5122_e00_hook.py  (next to ai_chr5122_e00.py)
from typing import TYPE_CHECKING
from falcom.ed9.writer.scp_writer_helper import *
if TYPE_CHECKING:                                   # Pylance only - never imported at runtime
    from ai_chr5122_e00 import *  # pyright: ignore[reportAssignmentType]
    import ai_chr5122_e00 as original


@replace_function('CheckAlgoUse')
def CheckAlgoUse(arg1, arg2, arg3 = 5):             # types from the original; arg3 gains the default 5
    PUSH_CURRENT_FUNC_ID()                          # a local call, as the decompiler prints one
    PUSH_RET_ADDR('hook_skill_table_ret')
    CALL(SkillTable)                                # a script function, by its plain name
    label('hook_skill_table_ret')
    inline_original_func()                          # then the original CheckAlgoUse's opcodes


@add_function
def HookExtra(arg1: Value32):                       # a new function, compiled after the script's own
    POP(WORD_SIZE)
    RETURN()


def swap_clone(opcode, *args):
    if opcode == ED9Opcode.CALL_SCRIPT and args[1] == 'GetCoolClone':
        CALL_SCRIPT('chr5122', 'GetCoolClone', args[2])
        return True                                 # drop the original opcode


registerOpcodeCallback(swap_clone)
```

Compiled and decompiled again, `CheckAlgoUse` is the three-opcode call followed by the game's own opcodes, keeps its
table index and reads `CheckAlgoUse(Value32, Value32, Value32 = 5)`; `HookExtra` is last in code order; the game's
`CALL_SCRIPT("this", "GetCoolClone", 0)` became `("chr5122", "GetCoolClone", 0)`; every other function is
unchanged.

**The API.** Each `register*` call returns its argument, so it also works as a decorator. Hooks are plain functions
(`def` or `lambda`), like every function `LLILCode()` / `LLILCommonCode()` register: anything else
(`functools.partial`, a callable object, a bound method) is a `TypeError`. Functions and hooks
register at hook import time or in a run callback; registering one from a function callback or from a body is an
error.
- `@replace_function('Name')`: the decorated function becomes `Name`'s body. `Name` may be a script function, a
  library function or an added one; an unknown name fails the compile at the hook's line, and a second replacement
  of the same name warns and wins.
- `registerFuncCallback(cb)`: `cb(name, func)` for every function, in registration order (`@replace_function`
  registers one too). Returning `None` (or `func` itself) keeps the body; returning a function replaces it, and a later
  callback receives that replacement as `func`. For pattern rules (every function named `AniBtl*`). It may add global
  vars (`GLOBAL_VAR`), not functions or hooks.
- `registerRunCallback(cb)`: `cb(g)` with the script's globals, before the function callbacks. It may add functions
  (`add_function(f)`, or `get_scp_writer().LLILCode()(f)`) and global vars (`GLOBAL_VAR`, appended after the script's,
  so their indices stay; at a hook's top level `GLOBAL_VAR` is an error); the function callbacks then see the added
  functions too.
- `@add_function`: a new function, compiled after the script's own. Existing functions keep their code order and
  their offsets from the code start; the function table is sorted by name, so a new name can shift other functions'
  indices, and every `CALL` follows. Every parameter needs a type. A name the script already has is an error that names
  both definitions: `@replace_function` replaces a function.
- `registerOpcodeCallback(cb)`: see Opcode callbacks below.
- `original.Name(...)`: inlines `Name`'s body from before any hook, at that point. Its arguments are checked like a
  normal call to that original (`original.CheckAlgoUse(1)` is a `TypeError`: missing `arg2`); an LLIL body reads its
  arguments from the VM stack, so the values themselves are never read. `CALL(original.Name)` is `CALL(Name)`: a call
  by name, so it calls the replacement when there is one (inside `Name`'s own replacement, a call to itself).
  `original` exists once the compile starts (in bodies and callbacks), not at hook import time.
- `inline_original_func()`: in a replaced function's body, inlines that function's body from before any hook; an
  error anywhere else.
- `get_scp_writer().globals`: the script's globals dict, once the compile starts.

**What `build()` does, in order.** (1) Saves the script's globals. (2) Registers the queued `@add_function`s. (3) Sets
the script's names in the hook modules (below). (4) Runs the run callbacks. (5) Runs every function through the function
callbacks, then merges each replaced function's signature (below). (6) Counts the header: nothing registers after this.
(7) Compiles the bodies, running the opcode callbacks as opcodes are emitted. (8) The compile check
(`docs/dsl/LLIL_DSL.md` §1).

**Script names in hooks.** Every module a hook function comes from - and the module of any function it wraps with
`functools.wraps` - gets each script name it doesn't define itself: the script's functions, `scena`, the library. So a
hook body writes `CALL(SkillTable)` like the script does. The names arrive when the compile starts, so code at a hook's
top level can't use them: use a run callback. A body a callback merely passes on (`return func`) gets nothing; a
`functools.wraps` wrapper of a library body does give the library's module the names (nothing in it is overwritten).

**Signatures.** A replaced function keeps its position, table index and common flag; its signature merges per
parameter: the replacement's type or default where it gives one, else the original's. The parameter count must match,
and `*args`, keyword-only and `**kwargs` parameters are rejected (a wrapper keeps the replaced signature with
`functools.wraps`). A default can change but never go: the engine can call a function by name with fewer arguments.
Annotations are evaluated, so `from __future__ import annotations` works; a missing or wrong type on a new function, a
`None` default, one the `.dat` can't store, or one of the wrong type (a string only on `str` / `NullableStr`, a number
only on the others) is an error at the `def`, and so is an `*args`, keyword-only or `**kwargs` parameter on any
function (the engine passes arguments by position). The merged signature is checked too: a replacement that changes a
parameter's type gives it a default of the new type when the original has one.

**Opcode callbacks.** `cb(opcode, *args)` runs for each opcode a body emits - library bodies included - before it is
written, the callbacks in registration order. `True` drops the opcode, and the later callbacks don't see it; `None` or
`False` keeps it; anything else is a `TypeError` at the callback's `def`. Opcodes a callback emits are written where
it emits them (before the triggering opcode, if that is kept) and skip the callbacks. The operands are as the DSL
function passed them: `LOAD_GLOBAL`/`SET_GLOBAL` an index (the name is already resolved), `CALL` the function object
or an `original.Name` object (compare `CALL` operands by `__name__`), `CALL_SCRIPT` plain strings in generated scripts
(a `str` or an `ScpValue`, as a hand-written script wrote it), the jumps, `PUSH_RET_ADDR` and `PUSH_CALLER_FRAME` a
label name, the push pseudo-ops their own opcode (`ED9Opcode.PUSH_INT`) with the value as given (`PUSH_FLOAT(1)`
shows the `int` 1). `label()` and `GLOBAL_VAR` aren't opcodes and never reach a callback. To act in one function
only, check `get_scp_writer().current_function.name`. Pitfalls:
- Emitting replacement opcodes without returning `True` writes both; the compile check notices only when that
  breaks the stack.
- Nothing a callback emits after a call opcode it emits runs: the call returns to the label after the triggering
  opcode, so the rest is unreachable: the compile check doesn't simulate it, only warns that it never runs, at the
  callback's line. To add code after a call, trigger on the first opcode after its return label (such as `GET_REG`).
- A drop that breaks the stack is reported where the stack breaks, at a later kept opcode (often the `RETURN`), never
  at the callback.
- Labels a callback emits need fresh names (`genLabel()`): a fixed name fails on the callback's second hit, and that
  error has no location.
- In round-trip mode, dropping part of a call sequence (`PUSH_CALLER_FRAME`, `PUSH_RET_ADDR`, an argument push)
  shifts the function's later debug records, and calls before the function's first kept `DEBUG_SET_LINENO` get none
  (dropping every one loses them all). The records don't affect the logic.

**Where errors point.** The writer's errors about a hook (a bad registration, a signature, an unknown name) and
compile-check failures name the hook's own line: a replacement's opcode, a wrapper's own opcode, an inlined
original's opcode (the script's line, or the library's file), each body of a callback chain. An opcode an opcode
callback emits names the callback's line - a `functools.wraps`-decorated callback's own, not its wrapper's - and the
opcode that triggered it:

```
ai_chr5122_e00_hook.py:27: (opcode callback swap_clone, triggered at ai_chr5122_e00.py:1110) CheckAlgoUse: ...
```

Errors Python raises inside a body (an unknown global, a `bool` operand) and a label defined twice have no such prefix:
the traceback shows the line.

**Decorators.** A registering decorator - `@replace_function`, `@add_function`, a `register*` call used as one - goes
on top, above any other decorator: below one, it registers the undecorated function and that decorator's work is
silently lost. Errors about the registered function (a replacement's signature, an opcode callback's return value)
then name the decorator's wrapper `def`.

**Inlining hazards** (not checked beyond what already fails):
- The original ends with `RETURN`, so a hook's own opcodes go before `inline_original_func()`.
- The stack must hold exactly the function's parameters when a body is inlined, or the inlined `LOAD_STACK` offsets
  read the wrong slots. That is why `inline_original_func()` is the wrapping idiom: `original.Other(...)` of a
  different function is only right when the stack matches `Other`'s frame. The compile check catches a stack that
  breaks, not a slot that is valid but wrong.
- Labels are file-wide: a body with literal labels can't be inlined twice, or inlined while it also compiles on its own
  ("label already defined"). A label-free body, or one using `genLabel()` - the whole common library - is copied
  silently, the second copy dead code after the first `RETURN`.
- `inline_original_func()` skips every other replacement too: a raw callback's wrapper that should keep earlier
  wrappers calls the `func` it was given (`func(*args)`, LLIL only).
- In round-trip mode a replaced function loses the original's debug-record argument trimming, even when the
  replacement only inlines the original: the bytes may differ, the logic doesn't.

**Pylance.** Hooks see the script's names only at runtime. The `TYPE_CHECKING` lines in the example show them to
Pylance: `from <stem> import *` for plain names, and `import <stem> as original` for `original.Name(...)` with the real
signatures. They work only when the stem is a valid module name (not `mon5078+`) that no other module takes: Pylance
finds a stdlib module or one of the checkout's top-level packages first - a script named `dc3.dat` gets the
checkout's `dc3/`. `# pyright: basic` turns on Pylance's
basic type checking for the hook file, without which Pylance reports no wrong argument counts or unknown attributes
(`original.Nmae`). The
ignore on the star-import line lets a replacement keep its function's name: basic mode otherwise reports the script's
imported `CheckAlgoUse` as clashing with the hook's own `def`. A hook that assigns its own `original` hides the
helper's. Importing the script for real from its hook would run it a second time ("duplicate function name").

**Hook template.** `ScenaDecompileConfig.write_hook_template` (off by default; only with `write_py`) writes a
starting `<stem>_hook.py` next to `<stem>.py` (`ScpParser.gen_hook_template`), never over an existing file (a log
line instead). It holds the Pylance lines above, then three hooks with their `register*` lines commented out: a
`run_hook(g)` that adds each function in its list (decompiler2's way of adding functions) and no-op `func_hook` and
`opcode_hook` callbacks. With the list empty, the template compiles to the same bytes as no hook, registered or not.
Adding a function:

```python
# Functions to add
def run_hook(g):
    for func in [
        HookExtra,                                  # read at compile time: defined anywhere in this file
    ]:
        add_function(func)

registerRunCallback(run_hook)
```

When no import can name the `.py`'s stem - it isn't a module name (`mon5078+`) or another module takes the name
(`dc3`, see Pylance above) - the `TYPE_CHECKING` block holds a hint instead of the imports: rename the `.py` to the
suggested name (`mon5078_.py`, `dc3_.py`; it still compiles to the same `.dat`, and the hook keeps its name) and
uncomment the two imports it lists. Until then, Pylance reports the script's names in that hook as undefined, though
they work when it compiles. A stem with a dot gets no template, only a warning.

**Limits.** One compile per process (the writer has no reset); hooks can't be unregistered; hooks on HLIL-level
scripts are future work (HLIL DSL: Hooks and Patching, below).

## HLIL DSL: Hooks and Patching

**Not started; after the HLIL DSL writer** (user, 2026-10-06). Hook files keep decompiler2's ED8.x layout:
each script `<stem>.py` imports the `<stem>_hook.py` next to it, and a build script runs each `.py` (which
compiles it) and moves the `.dat` into the game's patch folder. The hooks themselves already exist for LLIL
DSL scripts (LLIL DSL Hooks, above): the raw callbacks, `@replace_function`, `@add_function`,
`original.Name(...)` and `inline_original_func()`. An HLIL DSL writer keeps the same API.

- **Inlining in the list form:** in an executed list-form replacement, `inline_original_func()` inlines
  the original body, and the replacement then shares its locals.
- **Tree hooks for HLIL functions:** `@edit_function('Name')` edits the built tree anchored by content
  (`f.find_call('btl_chr_list_init').insert_after(...)`), and `@on_call('set_flag')` rewrites a call
  across the script. Inside callbacks, nodes are inspected with plain accessors (`.name`, `.args`,
  `.value`), since DSL operators build nodes.
- **Text patches:** keep addresses out of the printed text (labels by order), make the printer
  deterministic, and test that decompile → compile → decompile reproduces the file. After one recompile
  the LLIL round trip already differs only in `loc_` label lines (`docs/dsl/LLIL_DSL.md` §2), so an
  ordinary unified diff made against a decompiled script also applies to a recompiled one. Record the
  decompiler version a patch was made against. Anchoring patches to original bytecode addresses was
  rejected: it ties a patch to one `.dat`. Original source line numbers could later serve as anchors
  that survive decompiler changes (Line-Anchored Patches, below).

```python
# chr0000_hook.py
from ed9_hlil import *

@replace_function('AniBtlCraft05Main')
def AniBtlCraft05Main(arg1: Value32 = 0):
    effect_load(65534, 5040, "battle/cr0000_50_9", 1)
    inline_original_func()

@add_function
def GiveAllItems():
    for item in range(0x80, 0xFF):
        item_add(item, 1, 0)
    Return()

def funcCallBack(name, func):
    if name.startswith('AniBtl'):
        ...

registerFuncCallback(funcCallBack)
```

## Line-Anchored Patches

**Not started; after the HLIL DSL writer** (idea 2026-10-05). A hook file says where each patch goes; the
patcher decompiles the original `.dat`, the generated `.py` imports the hook, and compiling applies the
patches and runs the writer's compile check. The original `.dat` stays the only input, a hook file stays
small, and only the logic round trip is needed, not byte-exact output.

- **Anchor on the game's source lines, not the decompiled `.py`'s.** Line numbers in the generated `.py`
  move whenever the decompiler's output changes. The `DEBUG_SET_LINENO(n)` values compiled into the `.dat`
  don't: an anchor is (function, source line `n`, occurrence), and the writer applies "before / after /
  replace line `n` of `F`" while it runs the function body (an extension of the opcode callbacks), with
  no text edits to the `.py`. In the 500-file `sora2_1.0` sample (stored decompiler output, 2026-10-05):
  11,848 of 13,021 functions carry line numbers (the others are patched by function name), 58 have code
  before their first one, and 606 (4.7%) use a line number more than once - a loop compiles its
  condition at the head and again at the bottom (`ai_mon5220` `SkillTable`, line 50) - hence the
  occurrence.
- **Fingerprint:** each patch records the code it anchors to (the opcodes under the line, or the call
  there), so a game update that moves lines fails loudly instead of patching the wrong place.
- **Errors in the hook file** point at its own lines: the writer's source map, plus the `tokenize`-based
  finder of a function's `def` line past its decorators that the compile check uses.
- **Also consider anchors that don't need `DEBUG_SET_LINENO`:** older scripts don't carry source line numbers,
  decompiler3 may be extended to support them, and an HLIL DSL script has none at all (`docs/dsl/HLIL_DSL.md`, HLIL DSL:
  Form, Line numbers) - so for HLIL-level scripts this is the main anchor, not a fallback. Candidates: content anchors
  like the tree hooks above (the nth call to a function within `F`, a string it pushes), a statement's position in the
  HLIL DSL tree, or a fingerprint of the opcode sequence alone; line numbers would then be an optional shortcut where
  they exist.
