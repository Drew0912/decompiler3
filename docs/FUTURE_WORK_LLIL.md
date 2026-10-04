# Future Work: LLIL

> Ideas for the LLIL layer (the LLIL DSL `.py`, the writer and the `.llil.asm` listing) from a
> 2026-09-30 review of the decompiled output. All of them were decided with the user on 2026-10-01 and
> are planned, not started: the plan is `llil-dsl-neatening.md` (Steps 1-11; kept with Claude's active
> plans while it runs, then archived to `notes/plans/archive/`), and the decisions, with the evidence
> behind them, are in `notes/llil_dsl_neatening_handoff.md`. Both are local, gitignored notes. Each
> entry names its handoff item and plan step and is marked done when the step lands. HLIL-level ideas
> from the same review, including the HLIL DSL, are in `docs/FUTURE_WORK.md` (HLIL). As there, each
> entry links back to the doc or code it extends.

## LLIL DSL (`docs/LLIL_DSL.md`)

The LLIL DSL is the exact, recompilable stack view. It is used mostly for debugging and analysis and
is easier to read than the `.llil.asm`, but it can still be edited. Keep it close to the stack: one
opcode per line, arguments in push order, byte offsets, floats that encode to the exact stored word.
The changes below add comments or change how an operand is spelled; none of them changes a compiled
byte.

- **Shortest floats** (item 1; done: Step 3 for the `.py`, Step 4 for the rest). The VM stores a float as
  a float32 with its 2 lowest mantissa bits dropped (`ScpValue.FLOAT_DROPPED_BITS`,
  `falcom/ed9/parser/types_scp.py`), so each stored word stands for 4 float32 values, and the `.py`
  printed the one with those bits zero, in full: `PUSH_FLOAT(0.2999999523162842)`. It now prints the
  shortest decimal that encodes to the same word, always as a float literal: `PUSH_FLOAT(0.3)`,
  `PUSH_FLOAT(1.0)`, `PUSH_FLOAT(-0.0)`, in `PUSH_FLOAT` operands and float parameter defaults
  (`ScpValue.float_literal`, `docs/LLIL_DSL.md` §1). Step 4 gave the other outputs the same text: the
  Falcom lifter keeps the exact value in the IR as a `SourceFloat` (`ir/core/il_literals.py`) carrying that
  spelling, which every printer gets from `str()`. Before, `.ts`, `.hlil.ts` and `.mlil.asm` rounded to 3
  decimals, neither exact nor short: `0.033299997448921204` printed in full, `-2738.1494140625` as
  `-2738.149`, which encodes to a different word. The `.llil.asm` is under Listings. Step 3b (done)
  stopped SCCP folding floats and the algebraic identities firing on float constants, since the VM's
  float arithmetic is unverified (`docs/MLIL_DESIGN.md`, Optimization Passes).
- **Float bits comment, opt-in** (item 2; Step 8a). `PUSH_FLOAT(0.3)  # f32 0x3E999998, raw 0x8FA66666`:
  the float32 the VM computes with and the stored word a hex editor shows. Off by default, a
  `ScenaDecompileConfig` flag (`falcom/ed9/scena2py_config.py`).
- **Stack-slot comments, on by default** (item 8; Steps 6a, 6b, 7). The same variable gets a different
  offset as the stack moves: `LOAD_STACK(-16)` is `arg2` at `CheckAlgoUse`'s source line 162 and `arg3`
  at line 168. Step 6a (done) keeps the parser's simulated stack on `Function` as `stack_layout`
  (`docs/ARCHITECTURE.md`, Layer 2): the depth before every reachable instruction, and each offset
  opcode's slot with what may be in it at that point. Step 6b (done) comments the script `.py` from it
  and Step 7 (done) the library modules (always on), the way the `.llil.asm` shows the stack
  (`docs/LLIL_DSL.md` §1, Comments):
  - the 5 offset opcodes with the absolute slot and what it holds (`POP_TO` and `POP_TO_DEREF` count
    their offset from sp after their pop);
  - `# sp = N` at each label, and the slot count on `POP(n)`;
  - `(local)` on the instruction that put a local there, only when the code later addresses its slot
    by offset.

  Parameters are numbered as in every other output (`arg1` is the highest parameter slot); a parameter
  slot that is popped and pushed again (the tail-call idiom) is a local from then on. Unreachable code
  (fidelity mode) has no simulated stack, so it gets no comments. A `ScenaDecompileConfig` flag turns
  them off in scripts; the validator keeps the default, so the logic round trip checks that the comments
  reach the fixed point too.
  ```python
  def CheckAlgoUse(arg1: Value32, arg2: Value32, arg3: Value32):
      DEBUG_SET_LINENO(161)
      LOAD_STACK(-4)                  # slot 2 = arg1
      ...
      LOAD_STACK(-16)                 # slot 1 = arg2
      LOAD_STACK(-24)                 # slot 0 = arg3
      CALL(CheckSBreak)
      ...
      POP(12)                         # 3 slots
      RETURN()

      def _loc_3444(): pass
      label('loc_3444')               # sp = 3

      DEBUG_SET_LINENO(167)
      PUSH_RAW(RawInt(0x00000000))    # slot 3 (local)
      PUSH_INT(65535)
      POP_TO(-4)                      # slot 3
      DEBUG_SET_LINENO(168)
      LOAD_STACK(-16)                 # slot 0 = arg3
  ```
- **Call-argument comments, opt-in** (item 16; Step 8a). Each argument's last push gets the callee's
  parameter name, numbered like the callee (`arg1` is the last push): `PUSH_INT(1000)  # arg1`. Where a
  stack-slot comment is already on the line, the caller's and the callee's names meet as "passed as":
  ```python
      LOAD_STACK(-16)                 # slot 1 = arg2, passed as arg2
      LOAD_STACK(-24)                 # slot 0 = arg3, passed as arg1
      CALL(CheckSBreak)
  ```
  Off by default; when on, every call gets them. Which call kinds besides `CALL` get them (`CALL_SCRIPT`,
  and `SYSCALL`, which doesn't pop its arguments) is decided in Step 8a. Script `.py` only, not the
  library.
- **Per-function comment, opt-in** (item 3; Step 8a), with the function's table index and code offset,
  as decompiler2's output had: `# id: 0x0000 offset: 0x12FC`. The offset changes after the first
  recompile (library functions are registered first), like `loc_` labels; the fixed point still holds
  from round 2.
- **The hook import re-raises real errors** (item 6; Step 2a, done). The generated
  `except ModuleNotFoundError: pass` also swallowed a failed import inside the hook: the registrations
  before the failing line ran, the rest were skipped, and the script exited 0. The block
  (`gen_hook_import`, `falcom/ed9/parser/scp.py`) now re-raises unless the missing module is the hook
  itself, in both the `import` and the `__import__` form; for a dotted stem a missing parent package is
  ignored too (`if e.name not in ('X', 'X.original_hook')`):
  ```python
  try:
      import ai_chr5122_e00_hook
  except ModuleNotFoundError as e:
      if e.name != 'ai_chr5122_e00_hook':
          raise
  ```
- **Whitespace, footer and line endings** (items 4, 5, 18; Step 2a, done). Keep the `def _loc_X(): pass`
  stubs (they make labels symbols in an editor's outline) and the blank lines that mark blocks, but
  write the spacer after each label as an empty line instead of four spaces (editors that trim trailing
  whitespace change it: harmless for compiling, noisy in diffs). The footer loses its trailing spaces
  and calls `main()` instead of `Try(main)`, which prints the traceback, waits for a key and exits with
  code 0 even after an error. Every generated text file (script `.py`, `.ts`, `.hlil.ts`, `.llil.asm`,
  `.mlil.asm`, `.dot`, `.debug.txt`, the library modules, `common_index.py` and `common_all.py`) is
  written with `\n` line endings; today `write_text` uses the platform default, CRLF on Windows. Game
  strings and the `.dat` don't change.
- **`CALL_SCRIPT` with plain strings** (item 7; Step 3, done): `CALL_SCRIPT("this", "GetCoolClone", 0)`
  instead of `CALL_SCRIPT(ScpValue('this'), ScpValue('GetCoolClone'), 0)`, quoted like `PUSH_STR`. The
  writer already wraps a bare value.
- **`__all__` in the library modules** (item 14; Step 3, done). Pyright and Pylance flagged every
  parameter annotation in a generated script ("Variable not allowed in type expression") and its
  `common_all` import (`MAX_PATH` is `Final`): no module in the import chain had an `__all__`, so the
  header's second import brought the helper's names in again and `Value32` got a second declaration. The
  generator now writes each module's own function names as its `__all__`, and `common_all.py` imports
  `log` under a private name. No runtime change.
- **Debugging dumps** can use fidelity mode (`round_trip=True, keep_unreachable_code=True`), which keeps
  library functions and unreachable code inline.

## Writer (`falcom/ed9/writer/`)

- **In-memory compile, written only on success** (item 9; Step 5, done). `run2` opened the output file
  before it patched label references, so a failed compile left a broken `.dat` (66 bytes for an
  undefined label, over an older `.dat`). Now `build(g) -> bytes` compiles in memory and `run(g)` writes
  the file only after it succeeds.
- **Label error context** (item 10; Step 5, done). An undefined label was a bare `KeyError`, a
  duplicate gave only an offset, and a jump into another function compiled silently. Labels stay one
  file-wide namespace (user, 2026-10-03: function scope was tried and dropped - an advanced user may jump
  to another function on purpose, and names reused across functions add rules for no gain); errors now
  name the functions (`Foo: undefined label 'nowhere'`, `B: label 'ret' is already defined in A`) and a
  reference to another function's label compiles with a warning. Done in the same step: opcodes and
  `label()` outside a body and `GLOBAL_VAR` inside one raise (they failed with an `AttributeError`, or
  compiled a header that left the global out), and `ScpValue.to_bytes` rejects an Integer or `RawInt`
  past its 30-bit payload (`PUSH_INT(600000000)` compiled as `-473741824`). Compiled bytes don't change.
- **Catch stack mistakes by re-parsing and re-lifting** (item 11; Step 9). Compiling a `.py` checks
  operand counts, types and labels, but nothing tracks the stack: a wrong `POP(n)`, a missing push or
  an extra argument compiles into a `.dat`, and only decompiling it again notices. After `build()`,
  parse and lift the bytes in memory with the decompiler's own `ScpParser` and `ED9VMLifter`, and map an
  error back to the `.py` line that emitted the opcode (`file:line: function: detail`). A separate check
  module keeps `ScpWriter` an encoder and adds no import cycle. The check lands off, is measured on the
  corpus (every generated `.py` should pass, since the parser accepted the same bytecode), and is turned
  on only after that. This replaces the earlier design of a writer-side walker over an effect table, a
  second stack model next to the parser's; moving the parser's per-opcode stack effects into the opcode
  table is a separate plan (`notes/opcode_table_handoff.md`). Limits: neither the parser nor the lifter
  catches a read below the stack bottom today, and an offset inside the stack but on the wrong variable
  stays invisible at LLIL level. Checking an HLIL DSL `EmitLLIL` list before anything is written stays
  with the HLIL DSL (`docs/FUTURE_WORK.md`, HLIL DSL: Mixing LLIL and HLIL).
- **Hook callbacks** (item 19; Step 10, the plan's last step), moved here from the HLIL DSL work. Every
  generated script imports `<stem>_hook`, but the writer has nothing for a hook to register with (only a
  commented-out loop remains in `ScpWriter.build`), so a hook can add a function but not replace one: the
  script's own definition then hits `functionDecorator`'s duplicate-name `ValueError`. Restore
  decompiler2's raw callbacks: `registerFuncCallback` (replace a function by name, library functions
  included), `registerRunCallback` (add functions before compiling) and `registerOpCodeCallback`
  (intercept emitted opcodes). The lists are created in `ScpWriter.__init__`: the hook is imported
  before the header's `create_scp_writer()`, whose `init()` resets only the name and the globals, so
  registrations made at import survive. Hooks reach the writer through the existing `get_scp_writer()`;
  no `get_scena()` is needed. Compiling checks that every function a hook names exists and warns when
  two hooks replace the same one. The exact signatures are decided in Step 10. Decorator shorthand and
  tree hooks stay with the HLIL DSL (`docs/FUTURE_WORK.md`, HLIL DSL: Hooks and Patching).
- **Clear errors for bad values** (item 12; Step 2b, done). `ScpValue(True)` failed with a bare
  `KeyError` (`bool` is not in its type map, `falcom/ed9/parser/types_scp.py`), and `POP(True)` compiled
  silently as `POP(1)`, since `bool` passes every `int` check. `ScpValue` now rejects any type it can't
  encode, `ScpWriter.handle_opcode` rejects a `bool` operand for every opcode (`PUSH_INT(True)`,
  `POP(True)`, `SYSCALL(True, ...)`), and `GLOBAL_VAR` rejects a `bool` type. `CALL` was annotated
  `func: str` but takes the function itself, so a hand edit that followed the annotation
  (`CALL('CheckSBreak')`) failed with an `AttributeError` and Pyright flagged every `CALL(...)` line. It
  is now `CALL(func: Callable)`, with an assertion that names the mistake.
- **`GLOBAL_VAR` and `label()` moved into `scp_writer_helper.py`** (item 13; Step 2b, done), next to
  `genLabel()`: they are DSL statements that emit no instruction. `GLOBAL_VAR` was the only non-opcode in
  the opcode handler, and `label()` sat at the end of `scp_writer.py`. No output change.
- **Validate `debug_argc` keys** (found in Step 5's review, not planned). A key that names no return
  label of the function's calls is silently ignored, so the call's debug record keeps all its arguments:
  renaming a return label by hand quietly changes the debug-record bytes (not the game logic).
  `buildDebugRecords` could check that every key is the return label of one of the function's calls.
- **Simpler Integer decode** (found in Step 5's review, not planned). `ScpValue.from_value` sign-extends
  an Integer by shifting through `0xC0000000`/`0x80000000` and a bytes round trip; with Step 5's
  `INTEGER_MAX` it is `value &= PAYLOAD_MASK`, then `value -= 1 << TYPE_SHIFT` past `INTEGER_MAX` (same
  value on 316,385 words checked, including every boundary). It changes the parser's decode path, so it
  needs a decompile dump to land.

## Listings and Docstrings

- **`.llil.asm` floats** (item 20; Step 4, done): the shortest value, spelled as in the `.py` and `.ts` so
  one search finds a value in all three, plus an always-on comment with the bits:
  ```
    STACK[sp] = 27.2 ; [5] f32 0x41D99998, raw 0x90766666
  ```
  The value used to print with 6 fixed decimals: `27.199997`, and any float below 0.0000005 as `0`, which
  looked like an integer.
- **`.llil.asm` strings** (item 12; Step 2b, done) were printed in single quotes without escaping
  (`'Thunder God's Descent'`, raw backslashes, a raw newline splitting the line). They now go through
  `quote_string(value, "'")`.
- **Docstrings** (item 12; Step 2b, done) in `falcom/ed9/writer/scp_writer_opcode_handler.py`, checked
  against the LLIL builder and lifter: `LOAD_STACK` said parameter offsets are frame-relative, but the
  encoding is always sp-relative (`stack[sp + offset // WORD_SIZE]`); `POP_TO` and `POP_TO_DEREF` take sp
  after their pop; `RETURN` claimed to set `REG[0]`, but it only needs an empty stack (the script sets
  `REG[0]` with `SET_REG(0)`); `LOAD_STACK_DEREF`, `SYSCALL` (reads its arguments without popping) and
  `JMP` were vague. `tools/ir_semantic_validator.py`'s example variable name `"arg0"` is now `"arg1"`,
  since parameters are numbered from `arg1`.
- **A readable `.dat` listing** (item 15; Steps 8b, 8c). Today's `.debug.txt` prints the header, each
  function's table entry and its debug records, with no code, so a record can't be matched to its call.
  Extend it into a read-only listing of the whole file as the VM sees it, with one opt-in
  `ScenaDecompileConfig` flag per section, replacing `write_debug_info`: header, global variables,
  function entries, code, call records and string pool. The code section shows each instruction's
  offset, raw bytes, real opcode and operands as encoded, with the symbolic meaning as a comment; every
  push pseudo-op (`PUSH_INT`, `PUSH_RET_ADDR`, ...) prints as the real `PUSH`:
  ```
  0x03416  00 04 00 00 00 00    PUSH 4, Raw(0x0)           ; func id: CheckAlgoUse
  0x0341C  00 04 2f 34 00 00    PUSH 4, Raw(0x342F)        ; return address -> loc_342F
  0x03422  02 f0 ff ff ff       LOAD_STACK -16             ; slot 1 = arg2
  0x0342C  0c 01 00             CALL 1                     ; CheckSBreak
                                                           ;   record 0: Local CheckSBreak(Variable, Variable)
  ```
  A call's debug record is printed under it only where a per-pair content check confirms the pairing
  (`notes/debug_records_handoff.md`); otherwise the function notes `records not paired`. The string pool
  lists each string's section (code, names, defaults, debug-only, global names); the section split moves
  from the round-trip validator into `falcom/` first (Step 8b).

## Not Doing

Decided against on 2026-10-01 (reasons in the handoff):

- A one-line call form, names in place of stack offsets, and lossy rounded floats: they move away from
  the stack view. The shortest floats above encode to the same word, so they are not rounded.
- A raw-opcode mode for the `.py`. `PUSH_INT`, `PUSH_FLOAT`, `PUSH_STR` and `PUSH_RAW` are spellings of
  `PUSH` that show the value's type tag, and `PUSH_CURRENT_FUNC_ID`, `PUSH_RET_ADDR` and `CALL(f)` are
  references the writer resolves, like a label in an assembler; raw numbers would only be valid for an
  unedited byte-exact recompile. The `.debug.txt` code section gives the opcode view instead.
- Hex float operands, and hex in the HLIL DSL.
- A writer-side stack walker (see the re-lifting check above).
- 0-based `arg0..` parameter names: every layer names parameters from `arg1`, as Binary Ninja, IDA and
  Ghidra do.
- `# fmt: off`, a `run_script` helper, and `# pyright: ignore[reportMissingImports]` on the hook import.
- A single-import module for the generated header: it saves one line. Revisit with the HLIL DSL, whose
  scripts need more imports.
- A hand-editing section in `docs/LLIL_DSL.md`, for now; the handoff keeps a draft of its contents.
- A provenance comment at the top of each script naming its source and the `round_trip` /
  `keep_unreachable_code` flags (item 17; user, 2026-10-02, after it was implemented in Step 2a): everyday
  scripts always use the same flags, fidelity output is recognizable without it (no library manifest,
  unreachable code kept), and it adds lines to every file.

Known and left as is: `common_all.py`'s own `except ModuleNotFoundError` swallows a failed import inside
a library module, the way the hook import did before Step 2a; `ScpValue` quiets signaling-NaN float words
(none in the corpus).
