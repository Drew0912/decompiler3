# Future Work: LLIL

> Ideas for the LLIL layer (the LLIL DSL `.py`, the writer and the `.llil.asm` listing) from a
> 2026-09-30 review of the decompiled output. Nothing here is started. HLIL-level ideas from the same
> review, including the HLIL DSL, are in `docs/FUTURE_WORK.md` (HLIL). As there, each entry links back
> to the doc or code it extends.

## LLIL DSL (`docs/LLIL_DSL.md`)

The LLIL DSL is the exact, recompilable stack view. It is used mostly for debugging and analysis and
is easier to read than the `.llil.asm`, but it can still be edited. Keep it close to the stack: one
opcode per line, arguments in push order, byte offsets, exact float32 values. The ideas below add
information without changing any operand.

- **Stack-slot comments.** The same variable gets a different offset as the stack moves:
  `LOAD_STACK(-16)` is `arg2` at `CheckAlgoUse`'s source line 162 and `arg3` at line 168. Annotate the
  stack state the way the `.llil.asm` shows it, as comments: `# sp = N` at each label, and the absolute
  slot and variable on each offset-based op. The parser already simulates the stack, so the numbers
  exist.
  ```python
  LOAD_STACK(-16)                # slot 1 = arg2
  PUSH_RAW(RawInt(0x00000000))   # local slot 3
  POP(20)                        # 5 slots
  ```
- **Provenance header:** the source file, the commit, the `round_trip`/`keep_unreachable_code` flags
  and the float precision the file was generated with, and what the `<stem>_hook` import is for.
- **Per-function comment** with the function's table index and offset, as decompiler2's output had
  (`# id: 0x0000 offset: 0x12FC`).
- **A short hand-editing section** in `docs/LLIL_DSL.md`: arguments are pushed last-first; `POP(n)`
  counts bytes; locals are reserved by a push (usually `PUSH_RAW(RawInt(0))`) and freed by the `POP(n)`
  before `RETURN`; labels must be unique, and `genLabel()` makes one; syscalls have no names beyond the
  wrapper functions the scripts themselves define.
- **Keep** the `def _loc_X(): pass` stubs (they make labels symbols in an editor's outline) and the
  blank and spacer lines that mark blocks. The spacer after each label is four spaces rather than an
  empty line, so editors that trim trailing whitespace change it: harmless for compiling, noisy in
  diffs.
- **Not wanted,** because they move away from the stack view: a one-line call form, names in place of
  stack offsets, rounded floats.
- **Debugging dumps** can use fidelity mode (`round_trip=True, keep_unreachable_code=True`), which keeps
  library functions and unreachable code inline.

## Writer (`falcom/ed9/writer/`)

- **Catch stack mistakes.** Compiling a `.py` checks operand counts and types (the asserts in each
  opcode function and in `handle_opcode`) and labels, but nothing tracks the stack or checks argument
  counts (`_get_param_count` only feeds debug records). A wrong `POP(n)`, a missing push or an extra
  argument compiles into a `.dat`, and only decompiling that `.dat` again notices: the parser's stack
  simulation (`ScpParser.on_instruction_decoded`) raises with the function and the bytecode offset. The
  round-trip validator does that for generated files; a hand edit gets no check. Build the check on
  the writer's opcode calls, not on the compiled bytes: `EmitLLIL` lists (`docs/FUTURE_WORK.md`, HLIL
  DSL: Mixing LLIL and HLIL) must be checked before anything is written and refer to variables by
  name, jump targets are only written at the end of `run2`, and errors can name the function and the
  `.py` line.
  - **Effect table:** per opcode, the slots popped and pushed, worked out from the operands (`POP(n)`
    pops `n / WORD_SIZE`, `DEBUG_LOG(argc)` pops `argc`, `CALL` the callee's parameter count plus the
    2 call-setup slots, `CALL_SCRIPT` its `argc` plus the 5 caller-frame slots), and whether it falls
    through, jumps or stops. The parser keeps this as opcode groups (`PUSH_VARIANTS`, `BINARY_OPS`, …)
    and an `if` chain; one table used by both is the shared stack model (`docs/FUTURE_WORK.md`, HLIL
    DSL: Recompile Path).
  - **Walker:** follows fall-through and jumps from a starting depth, records the depth at each label
    and reports the first mismatch. Like the parser, it tracks which opcode pushed each slot, so an
    extra argument fails at its `CALL` (the slots under the arguments are not the two setup pushes)
    rather than at `RETURN`. Unreachable code is skipped; the parser does not simulate it either.
  - **LLIL functions** are checked after each body runs in `compileFunctions`, which needs each
    function's opcodes and labels in order (today there is one file-wide `self.calls` list, without
    labels): start at the parameter count, never go below 0, `RETURN` only at 0, and no offset reaches
    below the bottom of the stack. Lowered HLIL functions and hook callbacks go through the same
    `handle_opcode`, so this also covers lowered HLIL code, `EmitLLIL` contents and patches.
  - **`EmitLLIL` lists** use the same walker: start at the HLIL compiler's depth at that statement and
    never go below it; end there or in a `JMP`, with no `RETURN` or tail call; numeric offsets reach
    only slots the list pushed, and names cover the rest. This check points the error at the list
    itself.
  - **Limits:** at LLIL level, an offset inside the stack but on the wrong variable stays invisible,
    since nothing says which variable was meant. Re-lifting (decompiling the compiled output again)
    stays as a test-time check, since it also catches encoding bugs a check of the source can't see.
    Every generated `.py` should pass unchanged, since the parser accepted the same bytecode; one full
    round-trip run confirms it.
- **Hook callbacks.** Every generated script imports `<stem>_hook`, but the writer has nothing for it
  to register with; only a commented-out loop remains in `ScpWriter.run`. Restore decompiler2's
  `registerFuncCallback` (replace a function by name at registration), `registerRunCallback` (add
  functions before compiling) and `registerOpCodeCallback` (intercept emitted opcodes). Create the
  lists in `__init__`: `create_scp_writer()` calls `init()`, which resets only the name and the globals,
  so a hook imported at the top of a script keeps its registrations. Add a public accessor
  (`get_scena()`), and check at the end of compiling that every function a hook named exists. The
  callbacks work for today's LLIL DSL scripts as soon as they exist; decorator shorthand and tree hooks
  build on them (`docs/FUTURE_WORK.md`, HLIL DSL: Hooks and Patching).
- **Per-function label namespaces.** Labels are one file-wide namespace (`add_label`). Generated names
  are unique (addresses or `genLabel()` uuids), but hand-written names would collide across functions.
- **Error context.** A failure should name the function and the DSL call; an undefined label is a bare
  `KeyError` today.
- **In-memory compile.** `run2` always writes the output file; exactness checks want the bytes in
  memory.
- **Clear errors for bad values.** `ScpValue(True)` fails with a bare `KeyError`, because `bool` is not
  in its type map (`falcom/ed9/parser/types_scp.py`).

## Listings and Docstrings

- **`.llil.asm` strings** are printed in single quotes without escaping (`'Thunder God's Descent'`, raw
  backslashes). Harmless for a debug listing, but anything that parses it breaks.
- **`LOAD_STACK`'s docstring** (`falcom/ed9/writer/scp_writer_opcode_handler.py`) says parameter
  offsets are frame-relative; the encoding is always stack-pointer-relative.
