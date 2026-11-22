# HLIL DSL

> Status: design; started: the function stubs (Calls), the compile side of straight-line HLIL bodies, `If` and
> `While` (`@scena.HLILCode()`, Form: Implemented) and their printer with the exact check (the default `<stem>.py`,
> Recompile Path: Fallback and File names) are implemented; `Switch`, short-circuit tests and the rest are planned.
> Overview and decisions: `docs/dsl/DSL_FUTURE_WORK.md`, Recompilation Pipeline §1; its hooks: `docs/dsl/HOOKS.md`.

## HLIL DSL: Recompile Path

- **Lower into the LLIL DSL.** HLIL lowers into the LLIL DSL's opcode API and `ScpWriter` writes the
  file; it already owns operand encoding, labels, the function table, the string pool, globals, debug
  records and library linking. No second bytecode emitter and no MLIL DSL. Lower in-process;
  optionally dump the lowered stream as LLIL DSL text for debugging.
- **Exactness first.** The primary check is that an unedited function recompiles to its original
  opcodes (the per-function fingerprint, ignoring line markers); the logic check (`tools/logic_check/`;
  `docs/FUTURE_WORK.md`, Static Game-Logic Check) covers the rest. Measure the exact-match rate.
- **Stack checks.** The lowering tracks the stack pointer itself; re-lifting the compiled output with
  the LLIL lifter checks stack discipline - the writer's compile check does this at the end of every
  `build()` (`ScpWriter.check_compiled`, `docs/dsl/LLIL_DSL.md` §1), so lowered functions get it too. Its
  `.py` lines come from walking up to the frame running the body, which only works while the body
  emits opcodes: an HLIL body has returned before its tree is lowered, so the lowering sets the writer's
  source site from each node's recorded site (`ScpWriter.lowering_site`), else every error would fall back to the
  `def`.
  A syscall lowers its argc and the `POP` right after it from one count: the compile check warns when they
  differ. A pop of more than 255 bytes (`POP`'s operand is one byte) lowers as the compiler's does: `POP(255)`, then
  a `POP` of the rest right after it (`docs/falcom/ed9/ED9_VM.md`, Stack and slots).
- **What HLIL must keep for exact recompiles:** raw vs typed constants (kept: past LLIL's `is_raw`, a
  Raw constant stays a `RawInt` through MLIL and HLIL, and prints as its number, not as `RawInt(...)` (in hex
  beside a bitwise operation's value, as an Integer does); no pass folds it, and a
  Raw and an Integer constant never merge, since `constant_values_equal` compares types); which
  jump opcode was used (a "true arm is the fall-through" bit); block-scoped locals,
  including never-read ones and unused stores; stack temporaries rather than named locals; `reg0` as a
  register; constant expressions unfolded (`1 | 32768`; kept since 2026-10-27, no pass folds); bare truth tests
  vs `!= 0`; eager vs
  short-circuit logic; a tail-call node; the compiler's switch pattern; a NaN's word (the IR keeps its bits but
  prints every NaN `nan`, as the lifter spells finite floats only: printed `FloatWord(0x..)`, as the LLIL DSL does).
  Loop rotation, switch recovery,
  return hoisting and region cloning are not worth inverting; the logic check covers those functions.
- **Shared stack model.** The lowering reads the opcode table's stack effects
  (`falcom/ed9/assembler/stack_effects.py`), which the parser and the debug-record tracker already share and
  the lifter is tested against, and is designed as a pair with the rewrite's translator.
- **Two layers.** Structured statements lower to labels and jumps; the bottom layer lowers expressions,
  assignments, calls, labels and jumps. The bottom layer can compile the rewrite's MLIL directly: a
  round-trip test that isolates translator bugs from structuring bugs.
- **Small blockers:** `CALL` resolves functions by their Python `__name__`; a `CALL`'s `debug_argc` (a
  record keeping more args than the compiler's rule) has no HLIL form, so such a call gets the rule's record
  (debug records only); `HLILSyscall.subsystem`/`cmd` are annotated `str`.

## HLIL DSL: Form

Executed Python in the style of decompiler2's ED8.x output: every statement is a call that builds a
node, and blocks are Python lists. Chosen over `with` blocks, def/lambda bodies, decorator blocks,
begin/end markers, parsing native Python syntax, and `Block(...)` objects. `CheckSBreak`, traced
against its original opcodes, lowers to exactly them:

```python
@scena.HLILCode()
def CheckSBreak(arg1: Value32, arg2: Nullable32 = 2):
    var_s2 = Local('var_s2')
    var_s3 = Local('var_s3')
    If(arg1 == 3, [
        Let(var_s2, chr_info(65534, 0)),
        If(btl_check_condition(var_s2, 26, 0), [
            If(btl_get_chr_info(var_s2, 18), [
                Return(0),
            ]),
            Let(var_s3, 0),
            btl_chr_list_init(var_s2, Int(1) | 32768),
            While(btl_chr_list_get_remain(var_s2) > 0, [
                Set(var_s3, var_s3 + 1),
                btl_chr_list_next(var_s2),
            ]),
            If(var_s3 == 0, [
                Return(0),
            ]),
            If(chr_info(var_s2, 35), [
                Return(0),
            ]),
            If(btl_get_sys_info(4) != var_s2, [
                Return(1),
            ]),
            If(btl_get_condition_remain_turn(var_s2, 26) == arg2 - 1, [
                Return(1),
            ]),
        ]),
    ])
    Return(0)
```

- **Implemented (straight-line bodies, `If` and `While`):** `@scena.HLILCode()` compiles a body of these
  statements: a call (`f(...)`, `script.<module>.f(...)`, `Syscall(subsystem, cmd, ...)`), `Set(target, value)` (a
  parameter, a local, `this.x`, `REGS[n]`), `Let(x)` and `Let(x, value)`, `Return(value)` and `Return()`,
  `PopN(...)`, `DebugInt(n)`, `If(condition, [...])` with `.ElseIf(condition, [...])` arms and a last `.Else([...])`,
  each method returning the `If`, so a chain is one statement, `While(condition, [...])`, and `Break()` /
  `Continue()` in a `While`'s block; values are literals, `Int` / `Float` / `Str` / `Raw`, parameters, locals,
  `this.x`, `REGS[n]`, a call's result, `+ - * / % == != < <= > >= & |`, `-x`, `~x`, `And` / `Or` / `Not`. An arm
  runs when its condition is not 0: it lowers to the condition, `POP_JMP_ZERO` past the arm, the block, and a `JMP`
  to the `If`'s end unless the block ends its path or no arm follows. A `While` lowers to its head's label, the
  condition, `POP_JMP_ZERO` past the loop, the block, and a `JMP` back to the head unless the block ends its path;
  `Break()` jumps past the innermost loop and `Continue()` to its head, each after popping the locals of the blocks
  it leaves (Jumps, below). A block is a Python list of statements and calls, each in one block, a list inside it
  opened in place (a function's returned list, with or without `*`, a macro's statements) and a `None` skipped (a
  function returning nothing);
  a statement ends its path when it is a `Return`, a `Break`, a `Continue`, or an `If` with an `.Else` whose every
  block ends its path; a `While` never does (its test can be 0, `While(1)`'s too, so the code after a loop needs its
  own `Return`); a statement after one that ends its path raises at its line, and so do an exit outside a `While`
  and a body that does not end its path (a body can end in such an `If`). A mixed script gets these names from its
  game's `scp_hlil_dsl_helper` (`falcom/ed9/games/<game>/writer/`, which star-imports the shared
  `falcom/ed9/writer/scp_hlil_dsl_helper.py` and holds the game's own DSL helpers). The body runs once, with a
  parameter node per parameter, under a build of its own; its statements are checked, then lowered through the
  opcode functions (`falcom/ed9/writer/hlil_dsl/`: `nodes.py`, `calls.py`, `control.py`, `macro_statements.py`,
  `build.py`, `tree.py`, `lowering.py`, `llil_sink.py`, `source_check.py`), so the call tracker, the opcode callbacks
  and the compile check see each opcode as an LLIL body's, at the line of the node it came from. The nodes, the
  build, its checks and the source check are VM-neutral: an operation is keyed by HLIL's own operator
  (`ir/core/operators.py`), a constant by its value's type, and they import nothing from `falcom/ed9/`; the ED9-only
  nodes (`Raw`, `REGS`, `Syscall`, `PopN`, `DebugInt`) are in `ed9_nodes.py`, and the lowering turns the rest into
  ED9's opcodes (an operator ED9 lacks, `^`, `<<` or `>>`, raises at its line). A helper function builds its
  caller's statements, in order, each time it runs: a statement it kept from an earlier run (a cache) is another
  body's and is not lowered again. A value kept between functions goes in a global (`Set(this.target, arg1)`), never
  a Python variable: a parameter or a call from another function's body raises where it is used. Lowered labels are
  named for the function compiling (`AniFall:0`, ...).

- **Ownership:** every node registers when it is created, and a parent (`If`, `While`, `Set`, a call's
  arguments) claims what is passed to it; unclaimed statements are the function's top level, in order.
  The code runs units in turn - a statement with everything it claims, an `If`'s or a `While`'s each condition and
  then its block's units (`tree.py`, `units_in_code_order`) - and each unit must be one unbroken run of creation
  order, the runs in that order. So a node kept in a Python variable and used later (which would move a call), a
  block a helper makes before its condition, a statement made between an `If`'s arms (`chain = If(...)`, a
  statement, `chain.Else(...)`: no code runs there; an `If` takes arms only until a block holds it), a block's list
  changed after its `If` or `While` took it (it holds the list as it was), a node claimed twice, and an unclaimed
  non-statement (`arg1 = arg1 + 1`) all raise; operands within one unit may be made in any order (`And(a, b, c)`
  makes its operands before its operations). Build each function in isolation, validate it, then lower it; record
  each node's file and line for error messages.
- **Macros** (`macro_statements.py`): Python gives the place a function is called only what the function returns, so
  a function whose statements should go where it is called is marked `@macro`. A macro's own statements (those it
  makes and nothing holds when it returns) go with its call's value, wherever that value goes: a block's list
  holding it (also through the script's own wrappers, a function's Python variable, `functools.partial`, `map` or
  `starmap`; a body keeps no call in a variable),
  the statement using the value (they run just before it), a `While`'s or an `.ElseIf`'s condition (before each
  test of it; a `Continue` re-runs them), an `If`'s first condition (before the `If`, as on the line above). A
  macro returning nothing returns its statements (a list a block opens in place, which Python can't truth-test: an
  `or`, `and`, `not` or `if` on it raises); one returning a list returns it with its statements merged in, in the
  order made; a statement or a computed value comes back with its statements leading it; a leaf (a parameter, a
  local, `this.x`, `REGS[n]`, a constant) comes back carrying them, used once (twice raises). `@macro` on a generator
  raises (its body runs after its call returns). So the creation-order rule above sees an arm's statements made
  before its test, then its condition, then its block. Refused, each at its line: a macro's statements for an
  operand after one the same expression reads first (`Set(REGS[4], REGS[3] + set_then(REGS[3], REGS[5]))`: they
  would run before that read; with the macro first they compile, in Python's order; a constant, or an operation on
  constants only, is no read), a condition macro making its value before its own statement (the statement runs before
  the test), a condition macro whose statement ends its path before the test, and a macro returning a Python number
  or tuple after making statements, inside an expression.
- **Where a statement stands:** a statement no block holds stands where it was made only when no call on the way
  from its making up to the body put its value inside a larger expression, read from each calling frame's next
  bytecode instruction (dropped, returned or kept in a plain variable; one it doesn't know refuses). So an unmarked
  function works on a line of its own (also `x = f()` in a function, `return f()`, with keywords or a star), and a
  wrapper returning what it makes works anywhere (`def when(c, block): return If(c, block)`); an unmarked function
  making statements it does not return, called inside an expression (a block's list, a condition, an operand,
  through a wrapper or a star), raises, naming `@macro`; so do a statement written inside an expression nothing takes
  (`[Set(REGS[n], 0) for n in (1, 2)]` as a line: write a `for` loop; `(Set(...), Set(...))[1]`), an unmarked
  function's value stored on an attribute or an item, unpacked, kept in two variables, or abandoned by a caught
  exception (in a function, assign it to one plain variable first), and a generator's statements anywhere but
  yielded into a block's list (its body runs as it is iterated: make it a function returning a list). The decompile's
  exact check builds without the frames (its printed bodies have every statement as a list element and no macros).
- **Locals:** `Let` declares (where the source's declaring push is) and `Set` assigns. One `x = Local('x')`
  line per local names it; `Set` on an undeclared local, a read before its `Let` and a second `Let` of a live one (an
  outer block's too) raise. The end of a block frees the locals declared in it (its `POP`, before the label the jump
  past the arm goes to; none on a path that ended), and a read or `Set` after it raises; a later block may declare the
  name again. The compiler pops locals only at a block's end, so a lifetime that is no block has no source and no
  form. A `Let` a condition's macro makes lives through its arm: a `While`'s for one pass (pushed at the head,
  popped before the jump back, on the way out and by a `Break` or a `Continue`), an `.ElseIf`'s through that arm's
  test and block (popped on both paths, at one `POP` when no arm follows). Script globals are `this.x`.
- **Calls:** `f()` is a `CALL` by table index, `script.<module>.f()` a `CALL_SCRIPT` (`script['']` for
  the empty module name the bytecode also uses), `TailCall(...)` the tail-call sequence. Generated
  scripts star-import the shared library, whose functions are LLIL bodies that emit opcodes when
  called, so a bare call must never run one. Wrap each library function in a stub
  (`@library_function`): the body is unchanged, and the one name builds a call node in an HLIL body,
  still works as `CALL(f)` in LLIL code (it keeps `__name__`), and tells the writer to compile the body
  when listed in `@scena.CommonImports()` (`functools.update_wrapper` keeps the writer's signature
  handling working). The script's own decorators return stubs too. While an HLIL body is being built,
  an opcode call only builds a node that `EmitLLIL` must claim (Mixing LLIL and HLIL, below), so a
  leftover raw body fails loudly. **Implemented:** the stubs (`falcom/ed9/writer/hlil_dsl/stubs.py`), the
  generator's `@library_function` line above each library `def`, and the decorators returning stubs; registration
  and a function callback's return value see through a stub to its body. In an HLIL body a stub builds a call node,
  its arguments by position and exactly the callee's parameter count, defaults included (a local `CALL` ignores
  defaults, `docs/falcom/ed9/ED9_VM.md`, Calls); `script.<module>.f(...)` passes what is written (the engine fills a
  script call's trailing defaults). Anywhere else a bare call raises at its line: `AdjustSpeed(...) builds an HLIL
  call; in an LLIL body write CALL(AdjustSpeed)`. Until `EmitLLIL` exists, an opcode function in an HLIL body raises,
  and so does a library body from before `@library_function` (regenerate the library).
- **Jumps:** `JumpIfFalse`/`JumpIfTrue` (`POP_JMP_ZERO`/`POP_JMP_NOT_ZERO`), `Label` and `Jump` mix with
  blocks in one function: structure what is clean, jump elsewhere. Labels are per function and named by
  order, not address. A jump must arrive with the same live locals: `Break`/`Continue` pop the locals of each block
  they leave, a `POP` per block from the loop's own block inwards, as the compiler does (`mon5219_c10`
  `AniFieldSwarmAttack`: `POP(8); POP(4); JMP` for two locals of the loop's block and one of an `If`'s inside it).
- **Switch:** `Switch(value, [Case(k, [...]), ...], default=[...])` lowers to the compiler's own
  pattern: `SET_REG 0`; per case `GET_REG 0; PUSH_INT k; EQ; POP_JMP_NOT_ZERO`; a jump past the cases;
  the bodies in order, each ending in a jump to the end. A list rather than a dict keeps `1` and `1.0`
  apart.
- **Operators:** `And`/`Or`/`Not` are the VM's eager `LOGICAL_AND`/`LOGICAL_OR`/`EZ` and may contain
  calls, so eager chains print flat; `~` is bitwise `NOT`; `x == 0` is a real comparison; `/` is `DIV`
  and `%` is `MOD`; operators the VM lacks raise; a bare value as a condition emits no comparison.
  `AndThen`/`OrElse` are short-circuit logic recovered from jumps, allowed only in conditions and
  lowered to jumps. Two VM rules to keep in mind (`docs/falcom/ed9/ED9_VM.md`, Truth): `Not` on a non-Integer
  leaves the value, so `Not(f)` on a Float tests `f`, not its negation; and `And`/`Or` take a Float as true when it
  is not `0.0`, while a jump truncates it first (0.5 is true in `And`, false as a condition). Operands evaluate
  left to right, call arguments right to left (last pushed first); warn when an edit puts two calls in one argument
  list.
- **Other statements:** `Return(n)` computes its `POP` from the live locals and parameters; `Return()`
  is the raw-zero return. Out-parameters are `Ref(x)` (`PUSH_STACK_OFFSET`), `Deref(p)` and
  `Set(Deref(p), value)`, only on `Pointer` parameters. `Syscall(subsystem, cmd, ...)` covers unnamed
  syscalls, and `EmitLLIL(...)` places LLIL opcodes for a region no HLIL node expresses (Mixing LLIL
  and HLIL, below). `do … while` and a labelled `break` / `continue` (one leaving an outer loop) have no form: a
  function holding one stays LLIL (`do-while`, `labelled loop`); `sora2`'s census has one do-while and no labelled
  exit.
- **Python traps:**
  - a missing comma before a line starting with `[` or `(` parses as a subscript or a call, so nodes'
    `__getitem__` and `__call__` raise "missing comma?";
  - defining `__eq__` makes nodes unhashable, so the registry keys by `id()`; forbid
    `__int__`/`__float__`/`__index__`;
  - reject Python `bool` and `None` (`ScpValue(True)` fails with a bare `KeyError` today);
  - print with Python's operator precedence, not C's (`a == b & c` is `a == (b & c)`), and make chained
    comparisons raise;
  - Python folds an operation between two literals before the DSL sees it (`1 | 32768`, `7 / 2`), so
    the printer wraps one side (`Int(1) | 32768`). In a hand edit Python's result stands (`8 | 16` is 24), but `/`
    and `%` between two literals raise, as Python's rules for them are not the VM's (its `/` gives a Float and its
    `%` floors; `DIV` and `MOD` truncate): write `Int(7) / 2` for the VM's operation, or the value;
  - a node's `__str__` and `__format__` raise: text is fixed when the script compiles, so `f'HP {arg1}'` can't hold a
    game value (pass the value as an argument of its own);
  - `this.x = ...` and `REGS[n] = ...` set nothing in the game and raise: `Set(this.x, value)`;
  - keep `1` and `1.0` distinct, and emit `# fmt: off` so formatters don't reflow the lists;
  - a body ends its path (`Return(...)`, or an `If` whose every arm, `.Else` included, ends with one; a body ending
    in a `While` raises, naming why), and `return Return(...)` is the one Python `return` it takes;
  - a block is a list, never a tuple (`(foo(1))` without its comma is no tuple; a tuple inside one raises); an element
    that is a value raises at its line (a missing comma joining two lines into one value), any other at its arm's
    (`If(...)`, `.ElseIf(...)`, `.Else(...)` or `While(...)`), `Break` without its call naming `Break()`; `If`, its
    arms and `While` take their arguments by position, and a third one (C's else, a loop else) raises, naming
    `.Else([...])` or that the DSL has no loop else; `.Else` on a `While` is Python's `AttributeError`, at its line in
    the traceback;
  - a function called inside an `If(...)` or `While(...)` call's arguments makes its own statements before Python
    makes the call, and gives the call only what it returns: mark it `@macro` and its statements go with what it
    returns (Ownership, macros); unmarked, it raises, naming `@macro`, unless called on a line of its own (where a
    statement stands); a macro's value read in Python (`or`, `and`, `not`, `if`) raises, and so do `@macro` on a
    generator and `@macro` above `@classmethod` (put it right above the `def`); in C a macro's argument used twice runs twice, here Python runs it once and a computed one used twice
    raises (claimed twice: keep it with `Let`);
  - **the source check** (implemented: `falcom/ed9/writer/hlil_dsl/source_check.py`) reads each HLIL body's own
    source before it runs and raises at the line of a Python variable given a value holding a call (`a = f()`: the
    call would run where `a` is used, after the arguments to its right; write `Let(a, f())`), any binding of a
    parameter's or a local's name (`arg1 = 5`, `for arg1 in ...`, `with ... as arg1`: each rebinds the Python name;
    write `Set(arg1, 5)`), `is` / `is not` on a parameter or a local (Python's identity; the VM has no None), any
    other `return`, and `/` or `%` between two literals. It also reads each helper the body runs (when the helper
    makes a node) and each `functools.wraps` wrapper over the body, for a call of the DSL's kept in a variable (a
    stub, `Syscall`, `script....`, looked up in the helper's globals: `n = len(x)` is the helper's own business) and
    for `/` or `%` between two literals; the body under its wrappers by the body's rules;
  - a DSL error the body catches (`try` / `except`) still ends the build: the build raises its first one after the
    body returns.
- **Line numbers:** none in the DSL, and none planned (user, 2026-10-05): hand edits wouldn't carry
  `DEBUG_SET_LINENO`, so an HLIL function compiles without it. That changes no game logic: the engine
  only prints the value, in three log messages (`docs/falcom/ed9/ED9_VM.md`, Opcodes and operands). It
  still gets its call-site debug records, which the engine reads (`docs/ROUND_TRIP_POLICY.md`, Records
  the engine reads): records don't depend on a line marker.
  Line-Anchored Patches (`docs/dsl/HOOKS.md`) then need an anchor that doesn't use line numbers.
- **Printer:** one statement per line, a trailing comma on every list item, comments allowed inside
  brackets; named pseudo-IDs, hex bit flags, the shortest float that encodes identically. An `if` prints
  `If(test, [`, its block one level in, then `]).ElseIf(test, [` for an else holding one `if` and nothing else,
  `]).Else([` for any other else, and `])`; an empty block is `[]`, even a one-statement block takes its lines. The
  test leaves out HLIL's outermost `!= 0` against a plain 0, the jump's own test (`If(menu_is_canceled(0), [`). An
  outermost `== 0` is the jump's test negated: an else-less one prints `If(E, []).Else([...])`, the code's empty arm
  that HLIL dropped (where the code jumps if not zero instead, the exact check refuses it), and one with an else stays
  LLIL (`negated test`). A `while` prints `While(test, [`, its block, `])`, its test as an `if`'s (a top-level
  `== 0`: `negated test`), and a `break` / `continue` `Break()` / `Continue()` where the HLIL has one (in an arm,
  `.Else([..., Continue()])`; leaving out a trailing one keeps the code only under conditions the later tidying must
  check). Which constants name an
  ID is decided in HLIL (`HLILConst.id_kind`, set by `ED9TypeInferencePass`: at an ID slot, and compared with,
  labelling or assigned to a variable that holds an ID), so this printer reads the same tags `.ts` does. Still to
  do for it: reading `id_kind` with the game's table (`game_format_hints`), `ChrIdTable` / `PseudoChrId` in the
  script namespace so a name lowers to its number, and the file-level pass run when the DSL is written (today only
  for `.ts`: `need_file_passes` in `scp2py_base.py`).
- **Python limits:** nesting stops at 99 levels (200 nested brackets; `with`/`if` hit the same limit
  through indentation), and very long method chains overflow the compiler (an `.ElseIf` chain of 3,000
  arms compiles on Python 3.14, 10,000 does not). The exact check compiles each function's text, so one past
  these limits stays LLIL (`sora2`'s census nests blocks 3 deep at most, its longest chain 28 arms); tree walkers
  should be iterative.
- **Tooling:** generated `.pyi` stubs and explicit imports; keyword arguments for wide calls once the knowledge DB
  (`docs/dsl/DSL_FUTURE_WORK.md`, Recompilation Pipeline §3) names parameters; one syscall naming table used by both the
  printers and the writer (the raw ED9 syscalls have no name anywhere in the game data).

## HLIL DSL: Mixing LLIL and HLIL

One `.py` can hold functions at both levels: `@scena.HLILCode()` and `@scena.HLILCommonCode()` beside
today's `@scena.LLILCode()` and `@scena.LLILCommonCode()`. The decompiler prints HLIL and keeps a
function at LLIL level only when it has to.

- **One writer run, no link phase.** `ScpWriter.build` builds the function table from every registered function before
  it runs any body, then runs the bodies in file order into one code buffer; labels, strings and globals are
  writer-wide. An HLIL function lowers in place, at its turn, so `CALL` and `PUSH_CURRENT_FUNC_ID` resolve across levels
  without the link phase `docs/dsl/DSL_FUTURE_WORK.md` Recompilation Pipeline §2 expected. HLIL labels are per function
  (Form), so the lowering prefixes them (the writer's labels stay file-wide by decision, `docs/dsl/DSL_FUTURE_WORK.md`,
  Writer).
- **HLIL functions** register like LLIL ones (parameters, flags and defaults from the signature). At
  its turn the body runs with parameter nodes to build the tree, which is validated, passed to the tree
  hooks and lowered onto the writer. Both kinds of decorator return stubs, so the levels call each
  other by name: `f()` in HLIL, `CALL(f)` in LLIL.
- **`EmitLLIL`** places LLIL opcodes in an HLIL body, for an opcode no HLIL node expresses or a patch
  that needs exact opcodes. It takes one opcode or a list, like the other blocks. The list holds opcode
  calls and `label('x')` items (the `def _x(): pass` line can't sit in a list), and is emitted in order
  where it stands, never folded, reordered or dropped. While an HLIL body is built, `handle_opcode`
  (which every opcode function calls) and `label()` return nodes instead of writing, and only
  `EmitLLIL` may claim them. Chosen over `ExactLLIL`, since "exact" already names the exact recompile
  check.
- **Stack contract.** The HLIL compiler owns the stack layout and addresses every parameter and local
  from it, so a list that disturbs it compiles silently into reads and writes of the wrong slots, a
  `RETURN` that pops the wrong frame, or a loop that grows the stack each pass. A list therefore:
  - pops only what it pushed, and ends at the depth it started at or in a `JMP`;
  - reaches parameters and locals only by name (`LOAD_STACK(v.var_s5)`), with the offset worked out at
    that item, counting the list's earlier pushes. Numeric offsets reach only values the list pushed.
    The five stack-offset opcodes (`LOAD_STACK`, `LOAD_STACK_DEREF`, `PUSH_STACK_OFFSET`, `POP_TO`,
    `POP_TO_DEREF`) accept a name as well as a number;
  - holds no `RETURN` or tail call, whose `POP` needs the frame size only the compiler knows; `Return`
    and `TailCall` follow the list instead;
  - jumps only where depths agree: the depth at a label equals the depth at every jump to it, across
    the list's edge too.
- **Checked when built.** The lowering checks each list with the shared stack model (Recompile Path),
  and its errors name the variable to use ("`LOAD_STACK(-8)` here is `v.var_s5`"). Re-lifting the
  output would catch an imbalance, but not a numeric offset that lands on the wrong variable.
- **Fallback.** A function is printed with `@scena.LLILCode()` when structuring leaves an
  `HLILUnstructured` node, when it uses a construct the DSL has no form for, or, in an exact mode, when
  it does not compile back to its original opcodes. The decompiler runs that check while writing the
  file, so an exact-mode file recompiles exactly by construction. Implemented for straight-line bodies, `If` and
  `While` (`falcom/ed9/formatter/hlil_dsl/`): the function formatter (`function_formatter.py`) writes a function's
  text from its HLIL, the DSL's own (`hlil_for_dsl`, `falcom/ed9/ir/hlil/hlil_converter.py`: a function of one
  block keeps the shared tree, converted with its line markers kept whatever `line_markers` says; any other is
  structured as its code without the markers, with no return hoisting and each if's arms in the code's order,
  `docs/hlil/HLIL_DESIGN.md`), and
  `script_formatter.py` collects a script's functions and reasons; the exact check (`exact_check.py`) parses
  that text, runs the source check on it, runs it in a namespace of the DSL's names and a stub per
  function-table name, requires the one function it registers to be the source's, and lowers its tree into a
  list that must equal the source's code without its line markers (`body_fingerprint_without_line_markers`,
  `falcom/ed9/structs/fingerprint.py`). It loads neither the writer nor the library. Each function left
  LLIL is logged with its reason at DEBUG, each file with its counts at INFO
  (`brk_obj.dat: 3 of 8 functions as HLIL; LLIL: if 5`).
- **File names.** `<stem>.py` (`ScpDecompileConfig.write_py`, on by default) is the mixed file (`write_script`,
  `falcom/ed9/scp2py_base.py`); `<stem>.llil.py` (`write_llil_py`, off by default) is the pure LLIL listing, named
  like `.llil.asm`, with every common function inline (`write_listing_script`). `HLILScriptFormatter` and
  `LLILListingFormatter` print them, each a subclass of `LLILScriptFormatter` overriding the header's parts
  (`title_lines`, `helper_import_lines`, `hook_import_lines`), the first also its `format_function`, the second
  its `match_library_functions`. Both compile to `<stem>.dat` with the same game logic, the mixed file's HLIL
  functions without their line markers. With `round_trip` the listing comes from a second parse that keeps every
  byte (the call-site records, the dead code) and compiles to the source's bytes; no other output changes, and
  without `write_llil_py` it logs a warning and writes nothing. When the DSL can't be set up for a file,
  `<stem>.py` is all LLIL, with a warning. Only `<stem>.py` imports `<stem>_hook.py`, whose name comes from the
  `.dat` name (`gen_hook_import`, `falcom/ed9/formatter/llil_dsl/script_formatter.py`); the listing imports no
  hook. The round-trip validator's `--round-trip` compiles the byte-exact listing (`byte_exact_decompile`); its
  `--logic-round-trip --game <game>` decompiles each round to the mixed file (its own `logic_decompile`, the steps
  above), compares the source decompile's HLIL functions without their line markers and requires every round to
  print the same ones in the HLIL DSL, each with the same lines (`docs/ROUND_TRIP_POLICY.md`); its run files are
  internal and can keep
  their names.

The `POPN` in `ai_chr5122_e00`'s `CheckAlgoUse`, written as opcodes to show a list. The printer would use the
statement the TypeScript output has, `POPN("駆動解除レジストできないやつ発見：chrid：", v.var_s5)`: its values top of
stack first, so it lowers to their pushes in reverse, then `POPN(2)`. `DEBUG_INT(n)` is a statement the same way,
lowering to its opcode:

```python
If(btl_check_resist_condition(65507, 50, 0) == 0, [
    EmitLLIL(DEBUG_SET_LINENO(192)),
    EmitLLIL([
        LOAD_STACK(v.var_s5),     # +1, compiles to LOAD_STACK(-8)
        PUSH_STR("駆動解除レジストできないやつ発見：chrid："),   # +1
        POPN(2),                  # -2, pops both
    ]),
    Return(1),
]),
```

## HLIL DSL: Script-Facing Modules

**Not started; decide when the HLIL DSL plan is drafted** (idea 2026-10-07, from the writer neatening plan).
What a `.py` and a hook file call by bare name sits in `falcom/ed9/writer/` beside the compiler: the opcode
functions (`scp_writer_opcode_handler.py`), `label` / `GLOBAL_VAR` / `genLabel` (`scp_writer_helper.py`, the
module every script and hook file imports) and the hook API (`scp_writer_hooks.py`). The HLIL DSL adds a larger
surface (Form's nodes, `Locals`, `this` / `script`, library stubs, `@scena.HLILCode()`), and a mixed file needs
both levels, so the script-facing modules could move into a package of their own while the compiler
(`ScpWriter`, the hook registry, the compile check, the lowering) stays in `writer/`:

```
falcom/ed9/dsl/         # what scripts and hook files import
    opcodes.py          # scp_writer_opcode_handler.py: the opcode functions, used by both levels
    hooks.py            # scp_writer_hooks.py: the hook API, the same for both levels
    llil.py             # scp_writer_helper.py: label, GLOBAL_VAR, genLabel and the re-exports
    hlil.py             # the HLIL nodes, Locals, this / script, ...
```

- **The shape follows the open questions:** stubs or namespaces for calls (Open Questions), star imports or explicit
  imports with `.pyi` stubs (Form, Tooling), and the import module's name (the hook example in `docs/dsl/HOOKS.md` uses
  `ed9_hlil`).
- **The hook API stays one level-neutral module** that both levels' import modules re-export; it was kept apart
  from the LLIL helper for this reason (2026-10-07).
- **Cost:** every generated script, library module and hook file imports `falcom.ed9.writer.scp_writer_helper`,
  so the move needs a one-line forwarding module at the old path, or re-decompiling the scripts and regenerating
  the library. The `metadata/` move (2026-10-14) changed the scripts' `common_all` import line with no
  forwarder: scripts are decompiled again and the library regenerated.
- **Collision check:** the library generator reserves the DSL namespace's names (`RESERVED_HELPER_NAMES`,
  `gen_common_library.py`), so a package that adds names to it is checked against the corpus and the
  library first.
- **A deliberate namespace (`__all__`):** today what a script or hook sees is whatever leaks through star imports,
  because no module on the chain (`scp_writer_helper.py` -> `scp_writer_opcode_handler.py` -> `structs/scp_types.py`)
  defines `__all__`. When `scp_types.py`'s `from dc3 import *` became named imports (2026-10-13, as
  `parser/types_scp.py`), 7 `dc3` names left the namespace (`IntFlag2`, `PROJECT_ROOT`, `default_encoding`,
  `default_endian`, `default_indent`, `display_width`, `quote_string`); nothing generated used them. The script-facing
  modules should list their exports in `__all__`, so the namespace changes only on purpose.

## Open Questions

- **Calls:** stubs (bare names, above) or namespaces (`lib.chr_info(...)`, `this.Foo(...)`). Leaning
  stubs: namespaces can't collide with anything, but they put a prefix on most statements.
- **Literals:** wrap only operations between two literals, or every literal operand in generated
  output.
- **Very long `else if` chains:** keep the `.ElseIf` chain (a chain Python cannot compile fails the exact check and
  stays LLIL), or print a flat form (one call holding every arm; `c = If(...)` followed by one `c.ElseIf(...)`
  statement per arm would need the source check to allow keeping an `If`).
- **Switch order:** whether the compiler ever lays case bodies out in a different order from its
  tests; if it does, `Switch` needs a way to record both (for example `tests = [...]`).
- **Hooks across levels:** whether a replacement is written at the replaced function's level, and what
  `inline_original_func()` does when the levels differ (an LLIL body can't go in an `EmitLLIL` list: it pops its
  own frame and returns).
