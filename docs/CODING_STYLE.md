# Coding Style

PEP 8 (PEP 257 for docstrings) holds where it sets a rule; this file lists the house choices where it leaves one
open, plus the project's own rules. `CLAUDE.md` imports this file; `AGENTS.md` tells Codex to read it.

## Where the house departs from PEP 8 and PEP 257

- **Lines** up to 120 columns, not 79; longer only where a wrap would hurt (a table row, a long message).
- **Aligned columns** in a block of related assignments or annotations and in a table's rows (constants, a class's
  attributes, the opcode table): `ENDIAN      = 'little'`.
- **Star imports** are allowed: the DSL scripts and the IR packages are built on them.
- **A `sys.path` line among the imports** in every test, tool, demo and decompiled script: after the
  standard-library imports it needs, before the project imports. Each puts the repo root on `sys.path` itself; hook
  templates and the common-function library have none.
- **The DSL's names** follow the opcodes and decompiler2: `PUSH_INT`, `LLILCode`, `registerRunCallback`,
  `fileio.Open`.
- **A record class's file** is named exactly for its table section, as the DSL's names follow the opcodes:
  `games/<game>/tbl/schema/QuestTitle.py`, not `quest_title.py`.
- **Docstrings where they help:** a module, class or function whose name and signature say what it does needs none
  (Readable code, below).
- **Docstrings and comments are concise phrases** (Concise comments, below), not full sentences: no closing period;
  a multi-line docstring may close on its last line of text, with no blank line after its first.
- **Semicolons** may join a short assembler sequence in a test: `asm.get_reg(REG_INDEX); asm.jz('right')`.

## Code

- **No magic numbers.** A number that means something in the format or the VM (a size, an offset, an opcode, a
  flag mask) gets a named constant, so a reader sees its meaning and a change is one edit: `offset // WORD_SIZE`,
  not `offset // 4` (`WORD_SIZE = 4` in `ir/llil/llil.py`: byte / word conversions, stack offsets, sizes). Plain
  `0`, `1`, `-1` and index arithmetic need no name.
- **Comments name the constant, not its value:** `(offset // WORD_SIZE)`, not `(offset // 4)`.
- **Imports at module top level.** Two exceptions: a proven circular import inside a function, with a comment
  saying so; imports used only in type hints, under `if TYPE_CHECKING:`.
- **Annotations** use the builtins and `|`: `list[int]`, `dict[str, Node]`, `tuple[int, ...]`, `Node | None`,
  `int | str`, not `typing`'s `List`, `Dict`, `Tuple`, `Optional`, `Union`; type aliases too
  (`SlotValues = dict[int, MediumLevelILInstruction | None]`). `typing` keeps what has no builtin (`Any`,
  `Callable`, `Iterator`, `Sequence`, `NamedTuple`, `TYPE_CHECKING`).
- **No quotes in annotations:** Python 3.14 evaluates them lazily, so a class defined further down needs none.
  The exception: an annotation naming a `TYPE_CHECKING`-only import is one whole string (`'ScpParser | None'`,
  `'list[Instruction]'`), since `inspect.signature` and `annotationlib` evaluate annotations and the name does not
  exist at run time. No `from __future__ import annotations`.
- **`=` as in PEP 8:** spaces around an assignment's `=` and an annotated default's (`x: int = 5`,
  `def f(x: int = 0)`); none around a keyword argument's or an unannotated default's (`f(key=value)`,
  `def f(arg=0)`).
- **A section comment** one blank line above a top-level definition heads it: the two blank lines go above the
  comment.
- **`@classmethod`, never `@staticmethod`:** through `cls` the method reaches the class's other methods and sees a
  subclass's overrides; a staticmethod would have to name its class, which skips them.
- **Quotes:** single quotes for strings (`'text'`); double quotes only when the string contains a single quote
  (`"it's"`). Triple-quoted strings, docstrings included: `"""` (PEP 8, PEP 257).
- **English-only comments and docs.**
- **Concise comments:** brief and meaningful; a self-explanatory name beats a comment; never state the obvious
  (`x = 5  # Set x to 5`).
- **Readable code.** Code should read itself: a reader understands it from names and structure, with few comments.
  When readability and brevity conflict, readability wins over condensability: a well-named helper or a split that
  adds lines is fine. Split a large module into several files when its parts do separate jobs, each file named for
  its job; do not split only to make files smaller.
- **A standalone script's settings:** a plain class in its own module whose typed attribute defaults are the
  settings, instantiated by the script that uses it (e.g. `ScpDecompileConfig`, `falcom/ed9/scp2py_config.py`);
  no module-level instance, and no `--config` flag or dynamic loading unless asked.

## Files

- **Line endings:** git stores every text file with LF except `CLAUDE.md` (CRLF); a Windows checkout with
  `core.autocrlf = true` also has CRLF files in its working tree. Keep each file's own ending: scripts write with
  `write_bytes` or `write_text(..., newline='\n')`; check with `git ls-files --eol` (`w/lf` / `w/crlf`).

## Commit Messages

Short (1-2 sentences), with no signatures, attributions or tool metadata.
