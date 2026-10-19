# Coding Style

The house style for all code in this repo. `CLAUDE.md` imports this file; `AGENTS.md` tells Codex to read it.

## Code

- **No magic numbers.** A number that means something in the format or the VM (a size, an offset, an opcode, a
  flag mask) gets a named constant, so a reader sees its meaning and a change is one edit: `offset // WORD_SIZE`,
  not `offset // 4` (`WORD_SIZE = 4` in `ir/llil/llil.py`: byte / word conversions, stack offsets, sizes). Plain
  `0`, `1`, `-1` and index arithmetic need no name.
- **Comments name the constant, not its value:** `(offset // WORD_SIZE)`, not `(offset // 4)`.
- **Imports at module top level.** Two exceptions: a proven circular import inside a function, with a comment
  saying so; imports used only in type hints, under `if TYPE_CHECKING:`.
- **Spaces around every `=`:** assignments, default parameters (`def f(arg = 0)`), keyword arguments
  (`f(key = value)`), annotated assignments (`x: int = 5`).
- **A blank line between the blocks of a conditional:** `if` / `elif`, `elif` / `elif`, `elif` / `else`, `if` / `else`.
- **`@classmethod`, never `@staticmethod`:** through `cls` the method reaches the class's other methods and sees a
  subclass's overrides; a staticmethod would have to name its class, which skips them.
- **Quotes:** single quotes for strings (`'text'`); double quotes only when the string contains a single quote
  (`"it's"`). Docstrings: `"""` (PEP 257); a file still using `'''` keeps it until it is converted.
- **English-only comments and docs.**
- **Concise comments:** brief and meaningful; a self-explanatory name beats a comment; never state the obvious
  (`x = 5  # Set x to 5`).
- **Readable code.** Code should read itself: a reader understands it from names and structure, with few comments.
  When readability and brevity conflict, readability wins over condensability: a well-named helper or a split that
  adds lines is fine. Split a large module into several files when its parts do separate jobs, each file named for
  its job; do not split only to make files smaller.
- **A standalone script's settings:** a plain class in its own module whose typed attribute defaults are the
  settings, instantiated by the script that uses it (e.g. `ScenaDecompileConfig`, `falcom/ed9/scena2py_config.py`);
  no module-level instance, and no `--config` flag or dynamic loading unless asked.

## Files

- **Line endings:** git stores every text file with LF except `CLAUDE.md` (CRLF); a Windows checkout with
  `core.autocrlf = true` also has CRLF files in its working tree. Keep each file's own ending: scripts write with
  `write_bytes` or `write_text(..., newline = '\n')`; check with `git ls-files --eol` (`w/lf` / `w/crlf`).

## Commit Messages

Short (1-2 sentences), with no signatures, attributions or tool metadata.
