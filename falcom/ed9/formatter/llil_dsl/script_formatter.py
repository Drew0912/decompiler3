"""The whole LLIL DSL script (.py) of a parsed .dat: the header with its imports, every function the script still
defines itself, the footer; and the starting hook file next to it"""

from typing import TYPE_CHECKING
import functools
import importlib
import keyword
import pathlib
import sys

from dc3 import default_indent, quote_string
from dc3.logging import log
from dc3.utils import PROJECT_ROOT
from ...assembler.function import Function
from ...structs.common_library import (COMMON_ALL_MODULE, COMMON_INDEX_MODULE, COMMON_LIBRARY_MISSING_HINT,
                                       game_metadata_module)
from ...structs.fingerprint import function_fingerprint, fingerprint_digest
from ..generated_script import (DEFINITION_SPACING, SCP_WRITER_HELPER_IMPORT, SYS_PATH_SETUP_LINES,
                                game_writer_helper_import)
from .comments import GLOBAL_VAR_INDEX_COMMENT, CommentOptions, append_comment
from .function_formatter import Formatter, FormatterContext

if TYPE_CHECKING:
    from ...parser.scp import ScpParser


@functools.cache
def common_library_index(game: str) -> dict[str, tuple[str, str]]:
    """game's library index (name -> module, fingerprint digest), loaded once per game per process; {} when the library
    is not generated, with the hint logged that once. The index only, not common_all: the modules load the writer,
    which a decompile never uses. A missing game package re-raises, as in a script's library import"""
    module = game_metadata_module(game, COMMON_INDEX_MODULE)
    try:
        return importlib.import_module(module).COMMON_FUNCTIONS
    except ModuleNotFoundError as e:
        if e.name != module:
            raise

    log.info(f'Every common function inline: {COMMON_LIBRARY_MISSING_HINT.format(game=game)}')
    return {}


def is_module_name(name: str) -> bool:
    """An import statement can name it: an identifier that isn't a keyword"""
    return name.isidentifier() and not keyword.iskeyword(name)


def shadows_another_module(name: str) -> bool:
    """Pylance imports a stdlib module or one of this checkout's top-level packages of that name instead of a script
    next to the hook (e.g. dc3.dat, types.dat)"""
    return name in sys.stdlib_module_names or (PROJECT_ROOT / name).is_dir() or (PROJECT_ROOT / f'{name}.py').is_file()


def suggested_module_name(stem: str) -> str:
    """A module name close to stem that no other module takes, for the hook template's rename hint: mon5078+ ->
    mon5078_, dc3 -> dc3_"""
    name = ''.join(char if f'_{char}'.isidentifier() else '_' for char in stem.strip())
    if not name.isidentifier():
        name = f'_{name}'       # a leading digit

    if keyword.iskeyword(name) or shadows_another_module(name):
        name = f'{name}_'

    return name


class LLILScriptFormatter:
    """Prints a parsed script's .py, reading the parser's file-level facts: its name, game, fidelity settings, global
    vars and function table"""

    def __init__(self, parser: 'ScpParser'):
        self.parser = parser

    def format_function(self, func: Function, comments: CommentOptions = CommentOptions()) -> list[str]:
        """Format a disassembled function"""
        formatter_context = FormatterContext(
            get_func_name_from_func_id=self.parser.get_func_name_from_func_id,
            get_global_name_from_index=self.parser.get_global_name_from_index,
            comments=comments,
        )
        formatter = Formatter(formatter_context)
        return formatter.format_function(func)

    def gen_python_script(self, functions: list[Function], *, comments: CommentOptions = CommentOptions()) -> str:
        """Full generated .py text: header (incl. shared-library imports/manifest), every function this
        script must still define itself, then the footer. match_library_functions runs once here and its
        result feeds both the header and the inline-function filter, so the two never disagree about
        which functions are imported"""
        matched = self.match_library_functions(functions)

        lines = self.gen_python_header(functions, matched=matched)

        for func in self.get_inline_functions(functions, matched=matched):
            lines.extend(self.format_function(func, comments))
            lines.extend(DEFINITION_SPACING)

        lines.extend(self.gen_python_footer())
        return '\n'.join(lines) + '\n'

    def gen_python_header(self, functions: list[Function] | None = None, *,
                          matched: dict[str, str] | None = None) -> list[str]:
        """Generate Python header lines for output script execution.

        functions, when given, are this script's disassembled functions in code order - used to
        emit the @scena.CommonImports() manifest (see match_library_functions). Leave it as None
        when there's no function list to give (e.g. a caller building just the header on its own);
        matched lets gen_python_script pass in an already-computed match set instead of this
        recomputing it.

        With a game, the first import is the game's helper, which installs the game's writer before
        the hook import can register on it, and the whole-library import (gen_library_import) follows
        the hook import, whatever
        the fidelity mode and whether or not there is a function list, so a human editing the script
        has every common function in scope for CALL()/autocomplete even when adding one this script
        never originally used.
        """
        game = self.parser.game
        helper_import = SCP_WRITER_HELPER_IMPORT if game is None else game_writer_helper_import(game)
        lines = [*SYS_PATH_SETUP_LINES, helper_import, *self.gen_hook_import().splitlines(), '']
        if game is not None:
            lines += [*self.gen_library_import().splitlines(), '']

        lines.append(f"scena = create_scp_writer('{self.parser.name}')")
        lines.extend(DEFINITION_SPACING)

        if self.parser.global_vars:
            indent = default_indent()
            lines.append('@scena.GlobalVars()')
            lines.append('def globalvars():')
            for var in self.parser.global_vars:
                declaration = f'GLOBAL_VAR({quote_string(var.name)}, {var.type})'
                lines.append(indent + append_comment(declaration, [f'{GLOBAL_VAR_INDEX_COMMENT} {var.index}']))
            lines.extend(DEFINITION_SPACING)

        if functions is not None:
            lines.extend(self.gen_common_imports(functions, matched=matched))

        return lines

    def match_library_functions(self, functions: list[Function]) -> dict[str, str]:
        """This script's common functions whose body+signature exactly match the canonical variant in
        its game's library (falcom/ed9/games/<game>/metadata/common_index.py) - name -> library module key.

        Only meaningful in the everyday (non-fidelity) mode: a byte-exact recompile needs every
        function inline and every byte of it kept, so this always returns {} when self.parser.round_trip
        or self.parser.keep_unreachable_code is True - the library was generated with unreachable code
        dropped, so importing it under keep_unreachable_code=True would silently drop a script's
        own dead bytes even though that flag asked to keep them. A common function whose fingerprint
        diverges from the library (different body, signature, or subsystem) is left out here and
        stays inline as an ordinary @scena.LLILCommonCode() definition, same as a non-common one.

        Also returns {} without a game, and when the game's library isn't generated (fresh checkout,
        generator never run): the index is generated with the modules, so a missing index means no
        library to import from.
        """
        if self.parser.game is None or self.parser.round_trip or self.parser.keep_unreachable_code:
            return {}

        index = common_library_index(self.parser.game)
        matched = {}
        for func in functions:
            if not func.is_common_func:
                continue

            entry = index.get(func.name)
            if entry is None:
                continue

            module_key, digest = entry
            if fingerprint_digest(function_fingerprint(self.parser, func)) == digest:
                matched[func.name] = module_key

        return matched

    def get_inline_functions(self, functions: list[Function], *,
                             matched: dict[str, str] | None = None) -> list[Function]:
        """functions this script must still define itself - everything not matched to the shared
        library. Returns functions unchanged when the library isn't active or nothing matched."""
        if matched is None:
            matched = self.match_library_functions(functions)

        if not matched:
            return functions

        return [func for func in functions if func.name not in matched]

    def gen_common_imports(self, functions: list[Function], *, matched: dict[str, str] | None = None) -> list[str]:
        """The @scena.CommonImports() manifest, in this script's own code order, for every function
        matched to the shared library. Empty when nothing matched - including strict round-trip
        mode, no game and an ungenerated library, all handled by match_library_functions returning {}.
        The whole-library import itself is gen_library_import, written whenever there is a game - it's
        pure name resolution for autocomplete/hand-editing, so it doesn't need to track fidelity
        mode or match state the way the manifest (what's actually compiled in) does."""
        if matched is None:
            matched = self.match_library_functions(functions)

        if not matched:
            return []

        indent = default_indent()
        lines = ['@scena.CommonImports()', 'def commonImports():', f'{indent}return [']
        for func in functions:
            if func.name in matched:
                lines.append(f'{indent * 2}{func.name},')
        lines.append(f'{indent}]')
        lines.extend(DEFINITION_SPACING)

        return lines

    def hook_module_name(self) -> str:
        """The optional hook module the generated script imports"""
        return f'{pathlib.Path(self.parser.name).stem.strip()}_hook'

    def gen_hook_import(self) -> str:
        """The try/except block importing the optional <stem>_hook module - __import__ when the stem isn't a valid
        module path (e.g. mon5078+). Only a missing hook is ignored (for a dotted stem, also a missing parent package);
        a failed import inside the hook re-raises"""
        module = self.hook_module_name()
        parts = module.split('.')
        if all(is_module_name(part) for part in parts):
            statement = f'import {module}'
        else:
            statement = f'__import__({module!r})'

        if len(parts) == 1:
            check = f'e.name != {module!r}'
        else:
            prefixes = tuple('.'.join(parts[:end]) for end in range(1, len(parts) + 1))  # parents, then the hook
            check = f'e.name not in {prefixes!r}'

        return f"""\
try:
    {statement}
except ModuleNotFoundError as e:
    if {check}:
        raise"""

    def gen_library_import(self) -> str:
        """The try/except block star-importing the game's whole common-function library (common_all). Like the hook
        import, only a missing common_all is ignored (the library is not generated, so every common function is
        inline); a failed import inside the library re-raises"""
        module = game_metadata_module(self.parser.game, COMMON_ALL_MODULE)
        return f"""\
try:
    from {module} import *
except ModuleNotFoundError as e:
    if e.name != {module!r}:
        raise"""

    def gen_hook_template(self) -> str:
        """A starting <stem>_hook.py: every callback is a no-op even when registered, so it compiles to the same bytes
        as no hook. Its TYPE_CHECKING block shows the script's names to Pylance; when no import can name the .py's
        stem, a rename hint instead"""
        stem = pathlib.Path(self.parser.name).stem
        if is_module_name(stem) and not shadows_another_module(stem):
            type_checking = f"""\
    from {stem} import *  # pyright: ignore[reportAssignmentType]
    import {stem} as original"""
        else:
            reason = 'is also the name of another module' if is_module_name(stem) else "isn't a valid module name"
            suggested = suggested_module_name(stem)
            type_checking = f"""\
    # {stem!r} {reason}, so Pylance can't import the script's names. To get them, rename
    # {stem}.py to a valid name (it still compiles to {self.parser.name}; keep this file's name) and uncomment:
    # from {suggested} import *  # pyright: ignore[reportAssignmentType]
    # import {suggested} as original
    pass"""

        return f"""\
# pyright: basic
from typing import TYPE_CHECKING
{SCP_WRITER_HELPER_IMPORT}
if TYPE_CHECKING:
{type_checking}


# Functions to add
def run_hook(g):
    for func in [
    ]:
        add_function(func)


# registerRunCallback(run_hook)

def func_hook(name, func):
    return None


# registerFuncCallback(func_hook)

def opcode_hook(opcode, *args):
    return None

# registerOpcodeCallback(opcode_hook)
"""

    def gen_python_footer(self) -> list[str]:
        """Generate Python footer lines for output script execution"""
        return """\
def main():
    scena.run(globals())


if __name__ == '__main__':
    main()""".splitlines()
