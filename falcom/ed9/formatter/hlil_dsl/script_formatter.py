"""The mixed <stem>.py (docs/dsl/HLIL_DSL.md, File names): each function the DSL has a form for and whose text passes
the exact check in the HLIL DSL, the rest in the LLIL DSL; and why each other function stays LLIL, for the logs"""

from collections import Counter
from typing import TYPE_CHECKING

from dc3.logging import log
from ir.hlil import HighLevelILFunction
from ...assembler.function import Function
from ..generated_imports import hlil_dsl_helper_import, hlil_dsl_namespace
from ..llil_dsl.comments import CommentOptions
from ..llil_dsl.script_formatter import LLILScriptFormatter
from .exact_check import ExactCheck
from .function_formatter import LLILFallback, ScriptNames, function_lines

if TYPE_CHECKING:
    from ...parser.scp import ScpParser


class HLILScriptFormatter(LLILScriptFormatter):
    """add takes each function's HLIL; the inherited gen_python_script then prints the functions that passed in the HLIL
    DSL and the rest in the LLIL DSL"""

    def __init__(self, parser: 'ScpParser'):
        super().__init__(parser)
        namespace = hlil_dsl_namespace(parser.game)
        self.names = ScriptNames(parser.get_global_name_from_index, frozenset(func.name for func in parser.functions),
                                 frozenset(namespace))
        # A function so named would rebind the DSL's name for every HLIL function in the file
        clashes = sorted(self.names.functions & self.names.reserved)
        self.file_reason = f'functions named as DSL names: {', '.join(clashes)}' if clashes else None
        self.exact_check = ExactCheck(parser, namespace)
        self.lines: dict[str, list[str]] = {}       # each function in the DSL, by name
        self.reasons: dict[str, str] = {}           # why each other function the DSL saw stays LLIL

    def helper_import_lines(self) -> list[str]:
        return [*super().helper_import_lines(), hlil_dsl_helper_import(self.parser.game)]

    def format_function(self, func: Function, comments: CommentOptions = CommentOptions()) -> list[str]:
        """func's HLIL DSL lines when they passed the exact check, else its LLIL"""
        lines = self.lines.get(func.name)
        return lines if lines is not None else super().format_function(func, comments)

    def add(self, func: Function, hlil: HighLevelILFunction):
        """func's DSL lines when it has a form and they pass the exact check, else the reason it stays LLIL. A function
        the library holds is a common function, which refusal turns away"""
        refusal = self.refusal(func)
        if refusal is not None:
            self.reasons[func.name] = refusal
            return

        try:
            lines = function_lines(func, hlil, self.names)
        except LLILFallback as e:
            self.reasons[func.name] = str(e)
            return
        except Exception as e:
            self.reasons[func.name] = f'formatter failed: {type(e).__name__}: {e}'
            return

        try:
            problem = self.exact_check.problem(func, lines)
        except Exception as e:
            problem = f'check failed: {type(e).__name__}: {e}'

        if problem is None:
            self.lines[func.name] = lines
        else:
            self.reasons[func.name] = problem

    def refusal(self, func: Function) -> str | None:
        """Why func is not formatted at all: the file's name clash, or a common function"""
        if self.file_reason is not None:
            return self.file_reason

        return 'common function' if func.is_common_func else None

    def log(self, functions: list[Function]):
        """The file's INFO line, and the reason at DEBUG of each function the file defines in LLIL"""
        inline_functions = self.get_inline_functions(functions)
        categories = []
        for func in inline_functions:
            if func.name not in self.lines:
                # Never added: its lift or a conversion raised, so no HLIL reached the DSL
                reason = self.reasons.get(func.name, 'conversion failed')
                categories.append(reason_category(reason))
                log.debug(f'{self.parser.name} [{func.name}]: LLIL: {reason}')

        summary = f'{self.parser.name}: {len(self.lines)} of {len(inline_functions)} functions as HLIL'
        if categories:
            counts = Counter(categories).most_common()
            summary += f'; LLIL: {', '.join(f'{category} {count}' for category, count in counts)}'

        log.info(summary)


def reason_category(reason: str) -> str:
    """A reason is 'category' or 'category: detail'; the file's line counts the categories"""
    return reason.split(':')[0]
