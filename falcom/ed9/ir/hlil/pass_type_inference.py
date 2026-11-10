"""Falcom HLIL type inference: the file-level stage over a file's converted functions"""

from typing import TYPE_CHECKING, Callable

from ir.pipeline import Pass
from ir.hlil import *

from .id_marks import collect_parameter_uses, propagate_id_marks, tag_id_constants

if TYPE_CHECKING:
    from ...assembler.ed9_syscalls import SyscallArgs
    from ...assembler.function import Function


# Declared parameter type (ScpParamFlags.get_python_type()) -> HLIL type
PARAM_TYPE_KINDS = {
    'Value32'       : HLILTypeKind.NUMBER,
    'Nullable32'    : HLILTypeKind.NUMBER,
    'str'           : HLILTypeKind.STRING,
    'NullableStr'   : HLILTypeKind.STRING,
    'Pointer'       : HLILTypeKind.POINTER,
}


class FalcomTypeInferencePass(Pass):
    """Falcom-specific types over a file's HLIL functions, once every function is converted: each parameter's type from
    the flag the script declares for it; with the game's syscall rows, each ID parameter marked (HLILVariable.id_kind)
    and each ID constant tagged (HLILConst.id_kind) for .ts to print by name (the rule: id_marks.py). Each function's
    part on its own: one that raises sets nothing and is reported through warn (without warn, re-raised)"""

    def __init__(self, scp_funcs: 'list[Function]', syscall_args: 'SyscallArgs | None' = None,
                 warn: Callable[[str, Exception], None] | None = None):
        # The whole table, by name: functions not converted too
        self.scp_funcs = {func.name: func for func in scp_funcs}
        self.syscall_args = syscall_args
        self.warn = warn

    def run(self, hlil_funcs: list[HighLevelILFunction]) -> list[HighLevelILFunction]:
        self._each(hlil_funcs, self._set_declared_types)
        if self.syscall_args is None:
            return hlil_funcs

        functions = {func.name: func for func in hlil_funcs}
        collected = {}

        def collect(func: HighLevelILFunction):
            collected[func.name] = collect_parameter_uses(func, functions, self.syscall_args)

        failed = self._each(hlil_funcs, collect)
        for (name, index), kind in propagate_id_marks(collected).items():
            functions[name].parameters[index].id_kind = kind

        # After every function's marks: a call names its callee's marks, in any order. A function whose collection
        # failed gets no tags either: its rows lookup would fail again
        marked = {func.name: {index: param.id_kind for index, param in enumerate(func.parameters)
                              if param.id_kind is not None}
                  for func in hlil_funcs}
        self._each([func for func in hlil_funcs if func.name not in failed],
                   lambda func: tag_id_constants(func, marked, self.syscall_args))
        return hlil_funcs

    def _each(self, hlil_funcs: list[HighLevelILFunction], part: Callable[[HighLevelILFunction], None]) -> set[str]:
        """Runs part on each function; returns the names that raised (warned, or re-raised without warn)"""
        failed = set()
        for func in hlil_funcs:
            try:
                part(func)
            except Exception as e:
                if self.warn is None:
                    raise

                failed.add(func.name)
                self.warn(func.name, e)

        return failed

    def _set_declared_types(self, func: HighLevelILFunction):
        """Each parameter's type_hint from its declared flag; HLIL keeps the declared parameters, in declaration
        order"""
        scp_params = self.scp_funcs[func.name].params
        kinds = [PARAM_TYPE_KINDS.get(scp_params[index].type.get_python_type())
                 for index in range(len(func.parameters))]
        for param, kind in zip(func.parameters, kinds):
            if kind is not None:
                param.type_hint = kind
