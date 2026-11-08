"""Falcom HLIL Passes"""

from typing import TYPE_CHECKING, Callable

from ir.pipeline import Pass
from ir.hlil import *

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
    and each ID constant tagged (HLILConst.id_kind) for .ts to print by name. Each function's part on its own: one
    that raises sets nothing and is reported through warn (without warn, re-raised)"""

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

        self._each(hlil_funcs, self._mark_id_parameters)

        # After every function's marks: a call names its callee's marks, in any order
        marked = {func.name: {index: param.id_kind for index, param in enumerate(func.parameters)
                              if param.id_kind is not None}
                  for func in hlil_funcs}
        self._each(hlil_funcs, lambda func: self._tag_id_constants(func, marked))
        return hlil_funcs

    def _each(self, hlil_funcs: list[HighLevelILFunction], part: Callable[[HighLevelILFunction], None]):
        for func in hlil_funcs:
            try:
                part(func)
            except Exception as e:
                if self.warn is None:
                    raise

                self.warn(func.name, e)

    def _set_declared_types(self, func: HighLevelILFunction):
        """Each parameter's type_hint from its declared flag; HLIL keeps the declared parameters, in declaration
        order"""
        scp_params = self.scp_funcs[func.name].params
        kinds = [PARAM_TYPE_KINDS.get(scp_params[index].type.get_python_type())
                 for index in range(len(func.parameters))]
        for param, kind in zip(func.parameters, kinds):
            if kind is not None:
                param.type_hint = kind

    def _mark_id_parameters(self, func: HighLevelILFunction):
        """A function that is one syscall and nothing else marks each parameter passed as exactly the argument at an
        ID slot, unless the body writes it or takes its address"""
        syscall = wrapped_syscall(func.body)
        if syscall is None:
            return

        params = {param.name: param for param in func.parameters}
        excluded = excluded_parameters(func.body)
        marks = {}
        for index, kind in self.syscall_args.id_kinds(syscall.subsystem, syscall.cmd, len(syscall.args)).items():
            arg = syscall.args[index] if index < len(syscall.args) else None
            if (isinstance(arg, HLILVar) and arg.var.kind in (VariableKind.LOCAL, VariableKind.PARAM)
                    and arg.var.name in params and arg.var.name not in excluded):
                marks[arg.var.name] = kind

        for name, kind in marks.items():
            params[name].id_kind = kind

    def _tag_id_constants(self, func: HighLevelILFunction, marked: dict[str, dict[int, str]]):
        """Tag each int constant that is exactly the argument at an ID slot: of a syscall by the rows, of a call to this
        file's function by its marks"""
        tagged = []
        for node in iter_tree(func.body):
            if isinstance(node, HLILSyscall):
                kinds = self.syscall_args.id_kinds(node.subsystem, node.cmd, len(node.args))
            elif isinstance(node, HLILCall):
                kinds = marked.get(node.func_name, {})
            else:
                continue

            tagged.extend((node.args[index], kind) for index, kind in kinds.items()
                          if index < len(node.args) and is_id_constant(node.args[index]))

        for const, kind in tagged:
            const.id_kind = kind


def wrapped_syscall(body: HLILBlock) -> HLILSyscall | None:
    """The syscall of a body that is one syscall and nothing else, comments aside: return syscall(...), or
    syscall(...) then a return of a constant or of nothing"""
    statements = code_statements(body)
    match statements:
        case [HLILReturn(value=HLILSyscall() as syscall)]:
            return syscall
        case [HLILExprStmt(expr=HLILSyscall() as syscall), HLILReturn(value=HLILConst() | None)]:
            return syscall

    return None


def excluded_parameters(body: HLILBlock) -> set[str]:
    """The names body writes (an assignment's plain variable) or takes the address of (which *(&x) does too): the
    value they pass need not be the caller's"""
    names = set()
    for node in iter_tree(body):
        if isinstance(node, HLILAssign) and isinstance(node.dest, HLILVar):
            names.add(node.dest.var.name)
        elif isinstance(node, HLILAddressOf) and isinstance(node.operand, HLILVar):
            names.add(node.operand.var.name)

    return names


def is_id_constant(expr: HLILExpression) -> bool:
    """An exact int written in decimal: a bool, a Raw word, a float, a string or a hex mask is no ID"""
    return isinstance(expr, HLILConst) and type(expr.value) is int and not expr.is_hex
