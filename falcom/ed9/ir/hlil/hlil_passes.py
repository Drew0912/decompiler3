"""Falcom HLIL Passes"""

from collections import Counter, defaultdict
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

        functions = {func.name: func for func in hlil_funcs}
        collected = {}

        def collect(func: HighLevelILFunction):
            collected[func.name] = self._collect(func, functions)

        failed = self._each(hlil_funcs, collect)
        for (name, index), kind in propagate_id_marks(collected).items():
            functions[name].parameters[index].id_kind = kind

        # After every function's marks: a call names its callee's marks, in any order. A function whose collection
        # failed gets no tags either: its rows lookup would fail again
        marked = {func.name: {index: param.id_kind for index, param in enumerate(func.parameters)
                              if param.id_kind is not None}
                  for func in hlil_funcs}
        self._each([func for func in hlil_funcs if func.name not in failed],
                   lambda func: self._tag_id_constants(func, marked))
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

    def _collect(self, func: HighLevelILFunction, functions: dict[str, HighLevelILFunction]) -> ParameterUses:
        """What func does with its parameters over its reachable statements: the reads of each one never written or
        address-taken, and its passes at ID slots and to this file's functions' parameters"""
        excluded = excluded_parameters(func.body)
        candidates = {param.name: index for index, param in enumerate(func.parameters) if param.name not in excluded}
        uses = ParameterUses()
        for stmt in reachable_statements(func.body):
            for expr in statement_expressions(stmt):
                for node in iter_tree(expr):
                    self._record(node, candidates, functions, uses)

        return uses

    def _record(self, node: HLILInstruction, candidates: dict[str, int], functions: dict[str, HighLevelILFunction],
                uses: ParameterUses):
        """One node's part in the facts: a read of a candidate, and a syscall's or a call's arguments that are one"""
        index = parameter_index(node, candidates)
        if index is not None:
            uses.reads[index] += 1
        elif isinstance(node, HLILSyscall):
            for slot, kind in self.syscall_args.id_kinds(node.subsystem, node.cmd, len(node.args)).items():
                index = parameter_index(node.args[slot], candidates) if slot < len(node.args) else None
                if index is not None:
                    uses.syscall_kinds[index].append(kind)
        elif isinstance(node, HLILCall) and node.func_name in functions:
            callee = functions[node.func_name]
            for slot in range(min(len(node.args), len(callee.parameters))):
                index = parameter_index(node.args[slot], candidates)
                if index is not None:
                    uses.local_passes.append(((node.func_name, slot), index))

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


class ParameterUses:
    """A function's facts about its parameters, by index: the reads of each candidate, the ID kinds of its syscall
    passes, and its passes to this file's functions as ((callee, callee index), caller's parameter index)"""

    def __init__(self):
        self.reads: Counter[int] = Counter()
        self.syscall_kinds: dict[int, list[str]] = defaultdict(list)
        self.local_passes: list[tuple[tuple[str, int], int]] = []


class _Candidate:
    """A parameter that may be marked: its reads, the passes satisfied so far and their ID kinds"""

    def __init__(self, reads: int):
        self.reads = reads
        self.satisfied = 0
        self.kinds: set[str] = set()


def propagate_id_marks(collected: dict[str, ParameterUses]) -> dict[tuple[str, int], str]:
    """The ID marks of a file, (function, parameter index) -> kind: a parameter is marked when every one of its reads is
    a pass of one kind, a syscall's ID slot or a marked parameter of a callee. A worklist from the syscall passes gives
    the least fixpoint: a pass to a parameter never marked never counts, and a recursive pass counts only after the
    mark it needs, which it cannot have without a satisfied read of its own"""
    candidates = {}
    waiting = defaultdict(list)  # Callee parameter -> caller parameters, one entry per pass
    for name, uses in collected.items():
        for index, reads in uses.reads.items():
            candidates[(name, index)] = _Candidate(reads)
        for callee, index in uses.local_passes:
            waiting[callee].append((name, index))

    marks = {}
    ready = []

    def satisfy(key: tuple[str, int], kind: str):
        candidate = candidates.get(key)
        if candidate is None:
            return

        candidate.satisfied += 1
        candidate.kinds.add(kind)
        if candidate.satisfied == candidate.reads and len(candidate.kinds) == 1:
            marks[key] = kind
            ready.append(key)

    for name, uses in collected.items():
        for index, kinds in uses.syscall_kinds.items():
            for kind in kinds:
                satisfy((name, index), kind)

    while ready:
        callee = ready.pop()
        for caller in waiting[callee]:
            satisfy(caller, marks[callee])

    return marks


def parameter_index(expr: HLILInstruction, candidates: dict[str, int]) -> int | None:
    """The index of the candidate parameter expr reads, or None: a local or parameter of that name, not a constant"""
    if isinstance(expr, HLILVar) and expr.var.kind in (VariableKind.LOCAL, VariableKind.PARAM):
        return candidates.get(expr.var.name)

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
