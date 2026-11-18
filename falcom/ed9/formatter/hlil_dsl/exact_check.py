"""The HLIL DSL's exact check (docs/dsl/HLIL_DSL.md, Recompile Path): a function's printed text is parsed, source
checked, run, its tree built and lowered into a list, and the list must be the source function's code without its line
markers - else the function stays LLIL. It checks the text itself, the way the mixed file runs it, and loads neither
the writer nor the common-function library"""

import ast
import inspect
from typing import TYPE_CHECKING, Callable

from assembler.instruction import Operand
from assembler.instruction_table import OperandDescriptor, OperandType
from ...assembler import ED9_INSTRUCTION_TABLE, ED9Opcode
from ...assembler.function import Function
from ...assembler.opcode_table import ED9OperandType
from ...structs.fingerprint import body_fingerprint_without_line_markers, operand_key
from ...structs.scp_types import FloatWord, RawInt, ScpValue
from ...writer.hlil_dsl.build import Build
from ...writer.hlil_dsl.lowering import Lowering
from ...writer.hlil_dsl.source_check import parsed_body_problem
from ...writer.hlil_dsl.stubs import library_function
from ...writer.hlil_dsl.tree import build_tree
from ..llil_dsl.function_formatter import Formatter

if TYPE_CHECKING:
    from ...parser.scp import ScpParser

CHECK_FILENAME = '<HLIL DSL check>'


def stub_name(stub: Callable) -> str:
    """A lowered call's operand is its callee's stub, keyed by its name as the source's function ID is"""
    return stub.__name__


def given_global_name(name: str) -> str:
    """A lowered global operand is its name already"""
    return name


def no_site():
    """The check's build reports no source site: its errors are reasons, not located messages"""
    return None


def unlocated(site, text: str) -> str:
    return text


class FingerprintSink:
    """The lowering's opcodes, keyed as fingerprint.operand_key keys the source's: a label as the ordinal of the opcode
    after it, a call by its callee's name, a global by name, a Value operand as the ScpValue the disassembler reads, a
    float as the one its stored word decodes to"""

    def __init__(self):
        self.code: list[tuple[ED9Opcode, tuple]] = []
        self.label_ordinals: dict[str, int] = {}
        self.labels_made = 0

    def at(self, site):
        pass

    def new_label(self) -> str:
        self.labels_made += 1
        return f'L{self.labels_made}'

    def label(self, name: str):
        self.label_ordinals[name] = len(self.code)

    def emit(self, opcode: ED9Opcode, *operands):
        self.code.append((opcode, operands))

    def fingerprint(self) -> tuple:
        return tuple(self.keyed(opcode, operands) for opcode, operands in self.code)

    def keyed(self, opcode: ED9Opcode, operands: tuple) -> tuple:
        descriptors = ED9_INSTRUCTION_TABLE.get_descriptor(opcode).operand_descriptors
        return (int(opcode),
                *(self.key(descriptor, value) for descriptor, value in zip(descriptors, operands, strict=True)))

    def key(self, descriptor: OperandDescriptor, value) -> tuple:
        match descriptor.type:
            case ED9OperandType.Value:
                value = ScpValue(value)

            case OperandType.Float32:
                value = ScpValue.decode_word(ScpValue.encode_float(value))[1]

        return operand_key(Operand(descriptor, value), 0, self.label_ordinals, stub_name, given_global_name)


class RecordingScena:
    """The mixed script's scena, as far as a printed function uses it: HLILCode() records the body and returns its
    stub, as the writer's does"""

    def __init__(self):
        self.registered: list[Callable] = []

    def HLILCode(self):
        def register(body: Callable) -> Callable:
            self.registered.append(body)
            return library_function(body)

        return register


def table_stub(name: str, param_count: int) -> Callable:
    """The stub of a function-table entry: a call of it checks its argument count, as at compile time"""
    def body(*args):
        """Never runs: in a build the stub makes a call node"""

    body.__name__ = body.__qualname__ = name
    parameters = [inspect.Parameter(Formatter.param_name(index), inspect.Parameter.POSITIONAL_ONLY)
                  for index in range(param_count)]
    body.__signature__ = inspect.Signature(parameters)
    return library_function(body)


class ExactCheck:
    """The check of one script's printed functions, each run in one namespace: the DSL's names, the names a parameter
    default may use and a stub per function-table entry"""

    def __init__(self, parser: 'ScpParser', dsl_namespace: dict[str, object]):
        self.parser = parser
        self.scena = RecordingScena()
        self.stubs = {func.name: table_stub(func.name, len(func.params)) for func in parser.functions}
        self.namespace = {**dsl_namespace, 'FloatWord': FloatWord, 'RawInt': RawInt, 'scena': self.scena, **self.stubs}

    def problem(self, func: Function, lines: list[str]) -> str | None:
        """Why func's printed lines are not exact, None when they are"""
        tree = ast.parse('\n'.join(lines) + '\n', CHECK_FILENAME)
        [definition] = tree.body
        source_problem = parsed_body_problem(definition)
        if source_problem is not None:
            return f'source check: {source_problem.text}'

        registered = self.registered_bodies(func, tree)
        names = [body.__name__ for body in registered]
        if names != [func.name]:
            return f'registration: {names}'

        [body] = registered
        return None if self.lowered_fingerprint(func, body) == self.source_fingerprint(func) else 'not exact'

    def registered_bodies(self, func: Function, tree: ast.Module) -> list[Callable]:
        """The bodies the printed definition registers when it runs"""
        self.scena.registered.clear()
        try:
            exec(compile(tree, CHECK_FILENAME, 'exec'), self.namespace)
        finally:
            # The run bound func's name to the printed body's stub: the table's stub again, which the body's own
            # calls of func (run next, in lowered_fingerprint) and the next function's reach
            self.namespace[func.name] = self.stubs[func.name]

        return list(self.scena.registered)

    def lowered_fingerprint(self, func: Function, body: Callable) -> tuple:
        code = body.__code__
        build = Build(func.name, site_of=no_site, locate=unlocated)
        statements = build_tree(build, body, list(code.co_varnames[:code.co_argcount]))
        sink = FingerprintSink()
        Lowering(sink, len(func.params), build).run(statements)
        return sink.fingerprint()

    def source_fingerprint(self, func: Function) -> tuple:
        return body_fingerprint_without_line_markers(func.reachable_instructions(), func.offset,
                                                     self.parser.get_func_name_from_func_id,
                                                     self.parser.get_global_name_from_index)
