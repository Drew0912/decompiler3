#!/usr/bin/env python3
"""Unit tests for FalcomTypeInferencePass: parameter types come from the script's declared flags; with the syscall
rows, a parameter whose every read is a pass to an ID slot (a syscall's, or a marked parameter of a call, through any
chain) is marked, and an int constant at an ID slot of a syscall or of a call to a marked parameter is tagged."""

from pathlib import Path
import itertools
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from codegen.typescript import generate_typescript
from falcom.ed9.assembler.ed9_syscalls import ANY_ARGC, Subsystem, SyscallArgs, SyscallEntry
from falcom.ed9.consts import CHR_ID_KIND
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.ir.hlil.hlil_passes import (FalcomTypeInferencePass, ParameterUses, excluded_parameters,
                                           propagate_id_marks)
from falcom.ed9.assembler.function import Function, FunctionParam
from falcom.ed9.structs.scp_types import (Nullable32, NullableStr, Pointer, RawInt, ScpParamFlags, ScpValue,
                                          Value32)
from ir.core import SourceFloat
from ir.core.il_base import IRParameter
from ir.hlil import (BinaryOp, HighLevelILFunction, HLILAddressOf, HLILAssign, HLILBinaryOp, HLILBlock, HLILCall,
                     HLILComment, HLILConst, HLILDeref, HLILExprStmt, HLILExpression, HLILExternCall, HLILIf,
                     HLILReturn, HLILSyscall, HLILTypeKind, HLILVar, HLILVariable, HLILWhile, VariableKind)
from ir.mlil.mlil import MediumLevelILFunction, MLILRet
from ir.mlil.mlil_types import MLILType, MLILVariantType


TEST_FUNCTION_NAME = 'test_func'
FLOAT_DEFAULT = 0.1
STRING_DEFAULT = 'abc'


def make_scp_function(*params: FunctionParam) -> Function:
    func = Function()
    func.name = TEST_FUNCTION_NAME
    func.params = list(params)
    return func


def typed_hlil(mlil: MediumLevelILFunction, scp_func: Function) -> HighLevelILFunction:
    """mlil's HLIL with its declared types, as the file-level stage gives them"""
    hlil = convert_falcom_mlil_to_hlil(mlil)
    FalcomTypeInferencePass([scp_func]).run([hlil])
    return hlil


def make_mlil_function(type_name: str, default_value) -> MediumLevelILFunction:
    """One-parameter function whose body only returns"""
    func = MediumLevelILFunction(TEST_FUNCTION_NAME, params=[IRParameter('arg1', type_name, default_value)])
    func.get_or_create_parameter(1, 'arg1')
    func.create_block().add_instruction(MLILRet())
    return func


# What the SSA pass infers for a Value32 parameter that also receives a float: its int seed joined with the float
INT_FLOAT_VARIANT = MLILVariantType({MLILType.int_type(), MLILType.float_type()})


class TestDeclaredParameterTypes(unittest.TestCase):
    """Each declared flag gives its parameter's HLIL type."""

    def test_each_flag_maps_to_its_kind(self):
        scp_func = make_scp_function(
            FunctionParam(ScpParamFlags(Value32)),
            FunctionParam(ScpParamFlags(str)),
            FunctionParam(ScpParamFlags(Pointer)),
            FunctionParam(ScpParamFlags(Nullable32), ScpValue(FLOAT_DEFAULT)),
            FunctionParam(ScpParamFlags(NullableStr), ScpValue(STRING_DEFAULT)),
        )
        hlil = HighLevelILFunction(TEST_FUNCTION_NAME)
        hlil.parameters = [HLILVariable(f'arg{i + 1}', kind=VariableKind.PARAM) for i in range(len(scp_func.params))]

        FalcomTypeInferencePass([scp_func]).run([hlil])

        self.assertEqual(
            [param.type_hint for param in hlil.parameters],
            [HLILTypeKind.NUMBER, HLILTypeKind.STRING, HLILTypeKind.POINTER, HLILTypeKind.NUMBER, HLILTypeKind.STRING],
        )

    def test_declared_flag_wins_over_the_inferred_variant(self):
        # AniFieldAttack(arg1 = 0.1) stores floats into its Value32 parameter: the SSA pass gives
        # variant<int, float>, which rendered `arg1: any` while the pass was disabled
        mlil = make_mlil_function('int', FLOAT_DEFAULT)
        mlil.var_types = {'arg1': INT_FLOAT_VARIANT}
        scp_func = make_scp_function(FunctionParam(ScpParamFlags(Value32), ScpValue(FLOAT_DEFAULT)))

        ts = generate_typescript(typed_hlil(mlil, scp_func))

        self.assertIn(f'function {TEST_FUNCTION_NAME}(arg1: number = {FLOAT_DEFAULT})', ts)

    def test_string_default_is_quoted_once(self):
        # Guard: the default value still comes from the converter, formatted by codegen
        mlil = make_mlil_function('str', STRING_DEFAULT)
        scp_func = make_scp_function(FunctionParam(ScpParamFlags(NullableStr), ScpValue(STRING_DEFAULT)))

        ts = generate_typescript(typed_hlil(mlil, scp_func))

        self.assertIn(f'function {TEST_FUNCTION_NAME}(arg1: string = "{STRING_DEFAULT}")', ts)

    def test_without_the_stage_the_inferred_type_stays(self):
        # Guard: callers that convert without the file-level stage (the semantic validator) keep the converter's
        # mapping
        mlil = make_mlil_function('int', FLOAT_DEFAULT)
        mlil.var_types = {'arg1': INT_FLOAT_VARIANT}

        ts = generate_typescript(convert_falcom_mlil_to_hlil(mlil))

        self.assertIn(f'function {TEST_FUNCTION_NAME}(arg1: any = {FLOAT_DEFAULT})', ts)


WAIT = 0x19         # Chr: an ID first, with 3 arguments or the older 2
EMOTION = 0x89      # Chr: the emotion first, the ID second
ATTACH = 0x8C       # Chr: two IDs, a slot between
SPEAK = 0x13        # Mes: the speaker first, whatever the count
FLAG_MASK = 4
WRAPPER = 'chr_wait_animeclip'
BROKEN_CMD = 0x77   # Chr: a row lookup that raises, for the collection-failure test

SYSCALL_ENTRIES = [
    SyscallEntry(Subsystem.Chr, WAIT,    3,        'N'),
    SyscallEntry(Subsystem.Chr, WAIT,    2,        'N'),
    SyscallEntry(Subsystem.Chr, EMOTION, 3,        '.N'),
    SyscallEntry(Subsystem.Chr, ATTACH,  3,        'N.N'),
    SyscallEntry(Subsystem.Mes, SPEAK,   ANY_ARGC, 'N'),
]
SYSCALL_ARGS = SyscallArgs(SYSCALL_ENTRIES)


def ref(name: str) -> HLILVar:
    """A reference to a parameter in a body: LOCAL, as the converter makes them"""
    return HLILVar(HLILVariable(name))


def wait(*args: HLILVar | HLILConst) -> HLILSyscall:
    return HLILSyscall(Subsystem.Chr, WAIT, list(args))


def hlil_function(name: str, argc: int, *statements) -> HighLevelILFunction:
    func = HighLevelILFunction(name)
    func.parameters = [HLILVariable(f'arg{index + 1}', kind=VariableKind.PARAM) for index in range(argc)]
    for stmt in statements:
        func.body.add_statement(stmt)

    return func


def scp_function(func: HighLevelILFunction) -> Function:
    scp_func = Function()
    scp_func.name = func.name
    scp_func.params = [FunctionParam(ScpParamFlags(Value32)) for _ in func.parameters]
    return scp_func


def run_stage(*funcs: HighLevelILFunction, syscall_args: SyscallArgs | None = SYSCALL_ARGS, warn=None):
    FalcomTypeInferencePass([scp_function(func) for func in funcs], syscall_args, warn).run(list(funcs))


def marked(func: HighLevelILFunction) -> set[str]:
    return {param.name for param in func.parameters if param.id_kind == CHR_ID_KIND}


def a1() -> HLILVar:
    return ref('arg1')


def a2() -> HLILVar:
    return ref('arg2')


def a3() -> HLILVar:
    return ref('arg3')


class TestIdParameterMarks(unittest.TestCase):
    """A parameter whose every reachable read is a pass to an ID slot is marked: here a syscall's slot, by the rows"""

    def test_what_is_marked(self):
        flagged = HLILBinaryOp(BinaryOp.BIT_OR, a1(), HLILConst(FLAG_MASK))
        emotion = HLILSyscall(Subsystem.Chr, EMOTION, [a1(), a2(), a3()])
        speak = HLILSyscall(Subsystem.Mes, SPEAK, [a1(), a2(), a3()])
        cases = [
            # label, the marks, argc, the body
            ('return syscall',          {'arg1'}, 3, [HLILReturn(wait(a1(), a2(), a3()))]),
            ('syscall, return 0',       {'arg1'}, 3, [HLILExprStmt(wait(a1(), a2(), a3())), HLILReturn(HLILConst(0))]),
            ('syscall, return',         {'arg1'}, 3, [HLILExprStmt(wait(a1(), a2(), a3())), HLILReturn()]),
            ('a comment first',         {'arg1'}, 3, [HLILComment('line(3)'), HLILReturn(wait(a1(), a2(), a3()))]),
            ('a dot slot',              {'arg2'}, 3, [HLILReturn(emotion)]),
            ('reordered',               {'arg3'}, 3, [HLILReturn(wait(a3(), a1(), a2()))]),
            ('the older count',         {'arg1'}, 2, [HLILReturn(wait(a1(), a2()))]),
            ('passed twice, once at a dot', {'arg2'}, 3,
             [HLILReturn(HLILSyscall(Subsystem.Chr, ATTACH, [a2(), a1(), a1()]))]),
            ('any count',               {'arg1'}, 4, [HLILReturn(speak)]),
            ('in an expression',        set(), 3, [HLILReturn(wait(flagged, a2(), a3()))]),
            ('its address taken beside', set(), 3, [HLILReturn(wait(a1(), HLILAddressOf(a1()), a3()))]),
            ('no row for the count',    set(), 4, [HLILReturn(wait(a1(), a2(), a3(), ref('arg4')))]),
            ('two syscalls',            {'arg1'}, 3, [HLILExprStmt(wait(a1(), a2(), a3())),
                                                   HLILExprStmt(wait(a1(), a2(), a3())), HLILReturn()]),
            ('a call, not a syscall',   set(), 3, [HLILReturn(HLILCall(WRAPPER, [a1(), a2(), a3()]))]),
        ]
        for label, expected, argc, statements in cases:
            with self.subTest(label):
                func = hlil_function(WRAPPER, argc, *statements)
                run_stage(func)
                self.assertEqual(marked(func), expected)

    def test_without_rows_nothing_is_marked_and_the_types_are_still_set(self):
        func = hlil_function(WRAPPER, 3, HLILReturn(wait(a1(), a2(), a3())))

        run_stage(func, syscall_args=None)

        self.assertEqual(marked(func), set())
        self.assertEqual({param.type_hint for param in func.parameters}, {HLILTypeKind.NUMBER})

    def test_a_function_that_raises_is_reported_and_the_next_still_done(self):
        broken = hlil_function('broken', 3, HLILReturn(wait(a1(), a2(), a3())))
        func = hlil_function(WRAPPER, 3, HLILReturn(wait(a1(), a2(), a3())))
        warnings = []

        # No declared types for broken: its types part raises
        FalcomTypeInferencePass([scp_function(func)], SYSCALL_ARGS, lambda name, error: warnings.append((name, error))
                                ).run([broken, func])

        self.assertEqual([(name, type(error)) for name, error in warnings], [('broken', KeyError)])
        self.assertEqual([param.type_hint for param in broken.parameters], [None] * 3)
        self.assertEqual(func.parameters[0].type_hint, HLILTypeKind.NUMBER)
        self.assertEqual(marked(func), {'arg1'})


class FailingSyscallArgs(SyscallArgs):
    """The rows, except that one command's lookup raises"""

    def id_kinds(self, subsystem: int, cmd: int, argc: int) -> dict[int, str]:
        if cmd == BROKEN_CMD:
            raise ValueError(f'no row for command {cmd:#x}')

        return super().id_kinds(subsystem, cmd, argc)


def const(value: int = 0) -> HLILConst:
    return HLILConst(value)


def call(name: str, *args: HLILExpression) -> HLILCall:
    return HLILCall(name, list(args))


def wrapper() -> HighLevelILFunction:
    """Marks its parameter: its one read is a syscall's ID slot"""
    return hlil_function(WRAPPER, 3, HLILReturn(wait(a1(), a2(), a3())))


def forwarder(name: str, *statements) -> HighLevelILFunction:
    """A one-parameter function whose statements (or the given ones) pass arg1 on"""
    return hlil_function(name, 1, *statements, HLILReturn(const()))


class TestForwarding(unittest.TestCase):
    """A parameter whose every read is a pass to an ID slot is marked too: of a syscall's ID slot or of a marked
    parameter
    of a call to this file's function, whatever the order and the chain's depth"""

    def test_a_pass_to_a_marked_wrapper_marks_the_caller(self):
        for caller_first in (True, False):
            with self.subTest(caller_first=caller_first):
                caller = forwarder('Show', HLILExprStmt(call(WRAPPER, a1(), const(3), const(3))))
                funcs = [caller, wrapper()]
                run_stage(*(funcs if caller_first else funcs[::-1]))
                self.assertEqual(marked(caller), {'arg1'})

    def test_a_chain_of_three_marks_every_link(self):
        for order in itertools.permutations(range(3)):
            with self.subTest(order=order):
                outer = forwarder('Outer', HLILExprStmt(call('Middle', a1())))
                middle = forwarder('Middle', HLILExprStmt(call(WRAPPER, a1(), const(), const())))
                funcs = [outer, middle, wrapper()]
                run_stage(*[funcs[index] for index in order])
                self.assertEqual([marked(func) for func in (outer, middle)], [{'arg1'}, {'arg1'}])

    def test_a_forwarder_whose_callers_constant_is_tagged(self):
        show = forwarder('Show', HLILExprStmt(wait(a1(), const(), const())), HLILExprStmt(wait(a1(), const(), const())))
        arg = const()
        main = hlil_function('Main', 0, HLILExprStmt(call('Show', arg)), HLILReturn())

        run_stage(main, show)

        self.assertEqual(marked(show), {'arg1'})
        self.assertEqual(arg.id_kind, CHR_ID_KIND)

    def test_a_nested_call_in_a_condition_marks(self):
        wrapper_call = call(WRAPPER, a1(), const(), const())
        test = hlil_function('Test', 1, HLILIf(HLILBinaryOp(BinaryOp.NE, wrapper_call, const()),
                                               HLILBlock([HLILReturn(const(1))])),
                             HLILReturn(const()))

        run_stage(test, wrapper())

        self.assertEqual(marked(test), {'arg1'})

    def test_each_read_that_is_not_an_id_pass_blocks_the_mark(self):
        keeps_id_read = HLILExprStmt(wait(a1(), const(), const()))
        blocking_reads = [
            ('a comparison',            HLILReturn(HLILBinaryOp(BinaryOp.EQ, a1(), const(1)))),
            ('arithmetic',              HLILReturn(HLILBinaryOp(BinaryOp.ADD, a1(), const(1)))),
            ('a row-less count',        HLILExprStmt(wait(a1(), const(), const(), const()))),
            ('an unmarked callee',      HLILExprStmt(call('Other', a1()))),
            ('past the callee',         HLILExprStmt(call(WRAPPER, const(), const(), const(), a1()))),
            ('an extern call',          HLILExprStmt(HLILExternCall('module:Thing', [a1()]))),
        ]
        for label, blocking in blocking_reads:
            with self.subTest(label):
                test = hlil_function('Test', 1, keeps_id_read, blocking, HLILReturn(const()))
                run_stage(test, forwarder('Other', HLILReturn(const())), wrapper())
                self.assertEqual(marked(test), set())

    def test_a_write_or_an_address_anywhere_excludes(self):
        cases = [
            ('a write in a sibling arm', HLILIf(ref('arg4'), HLILBlock([HLILAssign(a1(), const())]))),
            ('a write after the call', HLILAssign(a1(), const())),
            ('an address taken', HLILExprStmt(call('Other', HLILAddressOf(a1())))),
        ]
        for label, extra in cases:
            with self.subTest(label):
                test = hlil_function('Test', 1, HLILExprStmt(wait(a1(), const(), const())), extra, HLILReturn(const()))
                run_stage(test, forwarder('Other', HLILReturn(const())))
                self.assertEqual(marked(test), set())

    def test_only_reachable_passes_and_reads_count(self):
        keeps_id_read = HLILExprStmt(wait(a1(), const(), const()))
        cases = [
            # label, the statements before the end, the marks
            ('a pass only under if (0)',       [HLILIf(const(0), HLILBlock([keeps_id_read]))], set()),
            ('a read only under if (0)',       [keeps_id_read, HLILIf(const(0), HLILBlock([HLILReturn(HLILBinaryOp(
                BinaryOp.EQ, a1(), const(1)))]))], {'arg1'}),
            ('the same pass in a live arm',    [HLILIf(ref('arg4'), HLILBlock([keeps_id_read]))], {'arg1'}),
            ('a read after return',            [keeps_id_read, HLILReturn(const()),
                                                HLILExprStmt(call('Other', a1()))], {'arg1'}),
            ('a read after while (1)',         [keeps_id_read, HLILWhile(const(1), HLILBlock([])),
                                                HLILExprStmt(call('Other', a1()))], {'arg1'}),
        ]
        for label, statements, expected in cases:
            with self.subTest(label):
                test = hlil_function('Test', 1, *statements, HLILReturn(const()))
                run_stage(test, forwarder('Other', HLILReturn(const())), wrapper())
                self.assertEqual(marked(test), expected)

    def test_recursion_never_marks_itself(self):
        cases = [
            ('self', [forwarder('Rec', HLILExprStmt(call('Rec', a1())))]),
            ('a mutual cycle', [forwarder('F', HLILExprStmt(call('G', a1()))),
                                forwarder('G', HLILExprStmt(call('F', a1())))]),
            ('a cycle with an ID read', [
                forwarder('F', HLILExprStmt(wait(a1(), const(), const())), HLILExprStmt(call('G', a1()))),
                forwarder('G', HLILExprStmt(call('F', a1())))]),
        ]
        for label, funcs in cases:
            with self.subTest(label):
                run_stage(*funcs)
                self.assertEqual([marked(func) for func in funcs], [set()] * len(funcs))

    def test_a_callee_left_out_of_the_run_blocks(self):
        test = hlil_function('Test', 1, HLILExprStmt(wait(a1(), const(), const())), HLILExprStmt(call('Missing', a1())),
                             HLILReturn(const()))

        run_stage(test)

        self.assertEqual(marked(test), set())

    def test_a_function_whose_collection_raises_gives_no_facts(self):
        broken = forwarder('broken', HLILExprStmt(HLILSyscall(Subsystem.Chr, BROKEN_CMD, [a1()])))
        test = hlil_function('Test', 1, HLILExprStmt(wait(a1(), const(), const())), HLILExprStmt(call('broken', a1())),
                             HLILReturn(const()))
        warnings = []

        FalcomTypeInferencePass([scp_function(broken), scp_function(test)], FailingSyscallArgs(SYSCALL_ENTRIES),
                                lambda name, error: warnings.append((name, error))).run([broken, test])

        self.assertEqual([name for name, _ in warnings], ['broken'])
        self.assertEqual(marked(broken), set())
        self.assertEqual(marked(test), set())


def uses_of(reads: dict[int, int], syscall_kinds: dict[int, list[str]]) -> ParameterUses:
    uses = ParameterUses()
    uses.reads.update(reads)
    for index, kinds in syscall_kinds.items():
        uses.syscall_kinds[index].extend(kinds)

    return uses


class TestPropagation(unittest.TestCase):
    """propagate_id_marks on hand-built facts: the kinds a parameter's passes carry"""

    def test_one_kind_marks(self):
        marks = propagate_id_marks({'F': uses_of({0: 2}, {0: [CHR_ID_KIND, CHR_ID_KIND]})})

        self.assertEqual(marks, {('F', 0): CHR_ID_KIND})

    def test_a_second_kind_leaves_it_unmarked(self):
        marks = propagate_id_marks({'F': uses_of({0: 2}, {0: [CHR_ID_KIND, 'item']})})

        self.assertEqual(marks, {})

    def test_an_unsatisfied_read_leaves_it_unmarked(self):
        marks = propagate_id_marks({'F': uses_of({0: 2}, {0: [CHR_ID_KIND]})})

        self.assertEqual(marks, {})


class TestExcludedParameters(unittest.TestCase):
    """The names a body may change, wherever in the body: a write, or an address taken"""

    def test_writes_and_addresses_anywhere(self):
        body = HLILBlock([
            HLILIf(ref('arg4'), HLILBlock([HLILAssign(a1(), HLILConst(0))])),
            HLILAssign(HLILDeref(HLILAddressOf(a2())), HLILConst(0)),
            HLILExprStmt(HLILCall(WRAPPER, [HLILAddressOf(a3())])),
            HLILReturn(ref('arg5')),
        ])

        self.assertEqual(excluded_parameters(body), {'arg1', 'arg2', 'arg3'})


class TestIdConstantTags(unittest.TestCase):
    """An int constant written in decimal that is exactly the argument at an ID slot: of a syscall by the rows, of a
    call by its callee's marks"""

    @classmethod
    def tags(cls, *args) -> list[str | None]:
        return [arg.id_kind for arg in args]

    def test_a_syscalls_id_constant_is_tagged(self):
        args = [HLILConst(0), HLILConst(1), HLILConst(2)]
        run_stage(hlil_function('Main', 0, HLILExprStmt(wait(*args)), HLILReturn()))

        self.assertEqual(self.tags(*args), [CHR_ID_KIND, None, None])

    def test_a_calls_constant_at_a_marked_parameter_is_tagged_whichever_comes_first(self):
        for caller_first in (True, False):
            with self.subTest(caller_first=caller_first):
                args = [HLILConst(0), HLILConst(1), HLILConst(2)]
                caller = hlil_function('Main', 0, HLILExprStmt(HLILCall(WRAPPER, args)), HLILReturn())
                wrapper = hlil_function(WRAPPER, 3, HLILReturn(wait(a1(), a2(), a3())))
                run_stage(*([caller, wrapper] if caller_first else [wrapper, caller]))
                self.assertEqual(self.tags(*args), [CHR_ID_KIND, None, None])

    def test_only_a_decimal_exact_int_is_an_id(self):
        cases = [(0, False, CHR_ID_KIND), (-1, False, CHR_ID_KIND), (True, False, None), (False, False, None),
                 (RawInt(0), False, None), (0.0, False, None), (SourceFloat(0.0, '0.0'), False, None),
                 (STRING_DEFAULT, False, None), (0, True, None)]
        for value, is_hex, expected in cases:
            with self.subTest(value=repr(value), is_hex=is_hex):
                const = HLILConst(value, is_hex)
                run_stage(hlil_function('Main', 0, HLILExprStmt(wait(const, HLILConst(1), HLILConst(2)))))
                self.assertEqual(const.id_kind, expected)

    def test_untagged_places(self):
        in_expression, in_extern_call, at_unconverted_callee = HLILConst(0), HLILConst(0), HLILConst(0)
        caller = hlil_function('Main', 0,
                               HLILExprStmt(wait(HLILBinaryOp(BinaryOp.ADD, in_expression, HLILConst(1)), HLILConst(1),
                                                 HLILConst(2))),
                               HLILExprStmt(HLILExternCall(f'module:{WRAPPER}', [in_extern_call, HLILConst(1),
                                                                                  HLILConst(2)])),
                               HLILExprStmt(HLILCall(WRAPPER, [at_unconverted_callee, HLILConst(1), HLILConst(2)])))

        run_stage(caller)

        self.assertEqual(self.tags(in_expression, in_extern_call, at_unconverted_callee), [None, None, None])


if __name__ == '__main__':
    unittest.main()
