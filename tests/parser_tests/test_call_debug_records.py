#!/usr/bin/env python3
'''Unit tests for pairing call-site debug records with their calls: CallDebugInfoTracker (its call tree, registers and
line gate; replay's record order and each call's instruction offset), falcom/ed9/parser/call_debug_records.py
(record_args, record_mismatch), function_extents, and the round-trip validator's compare_record built on them.'''

from pathlib import Path
import dataclasses
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from dc3.config import default_endian
from dc3.logging import log
from ir.llil import WORD_SIZE
from falcom.ed9.disasm import ED9Opcode
from falcom.ed9.disasm.stack_effects import CALLER_FRAME_SLOTS, RESULT_REGISTER
from falcom.ed9.parser.call_debug_records import CallDebugInfoTracker, TrackedValue, record_args, record_mismatch
from falcom.ed9.parser.code_layout import function_extents
from falcom.ed9.parser.types_scp import RawInt, ScpFunctionCallDebugInfo, ScpFunctionCallDebugInfoArg, ScpFunctionEntry, ScpValue
from falcom.ed9.writer.scp_writer_helper import *
from scp_roundtrip_validator import compare_record, load_script
from tests.shared.scp_writer_test_utils import fresh_writer

CallType = ScpFunctionCallDebugInfo.CallType
ArgType = ScpFunctionCallDebugInfoArg.Type
CALL_OPCODES = (ED9Opcode.CALL, ED9Opcode.CALL_SCRIPT, ED9Opcode.CALL_SCRIPT_NO_RETURN, ED9Opcode.SYSCALL)
SYSCALL_SUBSYSTEM = 1
SYSCALL_FUNC = 0x02
SYSCALL_CONSTANT = 7
CODE_END = 0x1000
SHARED_START = 0x58
NEXT_START = 0x60
NO_CALLER_FRAME_WARNING = ('CALL_SCRIPT mod.Func: no caller frame below its arguments in address order - its debug '
                           'record is a guess')

# btlsupport AniBtlSupportCover: chr_set_pos(POS_CHR, chr_info(INFO_CHR, 1), .. 2), .. 3), .. 9))
POS_CHR = 65534
INFO_CHR = 65516
INFO_KEYS = (1, 2, 3, 9)
INFO_RESULT = 5
# btlpom_common AniFieldAttack: chr_set_animeclip_speed(POS_CHR, ANIME_SPEED), then a tail call AniWait(TAIL_ARG)
ANIME_SPEED = 1.0
TAIL_ARG = 0.2
LOCALS_SIZE = 5 * WORD_SIZE
TAIL_REGISTER = 1
FIRST_ARG = 1
THIRD_ARG = 3
SAVED_VALUE = 7
UNSET_REGISTER = 5
LINE = [(ED9Opcode.DEBUG_SET_LINENO, [1])]
# Each fed local callee's parameters
PARAM_COUNTS = {
    'pos': len(INFO_KEYS) + 1, 'speed': 2, 'wait': 1, 'sub': 1, 'rand': 2, 'f': 0, 'g': 1, 'g2': 2, 'x': 0,
    **{f'info{key}': 2 for key in INFO_KEYS},
}


def push(value: int | float) -> list:
    '''A constant push, with its value as replay gives it'''
    opcode = ED9Opcode.PUSH_FLOAT if isinstance(value, float) else ED9Opcode.PUSH_INT
    return [(opcode, [value], ScpValue(value))]


def local_call(callee: str, *args: list) -> list:
    '''A local call: its setup, then its arguments pushed last first, then CALL'''
    ops = [(ED9Opcode.PUSH_CURRENT_FUNC_ID, []), (ED9Opcode.PUSH_RET_ADDR, [f'ret_{callee}'])]
    for arg in reversed(args):
        ops += arg

    return ops + [(ED9Opcode.CALL, [callee])]


def get_reg(register: int = RESULT_REGISTER) -> list:
    return [(ED9Opcode.GET_REG, [register])]


def set_reg(register: int) -> list:
    return [(ED9Opcode.SET_REG, [register])]


def nested(callee: str, *args: list) -> list:
    '''A local call whose result is pushed as an argument'''
    return local_call(callee, *args) + get_reg()


def script_call(argc: int) -> list:
    return [(ED9Opcode.PUSH_CALLER_FRAME, ['back']), (ED9Opcode.CALL_SCRIPT, [ScpValue('mod'), ScpValue('Func'), argc])]


def tail_call(argc: int) -> list:
    return [(ED9Opcode.CALL_SCRIPT_NO_RETURN, [ScpValue(''), ScpValue('AniWait'), argc])]


def syscall(argc: int) -> list:
    return [(ED9Opcode.SYSCALL, [SYSCALL_SUBSYSTEM, SYSCALL_FUNC, argc])]


def feed(*parts: list) -> CallDebugInfoTracker:
    tracker = CallDebugInfoTracker(get_param_count = PARAM_COUNTS.__getitem__)
    for opcode, operands, *payload in (op for part in parts for op in part):
        tracker.on_opcode(opcode, operands, *payload)

    return tracker


def targets(tracker: CallDebugInfoTracker) -> list:
    '''Each recorded call's callee, in record order'''
    return [call.target for call in tracker.ordered_calls()]


def constants(args: list[TrackedValue]) -> list:
    '''Each argument's type, and its value if it is a constant'''
    return [(arg.type, arg.payload.value if arg.payload is not None else None) for arg in args]


def compile_script(dat: Path):
    '''Main's records are in source order, not address order: Outer's record comes before the Inner call in its argument,
    and the SYSCALL's before the Inner call whose result it takes. Main's first call is made before any line info, so it
    has no record. Defined in source order Inner, Outer, Main, Tail; the table is sorted by name.'''
    writer = fresh_writer(dat)

    @writer.LLILCode()
    def Inner():
        PUSH_INT(5)
        SET_REG(RESULT_REGISTER)
        RETURN()

    @writer.LLILCode()
    def Outer(arg1: Value32):
        POP(WORD_SIZE)
        RETURN()

    @writer.LLILCode()
    def Main():
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('early')
        CALL(Inner)
        label('early')
        DEBUG_SET_LINENO(1)  # a call gets a debug record only after line info
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('outer')
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('inner')
        CALL(Inner)
        label('inner')
        GET_REG(RESULT_REGISTER)
        CALL(Outer)
        label('outer')
        PUSH_INT(SYSCALL_CONSTANT)
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('result')
        CALL(Inner)
        label('result')
        GET_REG(RESULT_REGISTER)
        SYSCALL(SYSCALL_SUBSYSTEM, SYSCALL_FUNC, 2)
        POP(2 * WORD_SIZE)
        PUSH_CALLER_FRAME('back')
        CALL_SCRIPT('this', 'Inner', 0)
        label('back')
        RETURN()

    @writer.LLILCode()
    def Tail():
        DEBUG_SET_LINENO(2)
        CALL_SCRIPT_NO_RETURN('mod', 'Tail', 0)

    writer.run({})


class TestWriterOnlyInputs(unittest.TestCase):
    '''What only the writer feeds the tracker - its DSL arguments, which the parser would never decode: a raw PUSH, a
    POP of a partial slot, UNKNOWN_28; and a CALL_SCRIPT with no caller frame below its arguments (unreachable code the
    compile check skips, or a branch inside the arguments)'''

    @classmethod
    def tracker_holding(cls, count: int) -> CallDebugInfoTracker:
        '''A tracker fed no call, with count constants on its stack'''
        tracker = CallDebugInfoTracker(get_param_count = lambda func: 0)
        for _ in range(count):
            tracker.on_opcode(ED9Opcode.PUSH_INT, [SYSCALL_CONSTANT], ScpValue(SYSCALL_CONSTANT))

        return tracker

    def test_raw_push_pushes_one_constant_with_its_payload(self):
        tracker = self.tracker_holding(0)
        value = ScpValue(RawInt(SYSCALL_CONSTANT))      # the writer's push gives the value and its pooled string (None)
        tracker.on_opcode(ED9Opcode.PUSH, [RawInt(SYSCALL_CONSTANT)], value, None)
        self.assertEqual(tracker.stack, [TrackedValue(ArgType.Constant, value)])

    def test_pop_of_a_partial_slot_pops_only_whole_slots(self):
        tracker = self.tracker_holding(2)
        tracker.on_opcode(ED9Opcode.POP, [WORD_SIZE + WORD_SIZE // 2])
        self.assertEqual(len(tracker.stack), 1)

    def test_unknown_28_changes_nothing(self):
        tracker = self.tracker_holding(1)
        before = list(tracker.stack)
        tracker.on_opcode(ED9Opcode.UNKNOWN_28, [b'\0'])
        self.assertEqual((tracker.stack, tracker.registers, tracker.frames, tracker.calls), (before, {}, [], []))

    @classmethod
    def call_script(cls, tracker: CallDebugInfoTracker, with_frame: bool):
        '''A CALL_SCRIPT of one argument, after its caller frame or after constants only'''
        if with_frame:
            tracker.on_opcode(ED9Opcode.PUSH_CALLER_FRAME, ['back'])

        else:
            for _ in range(CALLER_FRAME_SLOTS):
                tracker.on_opcode(ED9Opcode.PUSH_INT, [SYSCALL_CONSTANT], ScpValue(SYSCALL_CONSTANT))

        tracker.on_opcode(ED9Opcode.PUSH_INT, [SYSCALL_CONSTANT], ScpValue(SYSCALL_CONSTANT))
        tracker.on_opcode(ED9Opcode.CALL_SCRIPT, ['mod', 'Func', 1])

    @classmethod
    def script_call_warnings(cls, with_frame: bool) -> list[str]:
        warnings = []
        cls.call_script(CallDebugInfoTracker(get_param_count = lambda func: 0, warn = warnings.append), with_frame)
        return warnings

    def test_script_call_after_its_caller_frame_does_not_warn(self):
        self.assertEqual(self.script_call_warnings(with_frame = True), [])

    def test_script_call_without_a_caller_frame_warns(self):
        self.assertEqual(self.script_call_warnings(with_frame = False), [NO_CALLER_FRAME_WARNING])

    def test_a_tracker_logs_its_warnings_by_default(self):
        with self.assertLogs(log, 'WARNING') as logs:
            self.call_script(CallDebugInfoTracker(get_param_count = lambda func: 0), with_frame = False)

        self.assertEqual([record.getMessage() for record in logs.records], [NO_CALLER_FRAME_WARNING])


class TestCallTree(unittest.TestCase):
    '''Records in source pre-order: an outer call before the calls in its arguments, those in parameter order though the
    arguments are evaluated last first; each statement's calls in evaluation order'''

    def test_siblings_in_parameter_order(self):
        tracker = feed(LINE, local_call('pos', push(POS_CHR),
                                        *(nested(f'info{key}', push(INFO_CHR), push(key)) for key in INFO_KEYS)))
        self.assertEqual(targets(tracker), ['pos', *(f'info{key}' for key in INFO_KEYS)])

    def test_depth_two(self):
        '''wait(sub(rand(3, 4)))'''
        tracker = feed(LINE, local_call('wait', nested('sub', nested('rand', push(3), push(4)))))
        self.assertEqual(targets(tracker), ['wait', 'sub', 'rand'])

    def test_calls_in_a_binary_expression_argument_in_evaluation_order(self):
        '''g(f() + x())'''
        tracker = feed(LINE, local_call('g', nested('f') + nested('x') + [(ED9Opcode.ADD, [])]))
        f, x, g = tracker.calls
        self.assertEqual((constants(g.args), g.children), ([(ArgType.Expression, None)], [f, x]))
        self.assertEqual(tracker.ordered_calls(), [g, f, x])

    def test_a_call_in_a_unary_expression_argument(self):
        '''g(-f())'''
        tracker = feed(LINE, local_call('g', nested('f') + [(ED9Opcode.NEG, [])]))
        f, g = tracker.calls
        self.assertEqual((constants(g.args), g.children), ([(ArgType.Expression, None)], [f]))
        self.assertEqual(tracker.ordered_calls(), [g, f])

    def test_a_result_read_twice_is_adopted_once(self):
        '''x = f(); g(x, x), x read through register 0 twice'''
        tracker = feed(LINE, local_call('f'), local_call('g2', get_reg(), get_reg()))
        f, g = tracker.calls
        self.assertEqual((targets(tracker), g.children, f.parent), (['g2', 'f'], [f], g))


class TestLineGate(unittest.TestCase):
    '''A call gets a record only when it is made after line info'''

    def test_a_call_before_line_info_stays_unrecorded_when_a_recorded_call_takes_its_result(self):
        tracker = feed(local_call('f'), LINE, local_call('g', get_reg()))
        f, g = tracker.calls
        self.assertEqual((targets(tracker), g.children), (['g'], [f]))

    def test_a_call_set_up_before_line_info_and_made_after_it_has_a_record(self):
        tracker = feed(local_call('g', LINE + push(SAVED_VALUE)))
        self.assertEqual(targets(tracker), ['g'])


class TestRegisters(unittest.TestCase):
    '''A register holds the value last stored in it in address order; a returning call stores its result in
    register 0'''

    def test_a_tail_call_argument_parked_in_a_register(self):
        '''PUSH_FLOAT(0.2); SET_REG(1); POP(20); GET_REG(1); CALL_SCRIPT_NO_RETURN('', 'AniWait', 1): the previous
        line's call keeps its record first'''
        tracker = feed(LINE, local_call('speed', push(POS_CHR), push(ANIME_SPEED)),
                       LINE, push(TAIL_ARG), set_reg(TAIL_REGISTER), [(ED9Opcode.POP, [LOCALS_SIZE])],
                       get_reg(TAIL_REGISTER), tail_call(1))
        speed, tail = tracker.calls
        self.assertEqual(tracker.ordered_calls(), [speed, tail])
        self.assertEqual(constants(tail.args), [(ArgType.Constant, TAIL_ARG)])

    def test_several_registers_keep_each_argument(self):
        '''A tail call of three arguments, pushed last first: SET_REG(1..3) park them top first, GET_REG(3..1) push them
        back'''
        tracker = feed(LINE, push(THIRD_ARG), nested('f'), push(FIRST_ARG), set_reg(1), set_reg(2), set_reg(3),
                       get_reg(3), get_reg(2), get_reg(1), tail_call(3))
        f, tail = tracker.calls
        self.assertEqual(constants(tail.args), [(ArgType.Constant, FIRST_ARG), (ArgType.CallResult, None),
                                                (ArgType.Constant, THIRD_ARG)])
        self.assertEqual(tracker.ordered_calls(), [tail, f])

    def test_each_returning_call_leaves_its_result_in_register_zero(self):
        for name, made in (('CALL', local_call('f')), ('CALL_SCRIPT', script_call(0)), ('SYSCALL', syscall(0))):
            with self.subTest(call = name):
                tracker = feed(LINE, local_call('x'), made, local_call('g', get_reg()))
                _, call, g = tracker.calls
                self.assertEqual(g.children, [call])

    def test_a_tail_call_leaves_register_zero(self):
        tracker = feed(LINE, local_call('x'), tail_call(0), local_call('g', get_reg()))
        x, _, g = tracker.calls
        self.assertEqual(g.children, [x])

    def test_an_unset_register_reads_as_a_result_of_no_call(self):
        tracker = feed(LINE, local_call('x'), local_call('g', get_reg(UNSET_REGISTER)))
        _, g = tracker.calls
        self.assertEqual((constants(g.args), g.children), ([(ArgType.CallResult, None)], []))

    def test_a_register_set_in_both_branch_arms_reads_the_later_arm(self):
        '''r1 = f() if c else SAVED_VALUE; g(r1): replay reads both arms in a row, so g gets the later arm's constant
        and f stays a statement of its own (compiler provenance in address order, not path dataflow)'''
        tracker = feed(LINE, push(0), [(ED9Opcode.POP_JMP_ZERO, ['else'])], nested('f'), set_reg(TAIL_REGISTER),
                       [(ED9Opcode.JMP, ['end'])], push(SAVED_VALUE), set_reg(TAIL_REGISTER),
                       local_call('g', get_reg(TAIL_REGISTER)))
        f, g = tracker.calls
        self.assertEqual((constants(g.args), g.children), ([(ArgType.Constant, SAVED_VALUE)], []))
        self.assertEqual(tracker.ordered_calls(), [f, g])

    def test_a_register_set_in_one_branch_arm_is_read_after_the_join(self):
        '''if c: r1 = f() else: x(); g(r1): replay reads straight through the JMP, so g takes f's result from the arm
        before it (compiler provenance in address order, not path dataflow)'''
        tracker = feed(LINE, push(0), [(ED9Opcode.POP_JMP_ZERO, ['else'])], nested('f'), set_reg(TAIL_REGISTER),
                       [(ED9Opcode.JMP, ['end'])], local_call('x'), local_call('g', get_reg(TAIL_REGISTER)))
        f, x, g = tracker.calls
        self.assertEqual((constants(g.args), g.children), ([(ArgType.CallResult, None)], [f]))
        self.assertEqual(tracker.ordered_calls(), [x, g, f])

    def test_a_nonzero_register_keeps_its_value_across_a_call(self):
        tracker = feed(LINE, push(SAVED_VALUE), set_reg(TAIL_REGISTER), local_call('x'),
                       local_call('g', get_reg(TAIL_REGISTER)))
        self.assertEqual(constants(tracker.calls[-1].args), [(ArgType.Constant, SAVED_VALUE)])


def compile_siblings(dat: Path):
    '''Siblings calls Pos(POS_CHR, Info(INFO_CHR, key) for each of INFO_KEYS), its arguments pushed last first'''
    writer = fresh_writer(dat)

    @writer.LLILCode()
    def Info(arg1: Value32, arg2: Value32):
        PUSH_INT(INFO_RESULT)
        SET_REG(RESULT_REGISTER)
        POP(2 * WORD_SIZE)
        RETURN()

    @writer.LLILCode()
    def Pos(arg1: Value32, arg2: Value32, arg3: Value32, arg4: Value32, arg5: Value32):
        POP(PARAM_COUNTS['pos'] * WORD_SIZE)
        RETURN()

    @writer.LLILCode()
    def Siblings():
        DEBUG_SET_LINENO(1)
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('pos')
        for key in reversed(INFO_KEYS):
            PUSH_CURRENT_FUNC_ID()
            PUSH_RET_ADDR(f'info{key}')
            PUSH_INT(key)
            PUSH_INT(INFO_CHR)
            CALL(Info)
            label(f'info{key}')
            GET_REG(RESULT_REGISTER)

        PUSH_INT(POS_CHR)
        CALL(Pos)
        label('pos')
        RETURN()

    writer.run({})


class TestWriterRecordOrder(unittest.TestCase):
    '''The writer's records in the file, read back raw (not through the tracker that wrote them): the outer call, then
    the calls in its arguments in parameter order'''

    def test_siblings_in_parameter_order(self):
        dat = Path(self.enterContext(tempfile.TemporaryDirectory())) / 'siblings.dat'
        compile_siblings(dat)
        ctx = load_script(dat)
        self.addCleanup(ctx.fs.Close)
        functions = {func.name: func for func in ctx.parser.functions}
        records = dict(zip(functions, ctx.records))
        pos, *infos = records['Siblings']
        self.assertEqual(pos.func_id, functions['Pos'].index)
        self.assertEqual([record_args(ctx.data, record)[1][1] for record in infos],
                         [ScpValue(key).to_word() for key in INFO_KEYS])


class CompiledScript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dat = Path(cls.enterClassContext(tempfile.TemporaryDirectory())) / 'test.dat'
        compile_script(cls.dat)
        cls.ctx = load_script(cls.dat)
        cls.addClassCleanup(cls.ctx.fs.Close)
        cls.parser = cls.ctx.parser
        cls.data = cls.ctx.data
        names = [func.name for func in cls.parser.functions]
        cls.records = dict(zip(names, cls.ctx.records))
        cls.instructions = dict(zip(names, cls.ctx.instructions))

    def replay(self, name: str) -> list:
        return CallDebugInfoTracker.replay(self.instructions[name], self.parser.get_func_argc)

    def call_offsets(self, name: str) -> list[int]:
        '''Offsets of the function's call instructions, in address order'''
        return [inst.offset for inst in self.instructions[name] if inst.opcode in CALL_OPCODES]


class TestReplay(CompiledScript):
    def test_calls_in_record_order_with_their_instruction(self):
        early, inner, outer, result, syscall, script = self.call_offsets('Main')
        pairs = [(call.call_type, offset) for call, offset in self.replay('Main')]
        self.assertEqual(pairs, [(CallType.Local, outer), (CallType.Local, inner), (CallType.Syscall, syscall),
                                 (CallType.Local, result), (CallType.Script, script)])

    def test_call_before_line_info_has_no_record(self):
        early = self.call_offsets('Main')[0]
        self.assertNotIn(early, [offset for _, offset in self.replay('Main')])

    def test_tail_call(self):
        [(call, offset)] = self.replay('Tail')
        self.assertEqual((call.call_type, offset), (CallType.ScriptNoReturn, self.call_offsets('Tail')[0]))

    def test_every_record_matches_its_call(self):
        for name, records in self.records.items():
            with self.subTest(function = name):
                pairs = self.replay(name)
                self.assertEqual(len(pairs), len(records))
                self.assertEqual([record_mismatch(self.data, call, record) for (call, _), record in zip(pairs, records)],
                                 [None] * len(records))


class TestRecordMismatch(CompiledScript):
    def setUp(self):
        self.pairs = self.replay('Main')
        self.main_records = self.records['Main']

    def test_record_args(self):
        syscall_record = self.main_records[2]
        self.assertEqual(record_args(self.data, syscall_record), [
            (ArgType.Constant, ScpValue(SYSCALL_SUBSYSTEM).to_word()),
            (ArgType.Constant, ScpValue(SYSCALL_FUNC).to_word()),
            (ArgType.CallResult, ScpValue(RawInt(0)).to_word()),
            (ArgType.Constant, ScpValue(SYSCALL_CONSTANT).to_word()),
        ])

    def test_misordered_pair(self):
        outer_call, _ = self.pairs[0]
        # A local call is compared on as many args as the record keeps (trailing defaults may be dropped)
        self.assertEqual(record_mismatch(self.data, outer_call, self.main_records[1]),
                         'record (Local, func_id 0x0, 0 args) != call (Local, func_id 0x2, 0 args)')

    def test_constant_value(self):
        syscall_call, _ = self.pairs[2]
        other_func = dataclasses.replace(syscall_call, target = (SYSCALL_SUBSYSTEM, SYSCALL_FUNC + 1))
        self.assertEqual(record_mismatch(self.data, other_func, self.main_records[2]),
                         f'arg 1: value 0x{ScpValue(SYSCALL_FUNC).to_word():08X} != {SYSCALL_FUNC + 1}')

    def test_string_by_text(self):
        script_call, _ = self.pairs[4]
        module, func = script_call.target
        other_module = dataclasses.replace(script_call, target = (ScpValue('that'), func))
        self.assertIsNone(record_mismatch(self.data, script_call, self.main_records[4]))
        self.assertRegex(record_mismatch(self.data, other_module, self.main_records[4]), r"^arg 0: value 0x[0-9A-F]{8} != 'that\.Inner'$")

    def test_string_by_text_wherever_pooled(self):
        '''A record string with the call's text matches at any pool offset; other text doesn't'''
        script_call, _ = self.pairs[4]
        record = self.main_records[4]
        name_word = record.arg_offsets()[0]
        for text, problem in (('this.Inner', None), ('this.Outer', "'this.Inner'")):
            with self.subTest(text = text):
                data = bytearray(self.data)
                copy_word = ScpValue.Type.String << ScpValue.TYPE_SHIFT | len(data)
                data += text.encode() + b'\0'
                data[name_word:name_word + WORD_SIZE] = copy_word.to_bytes(WORD_SIZE, default_endian())
                expected = problem and f'arg 0: value 0x{copy_word:08X} != {problem}'
                self.assertEqual(record_mismatch(bytes(data), script_call, record), expected)

    def with_constant(self, value: ScpValue) -> tuple:
        '''The syscall's call with its constant argument (record arg 3) replaced by value, and the syscall's record'''
        syscall_call, _ = self.pairs[2]
        result, _ = syscall_call.args
        call = dataclasses.replace(syscall_call, args = [result, TrackedValue(ArgType.Constant, value)])
        return call, self.main_records[2]

    def test_raw_and_integer_differ(self):
        call, record = self.with_constant(ScpValue(RawInt(SYSCALL_CONSTANT)))
        self.assertEqual(record_mismatch(self.data, call, record),
                         f'arg 3: value 0x{ScpValue(SYSCALL_CONSTANT).to_word():08X} != {RawInt(SYSCALL_CONSTANT)!r}')

    def test_float_by_encoded_word(self):
        '''+0.0 and -0.0 are equal floats but different words'''
        zero_word = ScpValue(0.0).to_word()
        for value, problem in ((0.0, None), (-0.0, f'arg 3: value 0x{zero_word:08X} != -0.0')):
            with self.subTest(value = value):
                call, record = self.with_constant(ScpValue(value))
                data = bytearray(self.data)
                position = record.arg_offsets()[3]
                data[position:position + WORD_SIZE] = zero_word.to_bytes(WORD_SIZE, default_endian())
                self.assertEqual(record_mismatch(bytes(data), call, record), problem)

    def test_non_constant_argument(self):
        syscall_call, _ = self.pairs[2]
        record = self.main_records[2]
        result_arg = record.arg_offsets()[2]
        for name, position, word, problem in (
            ('value', result_arg, 1, 'arg 2: value 0x00000001 != None'),
            ('type', result_arg + WORD_SIZE, ArgType.Constant, f'arg 2: type {int(ArgType.Constant)} != {ArgType.CallResult}'),
        ):
            with self.subTest(changed = name):
                data = bytearray(self.data)
                data[position:position + WORD_SIZE] = word.to_bytes(WORD_SIZE, default_endian())
                self.assertEqual(record_mismatch(bytes(data), syscall_call, record), problem)

    def test_local_call_without_return_label(self):
        '''Content only: the label rule (the writer keys trimmed args by it) stays with the validator'''
        outer_call, _ = self.pairs[0]
        no_label = dataclasses.replace(outer_call, ret_label = None)
        self.assertIsNone(record_mismatch(self.data, no_label, self.main_records[0]))
        self.assertEqual(compare_record(self.ctx, no_label, self.main_records[0]), 'local CALL without a PUSH_RET_ADDR label')
        self.assertIsNone(compare_record(self.ctx, outer_call, self.main_records[0]))

        # The label rule comes first: a record whose content differs too still reports the label
        self.assertEqual(compare_record(self.ctx, no_label, self.main_records[1]), 'local CALL without a PUSH_RET_ADDR label')


class TestFunctionExtents(CompiledScript):
    def test_extents_follow_code_order(self):
        '''The table is sorted by name (Inner, Main, Outer, Tail), the code is in source order (Inner, Outer, Main, Tail)'''
        offsets = {func.name: func.offset for func in self.parser.functions}
        indices = {func.name: func.index for func in self.parser.functions}
        self.assertEqual(function_extents(self.parser.function_entries, CODE_END), {
            indices['Inner']    : (offsets['Inner'], offsets['Outer']),
            indices['Outer']    : (offsets['Outer'], offsets['Main']),
            indices['Main']     : (offsets['Main'], offsets['Tail']),
            indices['Tail']     : (offsets['Tail'], CODE_END),
        })

    def test_equal_starts_share_a_range(self):
        '''An empty function starts where the next one does: both get the range up to the next different start'''
        entries = [ScpFunctionEntry() for _ in range(3)]
        for entry, offset in zip(entries, (NEXT_START, SHARED_START, SHARED_START)):
            entry.offset = offset

        extents = function_extents(entries, CODE_END)
        self.assertEqual(list(extents.items()), [(1, (SHARED_START, NEXT_START)), (2, (SHARED_START, NEXT_START)),
                                                 (0, (NEXT_START, CODE_END))])


if __name__ == '__main__':
    unittest.main()
