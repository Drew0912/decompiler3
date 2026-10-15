#!/usr/bin/env python3
'''Unit tests for pairing call-site debug records with their calls: CallDebugInfoTracker (its call tree, registers and
line gate; replay's record order and each call's instruction offset), falcom/ed9/parser/call_debug_records.py
(canonical_argc, record_args, record_mismatch, script_call_identity), a local call's count on its CALL through a
round trip, function_extents, and the round-trip validator's record comparison built on them.'''

from pathlib import Path
import copy
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
from falcom.ed9.parser.call_debug_records import (CallDebugInfoTracker, TrackedValue, canonical_argc, record_args,
                                                  record_mismatch, script_call_identity)
from falcom.ed9.parser.code_layout import function_extents
from falcom.ed9.parser.string_pool import NUL, read_text, string_offset
from falcom.ed9.parser.types_scp import RawInt, ScpFunctionCallDebugInfo, ScpFunctionCallDebugInfoArg, ScpFunctionEntry, ScpValue
from falcom.ed9.writer.scp_writer_helper import *
from scp_roundtrip_validator import (PUSH_VALUE_OFFSET, Status, check_round_trip, compare_file_records,
                                     decompile_to_python, describe_difference, load_script)
from tests.shared.corpus import SORA2_SCRIPTS, require
from tests.shared.scp_writer_test_utils import fresh_writer

CallType = ScpFunctionCallDebugInfo.CallType
ArgType = ScpFunctionCallDebugInfoArg.Type
NO_FUNC_ID = ScpFunctionCallDebugInfo.NO_FUNC_ID
INVALID_CALL_TYPE = len(CallType)
EXTRA_FUNCTION = 'AFirst'           # compile_script's extra function
UNDEFINED_FUNCTION = 'Nowhere'
# The smallest sora2_1.0 script with a tail call into itself; 37 of its records drop trailing default arguments
SAME_SCRIPT_TAIL_CALL_FILE = SORA2_SCRIPTS / 'ani/mon5265_C.dat'
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


def compile_script(dat: Path, extra_function: bool = False):
    '''Main's records are in source order, not address order: Outer's record comes before the Inner call in its argument,
    and the SYSCALL's before the Inner call whose result it takes. Main's first call is made before any line info, so it
    has no record. Defined in source order Inner, Outer, Main, Tail; the table is sorted by name. extra_function adds
    EXTRA_FUNCTION, whose name sorts first: every table id and every debug string's pool offset shifts.'''
    writer = fresh_writer(dat)

    if extra_function:
        @writer.LLILCode()
        def AFirst():
            RETURN()

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


def compile_tail_calls(dat: Path):
    '''Tail calls into this script to a function defined before them in source (Earlier), one defined after (Later) and
    one it doesn't define; tail calls to 'this' and 'common'; and a CALL_SCRIPT into this script'''
    writer = fresh_writer(dat)

    @writer.LLILCode()
    def Earlier():
        DEBUG_SET_LINENO(1)
        RETURN()

    @writer.LLILCode()
    def ToEarlier():
        DEBUG_SET_LINENO(2)
        CALL_SCRIPT_NO_RETURN('', 'Earlier', 0)

    @writer.LLILCode()
    def ToLater():
        DEBUG_SET_LINENO(3)
        CALL_SCRIPT_NO_RETURN('', 'Later', 0)

    @writer.LLILCode()
    def ToNowhere():
        DEBUG_SET_LINENO(4)
        CALL_SCRIPT_NO_RETURN('', UNDEFINED_FUNCTION, 0)

    @writer.LLILCode()
    def ToThis():
        DEBUG_SET_LINENO(5)
        CALL_SCRIPT_NO_RETURN('this', 'Earlier', 0)

    @writer.LLILCode()
    def ToCommon():
        DEBUG_SET_LINENO(6)
        CALL_SCRIPT_NO_RETURN('common', 'Earlier', 0)

    @writer.LLILCode()
    def ScriptCall():
        DEBUG_SET_LINENO(7)
        PUSH_CALLER_FRAME('back')
        CALL_SCRIPT('', 'Earlier', 0)
        label('back')
        RETURN()

    @writer.LLILCode()
    def Later():
        DEBUG_SET_LINENO(8)
        RETURN()

    writer.run({})


def compile_counts(dat: Path):
    '''mp4000_ev EV_03_62_01's shape: two calls with identical bytes, the first as the compiler's rule leaves it
    (SetAuto(1)), the second written out in full (SetAuto(1, 0): debug_argc = 2)'''
    writer = fresh_writer(dat)

    @writer.LLILCode()
    def SetAuto(arg1: Value32, arg2: Value32 = 0):
        POP(2 * WORD_SIZE)
        RETURN()

    @writer.LLILCode()
    def Main():
        DEBUG_SET_LINENO(1)
        for ret, keywords in (('by_rule', {}), ('written_out', {'debug_argc': 2})):
            PUSH_CURRENT_FUNC_ID()
            PUSH_RET_ADDR(ret)
            PUSH_INT(0)
            PUSH_INT(1)
            CALL(SetAuto, **keywords)
            label(ret)

        RETURN()

    writer.run({})


def constant(value: int | float | str | RawInt) -> TrackedValue:
    return TrackedValue(ArgType.Constant, ScpValue(value))


class TestCanonicalArgc(unittest.TestCase):
    '''The compiler's rule: trailing constants equal to the callee's defaults (by type and encoded word, a string by its
    text) are dropped, up to the first that isn't one'''
    VARIABLE = TrackedValue(ArgType.Variable)
    DEFAULTS = [None, ScpValue(1), ScpValue(2.0)]

    def test_rule(self):
        cases = {
            'every default left out': ([constant(5), constant(1), constant(2.0)], self.DEFAULTS, 1),
            'the last one differs': ([constant(5), constant(1), constant(3.0)], self.DEFAULTS, 3),
            'a differing one stops the walk': ([constant(5), constant(7), constant(2.0)], self.DEFAULTS, 2),
            'a non-constant stops the walk': ([constant(5), self.VARIABLE, constant(2.0)], self.DEFAULTS, 2),
            'a non-constant is kept': ([constant(5), constant(1), self.VARIABLE], self.DEFAULTS, 3),
            'Integer for a Float default': ([constant(5), constant(1), constant(2)], self.DEFAULTS, 3),
            'Raw for an Integer default': ([constant(5), constant(RawInt(1))], [None, ScpValue(1)], 2),
            '-0.0 for a +0.0 default': ([constant(-0.0)], [ScpValue(0.0)], 1),
            '+0.0 for a +0.0 default': ([constant(0.0)], [ScpValue(0.0)], 0),
            'a string by its text': ([constant('a')], [ScpValue('a')], 0),
            'another string': ([constant('b')], [ScpValue('a')], 1),
            'an Integer for a string default': ([constant(0)], [ScpValue('')], 1),     # a String has no word to compare
            'no defaults': ([constant(1), constant(2)], [None, None], 2),
            'fewer defaults than args': ([constant(1)], [], 1),
            'more defaults than args': ([constant(1)], [ScpValue(1), ScpValue(1)], 1),
        }
        for case, (args, defaults, expected) in cases.items():
            with self.subTest(case):
                self.assertEqual(canonical_argc(args, defaults), expected)


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


class TestScriptCallIdentity(unittest.TestCase):
    '''A tail call into the same script names the bare function and its table index (NO_FUNC_ID when the script doesn't
    define it); every other script call 'module.func' and NO_FUNC_ID'''

    TABLE = {'First': 0, 'Loop': 3}

    def test_rule(self):
        tail, script = CallType.ScriptNoReturn, CallType.Script
        for name, call_type, module, func, expected in (
            ('tail call, defined',      tail,   '',         'Loop',     (3, 'Loop')),
            ('tail call, index 0',      tail,   '',         'First',    (0, 'First')),
            ('tail call, undefined',    tail,   '',         'Nowhere',  (NO_FUNC_ID, 'Nowhere')),
            ("tail call, 'this'",       tail,   'this',     'Loop',     (NO_FUNC_ID, 'this.Loop')),
            ("tail call, 'common'",     tail,   'common',   'Loop',     (NO_FUNC_ID, 'common.Loop')),
            ('tail call, other script', tail,   'btlcom',   'Loop',     (NO_FUNC_ID, 'btlcom.Loop')),
            ("CALL_SCRIPT, ''",         script, '',         'Loop',     (NO_FUNC_ID, '.Loop')),
        ):
            with self.subTest(name):
                self.assertEqual(script_call_identity(call_type, module, func, self.TABLE.get), expected)

    def test_writer_records_read_back(self):
        '''Each function's one record as the writer wrote it, and the content check passes every one'''
        dat = Path(self.enterContext(tempfile.TemporaryDirectory())) / 'tail_calls.dat'
        compile_tail_calls(dat)
        ctx = load_script(dat)
        self.addCleanup(ctx.fs.Close)
        index = ctx.parser.get_func_index
        expected = {
            'ToEarlier'     : (index('Earlier'), 'Earlier'),
            'ToLater'       : (index('Later'), 'Later'),
            'ToNowhere'     : (NO_FUNC_ID, UNDEFINED_FUNCTION),
            'ToThis'        : (NO_FUNC_ID, 'this.Earlier'),
            'ToCommon'      : (NO_FUNC_ID, 'common.Earlier'),
            'ScriptCall'    : (NO_FUNC_ID, '.Earlier'),
        }
        for name, identity in expected.items():
            with self.subTest(function = name):
                func_index = index(name)
                [record] = ctx.records[func_index]
                _, name_word = record_args(ctx.data, record)[0]
                self.assertEqual((record.func_id, read_text(ctx.data, string_offset(name_word))), identity)
                [(call, _)] = CallDebugInfoTracker.replay(ctx.instructions[func_index], ctx.parser.get_func_argc)
                self.assertIsNone(record_mismatch(ctx.data, call, record, index))


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

    def mismatch(self, data: bytes, call, record: ScpFunctionCallDebugInfo) -> str | None:
        return record_mismatch(data, call, record, self.parser.get_func_index)


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
                self.assertEqual([self.mismatch(self.data, call, record) for (call, _), record in zip(pairs, records)],
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
        self.assertEqual(self.mismatch(self.data, outer_call, self.main_records[1]),
                         'record (Local, func_id 0x0, 0 args) != call (Local, func_id 0x2, 0 args)')

    def test_constant_value(self):
        syscall_call, _ = self.pairs[2]
        other_func = dataclasses.replace(syscall_call, target = (SYSCALL_SUBSYSTEM, SYSCALL_FUNC + 1))
        self.assertEqual(self.mismatch(self.data, other_func, self.main_records[2]),
                         f'arg 1: value 0x{ScpValue(SYSCALL_FUNC).to_word():08X} != {SYSCALL_FUNC + 1}')

    def test_string_by_text(self):
        script_call, _ = self.pairs[4]
        module, func = script_call.target
        other_module = dataclasses.replace(script_call, target = (ScpValue('that'), func))
        self.assertIsNone(self.mismatch(self.data, script_call, self.main_records[4]))
        self.assertRegex(self.mismatch(self.data, other_module, self.main_records[4]),
                         r"^arg 0: value 0x[0-9A-F]{8} != 'that\.Inner'$")

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
                self.assertEqual(self.mismatch(bytes(data), script_call, record), expected)

    def with_constant(self, value: ScpValue) -> tuple:
        '''The syscall's call with its constant argument (record arg 3) replaced by value, and the syscall's record'''
        syscall_call, _ = self.pairs[2]
        result, _ = syscall_call.args
        call = dataclasses.replace(syscall_call, args = [result, TrackedValue(ArgType.Constant, value)])
        return call, self.main_records[2]

    def test_raw_and_integer_differ(self):
        call, record = self.with_constant(ScpValue(RawInt(SYSCALL_CONSTANT)))
        self.assertEqual(self.mismatch(self.data, call, record),
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
                self.assertEqual(self.mismatch(bytes(data), call, record), problem)

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
                self.assertEqual(self.mismatch(bytes(data), syscall_call, record), problem)

    def test_local_call_without_return_label(self):
        '''Content only: a local call's count rides on its CALL, so the record needs no return label'''
        outer_call, _ = self.pairs[0]
        no_label = dataclasses.replace(outer_call, ret_label = None)
        self.assertIsNone(self.mismatch(self.data, no_label, self.main_records[0]))


class TestRecordComparison(CompiledScript):
    '''The round-trip validator's record comparison of an original file (compile_script's) and a rebuilt one (a patched
    copy): each function's first difference, compared as stored - every argument's encoded word, strings by text'''

    @classmethod
    def with_word(cls, data: bytes, position: int, word: int) -> bytes:
        return data[:position] + word.to_bytes(WORD_SIZE, default_endian()) + data[position + WORD_SIZE:]

    @classmethod
    def with_string(cls, data: bytes, position: int, text: str) -> bytes:
        '''data with the String word at position pointing at text, appended after the pool'''
        word = ScpValue.Type.String << ScpValue.TYPE_SHIFT | len(data)
        return cls.with_word(data + text.encode() + NUL, position, word)

    def with_record(self, data: bytes, name: str, i: int, **fields) -> bytes:
        '''data with the function's record i rewritten, fields replaced'''
        record = self.records[name][i]
        values = dict(func_id = record.func_id, call_type = record.call_type, arg_count = record.arg_count,
                      info_offset = record.info_offset) | fields
        size = ScpFunctionCallDebugInfo.SIZE
        position = self.parser.function_entries[self.parser.get_func_index(name)].debug_info_offset + i * size
        return data[:position] + ScpFunctionCallDebugInfo.pack(**values) + data[position + size:]

    def with_record_count(self, name: str, delta: int) -> bytes:
        index = self.parser.get_func_index(name)
        entry = copy.copy(self.parser.function_entries[index])
        entry.debug_info_count += delta
        position = self.parser.header.function_entry_offset + index * ScpFunctionEntry.SIZE
        return self.data[:position] + entry.to_bytes() + self.data[position + ScpFunctionEntry.SIZE:]

    def syscall_constant(self) -> int:
        '''Position of the syscall record's constant argument (Int(SYSCALL_CONSTANT))'''
        return self.records['Main'][2].arg_offsets()[3]

    def test_identical_files(self):
        self.assertEqual(compare_file_records(self.data, self.data), [])

    def test_argument_count(self):
        for delta, line in ((-1, 'Main record 2: 3 args, original 4'), (1, 'Main record 2: 5 args, original 4')):
            with self.subTest(delta = delta):
                rebuilt = self.with_record(self.data, 'Main', 2, arg_count = self.records['Main'][2].arg_count + delta)
                self.assertEqual(compare_file_records(self.data, rebuilt), [line])

    def test_missing_and_extra_record(self):
        fewer = self.with_record_count('Main', -1)
        self.assertEqual(compare_file_records(self.data, fewer),
                         ["Main record 4: missing (original Script 'this.Inner', 1 args)"])
        self.assertEqual(compare_file_records(fewer, self.data), ["Main record 4: extra (Script 'this.Inner', 1 args)"])

    def test_call_type(self):
        rebuilt = self.with_record(self.data, 'Tail', 0, call_type = CallType.Script)
        self.assertEqual(compare_file_records(self.data, rebuilt), ['Tail record 0: Script, original ScriptNoReturn'])

    def test_callee(self):
        inner = self.parser.get_func_index('Inner')
        for name, line in (('Main', 'Main record 0: callee Inner, original Outer'),
                           ('Tail', 'Tail record 0: callee Inner, original none')):
            with self.subTest(function = name):
                rebuilt = self.with_record(self.data, name, 0, func_id = inner)
                self.assertEqual(compare_file_records(self.data, rebuilt), [line])

    def test_constant_value(self):
        rebuilt = self.with_word(self.data, self.syscall_constant(), ScpValue(SYSCALL_CONSTANT + 1).to_word())
        self.assertEqual(compare_file_records(self.data, rebuilt),
                         [f'Main record 2: arg 3 Int({SYSCALL_CONSTANT + 1}), original Int({SYSCALL_CONSTANT})'])

    def test_raw_and_integer_differ(self):
        rebuilt = self.with_word(self.data, self.syscall_constant(), ScpValue(RawInt(SYSCALL_CONSTANT)).to_word())
        self.assertEqual(compare_file_records(self.data, rebuilt),
                         [f'Main record 2: arg 3 Raw(0x{SYSCALL_CONSTANT:X}), original Int({SYSCALL_CONSTANT})'])

    def test_signed_zeros_differ(self):
        '''+0.0 and -0.0 are equal floats but different words'''
        original = self.with_word(self.data, self.syscall_constant(), ScpValue(0.0).to_word())
        rebuilt = self.with_word(self.data, self.syscall_constant(), ScpValue(-0.0).to_word())
        self.assertEqual(compare_file_records(original, rebuilt),
                         ['Main record 2: arg 3 Float(-0.0), original Float(0.0)'])

    def test_script_call_name(self):
        '''Two records with no callee id, the same call type and count, differing only in the script call's name - as
        an undefined tail callee's record did with a leading dot'''
        name = self.records['Tail'][0].arg_offsets()[0]
        original = self.with_string(self.data, name, UNDEFINED_FUNCTION)
        rebuilt = self.with_string(self.data, name, f'.{UNDEFINED_FUNCTION}')
        self.assertEqual(compare_file_records(original, rebuilt),
                         [f"Tail record 0: arg 0 '.{UNDEFINED_FUNCTION}', original '{UNDEFINED_FUNCTION}'"])

    def test_string_by_text_wherever_pooled(self):
        rebuilt = self.with_string(self.data, self.records['Main'][4].arg_offsets()[0], 'this.Inner')
        self.assertEqual(compare_file_records(self.data, rebuilt), [])

    def test_summary_with_identical_records(self):
        '''A byte outside the records differs: Inner's PUSH_INT operand'''
        operand = self.parser.get_func_by_name('Inner').offset + PUSH_VALUE_OFFSET
        rebuilt = self.with_word(self.data, operand, ScpValue(SAVED_VALUE).to_word())
        self.assertNotEqual(rebuilt, self.data)
        summary, lines = describe_difference(self.data, rebuilt)
        self.assertEqual((summary.split(', ')[-1], lines), ('records identical', []))

    def test_summary_counts_functions(self):
        twice_in_main = self.with_record(self.with_record(self.data, 'Main', 0, func_id = NO_FUNC_ID), 'Main', 2,
                                         arg_count = 0)
        in_main_and_tail = self.with_record(twice_in_main, 'Tail', 0, call_type = CallType.Script)
        for rebuilt, ending, line_count in ((twice_in_main, 'records differ in 1 function', 1),
                                            (in_main_and_tail, 'records differ in 2 functions', 2)):
            with self.subTest(ending = ending):
                summary, lines = describe_difference(self.data, rebuilt)
                self.assertEqual((summary.split(', ')[-1], len(lines)), (ending, line_count))

    def test_unreadable_records_keep_the_summary(self):
        rebuilt = self.with_record(self.data, 'Main', 0, call_type = INVALID_CALL_TYPE)
        summary, lines = describe_difference(self.data, rebuilt)
        self.assertRegex(summary,
                         r'^differs at 0x[0-9A-F]+ \(original \d+ bytes, rebuilt \d+ bytes\), records unreadable$')
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith('records unreadable: '), lines[0])


class TestShiftedTable(unittest.TestCase):
    '''compile_script with and without EXTRA_FUNCTION, whose name sorts first: every table id and debug string offset
    shifts, yet the shared functions' records compare equal - callees by name, strings by text'''

    @classmethod
    def setUpClass(cls):
        work = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        compile_script(work / 'base.dat')
        compile_script(work / 'extra.dat', extra_function = True)
        cls.base = (work / 'base.dat').read_bytes()
        cls.extra = (work / 'extra.dat').read_bytes()

    def test_only_the_extra_function_differs(self):
        self.assertEqual(compare_file_records(self.base, self.extra), [f'{EXTRA_FUNCTION}: not in the original'])
        self.assertEqual(compare_file_records(self.extra, self.base), [f'{EXTRA_FUNCTION}: not in the rebuilt file'])

    def test_ids_and_string_offsets_did_shift(self):
        '''The fixture's premise: Main's local callee id and the script call's name word differ between the files'''
        words = []
        for data in (self.base, self.extra):
            with tempfile.TemporaryDirectory() as tmp:
                dat = Path(tmp) / 'script.dat'
                dat.write_bytes(data)
                ctx = load_script(dat)
                ctx.fs.Close()

            main = ctx.records[ctx.parser.get_func_index('Main')]
            words.append((main[0].func_id, record_args(data, main[4])[0][1]))

        (base_id, base_name), (extra_id, extra_name) = words
        self.assertNotEqual(base_id, extra_id)
        self.assertNotEqual(base_name, extra_name)


class TestRealRoundTrip(unittest.TestCase):
    def test_a_same_script_tail_call_rebuilds_identical(self):
        '''Its tail call's record has the callee's table index and bare name; a failure shows the record comparison'''
        path = require(SAME_SCRIPT_TAIL_CALL_FILE)
        result = check_round_trip(path, Path(self.enterContext(tempfile.TemporaryDirectory())))
        self.assertEqual(result.status, Status.PASS, '\n'.join([result.summary, *result.details]))


class TestCountsOnTheCall(unittest.TestCase):
    '''A local call's record count rides on its CALL, written only where it isn't the compiler's rule: two calls with
    identical bytes keep their own counts through a round trip'''

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(cls.enterClassContext(tempfile.TemporaryDirectory()))
        cls.dat = cls.tmp / 'counts.dat'
        compile_counts(cls.dat)

    def test_records(self):
        ctx = load_script(self.dat)
        self.addCleanup(ctx.fs.Close)
        records = dict(zip([func.name for func in ctx.parser.functions], ctx.records))
        self.assertEqual([record.arg_count for record in records['Main']], [1, 2])

    def test_round_trip_py_writes_the_count_on_its_call(self):
        py_path = self.tmp / 'counts.py'
        _, functions = decompile_to_python(self.dat, py_path)
        main = next(func for func in functions if func.name == 'Main')
        first, second = sorted(main.call_written_argc)
        self.assertEqual(main.call_written_argc, {first: 1, second: 2})
        self.assertEqual(main.call_debug_argc, {second: 2})

        lines = [line.strip() for line in py_path.read_text().splitlines()]
        self.assertEqual([line for line in lines if line.startswith('CALL(')],
                         ['CALL(SetAuto)', 'CALL(SetAuto, debug_argc = 2)'])
        self.assertNotIn('debug_argc = {', '\n'.join(lines))

    def test_rebuilds_identical(self):
        result = check_round_trip(self.dat, Path(self.enterContext(tempfile.TemporaryDirectory())))
        self.assertEqual(result.status, Status.PASS, '\n'.join([result.summary, *result.details]))


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
