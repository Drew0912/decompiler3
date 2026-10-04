#!/usr/bin/env python3
'''Unit tests for pairing call-site debug records with their calls: CallDebugInfoTracker.replay (record order, each call's
instruction offset), falcom/ed9/parser/call_records.py (record_args, record_mismatch), function_extents, and the
round-trip validator's compare_record built on them.'''

from pathlib import Path
import dataclasses
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / 'tools'))
sys.path.insert(0, str(Path(__file__).parent))

from common.config import default_endian
from ir.llil import WORD_SIZE
from falcom.ed9.disasm import ED9Opcode
from falcom.ed9.parser.call_records import record_args, record_mismatch
from falcom.ed9.parser.code_layout import function_extents
from falcom.ed9.parser.scp import CallDebugInfoTracker
from falcom.ed9.parser.types_scp import RawInt, ScpFunctionCallDebugInfo, ScpFunctionCallDebugInfoArg, ScpValue
from falcom.ed9.writer.scp_writer_helper import *
from scp_writer_test_utils import fresh_writer
from scp_roundtrip_validator import compare_record, load_script

CallType = ScpFunctionCallDebugInfo.CallType
ArgType = ScpFunctionCallDebugInfoArg.Type
CALL_OPCODES = (ED9Opcode.CALL, ED9Opcode.CALL_SCRIPT, ED9Opcode.CALL_SCRIPT_NO_RETURN, ED9Opcode.SYSCALL)
SYSCALL_SUBSYSTEM = 1
SYSCALL_FUNC = 0x02
SYSCALL_CONSTANT = 7
CODE_END = 0x1000


def compile_script(dat: Path):
    '''Main's records are in source order, not address order: Outer's record comes before the Inner call in its argument,
    and the SYSCALL's before the Inner call whose result it takes. Main's first call is made before any line info, so it
    has no record. Defined in source order Inner, Outer, Main, Tail; the table is sorted by name.'''
    fresh_writer()
    writer = create_scp_writer(str(dat))

    @writer.LLILCode()
    def Inner():
        PUSH_INT(5)
        SET_REG(0)
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
        GET_REG(0)
        CALL(Outer)
        label('outer')
        PUSH_INT(SYSCALL_CONSTANT)
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('result')
        CALL(Inner)
        label('result')
        GET_REG(0)
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


class CompiledScript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.dat = Path(cls.tmp_dir.name) / 'test.dat'
        compile_script(cls.dat)
        cls.ctx = load_script(cls.dat)
        cls.parser = cls.ctx.parser
        cls.data = cls.ctx.data
        names = [func.name for func in cls.parser.functions]
        cls.records = dict(zip(names, cls.ctx.records))
        cls.instructions = dict(zip(names, cls.ctx.instructions))

    @classmethod
    def tearDownClass(cls):
        cls.ctx.fs.Close()
        cls.tmp_dir.cleanup()

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


if __name__ == '__main__':
    unittest.main()
