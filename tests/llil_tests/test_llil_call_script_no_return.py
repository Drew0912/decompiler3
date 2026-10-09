#!/usr/bin/env python3
'''Unit tests for CALL_SCRIPT_NO_RETURN (opcode 0x23), a script tail call that never gives control
back to the calling function.'''

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import LowLevelILCall
from ir.mlil.mlil import MLILCallScript, MLILRet, MLILVar
from falcom.ed9.ir.llil.llil_ext import LowLevelILCallScriptNoReturn
from falcom.ed9.ir.mlil.mlil_translator import FalcomLLILToMLILTranslator
from falcom.ed9.disasm.ed9_optable import ED9Opcode
from falcom.ed9.parser.scp import CallDebugInfoTracker
from falcom.ed9.parser.types_scp import ScpFunctionCallDebugInfo
from tests.shared.llil_utils import make_builder


MODULE_NAME = 'module'
FUNC_NAME = 'func'


def build_tail_call_function(arg_count: int):
    '''Single-block function ending in CALL_SCRIPT_NO_RETURN, no preceding caller frame'''
    builder = make_builder()
    entry = builder.current_block

    for i in range(arg_count):
        builder.push_int(i)

    builder.call_script_no_return(MODULE_NAME, FUNC_NAME, arg_count)

    return builder.finalize(), entry


class TestCallScriptNoReturnLLIL(unittest.TestCase):
    '''LLIL-level behavior of the tail-call opcode'''

    def test_zero_args_has_no_successors(self):
        _, entry = build_tail_call_function(0)

        self.assertEqual(entry.outgoing_edges, [])

    def test_pushed_args_become_its_arguments(self):
        _, entry = build_tail_call_function(3)

        inst = entry.instructions[-1]
        self.assertIsInstance(inst, LowLevelILCallScriptNoReturn)
        self.assertEqual([arg.slot_index for arg in inst.args], [2, 1, 0])     # arg1 is the last push

    def test_instruction_shape(self):
        _, entry = build_tail_call_function(2)
        inst = entry.instructions[-1]

        self.assertIsInstance(inst, LowLevelILCallScriptNoReturn)
        self.assertIsInstance(inst, LowLevelILCall)
        self.assertFalse(inst.returns)
        self.assertIsNone(inst.return_target)
        self.assertEqual(inst.module, MODULE_NAME)
        self.assertEqual(inst.func, FUNC_NAME)
        self.assertEqual(inst.arg_count, 2)


class TestCallScriptNoReturnMLIL(unittest.TestCase):
    '''MLIL-level shape: tail call becomes `return module.func(args)`'''

    def test_translates_to_call_then_return(self):
        llil_func, _ = build_tail_call_function(1)

        mlil_func = FalcomLLILToMLILTranslator().translate(llil_func)

        block = mlil_func.basic_blocks[0]
        # Pushing the argument emits its own MLIL statement(s) ahead of the call (same as any
        # other call's argument push) - only the last two instructions are asserted here.
        self.assertGreaterEqual(len(block.instructions), 2)

        call_inst, ret_inst = block.instructions[-2:]
        self.assertIsInstance(call_inst, MLILCallScript)
        self.assertEqual(call_inst.module, MODULE_NAME)
        self.assertEqual(call_inst.func, FUNC_NAME)
        self.assertEqual(len(call_inst.args), 1)
        self.assertIsNotNone(call_inst.output)

        self.assertIsInstance(ret_inst, MLILRet)
        self.assertIsInstance(ret_inst.value, MLILVar)
        self.assertIs(ret_inst.value.var, call_inst.output)

        self.assertEqual(block.outgoing_edges, [])


class TestCallScriptNoReturnDebugInfoTracker(unittest.TestCase):
    '''CallDebugInfoTracker.on_opcode: a tail call whose own argument is the result of a nested
    call must still sort before that nested call in source pre-order.'''

    def test_nested_call_in_own_argument_sorts_after_tail_call(self):
        # return outer(inner()) - INNER is an ordinary local CALL, its result becomes the tail
        # call's sole argument via GET_REG(0).
        tracker = CallDebugInfoTracker(get_param_count = lambda func_id: 0)

        tracker.on_opcode(ED9Opcode.DEBUG_SET_LINENO, [1])  # enables debug-record recording
        tracker.on_opcode(ED9Opcode.PUSH_CURRENT_FUNC_ID, [])
        tracker.on_opcode(ED9Opcode.PUSH_RET_ADDR, ['loc_ret'])
        tracker.on_opcode(ED9Opcode.CALL, ['inner_func_id'])
        tracker.on_opcode(ED9Opcode.GET_REG, [0])
        tracker.on_opcode(ED9Opcode.CALL_SCRIPT_NO_RETURN, ['module', 'outer', 1])

        ordered = tracker.ordered_calls()
        self.assertEqual(len(ordered), 2)

        outer_call, inner_call = ordered
        self.assertEqual(outer_call.call_type, ScpFunctionCallDebugInfo.CallType.ScriptNoReturn)
        self.assertEqual(inner_call.call_type, ScpFunctionCallDebugInfo.CallType.Local)


if __name__ == '__main__':
    unittest.main()
