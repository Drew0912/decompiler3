#!/usr/bin/env python3
'''The opt-in debug text of lifted LLIL - the .llil.asm listing, the .dot graph, each node's str/repr - the
function lookups the listing uses, and every node carrying the operation code that names it.'''

from pathlib import Path
import re
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.llil.llil import (
    LowLevelILCall, LowLevelILConst, LowLevelILFrameStore, LowLevelILIf, LowLevelILOperation, LowLevelILStackLoad,
    LowLevelILStackStore, LowLevelILStore, UNASSIGNED_INST_INDEX, WORD_SIZE,
)
from falcom.ed9.ir.llil.llil_builder import FalcomLLILFormatter
from falcom.ed9.ir.llil.llil_ext import LowLevelILCallScriptNoReturn, LowLevelILFalcomOperation
from tests.shared.llil_utils import instructions_of, lift_asm, make_builder
from tests.shared.scp_asm import (
    CALLEE_ID, CALLER_ID, GLOBAL_INDEX, MODULE_NAME, REG_INDEX, SCRIPT_FUNC_NAME, SYSCALL_FUNC, SYSCALL_SUBSYSTEM, Asm,
    returning_callee,
)


FIRST_VALUE = 7


def lifted_text_function():
    '''One function with every kind of instruction the debug text prints'''
    callee = returning_callee(1)
    asm = Asm()
    asm.debug_set_lineno(1)
    asm.load_stack(-WORD_SIZE)
    asm.push_int(3); asm.add(); asm.neg(); asm.not_(); asm.ez()
    asm.set_global(GLOBAL_INDEX)
    asm.load_global(GLOBAL_INDEX); asm.set_reg(REG_INDEX)
    asm.get_reg(REG_INDEX); asm.push_int(-FIRST_VALUE); asm.eq(); asm.pop_to(-WORD_SIZE)
    asm.push_float(1.5); asm.push_raw(255); asm.syscall(SYSCALL_SUBSYSTEM, SYSCALL_FUNC, 2); asm.pop(2 * WORD_SIZE)
    asm.push_str(MODULE_NAME); asm.push_int(2); asm.debug_log(2)
    asm.get_reg(REG_INDEX); asm.jz('else')
    asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.push_int(9); asm.call(CALLEE_ID); asm.label('back')
    asm.jmp('end')
    asm.label('else')
    asm.frame('after'); asm.push_int(4); asm.call_script(1); asm.label('after')
    asm.label('end'); asm.pop(WORD_SIZE); asm.ret()
    return lift_asm(asm, argc = 1, others = (callee,))[1]


EXPECTED_ASM = '''
; ---------- f ----------
block_0(0x0000), f, [sp = 1, fp = 0]
  dbg_line 1
  STACK[sp] = STACK[fp + 0] ; [1]
  sp++
  STACK[sp] = 3 ; [2]
  sp++
  rhs = STACK[--sp]  ; STACK[sp<2>]
  lhs = STACK[--sp]  ; STACK[sp<1>]
  STACK[sp++] = lhs + rhs
  operand = STACK[--sp]  ; STACK[sp<1>]
  STACK[sp++] = -operand
  operand = STACK[--sp]  ; STACK[sp<1>]
  STACK[sp++] = ~operand
  operand = STACK[--sp]  ; STACK[sp<1>]
  STACK[sp++] = (operand == 0) ? 1 : 0
  GLOBAL[0] = STACK[--sp] ; STACK[sp<1>]
  STACK[sp] = GLOBAL[0] ; [1]
  sp++
  REG[0] = STACK[--sp]  ; STACK[sp<1>]
  STACK[sp] = REG[0] ; [1]
  sp++
  STACK[sp] = -7 ; [2]
  sp++
  rhs = STACK[--sp]  ; STACK[sp<2>]
  lhs = STACK[--sp]  ; STACK[sp<1>]
  STACK[sp++] = (lhs == rhs) ? 1 : 0
  STACK[fp + 0] = STACK[--sp] ; STACK[sp<1>]
  STACK[sp] = 1.5 ; [1] f32 0x3FC00000, raw 0x8FF00000
  sp++
  STACK[sp] = 0xFF ; [2]
  sp++
  SYSCALL(1, 0x02, STACK[sp<2>], STACK[sp<1>])
  sp -= 2
  STACK[sp] = 'this' ; [1]
  sp++
  STACK[sp] = 2 ; [2]
  sp++
  DEBUG_LOG(STACK[sp<2>], STACK[sp<1>])
  sp -= 2
  STACK[sp] = REG[0] ; [1]
  sp++
  if (STACK[--sp] EQ 0) goto block_3 else block_1

block_1(0x0053), loc_53, [sp = 1]
  STACK[sp] = <func_id> ; [1]
  sp++
  STACK[sp] = <&loc_68> ; [2]
  sp++
  STACK[sp] = 9 ; [3]
  sp++
  call callee(STACK[sp<3>])

block_2(0x0068), loc_68, [sp = 1]
  goto block_4

block_3(0x006D), loc_6D, [sp = 1]
  STACK[sp] = <func_id> ; [1]
  sp++
  STACK[sp] = <&loc_82> ; [2]
  sp++
  STACK[sp] = <script_ptr> ; [3]
  sp++
  STACK[sp] = <script_ptr> ; [4]
  sp++
  STACK[sp] = <script_name> ; [5]
  sp++
  STACK[sp] = 4 ; [6]
  sp++
  call_script(`this.g`, [STACK[sp<6>]]) -> loc_82

block_4(0x0082), loc_82, [sp = 1]
  sp--
  return
'''.strip('\n').splitlines()

EXPECTED_DOT_EDGES = [
    '    block_0 -> block_3 [label="true", color=green];',
    '    block_0 -> block_1 [label="false", color=red];',
    '    block_1 -> block_2 [label="fall-through", style=dashed];',
    '    block_2 -> block_4 [label="goto", color=blue];',
    '    block_3 -> block_4 [label="fall-through", style=dashed];',
]

EXPECTED_BLOCK_SUMMARY = '''
; ---------- f ----------
block_0 f @ 0x0: [sp=1]
  -> block_3, block_1
block_1 loc_53 @ 0x53: [sp=1]
  -> block_2
block_2 loc_68 @ 0x68: [sp=1]
  -> block_4
block_3 loc_6D @ 0x6d: [sp=1]
  -> block_4
block_4 loc_82 @ 0x82: [sp=1]
'''.strip('\n').splitlines()


class TestLiftedDebugText(unittest.TestCase):
    '''The opt-in .llil.asm / .dot dumps and the nodes' own text, for a function with every kind of instruction'''

    @classmethod
    def setUpClass(cls):
        cls.llil_func = lifted_text_function()

    def test_llil_asm_listing(self):
        lines = FalcomLLILFormatter.format_llil_function(self.llil_func)

        self.assertEqual([line for line in lines if line != ''], [line for line in EXPECTED_ASM if line != ''])
        self.assertEqual(lines.count(''), len(self.llil_func.basic_blocks))      # one blank line after each block

    def test_dot_graph(self):
        dot = FalcomLLILFormatter.to_dot(self.llil_func).splitlines()

        self.assertEqual([line for line in dot if re.match(r'    block_\d+ -> ', line)], EXPECTED_DOT_EDGES)
        self.assertIn('fillcolor=lightgreen', next(line for line in dot if line.startswith('    block_0 [')))
        self.assertIn('fillcolor=lightblue', next(line for line in dot if line.startswith('    block_4 [')))
        self.assertNotIn('fillcolor', next(line for line in dot if line.startswith('    block_2 [')))
        self.assertIn('[sp = 1, fp = 0]', next(line for line in dot if line.startswith('    block_0 [')))
        self.assertNotIn('fp = 0', next(line for line in dot if line.startswith('    block_1 [')))
        self.assertIn('goto block_4', next(line for line in dot if line.startswith('    block_2 [')))

    def test_function_and_block_text(self):
        self.assertEqual(str(self.llil_func).splitlines(), EXPECTED_BLOCK_SUMMARY)

    def test_every_instruction_has_text_and_a_repr(self):
        for block in self.llil_func.basic_blocks:
            for inst in block.instructions:
                text = str(inst)
                self.assertIsInstance(text, str)
                self.assertTrue(text)
                self.assertEqual(repr(inst), f'<{type(inst).__name__}: {text}>')

    def test_stack_load_and_store_text(self):
        self.assertEqual(str(LowLevelILStackLoad(offset = 0, slot_index = 3)), 'STACK[sp<3>]')
        self.assertEqual(str(LowLevelILStackLoad(offset = WORD_SIZE, slot_index = 4)), 'STACK[sp + 1<4>]')
        self.assertEqual(str(LowLevelILStackLoad(offset = -WORD_SIZE, slot_index = 2)), 'STACK[sp - 1<2>]')
        self.assertEqual(str(LowLevelILStackStore(5, offset = WORD_SIZE, slot_index = 4)), 'STACK[sp + 1] = 5')
        self.assertEqual(str(LowLevelILStackStore(5, offset = -WORD_SIZE, slot_index = 2)), 'STACK[sp - 1] = 5')
        self.assertEqual(str(LowLevelILStackStore(5, offset = 0, slot_index = 3)), 'STACK[sp] = 5')

    def test_frame_and_sp_text(self):
        builder = make_builder(2)
        self.assertEqual(str(builder.frame_load(WORD_SIZE)), 'STACK[fp + 1]')
        self.assertEqual(str(builder.frame_load(-WORD_SIZE)), 'STACK[fp - 1]')
        self.assertEqual(str(builder.frame_addr(WORD_SIZE)), '&STACK[fp + 1]')
        self.assertEqual(str(builder.frame_addr(-WORD_SIZE)), '&STACK[fp - 1]')
        for delta, text in ((1, 'sp++'), (-1, 'sp--'), (3, 'sp += 3'), (-3, 'sp -= 3')):
            self.assertEqual(str(builder.emit_sp_add(delta)), text)

    def test_hex_and_raw_constants(self):
        self.assertEqual(str(LowLevelILConst(255)), '255')
        self.assertEqual(str(LowLevelILConst(255, is_hex = True)), '0xFF')
        self.assertEqual(str(LowLevelILConst(-255, is_hex = True)), '-0xFF')
        self.assertEqual(str(LowLevelILConst(255, is_raw = True)), '0xFF')
        self.assertEqual(str(LowLevelILConst(1.5)), '1.5')


def lifted_pointer_function():
    '''A function that reads, writes and takes the address of its parameter and of a local'''
    asm = Asm()
    asm.load_stack_deref(-WORD_SIZE); asm.pop(WORD_SIZE)
    asm.push_int(5); asm.pop_to_deref(-WORD_SIZE)
    asm.push_stack_offset(-WORD_SIZE); asm.pop(WORD_SIZE)
    asm.push_int(1); asm.push_stack_offset(-WORD_SIZE); asm.pop(2 * WORD_SIZE)
    asm.pop(WORD_SIZE); asm.ret()
    return lift_asm(asm, argc = 1)[1]


def tail_call_function(argc: int):
    asm = Asm()
    for value in range(argc):
        asm.push_int(value)

    asm.call_script_no_return(argc)
    return lift_asm(asm)[1]


def no_argument_call_function():
    asm = Asm()
    asm.push_raw(CALLER_ID); asm.push_raw('after'); asm.call(CALLEE_ID); asm.label('after'); asm.ret()
    return lift_asm(asm, others = (returning_callee(0),))[1]


TAIL_CALL_TEXT = f'call_script_no_return(`{MODULE_NAME}.{SCRIPT_FUNC_NAME}`, '


class TestMoreDebugText(unittest.TestCase):
    '''.llil.asm lines of pointer accesses, tail calls and a call without arguments'''

    def test_pointer_function_listing(self):
        lines = FalcomLLILFormatter.format_llil_function(lifted_pointer_function())

        self.assertEqual([line.strip() for line in lines if '*' in line or '&' in line], [
            'STACK[sp] = *STACK[fp + 0] ; [1]',
            '*STACK[fp + 0] = STACK[--sp] ; STACK[sp<1>]',
            'STACK[sp] = &STACK[fp + 0] ; [1]',
            'STACK[sp] = &STACK[1] ; [2]',
        ])

    def test_tail_call_listing(self):
        self.assertEqual(FalcomLLILFormatter.format_llil_function(tail_call_function(1))[-2],
                         f'  {TAIL_CALL_TEXT}[STACK[sp<0>]])')
        self.assertEqual(FalcomLLILFormatter.format_llil_function(tail_call_function(0))[-2],
                         f'  {TAIL_CALL_TEXT}[])')

    def test_node_text_of_instructions_the_listing_does_not_format_itself(self):
        self.assertEqual(str(LowLevelILFrameStore(5, offset = 0)), 'STACK[fp + 0] = 5')
        self.assertEqual(str(LowLevelILFrameStore(5, offset = WORD_SIZE)), 'STACK[fp + 1] = 5')
        self.assertEqual(str(LowLevelILFrameStore(5, offset = -WORD_SIZE)), 'STACK[fp - 1] = 5')

        llil_func = lifted_text_function()
        branch, = instructions_of(llil_func, LowLevelILIf)
        self.assertEqual(str(branch), 'if EQ(STACK[sp<1>], 0) goto block_3 else block_1')
        self.assertEqual(str(LowLevelILIf(branch.condition, branch.true_target)),
                         'if EQ(STACK[sp<1>], 0) goto block_3')

        call, = [inst for inst in instructions_of(llil_func, LowLevelILCall) if type(inst) is LowLevelILCall]
        self.assertEqual(str(call), 'call callee(STACK[sp<3>])')
        no_argument_call, = instructions_of(no_argument_call_function(), LowLevelILCall)
        self.assertEqual(str(no_argument_call), 'call callee')

        tail_call, = instructions_of(tail_call_function(1), LowLevelILCallScriptNoReturn)
        self.assertEqual(str(tail_call), f'{TAIL_CALL_TEXT}[STACK[sp<0>]])')

        store, = instructions_of(lifted_pointer_function(), LowLevelILStore)
        self.assertEqual(str(store), '*STACK[fp + 0] = STACK[sp<1>]')


def nested_expressions(inst) -> list:
    '''The expression nodes under inst'''
    children = []
    for attribute in ('value', 'condition', 'lhs', 'rhs', 'operand', 'src', 'dest'):
        child = getattr(inst, attribute, None)
        if hasattr(child, 'operation'):
            children.append(child)
            children.extend(nested_expressions(child))

    return children


class TestNodeKinds(unittest.TestCase):
    '''Every operation code is its own value and every node carries the one that names it'''

    EXPECTED = {
        'LowLevelILAdd': LowLevelILOperation.LLIL_ADD,
        'LowLevelILEq': LowLevelILOperation.LLIL_EQ,
        'LowLevelILNeg': LowLevelILOperation.LLIL_NEG,
        'LowLevelILBitwiseNot': LowLevelILOperation.LLIL_BITWISE_NOT,
        'LowLevelILTestZero': LowLevelILOperation.LLIL_TEST_ZERO,
        'LowLevelILStackLoad': LowLevelILOperation.LLIL_STACK_LOAD,
        'LowLevelILStackStore': LowLevelILOperation.LLIL_STACK_STORE,
        'LowLevelILFrameLoad': LowLevelILOperation.LLIL_FRAME_LOAD,
        'LowLevelILFrameStore': LowLevelILOperation.LLIL_FRAME_STORE,
        'LowLevelILFrameAddr': LowLevelILOperation.LLIL_FRAME_ADDR,
        'LowLevelILStackAddr': LowLevelILOperation.LLIL_STACK_ADDR,
        'LowLevelILLoad': LowLevelILOperation.LLIL_LOAD,
        'LowLevelILStore': LowLevelILOperation.LLIL_STORE,
        'LowLevelILRegLoad': LowLevelILOperation.LLIL_REG_LOAD,
        'LowLevelILRegStore': LowLevelILOperation.LLIL_REG_STORE,
        'LowLevelILSpAdd': LowLevelILOperation.LLIL_SP_ADD,
        'LowLevelILConst': LowLevelILOperation.LLIL_CONST,
        'LowLevelILSyscall': LowLevelILOperation.LLIL_SYSCALL,
        'LowLevelILDebug': LowLevelILOperation.LLIL_DEBUG,
        'LowLevelILIf': LowLevelILOperation.LLIL_BRANCH,
        'LowLevelILJmp': LowLevelILOperation.LLIL_JMP,
        'LowLevelILRet': LowLevelILOperation.LLIL_RET,
        'LowLevelILCall': LowLevelILOperation.LLIL_CALL,
        'LowLevelILGlobalLoad': LowLevelILFalcomOperation.LLIL_GLOBAL_LOAD,
        'LowLevelILGlobalStore': LowLevelILFalcomOperation.LLIL_GLOBAL_STORE,
        'LowLevelILDebugLog': LowLevelILFalcomOperation.LLIL_DEBUG_LOG,
        'LowLevelILCallScript': LowLevelILFalcomOperation.LLIL_CALL_SCRIPT,
        'LowLevelILCallScriptNoReturn': LowLevelILFalcomOperation.LLIL_CALL_SCRIPT_NO_RETURN,
    }

    def test_operation_codes_are_distinct(self):
        for enum in (LowLevelILOperation, LowLevelILFalcomOperation):
            self.assertEqual(len(enum.__members__), len(set(enum)), enum.__name__)

    def test_lifted_nodes_carry_their_operation_and_index(self):
        seen = {}
        for llil_func in (lifted_text_function(), lifted_pointer_function(), tail_call_function(1)):
            for block in llil_func.basic_blocks:
                for inst in block.instructions:
                    seen[type(inst).__name__] = inst
                    self.assertNotEqual(inst.inst_index, UNASSIGNED_INST_INDEX)

                    for expr in nested_expressions(inst):
                        seen[type(expr).__name__] = expr

        for name, operation in self.EXPECTED.items():
            self.assertEqual(seen[name].operation, operation, name)

        for name, node in seen.items():
            self.assertEqual(node.operation_name, node.operation.name.replace('LLIL_', ''), name)

if __name__ == '__main__':
    unittest.main()
