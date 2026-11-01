#!/usr/bin/env python3
"""The symbolic-stack translator (ir/mlil/stack_translator.py, falcom/ed9/ir/mlil/stack_translator.py) on assembled
functions: the MLIL where the shape is the point, the logic check's two pairs clean and every temporary assigned once
and read only after that in its own block, for every case; the refusals"""

from collections import Counter
from pathlib import Path
import re
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.disasm.stack_effects import CALLER_FRAME_SLOTS
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil, convert_falcom_llil_to_mlil_stack
from ir.llil.llil import LowLevelILAdd, LowLevelILStackStore, WORD_SIZE
from ir.mlil.mlil import (
    MediumLevelILCall, MLILAdd, MLILAnd, MLILCallScript, MLILConst, MLILDebug, MLILSetVar, MLILVar,
    UNASSIGNED_INST_INDEX, walk,
)
from ir.mlil.stack_translator import UnsupportedStackShape
from tests.shared.llil_utils import lift_asm
from tests.shared.logic_check_functions import (
    GLOBAL_A, GLOBAL_B, GLOBAL_D, MESSAGE, REG_INDEX, branch_function, call, initialised_out_parameter_function,
    optional_call_result_function, return_nothing,
)
from tests.shared.scp_asm import Asm, returning_callee
import logic_check

TEMPORARY = re.compile(r'^t\d+$')
CHANGED = 9                     # the value each write stores
SUBSYSTEM, COMMAND, OTHER_COMMAND = 1, 2, 3


def written_by(inst):
    """The variable a statement assigns: a SetVar's, a call's output"""
    if isinstance(inst, MLILSetVar):
        return inst.var
    if isinstance(inst, MediumLevelILCall):
        return inst.output
    return None


def temporaries_misused(mlil) -> list[str]:
    """The translator's invariant: each temporary assigned once and read only after that, in its own block; what
    breaks it (G3's harness runs it on every function too)"""
    problems = []
    assigned = {}
    for block in mlil.basic_blocks:
        for index, inst in enumerate(block.instructions):
            var = written_by(inst)
            if var is not None and TEMPORARY.match(var.name):
                if var.name in assigned:
                    problems.append(f'{var.name} assigned twice')
                assigned[var.name] = (block, index)

    for block in mlil.basic_blocks:
        for index, inst in enumerate(block.instructions):
            for operand in inst.operands():
                for node in walk(operand):
                    if isinstance(node, MLILVar) and TEMPORARY.match(node.var.name):
                        where = assigned.get(node.var.name)
                        if where is None or where[0] is not block or where[1] >= index:
                            problems.append(f'{node.var.name} read in {inst}')
    return problems


def statements(mlil) -> list[str]:
    return [str(inst) for block in mlil.basic_blocks for inst in block.instructions]


def copies(mlil) -> list[str]:
    """The values copied into temporaries before a write"""
    return [str(inst.value) for block in mlil.basic_blocks for inst in block.instructions
            if isinstance(inst, MLILSetVar) and TEMPORARY.match(inst.var.name)]


def write_counts(mlil) -> Counter:
    """The counts of writes with a value pending, and of their copies"""
    return Counter({key: n for key, n in mlil.translation_counts.items() if key.startswith(('pending at', 'copy at'))})


class StackTranslatorTestCase(unittest.TestCase):
    def translate(self, asm: Asm, argc: int = 0, callee_argc: int = 0):
        """asm's MLIL through the new path, after checking it: both pairs clean, the temporaries' invariant"""
        _, llil = lift_asm(asm, argc=argc, others=(returning_callee(callee_argc),))
        reference = logic_check.analyze(logic_check.LLILLayer(llil))
        mlil = convert_falcom_llil_to_mlil_stack(llil)
        self.assertEqual(temporaries_misused(mlil), [])
        llil_mlil = logic_check.compare_facts(reference, logic_check.analyze(logic_check.MLILLayer(mlil)))
        self.assertEqual({difference.category for difference in llil_mlil}, set(), 'LLIL -> MLIL')
        mlil_hlil = logic_check.compare_mlil_hlil(mlil, convert_falcom_mlil_to_hlil(mlil))
        self.assertEqual({difference.category for difference in mlil_hlil}, set(), 'MLIL -> HLIL')
        self.llil = llil
        return mlil

    def translate_built(self, build, argc: int = 0):
        asm, callee_argc = build()
        return self.translate(asm, argc, callee_argc)


class TestCanonicalForm(StackTranslatorTestCase):
    def test_registers_are_storage_and_a_call_stores_its_result(self):
        asm = Asm()
        call(asm, 'after', 7); asm.get_reg(0); asm.set_global(GLOBAL_A)
        asm.push_int(5); asm.set_reg(REG_INDEX); asm.get_reg(REG_INDEX); asm.set_global(GLOBAL_B)
        return_nothing(asm)
        mlil = self.translate(asm, callee_argc=1)

        self.assertEqual(statements(mlil), [
            't1 = callee(7)', 'REG[0] = t1', f'GLOBAL[{GLOBAL_A}] = REG[0]',
            f'REG[{REG_INDEX}] = 5', f'GLOBAL[{GLOBAL_B}] = REG[{REG_INDEX}]',
            'REG[0] = 0', 'return REG[0]',
        ])
        self.assertEqual(mlil.result_register, 0)
        self.assertEqual(mlil.register_vars, {})
        self.assertTrue(all(block.has_terminal for block in mlil.basic_blocks))

    def test_a_call_result_pending_across_a_call_is_copied(self):
        asm = Asm()
        call(asm, 'first', 1); asm.get_reg(0)
        call(asm, 'second', 2); asm.get_reg(0)
        asm.add(); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        mlil = self.translate(asm, callee_argc=1)

        self.assertEqual(statements(mlil)[:6], [
            't1 = callee(1)', 'REG[0] = t1', 't2 = REG[0]', 't3 = callee(2)', 'REG[0] = t3',
            f'GLOBAL[{GLOBAL_A}] = (t2 + REG[0])',
        ])

    def test_conditions_stay_as_the_llil_has_them(self):
        mlil = self.translate_built(branch_function)

        self.assertIn(f'if ((GLOBAL[0] == 0)) goto loc_39 else loc_1F', statements(mlil))


class TestWriteModel(StackTranslatorTestCase):
    """Each write with each pending leaf: a copy exactly where the write may change the leaf, and the write and its
    copies counted. The function has one parameter (a pointer for the dereference) and a local; the leaf is pushed,
    the write made, the leaf's value stored"""

    # The leaf, pushed with sp at 2 (the parameter in slot 0, the local in slot 1)
    LEAVES = {
        'call result':     lambda asm: (call(asm, 'leaf'), asm.get_reg(0)),
        'register':        lambda asm: (asm.push_int(1), asm.set_reg(REG_INDEX), asm.get_reg(REG_INDEX)),
        'global':          lambda asm: asm.load_global(GLOBAL_A),
        'dereference':     lambda asm: asm.load_stack_deref(-2 * WORD_SIZE),
        'local':           lambda asm: asm.load_stack(-WORD_SIZE),
        'parameter':       lambda asm: asm.load_stack(-2 * WORD_SIZE),
    }
    # The write, made with the leaf pending in slot 2 (sp at 3)
    WRITES = {
        'call':            lambda asm: call(asm, 'write'),
        'script call':     lambda asm: (asm.frame('write'), asm.call_script(0), asm.label('write')),
        'syscall':         lambda asm: asm.syscall(SUBSYSTEM, COMMAND, 0),
        'result register': lambda asm: (asm.push_int(CHANGED), asm.set_reg(0)),
        'another register': lambda asm: (asm.push_int(CHANGED), asm.set_reg(REG_INDEX)),
        'the global':      lambda asm: (asm.push_int(CHANGED), asm.set_global(GLOBAL_A)),
        'another global':  lambda asm: (asm.push_int(CHANGED), asm.set_global(GLOBAL_B)),
        'the local':       lambda asm: (asm.push_int(CHANGED), asm.pop_to(-2 * WORD_SIZE)),
        'the parameter':   lambda asm: (asm.push_int(CHANGED), asm.pop_to(-3 * WORD_SIZE)),
        'memory':          lambda asm: (asm.push_int(CHANGED), asm.pop_to_deref(-3 * WORD_SIZE)),
        'a debug log':     lambda asm: (asm.push_int(CHANGED), asm.debug_log(1)),
    }
    CALL_COPIES = {'call result': ['REG[0]'], 'register': [f'REG[{REG_INDEX}]'], 'global': [f'GLOBAL[{GLOBAL_A}]'],
                   'dereference': ['*arg1']}
    # write -> leaf -> what is copied before the write; every pair not named here copies nothing
    EXPECTED = {
        'call':            CALL_COPIES,
        'script call':     CALL_COPIES,
        'syscall':         CALL_COPIES,
        'result register': {'call result': ['REG[0]']},
        'another register': {'register': [f'REG[{REG_INDEX}]']},
        'the global':      {'global': [f'GLOBAL[{GLOBAL_A}]']},
        'the local':       {'local': ['var_s1']},
        'the parameter':   {'parameter': ['arg1'], 'dereference': ['arg1']},    # the pointer changes, memory not
        'memory':          {'dereference': ['*arg1']},
    }
    # The write's statement and each copy's leaf, as the counts name them
    STATEMENTS = {
        'call': 'CALL', 'script call': 'CALL_SCRIPT', 'syscall': 'SYSCALL', 'result register': 'REG_STORE 0',
        'another register': f'REG_STORE {REG_INDEX}', 'the global': 'GLOBAL_STORE', 'another global': 'GLOBAL_STORE',
        'the local': 'STACK_STORE', 'the parameter': 'FRAME_STORE', 'memory': 'STORE', 'a debug log': 'DEBUG_LOG',
    }
    COPIED_LEAVES = {'REG[0]': 'register 0', f'REG[{REG_INDEX}]': f'register {REG_INDEX}',
                     f'GLOBAL[{GLOBAL_A}]': 'global', '*arg1': 'dereference', 'var_s1': 'variable', 'arg1': 'variable'}

    def test_each_write_with_each_pending_leaf(self):
        for write_name, write in self.WRITES.items():
            for leaf_name, leaf in self.LEAVES.items():
                with self.subTest(write=write_name, leaf=leaf_name):
                    asm = Asm()
                    asm.push_raw(0)                     # the local, slot 1
                    leaf(asm)
                    write(asm)
                    asm.set_global(GLOBAL_D)            # the leaf's value, read after the write
                    asm.pop(2 * WORD_SIZE)              # the local and the parameter
                    return_nothing(asm)
                    mlil = self.translate(asm, argc=1)

                    expected = self.EXPECTED.get(write_name, {}).get(leaf_name, [])
                    self.assertEqual(copies(mlil), expected)
                    statement = self.STATEMENTS[write_name]
                    self.assertEqual(write_counts(mlil), Counter(
                        [f'pending at {statement}']
                        + [f'copy at {statement}: {self.COPIED_LEAVES[copy]}' for copy in expected]))

    def test_two_leaves_of_one_kind_are_copied_each(self):
        asm = Asm()
        asm.push_int(5); asm.set_reg(REG_INDEX); asm.get_reg(REG_INDEX); asm.get_reg(REG_INDEX); asm.add()
        call(asm, 'write'); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        mlil = self.translate(asm)

        self.assertEqual(statements(mlil)[:6], [
            f'REG[{REG_INDEX}] = 5', f't1 = REG[{REG_INDEX}]', f't2 = REG[{REG_INDEX}]', 't3 = callee()',
            'REG[0] = t3', f'GLOBAL[{GLOBAL_A}] = (t1 + t2)',
        ])
        self.assertEqual(write_counts(mlil), Counter({'pending at CALL': 1, f'copy at CALL: register {REG_INDEX}': 2}))


class TestCalls(StackTranslatorTestCase):
    def test_a_syscall_nested_in_another_syscalls_arguments(self):
        asm = Asm()
        call(asm, 'first'); asm.get_reg(0)                              # the outer syscall's last argument
        asm.syscall(SUBSYSTEM, COMMAND, 0); asm.get_reg(0)              # nested, the call result pending
        asm.syscall(SUBSYSTEM, OTHER_COMMAND, 2); asm.pop(2 * WORD_SIZE)
        return_nothing(asm)
        mlil = self.translate(asm)

        self.assertEqual(statements(mlil)[:7], [
            't1 = callee()', 'REG[0] = t1', 't2 = REG[0]', f't3 = syscall({SUBSYSTEM}, {COMMAND})', 'REG[0] = t3',
            f't4 = syscall({SUBSYSTEM}, {OTHER_COMMAND}, REG[0], t2)', 'REG[0] = t4',
        ])
        self.assertEqual(write_counts(mlil), Counter({'pending at SYSCALL': 1, 'copy at SYSCALL: register 0': 1}))

    def test_a_syscall_argument_read_again_is_a_local(self):
        asm = Asm()
        asm.push_raw(0)                                                 # a local, slot 0
        asm.push_int(7); asm.syscall(SUBSYSTEM, COMMAND, 1)             # its argument in slot 1, read in place
        asm.pop_to(-WORD_SIZE)                                          # then popped into the local
        asm.load_stack(-WORD_SIZE); asm.set_global(GLOBAL_A)
        asm.pop(WORD_SIZE)
        return_nothing(asm)
        mlil = self.translate(asm)

        self.assertEqual(statements(mlil)[:6], [
            'var_s0 = 0', 'var_s1 = 7', f't1 = syscall({SUBSYSTEM}, {COMMAND}, var_s1)', 'REG[0] = t1',
            'var_s0 = var_s1', f'GLOBAL[{GLOBAL_A}] = var_s0',
        ])
        self.assertEqual(mlil.translation_counts['push read twice'], 1)

    def test_the_tail_call_shuffle_and_its_mark(self):
        asm = Asm()
        asm.push_int(3)                                                 # the tail call's second argument, pending
        asm.push_int(4); asm.set_reg(1); asm.get_reg(1)                 # the shuffle
        asm.call_script_no_return(2)
        mlil = self.translate(asm)

        self.assertEqual(statements(mlil), ['REG[1] = 4', 't1 = this.g(REG[1], 3)', 'REG[0] = t1', 'return REG[0]'])
        call_node = next(inst for inst in mlil.basic_blocks[0].instructions if isinstance(inst, MLILCallScript))
        self.assertTrue(call_node.tail_call)
        self.assertEqual(write_counts(mlil), Counter({'pending at REG_STORE 1': 1}))

    def test_a_script_call_then_a_return_is_no_tail_call(self):
        asm = Asm()
        asm.frame('back'); asm.push_int(3); asm.call_script(1); asm.label('back')
        asm.get_reg(0); asm.set_reg(0); asm.ret()
        mlil = self.translate(asm)

        self.assertEqual(statements(mlil), ['t1 = this.g(3)', 'REG[0] = t1', 'REG[0] = REG[0]', 'return REG[0]'])
        call_node = next(inst for inst in mlil.basic_blocks[0].instructions if isinstance(inst, MLILCallScript))
        self.assertFalse(call_node.tail_call)

    def test_a_continuation_joins_its_call_and_a_shared_return_target_is_a_goto(self):
        mlil = self.translate_built(branch_function)

        self.assertEqual([block.label for block in mlil.basic_blocks], ['f', 'loc_1F', 'loc_39', 'loc_44'])
        self.assertEqual(statements(mlil)[3:6], ['t2 = callee(1)', 'REG[0] = t2', 'goto loc_44'])


class TestLocals(StackTranslatorTestCase):
    def test_a_push_never_read_is_declared(self):
        asm = Asm()
        asm.push_raw(0); asm.push_int(1); asm.set_global(GLOBAL_A); asm.pop(WORD_SIZE)
        return_nothing(asm)
        mlil = self.translate(asm)

        self.assertEqual(statements(mlil), ['var_s0 = 0', f'GLOBAL[{GLOBAL_A}] = 1', 'REG[0] = 0', 'return REG[0]'])
        self.assertEqual(mlil.translation_counts, Counter({'push never read': 1}))

    def test_a_store_into_a_dead_slot_declares_a_local(self):
        asm = Asm()
        asm.push_int(5); asm.pop_to(0)                                  # popped, then stored at sp
        return_nothing(asm)
        mlil = self.translate(asm)

        self.assertEqual(statements(mlil), ['var_s0 = 5', 'REG[0] = 0', 'return REG[0]'])
        self.assertEqual(mlil.translation_counts, Counter({'push never read': 1}))     # at sp, as a push stores

    def test_sibling_scopes_in_one_slot_are_distinct_locals(self):
        asm = Asm()
        for value, index in ((1, GLOBAL_A), (2, GLOBAL_B)):
            asm.push_int(value); asm.load_stack(-WORD_SIZE); asm.set_global(index); asm.pop(WORD_SIZE)
        return_nothing(asm)
        mlil = self.translate(asm)

        self.assertEqual(statements(mlil)[:4], [
            'var_s0 = 1', f'GLOBAL[{GLOBAL_A}] = var_s0', 'var_s0_1 = 2', f'GLOBAL[{GLOBAL_B}] = var_s0_1',
        ])
        self.assertEqual(mlil.translation_counts, Counter({'sibling slots': 1, 'sibling locals': 2}))

    def test_a_parameter_written_in_place(self):
        asm = Asm()
        asm.push_int(5); asm.pop_to(-WORD_SIZE)
        asm.load_stack(-WORD_SIZE); asm.set_global(GLOBAL_A); asm.pop(WORD_SIZE)
        return_nothing(asm)
        mlil = self.translate(asm, argc=1)

        self.assertEqual(statements(mlil)[:2], ['arg1 = 5', f'GLOBAL[{GLOBAL_A}] = arg1'])


class TestResultRegister(StackTranslatorTestCase):
    """The call's result read as the register wherever it is read: the explicit store puts it there"""

    def test_read_after_a_join(self):
        mlil = self.translate_built(optional_call_result_function)

        self.assertIn(f'GLOBAL[{GLOBAL_A}] = REG[0]', statements(mlil))

    def test_read_after_a_loop(self):
        asm = Asm()
        asm.push_int(0)
        asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(3); asm.lt(); asm.jz('done')
        call(asm, 'back')
        asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
        asm.jmp('head')
        asm.label('done'); asm.get_reg(0); asm.set_global(GLOBAL_A); asm.pop(WORD_SIZE)
        return_nothing(asm)
        mlil = self.translate(asm)

        self.assertIn(f'GLOBAL[{GLOBAL_A}] = REG[0]', statements(mlil))

    def test_read_after_a_return_target_with_two_predecessors(self):
        asm = Asm()
        asm.load_global(0); asm.jz('else')
        call(asm, 'then'); asm.jmp('end')
        asm.label('else'); call(asm, 'other')
        asm.label('end'); asm.get_reg(0); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        mlil = self.translate(asm)

        self.assertIn(f'GLOBAL[{GLOBAL_A}] = REG[0]', statements(mlil))

    def test_read_after_a_debug_log(self):
        asm = Asm()
        call(asm, 'after'); asm.push_str(MESSAGE); asm.debug_log(1); asm.get_reg(0); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        mlil = self.translate(asm)

        self.assertEqual(statements(mlil)[:4], [
            't1 = callee()', 'REG[0] = t1', f'debug.log("{MESSAGE}")', f'GLOBAL[{GLOBAL_A}] = REG[0]',
        ])
        self.assertEqual(mlil.translation_counts, Counter())           # REG[0] the call's still: no unwritten read


class TestMarks(StackTranslatorTestCase):
    def test_every_expression_carries_its_llil_statements_source(self):
        asm = Asm()
        asm.push_int(1); asm.debug_set_lineno(5); asm.push_int(2); asm.add(); asm.set_global(GLOBAL_A)
        asm.load_global(0); asm.push_int(8); asm.bitwise_and(); asm.set_global(GLOBAL_B)    # BitwiseHexPass rebuilds
        return_nothing(asm)
        mlil = self.translate(asm)
        llil = {inst.inst_index: inst for block in self.llil.basic_blocks for inst in block.instructions}

        nodes = [node for inst in mlil.iter_instructions() for operand in inst.operands() for node in walk(operand)]
        for node in nodes:
            with self.subTest(node=str(node)):
                self.assertNotEqual(node.llil_index, UNASSIGNED_INST_INDEX)
                self.assertEqual(node.address, llil[node.llil_index].address)

        add = next(node for node in nodes if isinstance(node, MLILAdd))
        self.assertIsInstance(llil[add.llil_index], LowLevelILStackStore)
        self.assertIsInstance(llil[add.llil_index].value, LowLevelILAdd)
        hex_constant = next(node for node in nodes if isinstance(node, MLILAnd)).rhs
        self.assertTrue(isinstance(hex_constant, MLILConst) and hex_constant.is_hex)
        # The line marker inside the expression is a statement before it; the expression stays one tree
        body = mlil.basic_blocks[0].instructions
        store = statements(mlil).index(f'GLOBAL[{GLOBAL_A}] = (1 + 2)')
        self.assertTrue(any(isinstance(inst, MLILDebug) for inst in body[:store]))


class TestCounts(StackTranslatorTestCase):
    """The counts no other case makes: a value pending at a statement that writes nothing, a store above sp, register
    reads no store reaches; and a function without any"""

    def debug_log_with_a_value_pending(self) -> Asm:
        asm = Asm()
        asm.push_int(7); asm.push_str(MESSAGE); asm.debug_log(1); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        return asm

    def test_a_value_pending_across_a_debug_log(self):
        mlil = self.translate(self.debug_log_with_a_value_pending())

        self.assertEqual(mlil.translation_counts, Counter({'pending at DEBUG_LOG': 1}))

    def test_a_store_above_sp(self):
        asm = Asm()
        asm.push_int(5); asm.push_int(6); asm.pop_to(WORD_SIZE)         # popped, then stored a slot above sp
        asm.set_global(GLOBAL_A)
        return_nothing(asm)
        mlil = self.translate(asm)

        self.assertEqual(statements(mlil)[:2], ['var_s2 = 6', f'GLOBAL[{GLOBAL_A}] = 5'])
        self.assertEqual(mlil.translation_counts,
                         Counter({'store above sp': 1, 'push never read': 1, 'pending at STACK_STORE': 1}))

    def test_register_reads_no_store_reaches(self):
        shapes = {
            'before any write': lambda asm: asm.get_reg(REG_INDEX),
            'after a call':     lambda asm: (asm.push_int(4), asm.set_reg(REG_INDEX), call(asm, 'back'),
                                             asm.get_reg(REG_INDEX)),
            'one way wrote it': lambda asm: (asm.load_global(0), asm.jz('join'), asm.push_int(4),
                                             asm.set_reg(REG_INDEX), asm.label('join'), asm.get_reg(REG_INDEX)),
            # Written before the loop, the call in its body clobbers it: seen only once the dataflow iterates
            'after a loop':     lambda asm: (asm.push_int(4), asm.set_reg(REG_INDEX), asm.label('head'),
                                             asm.load_global(0), asm.jz('done'), call(asm, 'back'), asm.jmp('head'),
                                             asm.label('done'), asm.get_reg(REG_INDEX)),
        }
        for name, read in shapes.items():
            with self.subTest(read=name):
                asm = Asm()
                read(asm); asm.set_global(GLOBAL_A)
                return_nothing(asm)
                mlil = self.translate(asm)

                self.assertEqual(mlil.translation_counts, Counter({'unwritten register read': 1}))

    def test_a_bare_return_reads_the_callers_result_register(self):
        asm = Asm()
        asm.ret()
        mlil = self.translate(asm)

        self.assertEqual(statements(mlil), ['return REG[0]'])
        self.assertEqual(mlil.translation_counts, Counter({'unwritten register read': 1}))

    def test_a_function_without_any(self):
        asm = Asm()
        asm.push_int(1); asm.set_global(GLOBAL_A)
        return_nothing(asm)

        self.assertEqual(self.translate(asm).translation_counts, Counter())

    def test_the_ssa_path_counts_nothing(self):
        _, llil = lift_asm(self.debug_log_with_a_value_pending(), others=(returning_callee(),))
        mlil = convert_falcom_llil_to_mlil(llil, optimize=True, infer_types=False)

        self.assertEqual(mlil.translation_counts, Counter())


class TestRefusals(unittest.TestCase):
    def assertRefused(self, asm: Asm, reason: str, argc: int = 0, callee_argc: int = 0):
        _, llil = lift_asm(asm, argc=argc, others=(returning_callee(callee_argc),))
        with self.assertRaisesRegex(UnsupportedStackShape, reason):
            convert_falcom_llil_to_mlil_stack(llil)

    def test_an_address_taken_local(self):
        asm, callee_argc = initialised_out_parameter_function()
        self.assertRefused(asm, 'an address-taken local', callee_argc=callee_argc)

    def test_an_address_taken_parameter(self):
        asm = Asm()
        asm.push_stack_offset(-WORD_SIZE); asm.set_global(GLOBAL_A); asm.pop(WORD_SIZE)
        return_nothing(asm)
        self.assertRefused(asm, 'an address-taken parameter', argc=1)

    def test_a_value_pending_across_a_fork(self):
        asm = Asm()
        asm.push_int(5)
        asm.load_global(0); asm.jz('skip'); asm.push_int(1); asm.set_global(GLOBAL_B)
        asm.label('skip'); asm.set_global(GLOBAL_A)
        return_nothing(asm)
        self.assertRefused(asm, 'a value or call setup pending at a block boundary')

    def test_a_join_of_two_pushes_read_by_offset(self):
        asm = Asm()
        asm.load_global(0); asm.jz('else'); asm.push_int(5); asm.jmp('join')
        asm.label('else'); asm.push_int(7)
        asm.label('join'); asm.load_stack(-WORD_SIZE); asm.set_global(GLOBAL_A); asm.pop(WORD_SIZE)
        return_nothing(asm)
        self.assertRefused(asm, 'a block entry slot two pushes may hold')

    def test_a_call_frame_value_read_as_data(self):
        for slot in range(CALLER_FRAME_SLOTS):
            with self.subTest(slot=slot):
                asm = Asm()
                asm.frame('back'); asm.load_stack((slot - CALLER_FRAME_SLOTS) * WORD_SIZE); asm.set_global(GLOBAL_A)
                asm.call_script(0); asm.label('back')
                return_nothing(asm)
                self.assertRefused(asm, 'a call frame value read as data')


if __name__ == '__main__':
    unittest.main()
