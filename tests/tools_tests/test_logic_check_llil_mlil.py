#!/usr/bin/env python3
"""The logic check (tools/logic_check/), LLIL against MLIL: a bug planted in the MLIL of a small assembled function
shows up as its category, and the unchanged MLIL compares clean; an effect's values compared argument by argument; a
real script compares clean on both pairs"""

from pathlib import Path
import copy
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.ir.mlil.mlil_translator import DEBUG_LOG_CALL_TARGET
from ir.llil.llil import WORD_SIZE
from ir.mlil.mlil import (
    MediumLevelILCall, MLILAdd, MLILCall, MLILConst, MLILGe, MLILIf, MLILLoadGlobal, MLILLogicalNot, MLILLt, MLILRet,
    MLILSetVar, MLILStoreDeref, MLILStoreGlobal, MLILStoreReg, MLILVar, map_operands, walk,
)
from tests.shared.corpus import SORA2_SCRIPTS, require
from tests.shared.logic_check_functions import (
    GLOBAL_A, GLOBAL_B, GLOBAL_C, LOOP_LIMIT, MESSAGE, OUT_INITIAL, REG_INDEX, UNRELATED_ARG, branch_function, call,
    calls_function, categories, first, initialised_out_parameter_function, loop_call_function, reference_and_mlil,
    return_nothing, statements,
)
from tests.shared.scp_asm import CALLEE_ID, CALLER_ID, Asm
import logic_check
from logic_check.facts import Effect, Facts
from logic_check.state import PHI_DEPTH
from logic_check.trees import const

REG_OUT = 7
DEEP_INITIAL = 1
ENDLESS_TAIL_PARAMETERS = 2
TAIL_CALL_ARG = 6


# === Assembled functions ===

def two_results_function() -> tuple[Asm, int]:
    """x = callee(); y = callee(); GLOBAL[0] = callee() + (x - y): two results held across later calls"""
    asm = Asm()
    asm.push_raw(0); asm.push_raw(0)
    call(asm, 'x'); asm.get_reg(0); asm.pop_to(-2 * WORD_SIZE)
    call(asm, 'y'); asm.get_reg(0); asm.pop_to(-WORD_SIZE)
    call(asm, 'z'); asm.get_reg(0)
    asm.load_stack(-3 * WORD_SIZE); asm.load_stack(-3 * WORD_SIZE); asm.sub(); asm.add(); asm.set_global(0)
    asm.pop(2 * WORD_SIZE); return_nothing(asm)
    return asm, 0


def out_parameter_function() -> tuple[Asm, int]:
    """v; callee(&v); GLOBAL[0] = v"""
    asm = Asm()
    asm.push_raw(0)
    asm.push_raw(CALLER_ID); asm.push_raw('after'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('after'); asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def unrelated_call_function() -> tuple[Asm, int]:
    """v = OUT_INITIAL; callee(UNRELATED_ARG); GLOBAL[0] = v; callee(&v): the first call is given no pointer to v, so
    v holds its value across it"""
    asm = Asm()
    asm.push_int(OUT_INITIAL)
    call(asm, 'first', UNRELATED_ARG)
    asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.push_raw(CALLER_ID); asm.push_raw('second'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('second'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def escaped_address_function() -> tuple[Asm, int]:
    """v = OUT_INITIAL; GLOBAL_A = &v; callee(); GLOBAL_B = v: the callee is given no pointer, but can reach v through
    the global"""
    asm = Asm()
    asm.push_int(OUT_INITIAL); asm.push_stack_offset(-WORD_SIZE); asm.set_global(GLOBAL_A)
    call(asm, 'back')
    asm.load_stack(-WORD_SIZE); asm.set_global(GLOBAL_B)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def pointer_to_pointer_function() -> tuple[Asm, int]:
    """v = OUT_INITIAL; q = &v; callee(&q): the callee is given q's address, and reaches v through q"""
    asm = Asm()
    asm.push_int(OUT_INITIAL); asm.push_stack_offset(-WORD_SIZE)
    asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('back'); asm.pop(2 * WORD_SIZE); return_nothing(asm)
    return asm, 1


def one_arm_register_function() -> tuple[Asm, int]:
    """if GLOBAL_A: REG = REG_OUT; returned: the other arm leaves the register's incoming value for the caller"""
    asm = Asm()
    asm.load_global(GLOBAL_A); asm.jz('end')
    asm.push_int(REG_OUT); asm.set_reg(REG_INDEX)
    asm.label('end'); return_nothing(asm)
    return asm, 0


def loop_function() -> tuple[Asm, int]:
    """i = 0; while i < LOOP_LIMIT: i = i + 1; GLOBAL[0] = i"""
    asm = Asm()
    asm.push_int(0)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE); asm.jmp('head')
    asm.label('done'); asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def counter_loop_function() -> tuple[Asm, int]:
    """i = 0; while i < LOOP_LIMIT: callee(UNRELATED_ARG); i = i + 1: only the loop's condition reads i"""
    asm = Asm()
    asm.push_int(0)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.push_int(UNRELATED_ARG); asm.call(CALLEE_ID)
    asm.label('back'); asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('head')
    asm.label('done'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def register_loop_function() -> tuple[Asm, int]:
    """r = 0; i = 0; while i < LOOP_LIMIT: r = r + 1; i = i + 1 (r register REG_INDEX, updated first): only the return
    reads r, among the registers it passes on"""
    asm = Asm()
    asm.push_int(0); asm.push_int(0); asm.set_reg(REG_INDEX)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.get_reg(REG_INDEX); asm.push_int(1); asm.add(); asm.set_reg(REG_INDEX)
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('head')
    asm.label('done'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def deep_join_function() -> tuple[Asm, int]:
    """v = DEEP_INITIAL; then PHI_DEPTH + 1 times: if GLOBAL[i]: v = DEEP_INITIAL + i + 1; GLOBAL[0] = v: the value
    stored merges more joins deep than a phi is spelled out"""
    asm = Asm()
    asm.push_int(DEEP_INITIAL)
    for index in range(PHI_DEPTH + 1):
        asm.load_global(index); asm.jz(f'skip{index}')
        asm.push_int(DEEP_INITIAL + index + 1); asm.pop_to(-WORD_SIZE)
        asm.label(f'skip{index}')
    asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def endless_tail_function() -> tuple[Asm, int]:
    """f(a, b): if b: { if a: REG = 1 else REG = 2; callee() } then loop forever: the call runs on the outer arm only,
    in a block the endless loop post-dominates. The branches read parameters, which a call does not change, and only
    the call is an effect, so a moved call differs in its guard alone"""
    asm = Asm()
    asm.load_stack(-WORD_SIZE); asm.jz('forever')
    asm.load_stack(-2 * WORD_SIZE); asm.jz('else')
    asm.push_int(1); asm.set_reg(REG_INDEX); asm.jmp('join')
    asm.label('else'); asm.push_int(2); asm.set_reg(REG_INDEX)
    asm.label('join'); call(asm, 'outer')
    asm.label('forever'); asm.jmp('forever')
    return asm, 0


def tail_call_function() -> tuple[Asm, int]:
    """callee(1); then a tail call (CALL_SCRIPT_NO_RETURN) of another script's function, which MLIL writes as the
    script call and the return of its result"""
    asm = Asm()
    call(asm, 'first', 1)
    asm.push_int(TAIL_CALL_ARG); asm.call_script_no_return(1)
    return asm, 1


# === Mutations of the MLIL ===

def is_debug_log(inst) -> bool:
    return isinstance(inst, MLILCall) and inst.target == DEBUG_LOG_CALL_TARGET


def is_call(inst) -> bool:
    return isinstance(inst, MediumLevelILCall) and not is_debug_log(inst)


def rewrite(node, transform):
    """transform applied bottom-up to every expression under node"""
    return transform(map_operands(node, lambda operand: rewrite(operand, transform)))


def replace_reads(mlil, old, new, start: tuple):
    """Every read of variable old from the statement at start on (in its block) read as variable new instead"""
    block, index, _ = start
    for position in range(index, len(block.instructions)):
        block.instructions[position] = rewrite(
            block.instructions[position], lambda e: MLILVar(new) if isinstance(e, MLILVar) and e.var == old else e)


class TestPlantedBugs(unittest.TestCase):
    """Each bug class a translator or a pass could bring, planted in real MLIL: the logic check reports its category"""

    def check(self, build, mutate, expected: str, argc: int = 0):
        reference, mlil = reference_and_mlil(build, argc)
        self.assertEqual(categories(reference, mlil), set(), 'the unchanged MLIL compares clean')
        mutate(mlil)
        self.assertIn(expected, categories(reference, mlil))

    def test_swapped_arguments(self):
        def mutate(mlil):
            inst = first(mlil, is_call)[2]
            inst.args[0], inst.args[1] = inst.args[1], inst.args[0]
        self.check(calls_function, mutate, 'arg_differs')

    def test_changed_constant(self):
        def mutate(mlil):
            inst = first(mlil, is_call)[2]
            inst.args[0] = MLILConst(inst.args[0].value + 1)
        self.check(calls_function, mutate, 'arg_differs')

    def test_dropped_effect(self):
        def mutate(mlil):
            block, index, _ = first(mlil, lambda inst: isinstance(inst, MLILStoreGlobal))
            del block.instructions[index]
        self.check(calls_function, mutate, 'missing_effect')

    def test_duplicated_effect(self):
        def mutate(mlil):
            block, index, inst = first(mlil, is_call)
            block.instructions.insert(index, inst.rebuild(*inst.args))
        self.check(calls_function, mutate, 'added_effect')

    def test_two_calls_swapped(self):
        def mutate(mlil):
            calls = [entry for entry in statements(mlil) if is_call(entry[2])]
            (block, a, call_a), (_, b, call_b) = calls[0], calls[1]
            block.instructions[a], block.instructions[b] = call_b, call_a
        self.check(calls_function, mutate, 'order_differs')

    def test_debug_log_argument_changed(self):
        def mutate(mlil):
            inst = first(mlil, is_debug_log)[2]
            inst.args[1] = MLILConst(MESSAGE + '!')
        self.check(calls_function, mutate, 'arg_differs')

    def test_debug_log_dropped(self):
        def mutate(mlil):
            block, index, _ = first(mlil, is_debug_log)
            del block.instructions[index]
        self.check(calls_function, mutate, 'missing_effect')

    def test_debug_log_duplicated(self):
        def mutate(mlil):
            block, index, inst = first(mlil, is_debug_log)
            block.instructions.insert(index, inst.rebuild(*inst.args))
        self.check(calls_function, mutate, 'added_effect')

    def test_flipped_branch(self):
        def mutate(mlil):
            branch = first(mlil, lambda inst: isinstance(inst, MLILIf))[2]
            branch.true_target, branch.false_target = branch.false_target, branch.true_target
        self.check(branch_function, mutate, 'branch_targets_differ')

    def test_changed_condition(self):
        def mutate(mlil):
            block, index, branch = first(mlil, lambda inst: isinstance(inst, MLILIf))
            condition = rewrite(branch.condition,
                                lambda e: MLILLoadGlobal(GLOBAL_C) if isinstance(e, MLILLoadGlobal) else e)
            block.instructions[index] = MLILIf(condition, branch.true_target, branch.false_target) \
                .copy_metadata_from(branch)
        self.check(branch_function, mutate, 'condition_differs')

    def test_call_moved_under_a_branch(self):
        def mutate(mlil):
            block, index, inst = first(mlil, is_call)
            branch = block.instructions[-1]
            del block.instructions[index]
            branch.false_target.instructions.insert(0, inst)
        self.check(branch_function, mutate, 'guard_differs')

    def test_stale_register_read(self):
        """x = reg0; call; use(x) read as use(reg0): the copy before the call left out"""
        def mutate(mlil):
            start = first(mlil, lambda inst: isinstance(inst, MLILSetVar) and isinstance(inst.value, MLILVar))
            copy = start[2]
            later = (start[0], start[1] + 1, None)
            replace_reads(mlil, copy.var, copy.value.var, later)
        self.check(two_results_function, mutate, 'arg_differs')

    def test_reused_temporary(self):
        """The second held result given the first one's variable"""
        def mutate(mlil):
            copies = [entry for entry in statements(mlil)
                      if isinstance(entry[2], MLILSetVar) and isinstance(entry[2].value, MLILVar)]
            (_, _, x), (block, index, y) = copies[0], copies[1]
            block.instructions[index] = MLILSetVar(x.var, y.value).copy_metadata_from(y)
            replace_reads(mlil, y.var, x.var, (block, index + 1, None))
        self.check(two_results_function, mutate, 'arg_differs')

    def test_out_parameter_read_before_its_call(self):
        """GLOBAL[0] = v moved before callee(&v): the read no longer sees what the call wrote"""
        def mutate(mlil):
            block, index, store = first(mlil, lambda inst: isinstance(inst, MLILStoreGlobal))
            call_index = first(mlil, is_call)[1]
            del block.instructions[index]
            block.instructions.insert(call_index, store)
        self.check(out_parameter_function, mutate, 'arg_differs')

    def test_value_behind_a_pointer_changed(self):
        """v's initial value changed before callee(&v): only the callee can read it, and v after the call is the call's
        leaf"""
        def mutate(mlil):
            init = first(mlil, lambda inst: isinstance(inst, MLILStoreDeref)    # v's memory form, *&v = OUT_INITIAL
                         and isinstance(inst.value, MLILConst) and inst.value.value == OUT_INITIAL)[2]
            init.value = MLILConst(OUT_INITIAL + 1)
        self.check(initialised_out_parameter_function, mutate, 'arg_differs')

    def test_value_merged_past_the_phi_depth_changed(self):
        """v's initial value changed: it reaches the store only through more joins than a phi spells out"""
        def mutate(mlil):
            init = first(mlil, lambda inst: isinstance(inst, MLILSetVar) and isinstance(inst.value, MLILConst)
                         and inst.value.value == DEEP_INITIAL)[2]
            init.value = MLILConst(DEEP_INITIAL + PHI_DEPTH + 2)
        self.check(deep_join_function, mutate, 'arg_differs')

    def test_register_written_before_the_return(self):
        """A register the bytecode leaves alone written before the return: the caller can read it after the call"""
        def mutate(mlil):
            block, index, _ = first(mlil, lambda inst: isinstance(inst, MLILRet))
            block.instructions.insert(index, MLILStoreReg(REG_INDEX, MLILConst(1)))
        self.check(calls_function, mutate, 'return_differs')

    def test_value_held_across_an_unrelated_call_changed(self):
        """v's initial value changed: read after a call that is given no pointer to v, which a later call is"""
        def mutate(mlil):
            init = first(mlil, lambda inst: isinstance(inst, MLILStoreDeref)    # v's memory form, *&v = OUT_INITIAL
                         and isinstance(inst.value, MLILConst) and inst.value.value == OUT_INITIAL)[2]
            init.value = MLILConst(OUT_INITIAL + 1)
        self.check(unrelated_call_function, mutate, 'arg_differs')

    def test_read_after_a_call_that_reaches_it_through_a_global_made_stale(self):
        """GLOBAL_B = v after the call read as v's value before it: the call can write v through GLOBAL_A"""
        def mutate(mlil):
            store = first(mlil, lambda inst: isinstance(inst, MLILStoreGlobal) and inst.index == GLOBAL_B)[2]
            store.value = MLILConst(OUT_INITIAL)
        self.check(escaped_address_function, mutate, 'arg_differs')

    def test_value_behind_a_pointer_to_a_pointer_changed(self):
        """v's initial value changed before callee(&q), q = &v: the callee can read v through q"""
        def mutate(mlil):
            init = first(mlil, lambda inst: isinstance(inst, MLILStoreDeref)    # v's memory form, *&v = OUT_INITIAL
                         and isinstance(inst.value, MLILConst) and inst.value.value == OUT_INITIAL)[2]
            init.value = MLILConst(OUT_INITIAL + 1)
        self.check(pointer_to_pointer_function, mutate, 'arg_differs')

    def test_register_one_arm_leaves_changed(self):
        """The arm's write changed; the other arm's incoming value compares clean on both layers (MLIL copies it, LLIL
        leaves it)"""
        def mutate(mlil):
            write = first(mlil, lambda inst: isinstance(inst, MLILSetVar) and isinstance(inst.value, MLILConst)
                          and inst.value.value == REG_OUT)[2]
            write.value = MLILConst(REG_OUT + 1)
        self.check(one_arm_register_function, mutate, 'return_differs')

    def test_call_hoisted_out_of_an_endless_tail(self):
        """The outer arm's second call moved before the branch: it now runs on both arms"""
        def mutate(mlil):
            block, index, inst = [entry for entry in statements(mlil) if is_call(entry[2])][-1]
            del block.instructions[index]
            mlil.basic_blocks[0].instructions.insert(0, inst)
        self.check(endless_tail_function, mutate, 'guard_differs', ENDLESS_TAIL_PARAMETERS)

    def test_loop_update_changed(self):
        """i = i + 1 made i = i + 3: the value after the loop is the same leaf, the value carried round differs; also
        where only the loop's condition reads it, or only the return's registers"""
        def mutate(mlil):
            block, index, update = first(mlil, lambda inst: isinstance(inst, MLILSetVar)
                                         and isinstance(inst.value, MLILAdd))
            block.instructions[index] = MLILSetVar(update.var, MLILAdd(update.value.lhs, MLILConst(3))) \
                .copy_metadata_from(update)
        for build in (loop_function, counter_loop_function, register_loop_function):
            with self.subTest(build.__name__):
                self.check(build, mutate, 'loop_value_differs')

    def test_tail_call(self):
        """The tail call compares clean with MLIL's script call and return; the call's result not returned differs"""
        def mutate(mlil):
            block, index, ret = first(mlil, lambda inst: isinstance(inst, MLILRet))
            block.instructions[index] = MLILRet(MLILConst(0)).copy_metadata_from(ret)
        self.check(tail_call_function, mutate, 'return_differs')

    def test_ordering_inverted(self):
        """!(i < LIMIT) written i >= LIMIT: equal but for NaN, its own category; a call inside the loop runs under the
        inverted branch, its arm read against the condition's representative core, so it is no guard difference"""
        def mutate(mlil):
            block, index, branch = first(mlil, lambda inst: isinstance(inst, MLILIf))
            negated = next(node for node in walk(branch.condition) if isinstance(node, MLILLogicalNot))
            ordering = negated.operand
            self.assertIsInstance(ordering, MLILLt)
            block.instructions[index] = MLILIf(MLILGe(ordering.lhs, ordering.rhs), branch.true_target,
                                               branch.false_target).copy_metadata_from(branch)
        for build in (loop_function, loop_call_function):
            with self.subTest(function=build.__name__):
                reference, mlil = reference_and_mlil(build)
                mutate(mlil)
                self.assertEqual(categories(reference, mlil), {'condition_ordering_inverted'})


class TestEffectValues(unittest.TestCase):
    """An effect's values compared LLIL against MLIL (compare.value_differences): a difference for each argument or
    storage key that differs, the arguments left out where the two pass different counts"""

    ADDRESS = 0x10
    KEY     = (ADDRESS, 'call')

    @classmethod
    def differences(cls, expected: tuple, found: tuple) -> list:
        """The differences of one call passing expected on the reference and found on the checked side"""
        sides = [Facts(effects={cls.KEY: [Effect(cls.ADDRESS, 'call', CALLEE_ID, args)]}) for args in (expected, found)]
        return logic_check.compare_facts(*sides)

    def test_unequal_argument_counts(self):
        """The first argument dropped: the count differs, and the arguments left are not compared by index"""
        self.assertEqual(self.differences((const(1), const(2)), (const(2),)),
                         [logic_check.Difference('argc_differs', self.KEY, (2, 1))])

    def test_two_arguments_differing(self):
        self.assertEqual([(difference.category, difference.detail[0])
                          for difference in self.differences((const(1), const(2)), (const(3), const(4)))],
                         [('arg_differs', 0), ('arg_differs', 1)])


class TestRealScript(unittest.TestCase):
    """A real script with loops and branches: its LLIL and MLIL, and its MLIL and HLIL, compare clean in every
    function"""

    def test_btlsys(self):
        path = require(SORA2_SCRIPTS / 'battle' / 'btlsys.dat')
        results = logic_check.check_script(path, 'sora2')
        self.assertTrue(results)
        for result in results:
            with self.subTest(function=result.name):
                self.assertIsNone(result.internal_error)
                self.assertIsNone(result.decompile_error)
                self.assertEqual(result.mlil_differences, [])
                self.assertEqual(result.hlil_differences, [])


if __name__ == '__main__':
    unittest.main()
