#!/usr/bin/env python3
"""The logic check (tools/logic_check/): a bug planted in the MLIL of a small assembled function shows up as its
category, and the unchanged MLIL compares clean; the condition normal form; post-dominators and control dependence;
a real script compares clean"""

from pathlib import Path
from typing import Callable
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.mlil.mlil_translator import DEBUG_LOG_CALL_TARGET
from ir.llil.llil import WORD_SIZE
from ir.mlil.mlil import (
    MediumLevelILCall, MLILAdd, MLILCall, MLILConst, MLILGe, MLILIf, MLILLoadGlobal, MLILLogicalNot, MLILLt,
    MLILRet, MLILSetVar, MLILStoreDeref, MLILStoreGlobal, MLILStoreReg, MLILVar, map_operands, walk,
)
from tests.shared.corpus import SORA2_SCRIPTS, require
from tests.shared.llil_utils import lift_asm
from tests.shared.scp_asm import CALLEE_ID, CALLER_ID, Asm, returning_callee
import logic_check
from logic_check.evaluation import FUNCTION_ENTRY, Branch, Effect, Facts
from logic_check.post_dominators import EXIT, control_dependence, immediate_post_dominators
from logic_check.trees import const, op, truth

GLOBAL_A, GLOBAL_B, GLOBAL_C = 1, 2, 3
MESSAGE = 'this'
LOOP_LIMIT = 3
OUT_INITIAL = 1
REG_INDEX = 5
ENDLESS_TAIL_PARAMETERS = 2


# === Assembled functions ===

def call(asm: Asm, label: str, *args: int):
    """A local call of the callee with int arguments, returning at label"""
    asm.push_raw(CALLER_ID); asm.push_raw(label)
    for arg in args:
        asm.push_int(arg)
    asm.call(CALLEE_ID); asm.label(label)


def return_nothing(asm: Asm):
    asm.push_raw(0); asm.set_reg(0); asm.ret()


def calls_function() -> tuple[Asm, int]:
    """callee(8, 7); GLOBAL_A = its result; callee(10, 9); a DEBUG_LOG; returned"""
    asm = Asm()
    call(asm, 'first', 7, 8); asm.get_reg(0); asm.set_global(GLOBAL_A)
    call(asm, 'second', 9, 10)
    asm.push_str(MESSAGE); asm.push_int(5); asm.debug_log(2)
    return_nothing(asm)
    return asm, 2


def branch_function() -> tuple[Asm, int]:
    """callee(4); if GLOBAL[0]: callee(1) else GLOBAL_B = 3"""
    asm = Asm()
    call(asm, 'before', 4)
    asm.load_global(0); asm.jz('else')
    call(asm, 'then', 1); asm.jmp('end')
    asm.label('else'); asm.push_int(3); asm.set_global(GLOBAL_B)
    asm.label('end'); return_nothing(asm)
    return asm, 1


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


def loop_function() -> tuple[Asm, int]:
    """i = 0; while i < LOOP_LIMIT: i = i + 1; GLOBAL[0] = i"""
    asm = Asm()
    asm.push_int(0)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE); asm.jmp('head')
    asm.label('done'); asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def initialised_out_parameter_function() -> tuple[Asm, int]:
    """v = OUT_INITIAL; callee(&v); GLOBAL[0] = v: the callee may read v before it writes it"""
    asm = Asm()
    asm.push_int(OUT_INITIAL)
    asm.push_raw(CALLER_ID); asm.push_raw('after'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('after'); asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


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


def reference_and_mlil(build, argc: int = 0) -> tuple:
    """The function's LLIL facts (taken before the conversion) and its MLIL as the decompiler makes it; argc its
    parameters"""
    asm, callee_argc = build()
    _, llil = lift_asm(asm, argc=argc, others=(returning_callee(callee_argc),))
    reference = logic_check.analyze(logic_check.LLILLayer(llil))
    return reference, convert_falcom_llil_to_mlil(llil, optimize=True, infer_types=False)


def categories(reference, mlil) -> set[str]:
    return {difference.category for difference in
            logic_check.compare_facts(reference, logic_check.analyze(logic_check.MLILLayer(mlil)))}


# === Mutations of the MLIL ===

def statements(mlil) -> list[tuple]:
    """(block, index, statement) for every statement, in block order"""
    return [(block, index, inst) for block in mlil.basic_blocks for index, inst in enumerate(block.instructions)]


def first(mlil, predicate) -> tuple:
    found = [entry for entry in statements(mlil) if predicate(entry[2])]
    if not found:
        raise AssertionError('the mutation found nothing to change: the MLIL shape changed')
    return found[0]


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
    """Each bug class a translator or a pass could bring, planted in real MLIL: the comparator reports its category"""

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

    def test_register_written_before_the_return(self):
        """A register the bytecode leaves alone written before the return: the caller can read it after the call"""
        def mutate(mlil):
            block, index, _ = first(mlil, lambda inst: isinstance(inst, MLILRet))
            block.instructions.insert(index, MLILStoreReg(REG_INDEX, MLILConst(1)))
        self.check(calls_function, mutate, 'return_differs')

    def test_call_hoisted_out_of_an_endless_tail(self):
        """The outer arm's second call moved before the branch: it now runs on both arms"""
        def mutate(mlil):
            block, index, inst = [entry for entry in statements(mlil) if is_call(entry[2])][-1]
            del block.instructions[index]
            mlil.basic_blocks[0].instructions.insert(0, inst)
        self.check(endless_tail_function, mutate, 'guard_differs', ENDLESS_TAIL_PARAMETERS)

    def test_loop_update_changed(self):
        """i = i + 1 made i = i + 3: the value after the loop is the same leaf, the value carried round differs"""
        def mutate(mlil):
            block, index, update = first(mlil, lambda inst: isinstance(inst, MLILSetVar)
                                         and isinstance(inst.value, MLILAdd))
            block.instructions[index] = MLILSetVar(update.var, MLILAdd(update.value.lhs, MLILConst(3))) \
                .copy_metadata_from(update)
        self.check(loop_function, mutate, 'loop_value_differs')

    def test_ordering_inverted(self):
        """!(i < LIMIT) written i >= LIMIT: equal but for NaN, its own category"""
        def mutate(mlil):
            block, index, branch = first(mlil, lambda inst: isinstance(inst, MLILIf))
            negated = next(node for node in walk(branch.condition) if isinstance(node, MLILLogicalNot))
            ordering = negated.operand
            self.assertIsInstance(ordering, MLILLt)
            block.instructions[index] = MLILIf(MLILGe(ordering.lhs, ordering.rhs), branch.true_target,
                                               branch.false_target).copy_metadata_from(branch)
        reference, mlil = reference_and_mlil(loop_function)
        mutate(mlil)
        self.assertEqual(categories(reference, mlil), {'condition_ordering_inverted'})


class TestSplitLoopValues(unittest.TestCase):
    """Two de-SSA splits of one stack slot carried round one loop: each must carry the reference's value, so a right
    one does not hide a wrong one"""

    HEADER, BACK_EDGE = (FUNCTION_ENTRY, 10), 10
    SLOT, SPLIT, OTHER_SPLIT = ('stack', 0), ('name', 'var_s0'), ('name', 'var_s0_v0')

    def facts(self, read_by_store: tuple, carried: dict, neutral_key=None) -> Facts:
        """A loop test reading the first key carried, a global store after the loop reading read_by_store"""
        first_key = next(iter(carried))
        loop_leaf = lambda key: ('loop', self.HEADER, key)
        condition = op('LT', [loop_leaf(first_key), const(LOOP_LIMIT)])
        facts = Facts(neutral_key=neutral_key)
        facts.effects[(20, 'store global')] = [Effect(20, 'store global', 0, (loop_leaf(read_by_store),))]
        facts.branches[5] = Branch(5, condition, 6, 20)
        for key, step in carried.items():
            facts.loop_values[(self.HEADER, key, FUNCTION_ENTRY)] = const(0)
            facts.loop_values[(self.HEADER, key, self.BACK_EDGE)] = op('ADD', [loop_leaf(key), const(step)])
        return facts

    def compare(self, other_split_step: int) -> set[str]:
        reference = self.facts(self.SLOT, {self.SLOT: 1})
        checked = self.facts(self.OTHER_SPLIT, {self.SPLIT: 1, self.OTHER_SPLIT: other_split_step},
                             neutral_key=lambda key: self.SLOT if key in (self.SPLIT, self.OTHER_SPLIT) else key)
        return {difference.category for difference in logic_check.compare_facts(reference, checked)}

    def test_both_splits_right(self):
        self.assertEqual(self.compare(1), set())

    def test_wrong_split_beside_a_right_one(self):
        self.assertEqual(self.compare(3), {'loop_value_differs'})


class TestConditionNormalForm(unittest.TestCase):
    """Conditions compare in a normal form: the truth-test spellings equated, negation pushed through && and ||, ==
    and != commutative; an ordering is never inverted"""

    A, B = ('param', 1), ('param', 2)
    ZERO = const(0)

    def test_truth_test_spellings(self):
        condition = op('EQ', [self.A, self.B])
        negated = truth(condition)
        for spelling in (op('NE', [self.A, self.B]), op('EQ', [condition, self.ZERO]), op('TEST_ZERO', [condition]),
                         op('LOGICAL_NOT', [condition])):
            self.assertEqual(truth(spelling), (negated[0], not negated[1]), spelling)
        self.assertEqual(truth(op('NE', [condition, self.ZERO])), negated)

    def test_constant_condition(self):
        self.assertEqual(truth(op('EQ', [self.ZERO, self.ZERO])), truth(op('LOGICAL_NOT', [self.ZERO])))

    def test_negation_through_logic(self):
        both = op('LOGICAL_AND', [self.A, self.B])
        either_not = op('LOGICAL_OR', [op('TEST_ZERO', [self.A]), op('TEST_ZERO', [self.B])])
        self.assertEqual(truth(op('TEST_ZERO', [both])), truth(either_not))

    def test_equality_is_commutative(self):
        self.assertEqual(op('EQ', [self.A, self.B]), op('EQ', [self.B, self.A]))
        self.assertNotEqual(op('LT', [self.A, self.B]), op('LT', [self.B, self.A]))

    def test_orderings_are_not_inverted(self):
        self.assertNotEqual(truth(op('TEST_ZERO', [op('LT', [self.A, self.B])]))[0], op('GE', [self.A, self.B]))
        self.assertEqual(truth(op('TEST_ZERO', [op('LT', [self.A, self.B])]), invert_orderings=True),
                         (op('GE', [self.A, self.B]), False))


class TestPostDominators(unittest.TestCase):
    """Cooper-Harvey-Kennedy on the reversed graph, and control dependence read off its tree"""

    @classmethod
    def graph(cls, edges: dict) -> tuple[list, Callable]:
        return list(edges), lambda block: edges[block]

    def test_diamond(self):
        blocks, successors = self.graph({'a': ['b', 'c'], 'b': ['d'], 'c': ['d'], 'd': []})
        ipdom = immediate_post_dominators(blocks, successors)
        self.assertEqual({block: ipdom[block] for block in blocks}, {'a': 'd', 'b': 'd', 'c': 'd', 'd': EXIT})

        branches = lambda block: (1, 'b', 'c') if block == 'a' else None
        dependence = control_dependence(blocks, successors, branches)
        self.assertEqual(dependence, {'a': frozenset(), 'b': {(1, 't')}, 'c': {(1, 'f')}, 'd': frozenset()})

    def test_loop_test_controls_the_body_and_itself(self):
        blocks, successors = self.graph({'entry': ['head'], 'head': ['body', 'exit'], 'body': ['head'], 'exit': []})
        branches = lambda block: (2, 'body', 'exit') if block == 'head' else None
        dependence = control_dependence(blocks, successors, branches)
        self.assertEqual(dependence['body'], {(2, 't')})
        self.assertEqual(dependence['head'], {(2, 't')})
        self.assertEqual(dependence['exit'], frozenset())

    def test_endless_loop_still_has_a_post_dominator(self):
        blocks, successors = self.graph({'a': ['b', 'c'], 'b': ['b'], 'c': []})
        ipdom = immediate_post_dominators(blocks, successors)
        self.assertEqual(ipdom['b'], EXIT)
        self.assertEqual(ipdom['a'], EXIT)

    def test_block_before_an_endless_loop_keeps_its_guard(self):
        """d runs only on a's true arm, and every path ends in the endless loop e"""
        blocks, successors = self.graph({'a': ['b', 'c'], 'b': ['d'], 'c': ['e'], 'd': ['e'], 'e': ['e']})
        self.assertEqual(immediate_post_dominators(blocks, successors)['d'], 'e')
        branches = lambda block: (1, 'b', 'c') if block == 'a' else None
        dependence = control_dependence(blocks, successors, branches)
        self.assertEqual(dependence['d'], {(1, 't')})
        self.assertEqual(dependence['e'], frozenset())


class TestRealScript(unittest.TestCase):
    """A real script with loops and branches: its LLIL and MLIL compare clean in every function"""

    def test_btlsys(self):
        path = require(SORA2_SCRIPTS / 'battle' / 'btlsys.dat')
        results = logic_check.check_script(path, 'sora2')
        self.assertTrue(results)
        for result in results:
            with self.subTest(function=result.name):
                self.assertIsNone(result.internal_error)
                self.assertIsNone(result.decompile_error)
                self.assertEqual(result.differences, [])


if __name__ == '__main__':
    unittest.main()
