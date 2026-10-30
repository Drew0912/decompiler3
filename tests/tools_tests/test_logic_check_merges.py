#!/usr/bin/env python3
"""The logic check's merged values (tools/logic_check/): the de-SSA splits of one slot carried round a loop, chains of
gated merges never cut, values met at a join compared exactly"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from dc3.utils import raise_recursion_limit
from ir.llil.llil import WORD_SIZE
from tests.shared.logic_check_functions import (
    GLOBAL_A, GLOBAL_B, GLOBAL_C, LOOP_LIMIT, REG_INDEX, categories, hlil_categories, mlil_and_hlil, reference_and_mlil,
    return_nothing,
)
from tests.shared.scp_asm import Asm
import logic_check
from logic_check import formulas
from logic_check.evaluation import widen_loop_headers
from logic_check.facts import Branch, Effect, Facts
from logic_check.naming import FUNCTION_ENTRY, GatedNaming
from logic_check.neutral_names import Fingerprints
from logic_check.post_dominators import ControlFlow
from logic_check.state import State, merged_value
from logic_check.trees import const, equal_trees, op

REPEATED_REG, EQUAL_REG, LARGER_REG = 1, 2, 3   # repeated_register_arms_function's registers
DEEP_MERGES = 1_500             # TestDeepValues' chains: a call through __call__ fails from 1,200, Python frames 2,000


# === Assembled functions ===

def repeated_register_arms_function() -> tuple[Asm, int]:
    """r1 = r2 = 1, r3 = 2; REG = r3 + r2 if GLOBAL_A else r1 + r1; GLOBAL[0] = REG: one arm's sum reads one value
    twice, the other's an equal value and an unequal one"""
    asm = Asm()
    for register, value in ((REPEATED_REG, 1), (EQUAL_REG, 1), (LARGER_REG, 2)):
        asm.push_int(value); asm.set_reg(register)
    asm.load_global(GLOBAL_A); asm.jz('other')
    asm.get_reg(LARGER_REG); asm.get_reg(EQUAL_REG); asm.add(); asm.set_reg(REG_INDEX); asm.jmp('join')
    asm.label('other'); asm.get_reg(REPEATED_REG); asm.get_reg(REPEATED_REG); asm.add(); asm.set_reg(REG_INDEX)
    asm.label('join'); asm.get_reg(REG_INDEX); asm.set_global(0)
    return_nothing(asm)
    return asm, 0


def uneven_inner_choices_function() -> tuple[Asm, int]:
    """v = 0; if GLOBAL_A: (if GLOBAL_B: v = 1 elif GLOBAL_C: v = 2 else return) else (if GLOBAL_B: v = 1 elif GLOBAL_C:
    v = 2 else v = 3); each arm then v = v + 0; GLOBAL[0] = v: the arms' choices of two and three values, the first two
    alike"""
    asm = Asm()
    asm.push_int(0)
    asm.load_global(GLOBAL_A); asm.jz('long')
    asm.load_global(GLOBAL_B); asm.jz('short_c')
    asm.push_int(1); asm.pop_to(-WORD_SIZE); asm.jmp('short_join')
    asm.label('short_c'); asm.load_global(GLOBAL_C); asm.jz('early')
    asm.push_int(2); asm.pop_to(-WORD_SIZE); asm.jmp('short_join')
    asm.label('early'); asm.pop(WORD_SIZE); return_nothing(asm)
    asm.label('short_join'); asm.load_stack(-WORD_SIZE); asm.push_int(0); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('outer')
    asm.label('long'); asm.load_global(GLOBAL_B); asm.jz('long_c')
    asm.push_int(1); asm.pop_to(-WORD_SIZE); asm.jmp('long_join')
    asm.label('long_c'); asm.load_global(GLOBAL_C); asm.jz('long_last')
    asm.push_int(2); asm.pop_to(-WORD_SIZE); asm.jmp('long_join')
    asm.label('long_last'); asm.push_int(3); asm.pop_to(-WORD_SIZE)
    asm.label('long_join'); asm.load_stack(-WORD_SIZE); asm.push_int(0); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.label('outer'); asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


class WriteBlock:
    def __init__(self, *writes: tuple):
        self.instructions = list(writes)


class LoopOfWrites:
    """A layer adapter (evaluation.py) as far as widen_loop_headers reads one: entry -> header -> body -> header,
    header -> exit; each instruction a (key, tree) write"""

    OWN_STORAGE_NAMES = True
    BRANCH_ADDRESS, HEADER_NAME = 5, (FUNCTION_ENTRY, 10)

    def __init__(self, entry_write: tuple, body_write: tuple, neutral_key):
        self.entry, self.body = WriteBlock(entry_write), WriteBlock(body_write)
        self.header, self.exit = WriteBlock(), WriteBlock()
        self.edges = {self.entry: [self.header], self.header: [self.body, self.exit], self.body: [self.header],
                      self.exit: []}
        self.neutral_key = neutral_key

    def successors(self, block) -> list:
        return self.edges[block]

    def predecessors(self, block) -> list:
        return [other for other, targets in self.edges.items() if block in targets]

    def branch(self, block) -> tuple | None:
        return (self.BRANCH_ADDRESS, self.body, self.exit) if block is self.header else None

    def header_name(self, block):
        return self.HEADER_NAME if block is self.header else None

    @classmethod
    def step(cls, inst: tuple, state: State, facts: Facts) -> list[Effect]:
        key, tree = inst
        state.items[key] = tree
        return []


class TestSplitLoopValues(unittest.TestCase):
    """Two de-SSA splits of one stack slot: carried round one loop, each must carry the reference's value, so a right
    one does not hide a wrong one; met at a join or round a loop, they stay two values, not one under neutral names"""

    HEADER, BACK_EDGE, OUTER_HEADER = (FUNCTION_ENTRY, 10), 10, (FUNCTION_ENTRY, 20)
    SLOT, SPLIT, OTHER_SPLIT = ('stack', 0), ('name', 'var_s0'), ('name', 'var_s0_v0')
    KEY = ('reg', REG_INDEX)

    def facts(self, read_by_store: tuple, carried: dict, neutral_key=None) -> Facts:
        """A loop test reading the first key carried, a global store after the loop reading read_by_store"""
        first_key = next(iter(carried))
        loop_leaf = lambda key: ('loop', self.HEADER, key)
        condition = op('LT', [loop_leaf(first_key), const(LOOP_LIMIT)])
        facts = Facts(neutral_key=neutral_key)
        facts.effects[(20, 'store global')] = [Effect(20, 'store global', 0, (loop_leaf(read_by_store),))]
        facts.branches[5] = Branch(5, condition, 6, 20)
        for key, step in carried.items():
            facts.loop_values[(self.HEADER, key, FUNCTION_ENTRY)] = [(formulas.TRUE, const(0))]
            facts.loop_values[(self.HEADER, key, self.BACK_EDGE)] = [(formulas.TRUE,
                                                                      op('ADD', [loop_leaf(key), const(step)]))]
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

    def neutral_key(self, key):
        return self.SLOT if key in (self.SPLIT, self.OTHER_SPLIT) else key

    def test_splits_kept_apart_at_a_join(self):
        """Each arm writes a register from another split's loop leaf: one name under neutral names, two values"""
        leaves = [('loop', self.HEADER, split) for split in (self.SPLIT, self.OTHER_SPLIT)]
        states = [(formulas.literal(('param', 0), polarity), State({self.KEY: leaf}))
                  for polarity, leaf in zip((True, False), leaves)]
        value = merged_value(None, self.KEY, states, Fingerprints(self.neutral_key))
        self.assertEqual(value[0], 'gamma')
        self.assertEqual([leaf for _, leaf in value[1]], leaves)

    def test_splits_kept_apart_round_a_loop(self):
        """A register enters a loop with one split's leaf of an outer loop and goes round with the other's: the loop
        changes it, so its header widens it"""
        entered, carried = (('loop', self.OUTER_HEADER, split) for split in (self.SPLIT, self.OTHER_SPLIT))
        layer = LoopOfWrites((self.KEY, entered), (self.KEY, carried), self.neutral_key)
        flow = ControlFlow(layer.entry, layer.successors, layer.predecessors, layer.branch, GatedNaming.exit_rank)
        _, _, widened = widen_loop_headers(layer, flow, GatedNaming(layer, flow), Fingerprints(self.neutral_key))
        self.assertEqual(widened[layer.header], {self.KEY})


class TestDeepValues(unittest.TestCase):
    """Chains of DEEP_MERGES gated merges, never cut, built as trees (a function so deep takes seconds to decompile):
    digested and compared at the decompiler's recursion limit, through Python frames, each shared part once"""

    def setUp(self):
        self.addCleanup(sys.setrecursionlimit, sys.getrecursionlimit())
        raise_recursion_limit()

    @classmethod
    def increments(cls, initial: int = 0) -> tuple:
        """v = initial; DEEP_MERGES times: if p_i: v = v + 1: both arms of each merge hold the one before"""
        value = const(initial)
        for index in range(DEEP_MERGES):
            condition = ('param', index)
            value = ('gamma', ((formulas.literal(condition, True), op('ADD', [value, const(1)])),
                               (formulas.literal(condition, False), value)))
        return value

    @classmethod
    def retested_value(cls) -> tuple:
        """v = 0; DEEP_MERGES times: v = 1 if v == i else 0: each merge's formulas test the one before"""
        value = const(0)
        for index in range(1, DEEP_MERGES + 1):
            core = op('EQ', [value, const(index)])
            value = ('gamma', ((formulas.literal(core, True), const(1)), (formulas.literal(core, False), const(0))))
        return value

    def test_increments_digested(self):
        digest = Fingerprints(lambda key: key)
        self.assertNotEqual(digest(self.increments()), digest(self.increments(initial=1)))

    def test_increments_compared(self):
        self.assertTrue(equal_trees(self.increments(), self.increments()))
        self.assertFalse(equal_trees(self.increments(), self.increments(initial=1)))

    def test_retested_value_digested(self):
        """Each formula's key digests the merge before it"""
        self.assertEqual(Fingerprints(lambda key: key)(self.retested_value()),
                         Fingerprints(lambda key: key)(self.retested_value()))


class TestJoinedValues(unittest.TestCase):
    """Values met at a join compared exactly (trees.equal_trees): arms that write alike merge to one value, any others
    stay a choice on every layer, so a function compares clean"""

    def test_register_added_to_itself_in_one_arm(self):
        """One arm's sum reads one value twice, the other's an equal value and an unequal one: two values"""
        self.assertEqual(categories(*reference_and_mlil(repeated_register_arms_function)), set())

    def test_choices_of_two_and_three_values(self):
        """The arms' choices agree in their first two values: one with a third is not equal to one without"""
        self.assertEqual(hlil_categories(*mlil_and_hlil(uneven_inner_choices_function)), set())


if __name__ == '__main__':
    unittest.main()
