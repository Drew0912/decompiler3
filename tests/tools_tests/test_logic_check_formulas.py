#!/usr/bin/env python3
"""The logic check's conditions and formulas (tools/logic_check/): gated choices lifted into formulas, a formula as
text, the condition normal form, formulas compared as functions of their conditions"""

from pathlib import Path
from unittest import mock
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from ir.core.il_literals import SourceFloat
from tests.shared.hlil_cfg_utils import structure
from tests.shared.logic_check_functions import GLOBAL_A, NESTED_TESTS, first
import logic_check
from logic_check import choice_lifting, decision_diagrams, formulas, gated_comparison
from logic_check.facts import Branch, Facts
from logic_check.neutral_names import Fingerprints
from logic_check.trees import const, constant_truth, op, truth

PAIRS = 9                       # pairs of tests in TestFormulaKeys.pairs_formulas: 18 variables, past ROW_CAP's rows
PAIRS_KEY_NODES = 500           # a DIAGRAM_KEY_NODE_CAP: pair by pair 103-137 nodes fit, firsts first 1,537+ do not


class TestLiftedChoices(unittest.TestCase):
    """Gated choices inside a value or a condition lifted into the formulas their values arrive under
    (choice_lifting.choice_alternatives, choice_lifting.lifted_formula)"""

    EDGES = 7                       # incoming edges of each choice below, over two values

    def setUp(self):
        self.fingerprints = Fingerprints.of(Facts())

    def choice(self, first: int) -> tuple:
        """A choice over EDGES edges, each under a literal of its own, of the values 0 and 1"""
        return ('gamma', tuple((formulas.literal(('param', first + index), True), const(index % 2))
                               for index in range(self.EDGES)))

    def test_choice_in_a_leaf_found(self):
        choice = self.choice(0)
        read = ('global', GLOBAL_A, choice)         # a global read after the calls of either arm
        self.assertIs(choice_lifting.inner_choice(op('EQ', [read, const(0)]), set()), choice)

    def test_substitution_keeps_untouched_parts(self):
        choice, untouched = self.choice(0), op('ADD', [('param', 1), const(1)])
        tree = op('ADD', [untouched, choice])
        lifted = choice_lifting.substitute(tree, choice, const(1), {})
        self.assertIs(lifted[2][0], untouched)
        self.assertEqual(lifted[2][1], const(1))

    @mock.patch.object(choice_lifting, 'LIFTED_CHOICES', EDGES ** 3 - 1)
    def test_choices_counted_by_value(self):
        """Three choices in one operation: EDGES ** 3 alternatives by edge, past LIFTED_CHOICES; 2 ** 3 by value"""
        tree = op('EQ', [op('ADD', [self.choice(0), op('ADD', [self.choice(10), self.choice(20)])]), const(0)])
        alternatives, capped = choice_lifting.choice_alternatives(self.fingerprints, formulas.TRUE, tree, inner=True)
        self.assertFalse(capped)
        self.assertEqual(len(alternatives), 2 ** 3)

    def test_condition_split_before_its_choices_are_lifted(self):
        """a == 0 && b == 0 && c == 0 with room for two values only: lifted part by part, as FormulaKeys splits it"""
        parts = [op('EQ', [self.choice(first), const(0)]) for first in (0, 10, 20)]
        condition = op('LOGICAL_AND', [parts[0], op('LOGICAL_AND', parts[1:])])
        with mock.patch.object(choice_lifting, 'LIFTED_CHOICES', 2):
            lifted = choice_lifting.lifted_formula(self.fingerprints, formulas.literal(condition, True), {})
        self.assertIsNone(choice_lifting.inner_choice(lifted, set()))


class TestRenderedFormula(unittest.TestCase):
    """A gated detail's formula as text (gated_comparison.render), cut at RENDERED_FORMULA_CHARACTERS"""

    FORMULA = ('or', (formulas.TRUE, formulas.TRUE))   # (true || true)

    def test_cut_exactly_at_the_cap(self):
        """Text that reaches the cap with parts left is cut, and shown cut; text that ends there is whole"""
        with mock.patch.object(gated_comparison, 'RENDERED_FORMULA_CHARACTERS', len('(true || ')):
            self.assertEqual(gated_comparison.render(self.FORMULA), '(true || ...')
        with mock.patch.object(gated_comparison, 'RENDERED_FORMULA_CHARACTERS', len('(true || true)')):
            self.assertEqual(gated_comparison.render(self.FORMULA), '(true || true)')


class TestConditionNormalForm(unittest.TestCase):
    """Conditions compare in a normal form: the truth-test spellings equated, negation pushed through && and ||, ==
    and != commutative; an ordering is never inverted"""

    A, B = ('param', 1), ('param', 2)
    ZERO = const(0)

    def test_a_constant_condition_negated(self):
        """`!c` of a constant c is decided, as ir/hlil's constant_truth decides it: HLIL folds its branch"""
        self.assertIs(constant_truth(op('LOGICAL_NOT', [op('LT', [const(1), const(2)])])), False)

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

    def test_truth_test_values_are_one_tree(self):
        self.assertEqual(op('LOGICAL_NOT', [self.A]), op('TEST_ZERO', [self.A]))
        self.assertEqual(op('TEST_ZERO', [self.A]), op('EQ', [self.A, self.ZERO]))

    def test_equality_is_commutative(self):
        fingerprints = Fingerprints.of(Facts())
        self.assertEqual(fingerprints(op('EQ', [self.A, self.B])), fingerprints(op('EQ', [self.B, self.A])))
        self.assertNotEqual(fingerprints(op('LT', [self.A, self.B])), fingerprints(op('LT', [self.B, self.A])))

    def test_orderings_are_not_inverted(self):
        less, at_least = op('LT', [self.A, self.B]), op('GE', [self.A, self.B])
        self.assertNotEqual(truth(op('TEST_ZERO', [less]))[0], at_least)
        self.assertEqual(truth(at_least, representative=True), (less, True))
        self.assertEqual(truth(op('TEST_ZERO', [at_least]), representative=True), (less, False))

    @classmethod
    def branch_categories(cls, reference: tuple, checked: tuple) -> set[str]:
        """The categories of one branch's (condition, true target, false target) on two layers"""
        sides = []
        for condition, true_target, false_target in (reference, checked):
            facts = Facts()
            facts.branches[cls.BRANCH] = Branch(cls.BRANCH, condition, true_target, false_target)
            sides.append(facts)
        return {difference.category for difference in logic_check.compare_facts(*sides)}

    BRANCH, THEN, ELSE = 5, 6, 7

    def test_negation_dropped_by_swapping_targets(self):
        """!(a < b) to THEN against a < b to ELSE: exact, no difference"""
        less = op('LT', [self.A, self.B])
        self.assertEqual(self.branch_categories((op('TEST_ZERO', [less]), self.THEN, self.ELSE),
                                                (less, self.ELSE, self.THEN)), set())

    def test_inversion_with_swapped_arms(self):
        """a < b to THEN against a >= b to ELSE: equal but for NaN, counted once"""
        self.assertEqual(self.branch_categories((op('LT', [self.A, self.B]), self.THEN, self.ELSE),
                                                (op('GE', [self.A, self.B]), self.ELSE, self.THEN)),
                         {'condition_ordering_inverted'})


class TestFormulaKeys(unittest.TestCase):
    """Formulas compare as functions of their conditions: the equality tests of one value exclude each other, but
    for float constants; a condition nothing depends on is left out; past the truth table's rows, by decision
    diagram, over the variables a formula depends on"""

    X, Y = ('param', 1), ('param', 2)

    def setUp(self):
        self.keys = formulas.FormulaKeys(Fingerprints(lambda key: key))

    @classmethod
    def equals(cls, value: tuple, constant: int | float, polarity: bool = True) -> tuple:
        return formulas.literal(op('EQ', [value, const(constant)]), polarity)

    @classmethod
    def named_digest(cls, tree) -> str:
        """A digest naming a parameter ('param', name) by its name, and / or items sorted, so a test sets the variable
        orders by the names; a literal sorts before an and / or"""
        if not isinstance(tree, tuple):
            return repr(tree)
        if tree[0] == 'param':
            return tree[1]
        if tree[0] in ('and', 'or'):
            return f'({tree[0]} {" ".join(sorted(cls.named_digest(item) for item in tree[1]))})'
        return '(' + ' '.join(cls.named_digest(item) for item in tree) + ')'

    @classmethod
    def named(cls, name: str) -> tuple:
        return formulas.literal(op('EQ', [('param', name), const(1)]), True)

    @classmethod
    def pairs_formulas(cls, together: bool) -> tuple[tuple, tuple]:
        """(any of PAIRS pairs of tests both holding, any pair's first holding), the names in sorted order each pair
        together or every pair's first before every second"""
        names = ([(f'p{index:02d}a', f'p{index:02d}b') for index in range(PAIRS)] if together else
                 [(f'x{index:02d}', f'y{index:02d}') for index in range(PAIRS)])
        pairs = formulas.disjunction([formulas.conjunction(cls.named(first), cls.named(second))
                                      for first, second in names])
        return pairs, formulas.disjunction([cls.named(first) for first, _ in names])

    def test_a_case_of_a_chain_and_of_its_switch(self):
        chain = formulas.conjunction(self.equals(self.X, 1, False), self.equals(self.X, 2))
        self.assertEqual(self.keys(chain), self.keys(self.equals(self.X, 2)))

    def test_a_truth_test_among_its_equalities(self):
        both = formulas.conjunction(formulas.literal(self.X, True), self.equals(self.X, 3))
        self.assertEqual(self.keys(both), self.keys(self.equals(self.X, 3)))

    def test_float_constants_that_compare_equal(self):
        """0.0 and -0.0 are two constants equal under float ==, as are 1 and 1.0: tests of one value against them may
        both hold, and a test of two of them is not decided. Floats as scripts decode them, SourceFloat, as well"""
        zero, negative_zero, one = SourceFloat(0.0, '0.0'), SourceFloat(-0.0, '-0.0'), SourceFloat(1.0, '1.0')
        for first, second in ((0.0, -0.0), (1, 1.0), (zero, negative_zero), (1, one)):
            both = formulas.conjunction(self.equals(self.X, first), self.equals(self.X, second, False))
            self.assertNotEqual(self.keys(both), self.keys(self.equals(self.X, first)), (first, second))
        constants = formulas.literal(op('EQ', [const(zero), const(negative_zero)]), True)
        self.assertNotEqual(self.keys(constants), formulas.FALSE_KEY)
        self.assertEqual(const(SourceFloat(0.2999999523162842, '0.3')), const(0.2999999523162842))

    def test_a_condition_nothing_depends_on_left_out(self):
        less = formulas.literal(op('LT', [self.X, self.Y]), True)
        either = formulas.disjunction([formulas.conjunction(formulas.literal(self.Y, polarity), less)
                                       for polarity in (True, False)])
        self.assertEqual(self.keys(either), self.keys(less))

    def test_orderings_by_their_representatives(self):
        at_least = formulas.literal(op('GE', [self.X, self.Y]), True)
        not_less = formulas.literal(op('LT', [self.X, self.Y]), False)
        self.assertNotEqual(self.keys(at_least), self.keys(not_less))
        representative = formulas.FormulaKeys(Fingerprints(lambda key: key), representative=True)
        self.assertEqual(representative(at_least), representative(not_less))

    def test_past_the_row_cap(self):
        """any of NESTED_TESTS values, written flat and as an || chain one test at a time"""
        values = [('param', index) for index in range(NESTED_TESTS)]
        flat = formulas.disjunction(formulas.literal(value, True) for value in values)
        chained = formulas.literal(values[-1], True)
        for value in reversed(values[:-1]):
            chained = formulas.disjunction([formulas.literal(value, True),
                                            formulas.conjunction(formulas.literal(value, False), chained)])
        self.assertIsNone(self.keys.table_key(flat))
        self.assertEqual(self.keys(flat), self.keys(chained))
        structure = self.keys.structure
        self.assertTrue(decision_diagrams.Diagrams().same(structure(flat), structure(chained)))

        flipped = formulas.disjunction(formulas.literal(value, index != 0) for index, value in enumerate(values))
        self.assertNotEqual(self.keys(flipped), self.keys(flat))
        self.assertFalse(decision_diagrams.Diagrams().same(structure(flat), structure(flipped)))

    def test_relevant_variables(self):
        """(x == 1 && y == 2) || (x == 1 && y != 2) || x == 3 || (x == 4 && x == 1) depends on x alone, told from any
        other value at 1 and 3"""
        formula = formulas.disjunction([
            *(formulas.conjunction(self.equals(self.X, 1), self.equals(self.Y, 2, polarity))
              for polarity in (True, False)),
            self.equals(self.X, 3), formulas.conjunction(self.equals(self.X, 4), self.equals(self.X, 1))])
        _, expected = self.keys.structure_and_variables(formulas.disjunction([self.equals(self.X, 1),
                                                                              self.equals(self.X, 3)]))
        self.assertEqual(decision_diagrams.Diagrams.relevant(*self.keys.structure_and_variables(formula)), expected)

    @mock.patch.object(decision_diagrams, 'DIAGRAM_KEY_NODE_CAP', PAIRS_KEY_NODES)
    def test_key_past_the_sorted_orders_cap(self):
        """a || (a && pairs), past ROW_CAP rows, its diagram in sorted order (every pair's first before every second)
        past the key's cap: a's key, the variables found in the order a digest walk meets them, each pair together"""
        keys = formulas.FormulaKeys(self.named_digest)
        a = self.named('a')
        formula = formulas.disjunction([a, formulas.conjunction(a, self.pairs_formulas(together=False)[0])])
        with self.assertRaises(decision_diagrams.DiagramOverflow):
            decision_diagrams.Diagrams.key(*keys.structure_and_variables(formula))
        self.assertEqual(keys(formula), keys(a))

    @mock.patch.object(decision_diagrams, 'DIAGRAM_KEY_NODE_CAP', PAIRS_KEY_NODES)
    def test_variables_found_in_sorted_order_past_the_walks_cap(self):
        """pairs && any first, whose digest walk meets every pair's first before the pairs (a literal sorts before an
        and), past the key's cap that way: the variables found in sorted order, each pair together, as Diagrams.key
        finds them"""
        keys = formulas.FormulaKeys(self.named_digest)
        formula = formulas.conjunction(*self.pairs_formulas(together=True))
        structure, variables = keys.structure_and_variables(formula)
        with self.assertRaises(decision_diagrams.DiagramOverflow):
            decision_diagrams.Diagrams.relevant(structure, keys.canonical_variables(formula))
        self.assertEqual(keys(formula), decision_diagrams.Diagrams.key(structure, variables)[1])

    @mock.patch.object(decision_diagrams, 'DIAGRAM_KEY_NODE_CAP', PAIRS_KEY_NODES)
    def test_one_outcome_for_formulas_of_one_digest(self):
        """a || (a && (pairs && any first)) and the same with the inner and's items swapped, one digest: in the order
        each meets its variables one fits the key's cap and the other not; two layers key them alike"""
        a = self.named('a')
        pairs, any_first = self.pairs_formulas(together=False)
        written = [formulas.disjunction([a, formulas.conjunction(a, formulas.conjunction(*items))])
                   for items in ((pairs, any_first), (any_first, pairs))]
        self.assertEqual(self.named_digest(written[0]), self.named_digest(written[1]))
        keyed = [formulas.FormulaKeys(self.named_digest)(formula) for formula in written]
        self.assertEqual(keyed[0], keyed[1])

    def test_comparisons_remembered_by_both_sides(self):
        """x == 1 && y == 1 against the condition x == 1 && y == 1 (one function, written otherwise), then against
        x == 1 && y == 2: the second comparison, its first side's formula the same, still differs"""
        reading = gated_comparison.GatedReading((Fingerprints.of(Facts()), Fingerprints.of(Facts())), {})
        both = formulas.conjunction(self.equals(self.X, 1), self.equals(self.Y, 1))
        condition = formulas.literal(op('LOGICAL_AND', [op('EQ', [value, const(1)]) for value in (self.X, self.Y)]),
                                     True)
        other = formulas.conjunction(self.equals(self.X, 1), self.equals(self.Y, 2))
        self.assertIsNone(gated_comparison.compare_formulas(reading, (both, condition)))
        self.assertEqual(gated_comparison.compare_formulas(reading, (both, other)), 'guard_differs')


if __name__ == '__main__':
    unittest.main()
