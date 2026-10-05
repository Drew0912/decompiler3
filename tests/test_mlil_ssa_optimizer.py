#!/usr/bin/env python3
'''Unit tests for SSAOptimizer: the fixpoint loop's _snapshot must compare instruction structure,
not repr() (which no MLIL class overrides), or an operand-only rewrite can look unchanged and stop
the loop one iteration early.'''

from pathlib import Path
import io
import itertools
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import MediumLevelILFunction, MediumLevelILBasicBlock, MLILVariable, MLILConst, MLILLogicalNot, MLILNe
from ir.mlil.mlil_ssa import MLILVariableSSA, MLILVarSSA, MLILIf, MLILRet
from ir.mlil.mlil_ssa_optimizer import SSA_OPTIMIZER_MAX_ITERATIONS, SSAOptimizer


def make_func(name: str) -> MediumLevelILFunction:
    return MediumLevelILFunction(name, 0)


def make_double_negation_func(name: str) -> tuple:
    '''if (!(reg0#0 != 0)) goto true_block else false_block'''
    func = make_func(name)
    x = MLILVariable('reg0')
    func.register_vars[0] = x
    x0 = MLILVariableSSA(x, 0)

    entry = MediumLevelILBasicBlock(0)
    true_block = MediumLevelILBasicBlock(1)
    false_block = MediumLevelILBasicBlock(2)

    entry.instructions = [
        MLILIf(MLILLogicalNot(MLILNe(MLILVarSSA(x0), MLILConst(0))), true_block, false_block),
    ]
    true_block.instructions = [MLILRet()]
    false_block.instructions = [MLILRet()]
    entry.add_outgoing_edge(true_block)
    entry.add_outgoing_edge(false_block)
    func.basic_blocks = [entry, true_block, false_block]
    return func, entry


class TestFixpointReachesTrueConvergence(unittest.TestCase):
    '''Minimized from the real corpus bug (ai_chr5106p.CheckAlgoUse, sora2_1.0/script_en/ai,
    confirmed by instrumenting the production pass order): `if (!(reg0#19 != 0))` only reaches
    its fully-simplified form (`if (!reg0#19)`) because ConditionSimplificationPass rewrites it
    to `(reg0#19 == 0)` on one outer iteration, then to `!reg0#19` on the next. The old
    repr()-based _snapshot saw the same "<MLILIf IF>" text before and after the first
    iteration's rewrite and stopped the loop there - this was the one function in a
    2,897-function sample that this actually hit.'''

    def test_double_negation_chain_reaches_final_simplified_form(self):
        func, entry = make_double_negation_func('CheckAlgoUse_min')

        SSAOptimizer(func).optimize()

        final_condition = str(entry.instructions[0])
        self.assertEqual(
            final_condition, 'if (!reg0#0) goto mlil_1 else mlil_2',
            'must reach the fully-simplified !x form, not stop at the intermediate '
            '(x == 0) the old repr()-based snapshot mistook for a fixpoint')


class TestIdempotence(unittest.TestCase):
    '''Optimizing an already-optimized function must be a true no-op.'''

    def test_reoptimizing_an_already_optimized_function_changes_nothing(self):
        func, _ = make_double_negation_func('idempotent')

        # _snapshot(), not str(inst) - str() is exactly the imprecise comparison this step
        # replaces (MLILConst prints a SourceFloat's source text and masks hex ints), so it could pass here even if
        # a real, structurally-visible change happened on the second optimize() call.
        SSAOptimizer(func).optimize()
        once = SSAOptimizer(func)._snapshot()

        SSAOptimizer(func).optimize()
        twice = SSAOptimizer(func)._snapshot()

        self.assertEqual(once, twice)


class TestSnapshotSchedule(unittest.TestCase):
    '''A round's after-snapshot is reused as the next round's before-snapshot, so k rounds take k + 1 snapshots,
    not 2k. _snapshot is faked so the counts don't depend on how many rounds the passes need.'''

    def test_after_snapshot_is_reused(self):
        func, _ = make_double_negation_func('reuse')
        rounds = 2      # the first changes A -> B, the second confirms B

        with mock.patch.object(SSAOptimizer, '_snapshot', side_effect = itertools.chain(['A'], itertools.repeat('B'))) as snapshot:
            SSAOptimizer(func).optimize()

        self.assertEqual(snapshot.call_count, rounds + 1)

    def test_iteration_cap_keeps_warning(self):
        func, _ = make_double_negation_func('never_settles')

        with (
            mock.patch.object(SSAOptimizer, '_snapshot', side_effect = itertools.count()) as snapshot,
            mock.patch.object(sys, 'stderr', io.StringIO()) as stderr,
        ):
            SSAOptimizer(func).optimize()

        self.assertEqual(snapshot.call_count, SSA_OPTIMIZER_MAX_ITERATIONS + 1)
        self.assertEqual(stderr.getvalue(),
                         f'[optimizer] never_settles did not converge after {SSA_OPTIMIZER_MAX_ITERATIONS} iterations\n')


class TestStructuralKeyExactness(unittest.TestCase):
    '''Direct tests of _structural_key/_snapshot: distinct types never share a key (e.g. a float
    and a string holding the float's hex text), and a dict-valued attribute raises instead of
    becoming an unfrozen, potentially unsound key.'''

    def test_float_and_matching_hex_string_do_not_collide(self):
        float_key = SSAOptimizer._structural_key(1.0)
        string_key = SSAOptimizer._structural_key((1.0).hex())
        self.assertNotEqual(float_key, string_key)

    def test_dict_valued_attribute_raises(self):
        with self.assertRaises(NotImplementedError):
            SSAOptimizer._structural_key({'a': 1})

    def test_set_valued_attribute_raises(self):
        with self.assertRaises(NotImplementedError):
            SSAOptimizer._structural_key({1, 2, 3})

    def test_same_class_name_from_different_types_does_not_collide(self):
        # Two distinct classes sharing a __name__ - the key must discriminate by the actual
        # type object, not by class-name string.
        class_a = type('Dummy', (), {})
        class_b = type('Dummy', (), {})
        self.assertEqual(class_a.__name__, class_b.__name__)
        self.assertNotEqual(SSAOptimizer._structural_key(class_a()), SSAOptimizer._structural_key(class_b()))

    def test_operand_change_alters_snapshot(self):
        func = make_func('operand_change')
        block = MediumLevelILBasicBlock(0)
        const = MLILConst(5)
        block.instructions = [MLILRet(const)]
        func.basic_blocks = [block]

        before = SSAOptimizer(func)._snapshot()
        const.value = 10
        after = SSAOptimizer(func)._snapshot()

        self.assertNotEqual(before, after)

    def test_metadata_only_change_does_not_alter_snapshot(self):
        func = make_func('metadata_only')
        block = MediumLevelILBasicBlock(0)
        inst = MLILRet(MLILConst(5))
        block.instructions = [inst]
        func.basic_blocks = [block]

        before = SSAOptimizer(func)._snapshot()
        inst.address = 0x1234
        inst.inst_index = 99
        inst.llil_index = 77
        after = SSAOptimizer(func)._snapshot()

        self.assertEqual(before, after)


if __name__ == '__main__':
    unittest.main()
