#!/usr/bin/env python3
'''Unit tests for MLIL metadata preservation.'''

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ir.mlil import (
    MediumLevelILFunction,
    MLILConst,
    MLILEq,
    MLILIf,
    MLILNe,
    MLILRet,
    MLILSetVar,
    MLILVariable,
)
from ir.mlil.mlil_ssa import MLILSetVarSSA, MLILVariableSSA, MLILVarSSA
from ir.mlil.passes import (
    ConditionSimplificationPass,
    CopyPropagationPass,
    SSAConversionPass,
    SSADeconstructionPass,
)


TEST_FUNCTION_NAME = 'metadata_test'
TEST_VAR_NAME = 'var_s0'
SOURCE_ADDRESS = 0x1000
SOURCE_INST_INDEX = 42
SOURCE_LLIL_INDEX = 24
OTHER_ADDRESS = 0x2000
OTHER_INST_INDEX = 84
OTHER_LLIL_INDEX = 48
SOURCE_VALUE = 7
LEFT_VALUE = 1
RIGHT_VALUE = 1
ZERO_VALUE = 0
SOURCE_VERSION = 1
COPY_VERSION = 2
FIRST_STATEMENT_INDEX = 0
SECOND_STATEMENT_INDEX = 1


def set_metadata(inst, address: int, inst_index: int, llil_index: int):
    inst.address = address
    inst.inst_index = inst_index
    inst.llil_index = llil_index
    return inst


class TestMLILMetadataPreservation(unittest.TestCase):
    '''Tests for MLIL source metadata propagation.'''

    def assert_metadata(self, inst, address: int, inst_index: int, llil_index: int):
        self.assertEqual(inst.address, address)
        self.assertEqual(inst.inst_index, inst_index)
        self.assertEqual(inst.llil_index, llil_index)

    def test_copy_metadata_from_copies_source_tracking(self):
        source = set_metadata(MLILRet(), SOURCE_ADDRESS, SOURCE_INST_INDEX, SOURCE_LLIL_INDEX)
        target = MLILRet()

        copied = target.copy_metadata_from(source)

        self.assertIs(copied, target)
        self.assert_metadata(target, SOURCE_ADDRESS, SOURCE_INST_INDEX, SOURCE_LLIL_INDEX)

    def test_ssa_conversion_and_deconstruction_preserve_metadata(self):
        func = MediumLevelILFunction(TEST_FUNCTION_NAME)
        block = func.create_block(start = SOURCE_ADDRESS)
        source_var = MLILVariable(TEST_VAR_NAME)
        source_inst = set_metadata(
            MLILSetVar(source_var, MLILConst(SOURCE_VALUE), address = SOURCE_ADDRESS),
            SOURCE_ADDRESS,
            SOURCE_INST_INDEX,
            SOURCE_LLIL_INDEX,
        )
        block.add_instruction(source_inst)

        SSAConversionPass().run(func)

        ssa_inst = block.instructions[FIRST_STATEMENT_INDEX]
        self.assertIsInstance(ssa_inst, MLILSetVarSSA)
        self.assert_metadata(ssa_inst, SOURCE_ADDRESS, SOURCE_INST_INDEX, SOURCE_LLIL_INDEX)

        SSADeconstructionPass().run(func)

        restored_inst = block.instructions[FIRST_STATEMENT_INDEX]
        self.assertIsInstance(restored_inst, MLILSetVar)
        self.assert_metadata(restored_inst, SOURCE_ADDRESS, SOURCE_INST_INDEX, SOURCE_LLIL_INDEX)

    def test_condition_simplification_preserves_metadata(self):
        func = MediumLevelILFunction(TEST_FUNCTION_NAME)
        entry_block = func.create_block(start = SOURCE_ADDRESS)
        true_block = func.create_block(start = OTHER_ADDRESS)
        false_block = func.create_block(start = OTHER_ADDRESS)
        condition = MLILNe(MLILEq(MLILConst(LEFT_VALUE), MLILConst(RIGHT_VALUE)), MLILConst(ZERO_VALUE))
        if_inst = set_metadata(
            MLILIf(condition, true_block, false_block, address = SOURCE_ADDRESS),
            SOURCE_ADDRESS,
            SOURCE_INST_INDEX,
            SOURCE_LLIL_INDEX,
        )
        entry_block.add_instruction(if_inst)

        ConditionSimplificationPass().run(func)

        simplified_inst = entry_block.instructions[FIRST_STATEMENT_INDEX]
        self.assertIsInstance(simplified_inst.condition, MLILEq)
        self.assert_metadata(simplified_inst, SOURCE_ADDRESS, SOURCE_INST_INDEX, SOURCE_LLIL_INDEX)

    def test_copy_propagation_preserves_rewritten_instruction_metadata(self):
        func = MediumLevelILFunction(TEST_FUNCTION_NAME)
        block = func.create_block(start = SOURCE_ADDRESS)
        base_var = MLILVariable(TEST_VAR_NAME)
        source_var = MLILVariableSSA(base_var, SOURCE_VERSION)
        copy_var = MLILVariableSSA(base_var, COPY_VERSION)
        copy_inst = set_metadata(
            MLILSetVarSSA(copy_var, MLILVarSSA(source_var), address = SOURCE_ADDRESS),
            SOURCE_ADDRESS,
            SOURCE_INST_INDEX,
            SOURCE_LLIL_INDEX,
        )
        ret_inst = set_metadata(
            MLILRet(MLILVarSSA(copy_var), address = OTHER_ADDRESS),
            OTHER_ADDRESS,
            OTHER_INST_INDEX,
            OTHER_LLIL_INDEX,
        )
        block.add_instruction(copy_inst)
        block.add_instruction(ret_inst)

        CopyPropagationPass().run(func)

        rewritten_ret = block.instructions[SECOND_STATEMENT_INDEX]
        self.assertIsInstance(rewritten_ret.value, MLILVarSSA)
        self.assertEqual(rewritten_ret.value.var, source_var)
        self.assert_metadata(rewritten_ret, OTHER_ADDRESS, OTHER_INST_INDEX, OTHER_LLIL_INDEX)


if __name__ == '__main__':
    unittest.main()
