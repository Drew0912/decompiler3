#!/usr/bin/env python3
'''Unit tests for MLIL provenance: every statement's llil_index names the LLIL instruction it comes from, at the
same address, and every statement of a finished MLIL function has a unique inst_index, 0..N-1 in block order.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from ir.llil.llil import LowLevelILCall, LowLevelILFunction, LowLevelILRet
from ir.mlil.mlil import (
    MediumLevelILCall, MediumLevelILFunction, MLILConst, MLILDebug, MLILGoto, MLILSetVar, MLILVariable,
)
from ir.mlil.mlil_optimizer import optimize_mlil
from ir.mlil.mlil_ssa import MLILIf, MLILPhi, MLILRet, MLILSetVarSSA, MLILVariableSSA, MLILVarSSA, SSADeconstructor
from ir.mlil.passes import DeadPhiSourceEliminationPass, SSADeadCodeEliminationPass


FUNC_START = 0x3000
BLOCK_STRIDE = 0x10
ARG_VALUE = 7
TEXT = 'note'

ENTRY_BRANCH_ADDRESS = 0x3004
ENTRY_BRANCH_LLIL_INDEX = 1
OTHER_DEF_ADDRESS = 0x3010
OTHER_DEF_LLIL_INDEX = 2
OTHER_BRANCH_ADDRESS = 0x3014
OTHER_BRANCH_LLIL_INDEX = 3
DEAD_STORE_ADDRESS = 0x3020
DEAD_STORE_LLIL_INDEX = 4


def build_call_function() -> LowLevelILFunction:
    '''A call, then a return, one address per LLIL instruction - the call ends its LLIL block, so translation
    leaves a goto to the return block that block merge removes'''
    builder = FalcomVMBuilder()
    builder.create_function('provenance_test', FUNC_START, num_params = 0)
    builder.set_current_block(builder.create_basic_block(FUNC_START, 'entry'))
    ret_block = builder.create_basic_block(FUNC_START + BLOCK_STRIDE, 'ret')
    emits = (builder.push_func_id, lambda: builder.push_ret_addr(ret_block), lambda: builder.push_int(ARG_VALUE),
             lambda: builder.call('f'))
    for offset, emit in enumerate(emits):
        builder.set_current_address(FUNC_START + offset)
        emit()

    builder.begin_block(ret_block)
    builder.set_current_address(FUNC_START + BLOCK_STRIDE)
    builder.ret()
    return builder.finalize()


def llil_instructions(llil: LowLevelILFunction) -> dict:
    return {inst.inst_index: inst for inst in llil.iter_instructions()}


def stamp(inst, address: int, llil_index: int):
    inst.address = address
    inst.llil_index = llil_index
    return inst


class TestTranslatedProvenance(unittest.TestCase):
    '''Through the production converter, with and without the optimizer'''

    def check_contract(self, mlil: MediumLevelILFunction, llil: LowLevelILFunction):
        sources = llil_instructions(llil)
        mlil_statements = list(mlil.iter_instructions())
        for inst in mlil_statements:
            with self.subTest(inst = str(inst)):
                self.assertIn(inst.llil_index, sources)
                self.assertEqual(inst.address, sources[inst.llil_index].address)

        self.assertEqual([inst.inst_index for inst in mlil_statements], list(range(len(mlil_statements))))

    def test_every_statement_names_its_llil_instruction(self):
        for optimize in (False, True):
            with self.subTest(optimize = optimize):
                llil = build_call_function()
                mlil = convert_falcom_llil_to_mlil(llil, optimize = optimize)
                self.assertIs(mlil.llil_function, llil)
                self.check_contract(mlil, llil)

    def test_call_and_its_goto_share_the_call(self):
        llil = build_call_function()
        mlil = convert_falcom_llil_to_mlil(llil, optimize = False)
        call_index = next(i for i, inst in llil_instructions(llil).items() if isinstance(inst, LowLevelILCall))
        ret_index = next(i for i, inst in llil_instructions(llil).items() if isinstance(inst, LowLevelILRet))
        entry, ret_block = mlil.basic_blocks

        self.assertIsInstance(entry.instructions[-2], MediumLevelILCall)
        self.assertIsInstance(entry.instructions[-1], MLILGoto)
        self.assertEqual([inst.llil_index for inst in entry.instructions[-2:]], [call_index, call_index])
        self.assertEqual(ret_block.instructions[-1].llil_index, ret_index)

    def test_optimize_mlil_numbers_statements_after_block_merge(self):
        llil = build_call_function()
        mlil = optimize_mlil(convert_falcom_llil_to_mlil(llil, optimize = False))
        self.check_contract(mlil, llil)


class TestEdgeStatementProvenance(unittest.TestCase):
    '''Statements de-SSA places on a CFG edge take the branch that leaves along that edge'''

    def test_split_edge_copy_and_goto_take_the_branch(self):
        # join's phi reads x#2 over the other -> join edge, which is critical (other also goes to exit, join is
        # also reached from entry); x#1 stays live into exit, so x#2 needs a name of its own and the copy survives
        func = MediumLevelILFunction('split_edge', FUNC_START)
        x = MLILVariable('x')
        func.locals['x'] = x
        x1, x2, x3 = (MLILVariableSSA(x, version) for version in (1, 2, 3))
        entry, other, join, exit_block = (func.create_block(FUNC_START + i * BLOCK_STRIDE, label)
                                          for i, label in enumerate(('entry', 'other', 'join', 'exit')))
        entry.instructions = [
            MLILSetVarSSA(x1, MLILConst(1)),
            stamp(MLILIf(MLILVarSSA(MLILVariableSSA(MLILVariable('p'), 0)), join, other),
                  ENTRY_BRANCH_ADDRESS, ENTRY_BRANCH_LLIL_INDEX),
        ]
        other.instructions = [
            stamp(MLILSetVarSSA(x2, MLILConst(2)), OTHER_DEF_ADDRESS, OTHER_DEF_LLIL_INDEX),
            stamp(MLILIf(MLILVarSSA(MLILVariableSSA(MLILVariable('q'), 0)), join, exit_block),
                  OTHER_BRANCH_ADDRESS, OTHER_BRANCH_LLIL_INDEX),
        ]
        join.instructions = [MLILPhi(x3, [(x1, entry), (x2, other)]), MLILRet(MLILVarSSA(x3))]
        exit_block.instructions = [MLILRet(MLILVarSSA(x1))]
        for source, target in ((entry, join), (entry, other), (other, join), (other, exit_block)):
            source.add_outgoing_edge(target)

        SSADeconstructor(func).deconstruct()

        split = next(block for block in func.basic_blocks if block not in (entry, other, join, exit_block))
        self.assertIs(other.instructions[-1].true_target, split)
        self.assertEqual([type(inst) for inst in split.instructions], [MLILSetVar, MLILGoto])
        for inst in split.instructions:
            with self.subTest(inst = str(inst)):
                self.assertEqual((inst.address, inst.llil_index), (OTHER_BRANCH_ADDRESS, OTHER_BRANCH_LLIL_INDEX))


class TestDebugNoteProvenance(unittest.TestCase):
    '''A dead string assignment left as a debug note keeps the assignment's source'''

    def assert_note_keeps_source(self, block):
        note = next(inst for inst in block.instructions if isinstance(inst, MLILDebug))
        self.assertEqual((note.address, note.llil_index), (DEAD_STORE_ADDRESS, DEAD_STORE_LLIL_INDEX))

    def test_dead_code_elimination(self):
        func = MediumLevelILFunction('dead_string', FUNC_START)
        s = MLILVariable('s')
        func.locals['s'] = s
        block = func.create_block(FUNC_START, 'entry')
        block.instructions = [
            stamp(MLILSetVarSSA(MLILVariableSSA(s, 1), MLILConst(TEXT)), DEAD_STORE_ADDRESS, DEAD_STORE_LLIL_INDEX),
            MLILRet(),
        ]

        SSADeadCodeEliminationPass().run(func)

        self.assert_note_keeps_source(block)

    def test_dead_phi_elimination(self):
        # s#1 only feeds a phi nothing reads
        func = MediumLevelILFunction('dead_phi_string', FUNC_START)
        s = MLILVariable('s')
        func.locals['s'] = s
        s1, s2, s3 = (MLILVariableSSA(s, version) for version in (1, 2, 3))
        entry, arm, join = (func.create_block(FUNC_START + i * BLOCK_STRIDE, label)
                            for i, label in enumerate(('entry', 'arm', 'join')))
        entry.instructions = [
            stamp(MLILSetVarSSA(s1, MLILConst(TEXT)), DEAD_STORE_ADDRESS, DEAD_STORE_LLIL_INDEX),
            MLILIf(MLILVarSSA(MLILVariableSSA(MLILVariable('p'), 0)), arm, join),
        ]
        arm.instructions = [MLILSetVarSSA(s2, MLILConst(0)), MLILGoto(join)]
        join.instructions = [MLILPhi(s3, [(s1, entry), (s2, arm)]), MLILRet()]
        for source, target in ((entry, arm), (entry, join), (arm, join)):
            source.add_outgoing_edge(target)

        DeadPhiSourceEliminationPass().run(func)

        self.assert_note_keeps_source(entry)


if __name__ == '__main__':
    unittest.main()
