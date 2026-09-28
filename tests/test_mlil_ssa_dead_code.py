#!/usr/bin/env python3
'''Unit tests for SSA dead-code elimination: one run removes a whole dead chain. Removing an unread
definition can leave the definitions it read unread too, and a single sweep removes only the unread
end - so a chain would lose one link per optimizer round, and a long one would hit the round cap.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import MediumLevelILFunction, MLILCall, MLILConst, MLILGoto, MLILVariable
from ir.mlil.mlil_ssa import MLILIf, MLILPhi, MLILRet, MLILSetVarSSA, MLILVariableSSA, MLILVarSSA
from ir.mlil.passes import SSADeadCodeEliminationPass


FUNC_START = 0x1000
BLOCK_STRIDE = 0x10
VALUE = 7


def ssa_var(func: MediumLevelILFunction, name: str, version: int) -> MLILVariableSSA:
    '''SSA version of local `name`, registering the local on first use'''
    return MLILVariableSSA(func.locals.setdefault(name, MLILVariable(name)), version)


def kinds(block) -> list:
    return [type(inst) for inst in block.instructions]


class TestDeadChainRemovedInOneRun(unittest.TestCase):

    def test_copy_chain(self):
        # a#1 -> b#1 -> c#1, and nothing reads c#1
        func = MediumLevelILFunction('copy_chain', FUNC_START)
        a1, b1, c1 = (ssa_var(func, name, 1) for name in ('a', 'b', 'c'))
        block = func.create_block(FUNC_START, 'entry')
        block.instructions = [
            MLILSetVarSSA(a1, MLILConst(VALUE)),
            MLILSetVarSSA(b1, MLILVarSSA(a1)),
            MLILSetVarSSA(c1, MLILVarSSA(b1)),
            MLILRet(),
        ]

        SSADeadCodeEliminationPass().run(func)

        self.assertEqual(kinds(block), [MLILRet])

    def test_chain_through_a_phi(self):
        # v#1 and v#2 only feed v#3 = phi(v#1, v#2), which only feeds w#1, which nothing reads
        func = MediumLevelILFunction('phi_chain', FUNC_START)
        v1, v2, v3 = (ssa_var(func, 'v', version) for version in (1, 2, 3))
        w1 = ssa_var(func, 'w', 1)
        cond = MLILVarSSA(ssa_var(func, 'p', 0))
        entry, arm, join = (func.create_block(FUNC_START + i * BLOCK_STRIDE, label)
                            for i, label in enumerate(('entry', 'arm', 'join')))
        entry.instructions = [MLILSetVarSSA(v1, MLILConst(VALUE)), MLILIf(cond, arm, join)]
        arm.instructions = [MLILSetVarSSA(v2, MLILVarSSA(v1)), MLILGoto(join)]
        join.instructions = [MLILPhi(v3, [(v1, entry), (v2, arm)]), MLILSetVarSSA(w1, MLILVarSSA(v3)), MLILRet()]
        for source, target in ((entry, arm), (entry, join), (arm, join)):
            source.add_outgoing_edge(target)

        SSADeadCodeEliminationPass().run(func)

        self.assertEqual((kinds(entry), kinds(arm), kinds(join)), ([MLILIf], [MLILGoto], [MLILRet]))

    def test_call_output_read_only_by_the_chain(self):
        # x#1 = Foo(); y#1 = x#1, and nothing reads y#1 - the call stays, its output goes
        func = MediumLevelILFunction('call_output', FUNC_START)
        x1, y1 = ssa_var(func, 'x', 1), ssa_var(func, 'y', 1)
        call = MLILCall('Foo', [], output = x1)
        block = func.create_block(FUNC_START, 'entry')
        block.instructions = [call, MLILSetVarSSA(y1, MLILVarSSA(x1)), MLILRet()]

        SSADeadCodeEliminationPass().run(func)

        self.assertEqual(kinds(block), [MLILCall, MLILRet])
        self.assertIsNone(call.output)


if __name__ == '__main__':
    unittest.main()
