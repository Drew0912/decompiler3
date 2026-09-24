#!/usr/bin/env python3
'''Unit tests for MLILToHLILConverter's recursion depth on long functions: the code after an if or
a loop is followed iteratively, so depth grows with nesting, not with how many statements run one
after another. The deepest corpus function (sound.dat InitBGM) needed 989 of Python's default 1000
frames before this, mostly from its long run of top-level tests.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ir.mlil.mlil import MediumLevelILFunction, MLILCall, MLILIf, MLILGoto, MLILRet, MLILConst, MLILVar, MLILEq, MLILLt
from ir.hlil.hlil import HLILIf, HLILWhile
from ir.hlil.mlil_to_hlil import MLILToHLILConverter

# Long enough that two frames per statement would pass the limit below
CHAIN_LENGTH = 300

# Frames the conversion may use above its caller, whatever the chain length
FRAMES_ABOVE_CALLER = 150


def frame_depth() -> int:
    depth, frame = 0, sys._getframe()
    while frame is not None:
        depth, frame = depth + 1, frame.f_back
    return depth


def connect(func: MediumLevelILFunction):
    '''Add the edges each block's last instruction implies (fallthrough when it is not a branch)'''
    blocks = func.basic_blocks

    for idx, block in enumerate(blocks):
        last = block.instructions[-1]

        if isinstance(last, MLILIf):
            block.add_outgoing_edge(last.true_target)
            block.add_outgoing_edge(last.false_target)

        elif isinstance(last, MLILGoto):
            block.add_outgoing_edge(last.target)

        elif not isinstance(last, MLILRet) and idx + 1 < len(blocks):
            block.add_outgoing_edge(blocks[idx + 1])


def convert_with_tight_limit(func: MediumLevelILFunction):
    connect(func)
    saved = sys.getrecursionlimit()
    sys.setrecursionlimit(frame_depth() + FRAMES_ABOVE_CALLER)

    try:
        return MLILToHLILConverter(func).convert()

    finally:
        sys.setrecursionlimit(saved)


class TestLongRunOfIfs(unittest.TestCase):
    '''if (arg1 == i) { do_x(i) } repeated CHAIN_LENGTH times, each merging into the next test'''

    def test_converts_without_recursing_per_if(self):
        func = MediumLevelILFunction('long_if_run', 0)
        arg1 = func.get_or_create_parameter(1, 'arg1')
        tests = [func.create_block() for _ in range(CHAIN_LENGTH)]
        bodies = [func.create_block() for _ in range(CHAIN_LENGTH)]
        exit_block = func.create_block()
        following = tests[1:] + [exit_block]

        for i in range(CHAIN_LENGTH):
            tests[i].instructions = [MLILIf(MLILEq(MLILVar(arg1), MLILConst(i)), bodies[i], following[i])]
            bodies[i].instructions = [MLILCall('do_x', [MLILConst(i)]), MLILGoto(following[i])]

        exit_block.instructions = [MLILRet(MLILConst(0))]

        statements = convert_with_tight_limit(func).body.statements

        self.assertEqual(sum(isinstance(s, HLILIf) for s in statements), CHAIN_LENGTH)


class TestLongRunOfLoops(unittest.TestCase):
    '''while (arg1 < i) { do_x(i) } repeated CHAIN_LENGTH times, each exiting into the next loop'''

    def test_converts_without_recursing_per_loop(self):
        func = MediumLevelILFunction('long_loop_run', 0)
        arg1 = func.get_or_create_parameter(1, 'arg1')
        entry = func.create_block()
        headers = [func.create_block() for _ in range(CHAIN_LENGTH)]
        bodies = [func.create_block() for _ in range(CHAIN_LENGTH)]
        exit_block = func.create_block()
        following = headers[1:] + [exit_block]

        entry.instructions = [MLILGoto(headers[0])]

        for i in range(CHAIN_LENGTH):
            headers[i].instructions = [MLILIf(MLILLt(MLILVar(arg1), MLILConst(i)), bodies[i], following[i])]
            bodies[i].instructions = [MLILCall('do_x', [MLILConst(i)]), MLILGoto(headers[i])]

        exit_block.instructions = [MLILRet(MLILConst(0))]

        statements = convert_with_tight_limit(func).body.statements

        self.assertEqual(sum(isinstance(s, HLILWhile) for s in statements), CHAIN_LENGTH)


if __name__ == '__main__':
    unittest.main()
