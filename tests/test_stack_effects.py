#!/usr/bin/env python3
'''Unit tests for the ED9 stack effects: what a call's setup pushes, the call pops.'''

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent))

from falcom.ed9.disasm.stack_effects import STACK_EFFECTS, InstructionKind


class CallSetupInvariantTests(unittest.TestCase):
    def test_local_call_pops_its_setup(self):
        setup_pushes = STACK_EFFECTS[InstructionKind.PUSH_FUNC_ID].pushes + STACK_EFFECTS[InstructionKind.PUSH_RET_ADDR].pushes
        self.assertEqual(STACK_EFFECTS[InstructionKind.CALL].setup_pops, setup_pushes)

    def test_script_call_pops_the_caller_frame(self):
        self.assertEqual(STACK_EFFECTS[InstructionKind.CALL_SCRIPT].setup_pops,
                         STACK_EFFECTS[InstructionKind.PUSH_CALLER_FRAME].pushes)


if __name__ == '__main__':
    unittest.main()
