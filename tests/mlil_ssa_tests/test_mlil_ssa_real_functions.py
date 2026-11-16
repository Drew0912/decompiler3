#!/usr/bin/env python3
"""The SSA path end to end on real functions: four small sora2 functions, embedded as the LLIL DSL the decompiler
prints for them (so no game script is needed), compiled by the writer, lifted, and taken through
convert_ed9_llil_to_mlil_ssa and convert_ed9_mlil_ssa_to_hlil; the logic check finds no difference, LLIL against MLIL
or MLIL against HLIL"""

from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.assembler.vm import WORD_SIZE
from falcom.ed9.ir.hlil.hlil_converter_ssa import convert_ed9_mlil_ssa_to_hlil
from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.mlil_ssa.mlil_converter import convert_ed9_llil_to_mlil_ssa
from falcom.ed9.parser.scp import ScpParser
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.scp_writer_test_utils import fresh_writer
import logic_check


def define_functions(writer):
    """Each real function as the decompiler prints it (its quotes, labels and comments; its navigation stubs left
    out), under the script it comes from (falcom/ed9/games/sora2/extracted/script_en/); the common functions they call
    stand in with their real signatures, since a caller's translation reads only a callee's parameters"""
    @writer.GlobalVars()
    def globalvars():
        # battle/btl_EV_01_35_00.dat's globals: BattleTurnEnd reads and writes 2 and 3 by name
        GLOBAL_VAR("is_play_enemy_voice", 0)  # global var 0
        GLOBAL_VAR("is_play_party_voice", 0)  # global var 1
        GLOBAL_VAR("is_resurrect_enemy", 0)  # global var 2
        GLOBAL_VAR("is_hp_stopper_enemy", 0)  # global var 3

    @writer.LLILCode()
    def item_count_get(arg1: Value32):
        POP(WORD_SIZE); RETURN()

    @writer.LLILCode()
    def btl_register_hp_stopper(arg1: Value32, arg2: Value32, arg3: Nullable32 = 0):
        POP(3 * WORD_SIZE); RETURN()

    # scena/system.dat
    @writer.LLILCode()
    def IsHaveSomeQuartz():
        DEBUG_SET_LINENO(4466)
        PUSH_RAW(RawInt(0x00000000))    # slot 0 (local)
        PUSH_INT(0)
        POP_TO(-4)                      # slot 0
        DEBUG_SET_LINENO(4467)
        PUSH_RAW(RawInt(0x00000000))    # slot 1 (local)
        PUSH_INT(3700)
        POP_TO(-4)                      # slot 1
        DEBUG_SET_LINENO(4468)
        label('loc_31C7F')              # sp = 2
        LOAD_STACK(-4)                  # slot 1
        PUSH_INT(4360)
        PUSH_INT(1)
        ADD()
        LT()
        POP_JMP_ZERO('loc_31CE3')
        DEBUG_SET_LINENO(4469)
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('loc_31CAE')
        LOAD_STACK(-12)                 # slot 1
        CALL(item_count_get)
        label('loc_31CAE')              # sp = 2
        GET_REG(0)
        PUSH_INT(1)
        GE()
        POP_JMP_ZERO('loc_31CCA')
        DEBUG_SET_LINENO(4471)
        PUSH_INT(1)
        POP_TO(-8)                      # slot 0
        label('loc_31CCA')              # sp = 2
        DEBUG_SET_LINENO(4473)
        LOAD_STACK(-4)                  # slot 1
        PUSH_INT(1)
        ADD()
        POP_TO(-4)                      # slot 1
        JMP('loc_31C7F')
        label('loc_31CE3')              # sp = 2
        DEBUG_SET_LINENO(4475)
        LOAD_STACK(-8)                  # slot 0
        SET_REG(0)
        POP(8)                          # 2 slots
        RETURN()

    # scena/mp8010_01.dat
    @writer.LLILCode()
    def TK_npc_setting_TITA(arg1: Value32):
        DEBUG_SET_LINENO(271)
        LOAD_STACK(-4)                  # slot 0 = arg1
        SET_REG(0)
        GET_REG(0)
        PUSH_INT(62008)
        EQ()
        POP_JMP_NOT_ZERO('loc_42E8D')
        GET_REG(0)
        PUSH_INT(62504)
        EQ()
        POP_JMP_NOT_ZERO('loc_42E92')
        GET_REG(0)
        PUSH_INT(63004)
        EQ()
        POP_JMP_NOT_ZERO('loc_42E97')
        JMP('loc_42E9C')
        label('loc_42E8D')              # sp = 1
        JMP('loc_42E9C')
        label('loc_42E92')              # sp = 1
        JMP('loc_42E9C')
        label('loc_42E97')              # sp = 1
        JMP('loc_42E9C')
        label('loc_42E9C')              # sp = 1
        DEBUG_SET_LINENO(305)
        PUSH_RAW(RawInt(0x00000000))
        SET_REG(0)
        POP(4)                          # 1 slot
        RETURN()

    # battle/btl_EV_01_35_00.dat
    @writer.LLILCode()
    def BattleTurnEnd():
        DEBUG_SET_LINENO(105)
        LOAD_GLOBAL("is_resurrect_enemy")  # global var 2
        LOAD_GLOBAL("is_hp_stopper_enemy")  # global var 3
        EZ()
        LOGICAL_AND()
        POP_JMP_ZERO('loc_82D')
        DEBUG_SET_LINENO(106)
        PUSH_CURRENT_FUNC_ID()
        PUSH_RET_ADDR('loc_81F')
        PUSH_INT(0)
        PUSH_INT(0)
        PUSH_INT(61066)
        CALL(btl_register_hp_stopper)
        label('loc_81F')                # sp = 0
        DEBUG_SET_LINENO(107)
        PUSH_INT(1)
        SET_GLOBAL("is_hp_stopper_enemy")  # global var 3
        label('loc_82D')                # sp = 0
        DEBUG_SET_LINENO(109)
        PUSH_RAW(RawInt(0x00000000))
        SET_REG(0)
        RETURN()

    # ani/chr0104.dat
    @writer.LLILCode()
    def AniBtlArmed(arg1: Nullable32 = 0.1):
        DEBUG_SET_LINENO(1181)
        LOAD_STACK(-4)                  # slot 0 = arg1
        SET_REG(1)
        POP(4)                          # 1 slot
        GET_REG(1)
        CALL_SCRIPT_NO_RETURN("", "AniEvArmed", 1)


class TestRealFunctionsKeepTheirLogic(unittest.TestCase):
    """Each function's LLIL against its SSA-path MLIL, and that MLIL against its HLIL, as the decompile path's
    logic-check tests compare them (tests/shared/logic_check_functions.py)"""

    @classmethod
    def setUpClass(cls):
        writer = fresh_writer(Path('real_functions.dat'))
        writer.check_compiled = True
        define_functions(writer)
        parser, functions = ScpParser.load_bytes(writer.build({}), 'real_functions.dat', round_trip=False,
                                                 keep_unreachable_code=False, quiet=True)
        lifter = ED9VMLifter(parser=parser)
        cls.llil = {func.name: lifter.lift_function(func) for func in functions}

    def assert_logic_kept(self, name: str):
        llil = self.llil[name]
        reference = logic_check.analyze(logic_check.LLILLayer(llil))    # before the conversion, as the check takes it
        mlil = convert_ed9_llil_to_mlil_ssa(llil)
        self.assertEqual(logic_check.compare_facts(reference, logic_check.analyze(logic_check.MLILLayer(mlil))), [])
        self.assertEqual(logic_check.compare_mlil_hlil(mlil, convert_ed9_mlil_ssa_to_hlil(mlil)), [])

    def test_counter_loop_with_a_variable_set_in_its_if(self):
        self.assert_logic_kept('IsHaveSomeQuartz')

    def test_switch_on_a_register(self):
        self.assert_logic_kept('TK_npc_setting_TITA')

    def test_globals_in_an_and_chain(self):
        self.assert_logic_kept('BattleTurnEnd')

    def test_register_passed_to_an_extern_tail_call(self):
        self.assert_logic_kept('AniBtlArmed')


if __name__ == '__main__':
    unittest.main()
