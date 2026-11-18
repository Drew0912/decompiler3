#!/usr/bin/env python3
"""The HLIL DSL's forms (docs/dsl/HLIL_DSL.md, Form): each in a hand-written HLIL body compiles to the bytes of its LLIL
twin without line markers, by each kind of game writer. A twin from a real script is its listing in the stored sora2
dump, the line markers dropped; the others follow the VM's rules (docs/falcom/ed9/ED9_VM.md)"""

import operator
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from falcom.ed9.writer.scp_hlil_dsl_helper import *
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.hlil_dsl_test_utils import *
from tests.shared.scp_writer_test_utils import local_call


class TestRealFunctions(HLILTestCase):
    """Functions from sora2's scripts, as the HLIL DSL writes them, against the compiler's own bytes"""

    def test_calls_a_call_value_and_a_syscall(self):
        """chr5001's AniFall: library calls, a call's value stored in a parameter, a syscall, Return()"""
        def hlil(scena):
            use_library(scena)

            @scena.HLILCode()
            def AniFall(arg1: Nullable32 = 0.11, arg2: Nullable32 = 1.0, arg3: Nullable32 = 0):
                Set(arg2, AdjustSpeed(arg2))
                Set(arg1, AdjustBlend(arg1, 0.1))
                Syscall(6, 35, 65534, 0, 0, 0, 0, 1529, 1417, 1418)
                chr_play_animeclip(65534, "fall", arg1, 1, 0)
                chr_set_animeclip_speed(65534, arg2, 0)
                chr_wait_animeclip(65534, 0)
                Return()

        def llil(scena):
            use_library(scena)

            @scena.LLILCode()
            def AniFall(arg1: Nullable32 = 0.11, arg2: Nullable32 = 1.0, arg3: Nullable32 = 0):
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('loc_5207A')
                LOAD_STACK(-16)
                CALL(AdjustSpeed)
                label('loc_5207A')
                GET_REG(0)
                POP_TO(-8)
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('loc_5209E')
                PUSH_FLOAT(0.1)
                LOAD_STACK(-16)
                CALL(AdjustBlend)
                label('loc_5209E')
                GET_REG(0)
                POP_TO(-4)
                for value in (1418, 1417, 1529, 0, 0, 0, 0, 65534):
                    PUSH_INT(value)

                SYSCALL(6, 0x23, 0x08)
                POP(32)
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('loc_5210D')
                PUSH_INT(0)
                PUSH_INT(1)
                LOAD_STACK(-20)
                PUSH_STR("fall")
                PUSH_INT(65534)
                CALL(chr_play_animeclip)
                label('loc_5210D')
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('loc_52130')
                PUSH_INT(0)
                LOAD_STACK(-20)
                PUSH_INT(65534)
                CALL(chr_set_animeclip_speed)
                label('loc_52130')
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('loc_5214E')
                PUSH_INT(0)
                PUSH_INT(65534)
                CALL(chr_wait_animeclip)
                label('loc_5214E')
                PUSH_RAW(RawInt(0x00000000))
                SET_REG(0)
                POP(12)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_a_global_set_and_returned(self):
        """chr0005's GetCookCount: this.x read, set and returned; 1 - x keeps the literal on the left"""
        def globals_block(scena):
            @scena.GlobalVars()
            def globalvars():
                GLOBAL_VAR("cook_count", 0)

        def hlil(scena):
            globals_block(scena)

            @scena.HLILCode()
            def GetCookCount():
                Set(this.cook_count, 1 - this.cook_count)
                Return(this.cook_count)

        def llil(scena):
            globals_block(scena)

            @scena.LLILCode()
            def GetCookCount():
                PUSH_INT(1)
                LOAD_GLOBAL("cook_count")
                SUB()
                SET_GLOBAL("cook_count")
                LOAD_GLOBAL("cook_count")
                SET_REG(0)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_a_local_declared_and_stored_at_once(self):
        """brk_obj's AniSwitchOnWait and btlcom's GetCharaEffectScale: Let(x, value), a local read and returned"""
        def hlil(scena):
            use_library(scena)

            @scena.HLILCode()
            def AniSwitchOnWait():
                var_s0 = Local('var_s0')
                map_obj_play_animeclip("", "switch_on", 0.0, 0, 0)
                Let(var_s0, map_obj_get_animeclip_frame_length("", 0))
                map_obj_set_animeclip_frame("", var_s0, 0)
                Return()

            @scena.HLILCode()
            def GetCharaEffectScale():
                var_s0 = Local('var_s0')
                Let(var_s0, 1.0)
                Return(var_s0)

        def llil(scena):
            use_library(scena)

            @scena.LLILCode()
            def AniSwitchOnWait():
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('loc_1A3F')
                PUSH_INT(0)
                PUSH_INT(0)
                PUSH_FLOAT(0.0)
                PUSH_STR("switch_on")
                PUSH_STR("")
                CALL(map_obj_play_animeclip)
                label('loc_1A3F')
                PUSH_RAW(RawInt(0x00000000))
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('loc_1A63')
                PUSH_INT(0)
                PUSH_STR("")
                CALL(map_obj_get_animeclip_frame_length)
                label('loc_1A63')
                GET_REG(0)
                POP_TO(-4)
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('loc_1A8D')
                PUSH_INT(0)
                LOAD_STACK(-16)
                PUSH_STR("")
                CALL(map_obj_set_animeclip_frame)
                label('loc_1A8D')
                PUSH_RAW(RawInt(0x00000000))
                SET_REG(0)
                POP(4)
                RETURN()

            @scena.LLILCode()
            def GetCharaEffectScale():
                PUSH_RAW(RawInt(0x00000000))
                PUSH_FLOAT(1.0)
                POP_TO(-4)
                LOAD_STACK(-4)
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_a_syscall_value_in_a_local(self):
        """mon5264_R's AniNoteSetup: a syscall's value stored in a local, the local as a syscall argument"""
        def hlil(scena):
            use_library(scena)

            @scena.HLILCode()
            def AniNoteSetup():
                var_s0 = Local('var_s0')
                chr_change_skin(65534, "mon5264", 1)
                chr_play_animeclip(65534, "btl_wait", 0, 1, 0)
                Let(var_s0, Syscall(1, 208, 61610, "AttributeVer"))
                Syscall(1, 208, 65534, "CreatAttribute")
                Syscall(1, 208, 65534, "ChangeAttribute", var_s0)
                Return()

        def llil(scena):
            use_library(scena)

            @scena.LLILCode()
            def AniNoteSetup():
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('loc_56F0')
                PUSH_INT(1)
                PUSH_STR("mon5264")
                PUSH_INT(65534)
                CALL(chr_change_skin)
                label('loc_56F0')
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('loc_5720')
                PUSH_INT(0)
                PUSH_INT(1)
                PUSH_INT(0)
                PUSH_STR("btl_wait")
                PUSH_INT(65534)
                CALL(chr_play_animeclip)
                label('loc_5720')
                PUSH_RAW(RawInt(0x00000000))
                PUSH_STR("AttributeVer")
                PUSH_INT(61610)
                SYSCALL(1, 0xD0, 0x02)
                POP(8)
                GET_REG(0)
                POP_TO(-4)
                PUSH_STR("CreatAttribute")
                PUSH_INT(65534)
                SYSCALL(1, 0xD0, 0x02)
                POP(8)
                LOAD_STACK(-4)
                PUSH_STR("ChangeAttribute")
                PUSH_INT(65534)
                SYSCALL(1, 0xD0, 0x03)
                POP(12)
                PUSH_RAW(RawInt(0x00000000))
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_wrapped_literals_script_calls_and_popn(self):
        """chr0007's AniStopRun (~Int(8)), chr0000's AniBtlCraft02EndHook (Int(4) | 2), a script call with arguments
        (chr0000's call of btlcom's AniBtlArts) and ai_chr0118_e00's PopN"""
        def hlil(scena):
            use_library(scena)

            @scena.HLILCode()
            def AniStopRun(arg1: Nullable32 = 0.2):
                chr_allow_controll(65534, 65535 & ~Int(8))
                chr_allow_controll(65534, Int(4) | 2)
                script.btlcom.AniBtlArts(13, 0.95)
                PopN("本体もアンチセプト詠唱しとるんか？じゃあ俺は止めとくわ！")
                Return(0)

        def llil(scena):
            use_library(scena)

            @scena.LLILCode()
            def AniStopRun(arg1: Nullable32 = 0.2):
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('loc_50420')
                PUSH_INT(65535)
                PUSH_INT(8)
                NOT()
                BITWISE_AND()
                PUSH_INT(65534)
                CALL(chr_allow_controll)
                label('loc_50420')
                PUSH_CURRENT_FUNC_ID()
                PUSH_RET_ADDR('loc_6AB02')
                PUSH_INT(4)
                PUSH_INT(2)
                BITWISE_OR()
                PUSH_INT(65534)
                CALL(chr_allow_controll)
                label('loc_6AB02')
                PUSH_CALLER_FRAME('loc_614E3')
                PUSH_FLOAT(0.95)
                PUSH_INT(13)
                CALL_SCRIPT("btlcom", "AniBtlArts", 2)
                label('loc_614E3')
                PUSH_STR("本体もアンチセプト詠唱しとるんか？じゃあ俺は止めとくわ！")
                POPN(1)
                PUSH_INT(0)
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)


# Each DSL operator with its opcode: Set(arg1, op(arg1, arg2)) is LOAD_STACK(-4), LOAD_STACK(-12), the opcode and
# POP_TO(-4)
BINARY_OPERATORS = ((operator.add, ADD), (operator.sub, SUB), (operator.mul, MUL), (operator.truediv, DIV),
                    (operator.mod, MOD), (operator.eq, EQ), (operator.ne, NE), (operator.gt, GT), (operator.ge, GE),
                    (operator.lt, LT), (operator.le, LE), (operator.and_, BITWISE_AND), (operator.or_, BITWISE_OR),
                    (And, LOGICAL_AND), (Or, LOGICAL_OR))
UNARY_OPERATORS = ((operator.neg, NEG), (operator.invert, NOT), (Not, EZ))


class TestForms(HLILTestCase):
    """The forms no real function above has, against twins from the VM's rules"""

    def test_each_operator(self):
        """Two parameters: arg1 is slot 1, arg2 slot 0; And / Or of three is the left spine"""
        def hlil(scena):
            @scena.HLILCode()
            def Operators(arg1: Value32, arg2: Value32):
                for operation, _ in BINARY_OPERATORS:
                    Set(arg1, operation(arg1, arg2))

                for operation, _ in UNARY_OPERATORS:
                    Set(arg1, operation(arg1))

                Set(arg2, And(arg1, arg2, 1))
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Operators(arg1: Value32, arg2: Value32):
                for _, opcode in BINARY_OPERATORS:
                    LOAD_STACK(-4)
                    LOAD_STACK(-12)
                    opcode()
                    POP_TO(-4)

                for _, opcode in UNARY_OPERATORS:
                    LOAD_STACK(-4)
                    opcode()
                    POP_TO(-4)

                LOAD_STACK(-4)
                LOAD_STACK(-12)
                LOGICAL_AND()
                PUSH_INT(1)
                LOGICAL_AND()
                POP_TO(-8)
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(8)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_constants_registers_and_debug_int(self):
        """Each constant kind (a NaN by its word), a register read and set, DEBUG_INT; 8 | 16 is Python's 24, and an
        f-string of a Python value is its text"""
        number = 5264

        def hlil(scena):
            use_library(scena)

            @scena.HLILCode()
            def Constants(arg1: Value32):
                Syscall(1, 2, 7, 0.5, "text", Raw(3), RawInt(4), FloatWord(0x9FF00001), Int(5), Float(2.0), Str("s"))
                Syscall(1, 2, 8 | 16, Int(8) | 16)
                chr_change_skin(65534, f'mon{number}', 1)
                Set(REGS[1], arg1)
                Set(arg1, REGS[2])
                DebugInt(7)
                Return(AdjustSpeed(arg1))

        def llil(scena):
            use_library(scena)

            @scena.LLILCode()
            def Constants(arg1: Value32):
                PUSH_STR("s")
                PUSH_FLOAT(2.0)
                PUSH_INT(5)
                PUSH_FLOAT(FloatWord(0x9FF00001))
                PUSH_RAW(RawInt(4))
                PUSH_RAW(RawInt(3))
                PUSH_STR("text")
                PUSH_FLOAT(0.5)
                PUSH_INT(7)
                SYSCALL(1, 2, 9)
                POP(36)
                PUSH_INT(8)
                PUSH_INT(16)
                BITWISE_OR()
                PUSH_INT(24)
                SYSCALL(1, 2, 2)
                POP(8)
                local_call(chr_change_skin, 'skin', [(PUSH_INT, 1), (PUSH_STR, 'mon5264'), (PUSH_INT, 65534)])
                LOAD_STACK(-4)
                SET_REG(1)
                GET_REG(2)
                POP_TO(-4)
                DEBUG_INT(7)
                local_call(AdjustSpeed, 'adjust', [(LOAD_STACK, -12)])
                GET_REG(0)
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_a_long_pop_is_split(self):
        """70 locals and their Return: a POP pops at most 255 bytes, the rest in a second one; a Python loop writes
        one statement per turn"""
        def hlil(scena):
            @scena.HLILCode()
            def ManyLocals():
                for index in range(70):
                    Let(Local(f'var_{index}'))

                Return()

        def llil(scena):
            @scena.LLILCode()
            def ManyLocals():
                for _ in range(70):
                    PUSH_RAW(RawInt(0))

                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(255)
                POP(25)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_calls_to_script_functions_recursion_and_a_later_function(self):
        """A script function by its name, itself included, and one defined after the caller: bodies run once every
        function is registered"""
        def hlil(scena):
            @scena.HLILCode()
            def Caller(arg1: Value32):
                Caller(arg1)
                Set(arg1, Later(arg1, 2))
                Return()

            @scena.LLILCode()
            def Later(arg1: Value32, arg2: Value32 = 0):
                POP(2 * WORD_SIZE)
                RETURN()

        def llil(scena):
            @scena.LLILCode()
            def Caller(arg1: Value32):
                local_call(Caller, 'self', [(LOAD_STACK, -12)])
                local_call(Later, 'later', [(PUSH_INT, 2), (LOAD_STACK, -16)])
                GET_REG(0)
                POP_TO(-4)
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(4)
                RETURN()

            @scena.LLILCode()
            def Later(arg1: Value32, arg2: Value32 = 0):
                POP(2 * WORD_SIZE)
                RETURN()

        self.assert_twins(hlil, llil)


if __name__ == '__main__':
    unittest.main()
