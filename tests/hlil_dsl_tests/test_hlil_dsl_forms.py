#!/usr/bin/env python3
"""The HLIL DSL's forms (docs/dsl/HLIL_DSL.md, Form): each in a hand-written HLIL body compiles to the bytes of its LLIL
twin without line markers, by each kind of game writer. A twin from a real script is its listing in the stored sora2
dump, the line markers dropped; the others follow the VM's rules (docs/falcom/ed9/ED9_VM.md)"""

import functools
import itertools
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


# The real functions the control-flow twins call, beyond the shared LIBRARY

@library_function
def global_work(arg1: Value32):
    """Returns its argument"""
    LOAD_STACK(-WORD_SIZE)
    SET_REG(0)
    POP(WORD_SIZE)
    RETURN()


@library_function
def set_global_work(arg1: Value32, arg2: Value32):
    POP(2 * WORD_SIZE)
    RETURN()


@library_function
def menu_create(arg1: Value32, arg2: Value32, arg3: Value32, arg4: Value32):
    POP(4 * WORD_SIZE)
    RETURN()


@library_function
def menu_additem(arg1: Value32, arg2: NullableStr, arg3: Value32):
    POP(3 * WORD_SIZE)
    RETURN()


@library_function
def menu_open(arg1: Value32, arg2: Value32, arg3: Value32, arg4: Value32, arg5: NullableStr):
    POP(5 * WORD_SIZE)
    RETURN()


@library_function
def menu_wait(arg1: Value32):
    """Returns its argument"""
    LOAD_STACK(-WORD_SIZE)
    SET_REG(0)
    POP(WORD_SIZE)
    RETURN()


@library_function
def menu_close(arg1: Value32):
    POP(WORD_SIZE)
    RETURN()


@library_function
def menu_is_canceled(arg1: Value32):
    """Returns its argument"""
    LOAD_STACK(-WORD_SIZE)
    SET_REG(0)
    POP(WORD_SIZE)
    RETURN()


@library_function
def chr_info(arg1: Value32, arg2: Value32):
    """Returns its first argument"""
    LOAD_STACK(-WORD_SIZE)
    SET_REG(0)
    POP(2 * WORD_SIZE)
    RETURN()


@library_function
def btl_check_flag(arg1: Value32):
    """Returns its argument"""
    LOAD_STACK(-WORD_SIZE)
    SET_REG(0)
    POP(WORD_SIZE)
    RETURN()


@library_function
def btl_get_sys_info(arg1: Value32):
    """Returns its argument"""
    LOAD_STACK(-WORD_SIZE)
    SET_REG(0)
    POP(WORD_SIZE)
    RETURN()


@library_function
def btl_chr_list_init(arg1: Value32, arg2: Value32):
    POP(2 * WORD_SIZE)
    RETURN()


@library_function
def btl_chr_list_get_remain(arg1: Value32):
    """Returns its argument"""
    LOAD_STACK(-WORD_SIZE)
    SET_REG(0)
    POP(WORD_SIZE)
    RETURN()


@library_function
def wait(arg1: Value32):
    POP(WORD_SIZE)
    RETURN()


@library_function
def reset_flag(arg1: Value32):
    POP(WORD_SIZE)
    RETURN()


@library_function
def btl_sort_target(arg1: Value32, arg2: Value32):
    POP(2 * WORD_SIZE)
    RETURN()


@library_function
def btl_get_remain_target(arg1: Value32):
    """Returns its argument"""
    LOAD_STACK(-WORD_SIZE)
    SET_REG(0)
    POP(WORD_SIZE)
    RETURN()


@library_function
def chr_delete_joint_controller(arg1: Value32, arg2: str, arg3: Nullable32 = 0.0, arg4: Nullable32 = 0):
    POP(4 * WORD_SIZE)
    RETURN()


@library_function
def btl_next_target(arg1: Value32):
    POP(WORD_SIZE)
    RETURN()


CONTROL_LIBRARY = [global_work, set_global_work, menu_create, menu_additem, menu_open, menu_wait, menu_close,
                   menu_is_canceled, chr_info, btl_check_flag, btl_get_sys_info, btl_chr_list_init,
                   btl_chr_list_get_remain, wait, reset_flag, btl_sort_target, btl_get_remain_target,
                   chr_delete_joint_controller, btl_next_target]


def use_control_library(scena):
    """The script imports CONTROL_LIBRARY"""
    @scena.CommonImports()
    def commonImports():
        return CONTROL_LIBRARY


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


class TestControlFlow(HLILTestCase):
    """If / ElseIf / Else and the blocks they hold, against twins from real functions and from the VM's rules"""

    def test_an_if_in_an_if_and_a_local_in_its_block(self):
        """mp8300_01's EV_07_03_00_SELECT_00: an If with its Else inside an If; a local declared in the outer block,
        popped at its end, after the inner If's end and before the label the outer test jumps to"""
        def hlil(scena):
            use_control_library(scena)

            @scena.HLILCode()
            def EV_07_03_00_SELECT_00():
                var_s0 = Local('var_s0')
                If(global_work(0) == -1, [
                    menu_create(0, 2, 0, 28),
                    menu_additem(0, "Take the elevator", 0),
                    menu_additem(0, "I still have things to do", 1),
                    menu_open(0, -1, -1, 1, ""),
                    Let(var_s0, menu_wait(0)),
                    menu_close(0),
                    If(menu_is_canceled(0), [
                        set_global_work(0, 1),
                    ]).Else([
                        set_global_work(0, var_s0),
                    ]),
                ])
                Return()

        def llil(scena):
            use_control_library(scena)

            @scena.LLILCode()
            def EV_07_03_00_SELECT_00():
                local_call(global_work, 'loc_E9571', [(PUSH_INT, 0)])
                GET_REG(0)
                PUSH_INT(-1)
                EQ()
                POP_JMP_ZERO('loc_E96BF')
                local_call(menu_create, 'loc_E95A9', [(PUSH_INT, 28), (PUSH_INT, 0), (PUSH_INT, 2), (PUSH_INT, 0)])
                local_call(menu_additem, 'loc_E95CD', [(PUSH_INT, 0), (PUSH_STR, "Take the elevator"), (PUSH_INT, 0)])
                local_call(menu_additem, 'loc_E95F1', [(PUSH_INT, 1), (PUSH_STR, "I still have things to do"),
                                                       (PUSH_INT, 0)])
                local_call(menu_open, 'loc_E9621', [(PUSH_STR, ""), (PUSH_INT, 1), (PUSH_INT, -1), (PUSH_INT, -1),
                                                    (PUSH_INT, 0)])
                PUSH_RAW(RawInt(0x00000000))
                local_call(menu_wait, 'loc_E963F', [(PUSH_INT, 0)])
                GET_REG(0)
                POP_TO(-4)
                local_call(menu_close, 'loc_E965E', [(PUSH_INT, 0)])
                local_call(menu_is_canceled, 'loc_E9676', [(PUSH_INT, 0)])
                GET_REG(0)
                POP_JMP_ZERO('loc_E96A0')
                local_call(set_global_work, 'loc_E969B', [(PUSH_INT, 1), (PUSH_INT, 0)])
                JMP('loc_E96BD')
                label('loc_E96A0')
                local_call(set_global_work, 'loc_E96BD', [(LOAD_STACK, -12), (PUSH_INT, 0)])
                POP(4)
                label('loc_E96BF')
                PUSH_RAW(RawInt(0x00000000))
                SET_REG(0)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_an_else_if_chain(self):
        """btlcom's AniBtlConditionCantAction: the last arm, with no Else after it, jumps nowhere"""
        def callees(scena):
            @scena.LLILCode()
            def AniBtlConditionCantActionSealCraft():
                PUSH_RAW(RawInt(0x00000000))
                SET_REG(0)
                RETURN()

            @scena.LLILCode()
            def AniBtlConditionCantActionSealArts():
                PUSH_RAW(RawInt(0x00000000))
                SET_REG(0)
                RETURN()

            return AniBtlConditionCantActionSealCraft, AniBtlConditionCantActionSealArts

        def hlil(scena):
            @scena.HLILCode()
            def AniBtlConditionCantAction(arg1: Value32):
                If(arg1 == 6, [
                    seal_craft(),
                ]).ElseIf(arg1 == 7, [
                    seal_arts(),
                ])
                Return()

            seal_craft, seal_arts = callees(scena)

        def llil(scena):
            @scena.LLILCode()
            def AniBtlConditionCantAction(arg1: Value32):
                LOAD_STACK(-4)
                PUSH_INT(6)
                EQ()
                POP_JMP_ZERO('loc_3F53D')
                local_call(seal_craft, 'loc_3F538', [])
                JMP('loc_3F563')
                label('loc_3F53D')
                LOAD_STACK(-4)
                PUSH_INT(7)
                EQ()
                POP_JMP_ZERO('loc_3F563')
                local_call(seal_arts, 'loc_3F563', [])
                PUSH_RAW(RawInt(0x00000000))
                SET_REG(0)
                POP(4)
                RETURN()

            seal_craft, seal_arts = callees(scena)

        self.assert_twins(hlil, llil)

    def test_a_body_ending_in_an_if_whose_arms_return(self):
        """btlsys's DecideBattleStartType: no Return after the If, each arm returning, the Else's after an If of its
        own"""
        def globals_block(scena):
            @scena.GlobalVars()
            def globalvars():
                GLOBAL_VAR("start_type", 0)

        def hlil(scena):
            globals_block(scena)
            use_control_library(scena)

            @scena.HLILCode()
            def DecideBattleStartType():
                If(this.start_type, [
                    Return(this.start_type),
                ]).Else([
                    If(Or(chr_info(65460, 7) > 3.9, chr_info(65460, 8) > 3.0), [
                        PopN("戦闘開始演出：大型１体"),
                        Return(1),
                    ]),
                    Return(0),
                ])

        def llil(scena):
            globals_block(scena)
            use_control_library(scena)

            @scena.LLILCode()
            def DecideBattleStartType():
                LOAD_GLOBAL("start_type")
                POP_JMP_ZERO('loc_6074')
                LOAD_GLOBAL("start_type")
                SET_REG(0)
                RETURN()
                label('loc_6074')
                local_call(chr_info, 'loc_6092', [(PUSH_INT, 7), (PUSH_INT, 65460)])
                GET_REG(0)
                PUSH_FLOAT(3.9)
                GT()
                local_call(chr_info, 'loc_60B6', [(PUSH_INT, 8), (PUSH_INT, 65460)])
                GET_REG(0)
                PUSH_FLOAT(3.0)
                GT()
                LOGICAL_OR()
                POP_JMP_ZERO('loc_60E1')
                PUSH_STR("戦闘開始演出：大型１体")
                POPN(1)
                PUSH_INT(1)
                SET_REG(0)
                RETURN()
                label('loc_60E1')
                PUSH_INT(0)
                SET_REG(0)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_an_empty_arm(self):
        """mon5005's AniBtlDead: the code's empty arm, its jump over the Else kept"""
        def hlil(scena):
            @scena.HLILCode()
            def AniBtlDead(arg1: Nullable32 = 0.2, arg2: Nullable32 = 1.0, arg3: Nullable32 = 0):
                If(arg3 & 64, []).Else([
                    script.btlcom.AniMonsDeadEffect(arg1),
                ])
                Return()

        def llil(scena):
            @scena.LLILCode()
            def AniBtlDead(arg1: Nullable32 = 0.2, arg2: Nullable32 = 1.0, arg3: Nullable32 = 0):
                LOAD_STACK(-12)
                PUSH_INT(64)
                BITWISE_AND()
                POP_JMP_ZERO('loc_4D46')
                JMP('loc_4D5D')
                label('loc_4D46')
                PUSH_CALLER_FRAME('loc_4D5D')
                LOAD_STACK(-24)
                CALL_SCRIPT("btlcom", "AniMonsDeadEffect", 1)
                label('loc_4D5D')
                PUSH_RAW(RawInt(0x00000000))
                SET_REG(0)
                POP(12)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_returns_and_locals_in_nested_blocks(self):
        """A Return under two locals pops every live slot, and the code after its block starts at the depth before
        it; a name declared again in two sibling blocks after its block ends; an empty If and an empty Else"""
        def hlil(scena):
            @scena.HLILCode()
            def Nested(arg1: Value32):
                x = Local('x')
                y = Local('y')
                Let(x, 1)
                If(arg1, [
                    Let(y, 2),
                    If(y, [
                        Return(y),
                    ]),
                    Set(arg1, y),
                ])
                If(arg1, [
                    Let(y, 3),
                ]).Else([
                    Let(y, 4),
                ])
                If(arg1, [])
                If(arg1, [
                    Set(arg1, 5),
                ]).Else([])
                Return(x)

        def llil(scena):
            @scena.LLILCode()
            def Nested(arg1: Value32):
                PUSH_RAW(RawInt(0))
                PUSH_INT(1)
                POP_TO(-4)
                LOAD_STACK(-8)
                POP_JMP_ZERO('after_first')
                PUSH_RAW(RawInt(0))
                PUSH_INT(2)
                POP_TO(-4)
                LOAD_STACK(-4)
                POP_JMP_ZERO('after_return')
                LOAD_STACK(-4)
                SET_REG(0)
                POP(12)
                RETURN()
                label('after_return')
                LOAD_STACK(-4)
                POP_TO(-12)
                POP(4)
                label('after_first')
                LOAD_STACK(-8)
                POP_JMP_ZERO('second_else')
                PUSH_RAW(RawInt(0))
                PUSH_INT(3)
                POP_TO(-4)
                POP(4)
                JMP('second_end')
                label('second_else')
                PUSH_RAW(RawInt(0))
                PUSH_INT(4)
                POP_TO(-4)
                POP(4)
                label('second_end')
                LOAD_STACK(-8)
                POP_JMP_ZERO('empty_end')
                label('empty_end')
                LOAD_STACK(-8)
                POP_JMP_ZERO('empty_else')
                PUSH_INT(5)
                POP_TO(-8)
                JMP('empty_else')
                label('empty_else')
                LOAD_STACK(-4)
                SET_REG(0)
                POP(8)
                RETURN()

        self.assert_twins(hlil, llil)


class TestLoops(HLILTestCase):
    """While, Break and Continue, against twins from real functions and from the VM's rules"""

    def test_an_endless_loop_its_arms_leave(self):
        """btlsys's BattlePreEnd: while (1) is a real test; a Break in one arm and a Continue in the other, so no jump
        back after them; the If's false jump and the loop's exit go to one label"""
        def hlil(scena):
            use_control_library(scena)

            @scena.HLILCode()
            def BattlePreEnd():
                If(And(btl_check_flag(1048576), btl_get_sys_info(6) == 1), [
                    While(1, [
                        btl_chr_list_init(65534, 128),
                        If(btl_chr_list_get_remain(65534) <= 0, [
                            wait(0.5),
                            Break(),
                        ]).Else([
                            wait(0),
                            Continue(),
                        ]),
                    ]),
                ])
                reset_flag(500)
                Return()

        def llil(scena):
            use_control_library(scena)

            @scena.LLILCode()
            def BattlePreEnd():
                local_call(btl_check_flag, 'loc_9BC1', [(PUSH_INT, 1048576)])
                GET_REG(0)
                local_call(btl_get_sys_info, 'loc_9BDB', [(PUSH_INT, 6)])
                GET_REG(0)
                PUSH_INT(1)
                EQ()
                LOGICAL_AND()
                POP_JMP_ZERO('loc_9C76')
                label('loc_9BED')
                PUSH_INT(1)
                POP_JMP_ZERO('loc_9C76')
                local_call(btl_chr_list_init, 'loc_9C16', [(PUSH_INT, 128), (PUSH_INT, 65534)])
                local_call(btl_chr_list_get_remain, 'loc_9C2E', [(PUSH_INT, 65534)])
                GET_REG(0)
                PUSH_INT(0)
                LE()
                POP_JMP_ZERO('loc_9C59')
                local_call(wait, 'loc_9C54', [(PUSH_FLOAT, 0.5)])
                JMP('loc_9C76')
                label('loc_9C59')
                local_call(wait, 'loc_9C71', [(PUSH_INT, 0)])
                JMP('loc_9BED')
                label('loc_9C76')
                local_call(reset_flag, 'loc_9C8E', [(PUSH_INT, 500)])
                PUSH_RAW(RawInt(0x00000000))
                SET_REG(0)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_a_local_of_the_loop_block(self):
        """chr5002's AniBtlSCraft_TargetSclReset: a local declared in the loop's block, pushed every run and popped at
        the block's end, before the jump back to the test"""
        def hlil(scena):
            use_control_library(scena)

            @scena.HLILCode()
            def AniBtlSCraft_TargetSclReset():
                var_s0 = Local('var_s0')
                btl_sort_target(65534, 0)
                While(btl_get_remain_target(65534) > 0, [
                    Let(var_s0, chr_info(65516, 7)),
                    chr_delete_joint_controller(65516, "", 0.0, 0),
                    btl_next_target(65534),
                ])
                Return()

        def llil(scena):
            use_control_library(scena)

            @scena.LLILCode()
            def AniBtlSCraft_TargetSclReset():
                local_call(btl_sort_target, 'loc_9A874', [(PUSH_INT, 0), (PUSH_INT, 65534)])
                label('loc_9A877')
                local_call(btl_get_remain_target, 'loc_9A88C', [(PUSH_INT, 65534)])
                GET_REG(0)
                PUSH_INT(0)
                GT()
                POP_JMP_ZERO('loc_9A90E')
                PUSH_RAW(RawInt(0x00000000))
                local_call(chr_info, 'loc_9A8BE', [(PUSH_INT, 7), (PUSH_INT, 65516)])
                GET_REG(0)
                POP_TO(-4)
                local_call(chr_delete_joint_controller, 'loc_9A8EF', [(PUSH_INT, 0), (PUSH_FLOAT, 0.0), (PUSH_STR, ""),
                                                                       (PUSH_INT, 65516)])
                local_call(btl_next_target, 'loc_9A907', [(PUSH_INT, 65534)])
                POP(4)
                JMP('loc_9A877')
                label('loc_9A90E')
                PUSH_RAW(RawInt(0x00000000))
                SET_REG(0)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_exits_pop_each_block_they_leave(self):
        """The exits of mon5219_c10's AniFieldSwarmAttack: a Break under the loop block's locals and an If block's pops
        each block's in turn, the loop's first (POP(8); POP(4)), and no more; a Break and a Continue at the block's end
        pop the loop block's alone"""
        def hlil(scena):
            @scena.HLILCode()
            def Swarm(arg1: Value32):
                a = Local('a')
                b = Local('b')
                c = Local('c')
                While(arg1 < 20, [
                    Let(a, 2),
                    Let(b, 8),
                    If(arg1, [
                        Let(c, arg1 + 1),
                        If(c < 1, [
                            Set(REGS[1], c),
                            Break(),
                        ]),
                    ]),
                    Set(arg1, arg1 + 1),
                    If(b >= arg1, [
                        Break(),
                    ]).Else([
                        Continue(),
                    ]),
                ])
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Swarm(arg1: Value32):
                label('head')
                LOAD_STACK(-4)
                PUSH_INT(20)
                LT()
                POP_JMP_ZERO('end')
                PUSH_RAW(RawInt(0))
                PUSH_INT(2)
                POP_TO(-4)
                PUSH_RAW(RawInt(0))
                PUSH_INT(8)
                POP_TO(-4)
                LOAD_STACK(-12)
                POP_JMP_ZERO('after_if')
                PUSH_RAW(RawInt(0))
                LOAD_STACK(-16)
                PUSH_INT(1)
                ADD()
                POP_TO(-4)
                LOAD_STACK(-4)
                PUSH_INT(1)
                LT()
                POP_JMP_ZERO('after_inner')
                LOAD_STACK(-4)
                SET_REG(1)
                POP(8)                  # a and b, the loop's block
                POP(4)                  # c, the If's
                JMP('end')
                label('after_inner')
                POP(4)                  # c at its block's end
                label('after_if')
                LOAD_STACK(-12)
                PUSH_INT(1)
                ADD()
                POP_TO(-12)
                LOAD_STACK(-4)
                LOAD_STACK(-16)
                GE()
                POP_JMP_ZERO('again')
                POP(8)
                JMP('end')
                label('again')
                POP(8)
                JMP('head')
                label('end')
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_nested_loops_a_return_and_an_empty_block(self):
        """A Break leaves the innermost loop, popping its block's local only; a Return in a loop pops every live slot;
        an empty block still jumps back to its test"""
        def hlil(scena):
            @scena.HLILCode()
            def Nested(arg1: Value32):
                x = Local('x')
                y = Local('y')
                While(arg1, [
                    Let(x, 1),
                    While(x, [
                        Let(y, 2),
                        If(y, [
                            Break(),
                        ]),
                        Set(x, 0),
                    ]),
                    If(x, [
                        Return(x),
                    ]),
                    Set(arg1, 0),
                ])
                While(arg1, [])
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Nested(arg1: Value32):
                label('outer')
                LOAD_STACK(-4)
                POP_JMP_ZERO('outer_end')
                PUSH_RAW(RawInt(0))
                PUSH_INT(1)
                POP_TO(-4)
                label('inner')
                LOAD_STACK(-4)
                POP_JMP_ZERO('inner_end')
                PUSH_RAW(RawInt(0))
                PUSH_INT(2)
                POP_TO(-4)
                LOAD_STACK(-4)
                POP_JMP_ZERO('after_break')
                POP(4)                  # y, the inner loop's block
                JMP('inner_end')
                label('after_break')
                PUSH_INT(0)
                POP_TO(-8)
                POP(4)
                JMP('inner')
                label('inner_end')
                LOAD_STACK(-4)
                POP_JMP_ZERO('after_return')
                LOAD_STACK(-4)
                SET_REG(0)
                POP(8)                  # x and arg1: the whole frame
                RETURN()
                label('after_return')
                PUSH_INT(0)
                POP_TO(-8)
                POP(4)
                JMP('outer')
                label('outer_end')
                label('empty')
                LOAD_STACK(-4)
                POP_JMP_ZERO('empty_end')
                JMP('empty')
                label('empty_end')
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)


# The functions the macro twins call: each macro makes statements besides what it returns; the others are unmarked

@macro
def note(value):
    """Makes a statement and returns nothing"""
    Set(REGS[3], value)


def notes(first, second):
    """Returns the list of the statements it makes"""
    return [Set(REGS[first], first), Set(REGS[second], second)]


@macro
def step_and_leave(done):
    """Makes a statement and returns an If leaving the loop"""
    Set(REGS[1], 7)
    return If(done, [Break()])


@macro
def counted(value):
    """Makes a statement and returns value as it is"""
    Set(REGS[2], 9)
    return value


@macro
def tested(register, value):
    """Makes a statement, then the test it returns"""
    Set(REGS[register], register)
    return value == register


@macro
def leave_when(done, value):
    """Makes an If leaving the loop, returns value as it is"""
    If(done, [Break()])
    return value


@macro
def countdown(counter):
    """Makes a whole loop, its block calling a macro too"""
    While(counter, [
        note(5),
        Set(counter, counter - 1),
    ])


@macro
def marks(register):
    """Recursive: each call's statement where that call is made, an inner call's in the block of its caller's If"""
    Set(REGS[register], register)
    if register > 1:
        If(REGS[register], [marks(register - 1)])


@macro
def declared(local, value):
    """Declares local and returns it"""
    Let(local, value)
    return local


def loop_parts(counter):
    """A While's condition and block, for While(*loop_parts(...))"""
    return counter, [Set(counter, 0)]


@macro
def set_then(register, value):
    """Sets register to 9, returns value as it is"""
    Set(register, 9)
    return value


@macro
def slot(register):
    """Makes a statement and returns the register it names, for Set's target"""
    Set(REGS[1], register)
    return REGS[register]


@macro
def two_notes(first, second):
    """A macro calling a macro twice, on lines of their own"""
    note(first)
    note(second)


@macro
def note_then_list(value):
    """Makes a statement, then returns a list of another"""
    Set(REGS[1], value)
    return [Set(REGS[2], value)]


@macro
def set_counted(value):
    """A macro making a statement of another macro's value: that macro's statement leads it, not the block"""
    Set(REGS[6], counted(value))


@macro
def two_then(value):
    """Makes two statements, returns value as it is"""
    Set(REGS[1], 1)
    Set(REGS[2], 2)
    return value


@macro
def if_then_note(condition):
    """Returns an If, then makes a statement after it"""
    made = If(condition, [Set(REGS[1], 1)])
    Set(REGS[2], 2)
    return made


@macro
def list_then_note(value):
    """Makes a list, then a statement, and returns the list"""
    listed = [Set(REGS[1], value)]
    Set(REGS[2], value)
    return listed


@macro
def outer_counted(value):
    """Returns another macro's value"""
    return counted(value)


@macro
def fresh(local):
    """Makes a statement, returns the local it is given, for Let"""
    Set(REGS[1], 1)
    return local


kept_value = None


def keep_in_a_global():
    """Unmarked, called on a line of its own: an unmarked function's value kept in a global"""
    global kept_value
    kept_value = plain_note(1)


def keep_in_a_closure():
    """Unmarked, called on a line of its own: an unmarked function's value kept in a closure's variable"""
    kept = None

    def keep():
        nonlocal kept
        kept = plain_note(2)

    keep()
    return kept


class Notes:
    @macro
    def note(self, value):
        """A macro as a method"""
        Set(REGS[3], value)


NOTES = Notes()


def plain_note(value):
    """Unmarked: makes a statement and returns nothing"""
    Set(REGS[3], value)


def when(condition, block):
    """The script's own wrapper, unmarked: returns the If it makes"""
    return If(condition, block)


def until_zero(condition, block):
    """An unmarked wrapper making a While, called on a line of its own"""
    While(condition, block)


def block_in_a_variable(condition):
    """Unmarked, called on a line of its own: a block kept in a variable before its If takes it"""
    block = [note(1), Set(REGS[4], 2)]
    If(condition, block)


def plain_boundaries(flag):
    """Unmarked, called on a line of its own: an unmarked function's statement stands where made when its call is a
    line of its own, kept in a variable, called with keywords or a star, one side of a ternary line, or returned"""
    plain_note(1)
    _ = plain_note(2)
    plain_note(value=3)
    plain_note(*(4,))
    plain_note(5) if flag else plain_note(6)
    return plain_note(7)


class TestMacroStatements(HLILTestCase):
    """A macro's own statements, those it does not return, run where its call's value goes: in the block holding the
    call, through the script's own wrappers, a Python variable or a C-level callable; before each test of the condition
    holding it; an If's first condition's before the If. An unmarked function's stand where made, on a line of its
    own"""

    def test_block_macros(self):
        """A macro as a block's first and later element, returning an If, a list and nothing; a list inside a block
        opened in place; also with the compile check off"""
        def hlil(scena):
            @scena.HLILCode()
            def Blocks(arg1: Value32):
                While(arg1, [
                    step_and_leave(REGS[4]),
                    Set(arg1, arg1 - 1),
                    note(3),
                ])
                If(arg1, [notes(5, 6), *notes(7, 8), [note(9)]])
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Blocks(arg1: Value32):
                label('head')
                LOAD_STACK(-4)
                POP_JMP_ZERO('end')
                PUSH_INT(7)
                SET_REG(1)
                GET_REG(4)
                POP_JMP_ZERO('stay')
                JMP('end')
                label('stay')
                LOAD_STACK(-4)
                PUSH_INT(1)
                SUB()
                POP_TO(-4)
                PUSH_INT(3)
                SET_REG(3)
                JMP('head')
                label('end')
                LOAD_STACK(-4)
                POP_JMP_ZERO('done')
                PUSH_INT(5)
                SET_REG(5)
                PUSH_INT(6)
                SET_REG(6)
                PUSH_INT(7)
                SET_REG(7)
                PUSH_INT(8)
                SET_REG(8)
                PUSH_INT(9)
                SET_REG(3)
                label('done')
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)
        self.assertEqual(self.compiled(hlil, check=False), self.compiled(llil))

    def test_while_condition_macros(self):
        """A While condition's macro runs before each test, after a Continue too; one making an If that leaves the
        loop"""
        def hlil(scena):
            @scena.HLILCode()
            def Conditions(arg1: Value32, arg2: Value32):
                While(counted(arg1), [
                    Set(arg1, arg1 - 1),
                    If(arg2, [Continue()]),
                    Set(arg2, 1),
                ])
                While(leave_when(REGS[5], arg2), [
                    Set(arg2, arg2 - 1),
                ])
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Conditions(arg1: Value32, arg2: Value32):
                label('first')
                PUSH_INT(9)
                SET_REG(2)
                LOAD_STACK(-4)
                POP_JMP_ZERO('first_end')
                LOAD_STACK(-4)
                PUSH_INT(1)
                SUB()
                POP_TO(-4)
                LOAD_STACK(-8)
                POP_JMP_ZERO('no_continue')
                JMP('first')
                label('no_continue')
                PUSH_INT(1)
                POP_TO(-8)
                JMP('first')
                label('first_end')
                label('second')
                GET_REG(5)
                POP_JMP_ZERO('stay')
                JMP('second_end')
                label('stay')
                LOAD_STACK(-8)
                POP_JMP_ZERO('second_end')
                LOAD_STACK(-8)
                PUSH_INT(1)
                SUB()
                POP_TO(-8)
                JMP('second')
                label('second_end')
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(8)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_if_condition_macros(self):
        """An If's first condition's macro runs before the If, inside the loop holding it (an .ElseIf after it
        keeping it there); an .ElseIf condition's at that arm's test, a later .ElseIf's too; an .Else block's macro in
        the block"""
        def hlil(scena):
            @scena.HLILCode()
            def Arms(arg1: Value32):
                If(tested(1, arg1), [
                    Set(REGS[4], 1),
                ]).ElseIf(tested(2, arg1), [
                    Set(REGS[4], 2),
                ]).ElseIf(tested(3, arg1), [
                    Set(REGS[4], 4),
                ]).Else([
                    note(3),
                    Set(REGS[4], 3),
                ])
                While(arg1, [
                    If(tested(5, arg1), [Break()]).ElseIf(REGS[6], [Set(REGS[6], 0)]),
                    Set(arg1, arg1 - 1),
                ])
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Arms(arg1: Value32):
                PUSH_INT(1)
                SET_REG(1)
                LOAD_STACK(-4)
                PUSH_INT(1)
                EQ()
                POP_JMP_ZERO('second')
                PUSH_INT(1)
                SET_REG(4)
                JMP('if_end')
                label('second')
                PUSH_INT(2)
                SET_REG(2)
                LOAD_STACK(-4)
                PUSH_INT(2)
                EQ()
                POP_JMP_ZERO('third')
                PUSH_INT(2)
                SET_REG(4)
                JMP('if_end')
                label('third')
                PUSH_INT(3)
                SET_REG(3)
                LOAD_STACK(-4)
                PUSH_INT(3)
                EQ()
                POP_JMP_ZERO('else')
                PUSH_INT(4)
                SET_REG(4)
                JMP('if_end')
                label('else')
                PUSH_INT(3)
                SET_REG(3)
                PUSH_INT(3)
                SET_REG(4)
                label('if_end')
                label('head')
                LOAD_STACK(-4)
                POP_JMP_ZERO('loop_end')
                PUSH_INT(5)
                SET_REG(5)
                LOAD_STACK(-4)
                PUSH_INT(5)
                EQ()
                POP_JMP_ZERO('stay')
                JMP('loop_end')
                label('stay')
                GET_REG(6)
                POP_JMP_ZERO('inner_end')
                PUSH_INT(0)
                SET_REG(6)
                label('inner_end')
                LOAD_STACK(-4)
                PUSH_INT(1)
                SUB()
                POP_TO(-4)
                JMP('head')
                label('loop_end')
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_macros_making_whole_statements(self):
        """A macro making a whole loop whose block calls a macro; a recursive macro, each call's statements in its
        caller's block"""
        def hlil(scena):
            @scena.HLILCode()
            def Whole(arg1: Value32):
                If(arg1, [countdown(arg1)])
                marks(3)
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Whole(arg1: Value32):
                LOAD_STACK(-4)
                POP_JMP_ZERO('after_if')
                label('loop')
                LOAD_STACK(-4)
                POP_JMP_ZERO('loop_end')
                PUSH_INT(5)
                SET_REG(3)
                LOAD_STACK(-4)
                PUSH_INT(1)
                SUB()
                POP_TO(-4)
                JMP('loop')
                label('loop_end')
                label('after_if')
                PUSH_INT(3)
                SET_REG(3)
                GET_REG(3)
                POP_JMP_ZERO('end3')
                PUSH_INT(2)
                SET_REG(2)
                GET_REG(2)
                POP_JMP_ZERO('end2')
                PUSH_INT(1)
                SET_REG(1)
                label('end2')
                label('end3')
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_a_starred_call_run_again(self):
        """A starred While call, after a statement made in the same body, and run again by a Python loop"""
        def hlil(scena):
            @scena.HLILCode()
            def Starred(arg1: Value32, arg2: Value32):
                Set(REGS[1], 1)
                for counter in (arg1, arg2):
                    While(*loop_parts(counter))
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Starred(arg1: Value32, arg2: Value32):
                PUSH_INT(1)
                SET_REG(1)
                label('first')
                LOAD_STACK(-4)
                POP_JMP_ZERO('first_end')
                PUSH_INT(0)
                POP_TO(-4)
                JMP('first')
                label('first_end')
                label('second')
                LOAD_STACK(-8)
                POP_JMP_ZERO('second_end')
                PUSH_INT(0)
                POP_TO(-8)
                JMP('second')
                label('second_end')
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(8)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_locals_macros_declare(self):
        """A block macro's local lives in that block, pushed and popped every pass; a While condition macro's for one
        pass, popped before the jump back, on the way out and by a Break or a Continue; an .ElseIf condition macro's
        through that arm, popped on both its paths, at one POP when no arm follows; an If's first condition macro's
        before the If, to the end of the block holding it"""
        def hlil(scena):
            @scena.HLILCode()
            def Locals(arg1: Value32):
                x = Local('x')
                y = Local('y')
                z = Local('z')
                w = Local('w')
                While(arg1, [
                    Set(arg1, declared(x, 1) - arg1),
                ])
                While(declared(y, arg1), [
                    If(y == 2, [Break()]),
                    If(y == 3, [Continue()]),
                    Set(arg1, y - 1),
                ])
                If(arg1 == 1, [
                    Set(REGS[1], 1),
                ]).ElseIf(declared(z, arg1 + 1), [
                    Set(REGS[1], z),
                ]).Else([
                    Set(REGS[1], 3),
                ])
                If(arg1, [
                    Set(REGS[2], 1),
                ]).ElseIf(declared(z, 2), [
                    Set(REGS[2], z),
                ])
                While(arg1, [
                    If(arg1 == 5, [
                        Break(),
                    ]).ElseIf(declared(z, 6), [
                        Break(),
                    ]),
                    Set(arg1, 0),
                ])
                If(declared(w, 4), [
                    Set(REGS[3], w),
                ])
                Set(REGS[4], w)
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Locals(arg1: Value32):
                label('first')
                LOAD_STACK(-4)
                POP_JMP_ZERO('first_end')
                PUSH_RAW(RawInt(0))
                PUSH_INT(1)
                POP_TO(-4)
                LOAD_STACK(-4)
                LOAD_STACK(-12)
                SUB()
                POP_TO(-8)
                POP(4)                  # x, the block's
                JMP('first')
                label('first_end')
                label('second')
                PUSH_RAW(RawInt(0))
                LOAD_STACK(-8)
                POP_TO(-4)
                LOAD_STACK(-4)
                POP_JMP_ZERO('second_out')
                LOAD_STACK(-4)
                PUSH_INT(2)
                EQ()
                POP_JMP_ZERO('no_break')
                POP(4)                  # y, by the Break
                JMP('second_end')
                label('no_break')
                LOAD_STACK(-4)
                PUSH_INT(3)
                EQ()
                POP_JMP_ZERO('no_continue')
                POP(4)                  # y, by the Continue
                JMP('second')
                label('no_continue')
                LOAD_STACK(-4)
                PUSH_INT(1)
                SUB()
                POP_TO(-8)
                POP(4)                  # y, before the jump back
                JMP('second')
                label('second_out')
                POP(4)                  # y, on the way out
                label('second_end')
                LOAD_STACK(-4)
                PUSH_INT(1)
                EQ()
                POP_JMP_ZERO('third_second')
                PUSH_INT(1)
                SET_REG(1)
                JMP('third_end')
                label('third_second')
                PUSH_RAW(RawInt(0))
                LOAD_STACK(-8)
                PUSH_INT(1)
                ADD()
                POP_TO(-4)
                LOAD_STACK(-4)
                POP_JMP_ZERO('third_else')
                LOAD_STACK(-4)
                SET_REG(1)
                POP(4)                  # z, before the jump to the end
                JMP('third_end')
                label('third_else')
                POP(4)                  # z, past the arm
                PUSH_INT(3)
                SET_REG(1)
                label('third_end')
                LOAD_STACK(-4)
                POP_JMP_ZERO('fourth_second')
                PUSH_INT(1)
                SET_REG(2)
                JMP('fourth_end')
                label('fourth_second')
                PUSH_RAW(RawInt(0))
                PUSH_INT(2)
                POP_TO(-4)
                LOAD_STACK(-4)
                POP_JMP_ZERO('fourth_last')
                LOAD_STACK(-4)
                SET_REG(2)
                label('fourth_last')
                POP(4)                  # z, both paths
                label('fourth_end')
                label('fifth')
                LOAD_STACK(-4)
                POP_JMP_ZERO('fifth_loop_end')
                LOAD_STACK(-4)
                PUSH_INT(5)
                EQ()
                POP_JMP_ZERO('fifth_second')
                JMP('fifth_loop_end')
                label('fifth_second')
                PUSH_RAW(RawInt(0))
                PUSH_INT(6)
                POP_TO(-4)
                LOAD_STACK(-4)
                POP_JMP_ZERO('fifth_last')
                POP(4)                  # z, by the Break leaving its arm
                JMP('fifth_loop_end')
                label('fifth_last')
                POP(4)
                PUSH_INT(0)
                POP_TO(-4)
                JMP('fifth')
                label('fifth_loop_end')
                PUSH_RAW(RawInt(0))
                PUSH_INT(4)
                POP_TO(-4)
                LOAD_STACK(-4)
                POP_JMP_ZERO('fifth_end')
                LOAD_STACK(-4)
                SET_REG(3)
                label('fifth_end')
                LOAD_STACK(-4)
                SET_REG(4)
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(8)                  # w and arg1: the whole frame
                RETURN()

        self.assert_twins(hlil, llil)

    def test_blocks_through_wrappers(self):
        """A macro in a block given to the script's own wrapper, in a wrapper's block nested in another's, and in a
        block kept in a Python variable before its If takes it"""
        def hlil(scena):
            @scena.HLILCode()
            def Wrapped(arg1: Value32):
                when(arg1, [note(1), Set(REGS[4], 2)])
                If(arg1, [when(REGS[5], [note(6)])])
                block_in_a_variable(arg1)
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Wrapped(arg1: Value32):
                LOAD_STACK(-4)
                POP_JMP_ZERO('first_end')
                PUSH_INT(1)
                SET_REG(3)
                PUSH_INT(2)
                SET_REG(4)
                label('first_end')
                LOAD_STACK(-4)
                POP_JMP_ZERO('outer_end')
                GET_REG(5)
                POP_JMP_ZERO('inner_end')
                PUSH_INT(6)
                SET_REG(3)
                label('inner_end')
                label('outer_end')
                LOAD_STACK(-4)
                POP_JMP_ZERO('third_end')
                PUSH_INT(1)
                SET_REG(3)
                PUSH_INT(2)
                SET_REG(4)
                label('third_end')
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_arms_called_indirectly(self):
        """A condition macro given to a While wrapper or to itertools.starmap runs before each test; a block macro
        given through functools.partial, or to a starred While call, runs in the block"""
        def hlil(scena):
            @scena.HLILCode()
            def Indirect(arg1: Value32, arg2: Value32):
                until_zero(counted(arg1), [Set(arg1, arg1 - 1)])
                for _ in itertools.starmap(While, [(counted(arg2), [Set(arg2, arg2 - 1)])]):
                    pass
                functools.partial(While, arg1)([note(1), Set(arg1, 0)])
                parts = (arg2,)
                While(*parts, [note(2), Set(arg2, 0)])
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Indirect(arg1: Value32, arg2: Value32):
                label('first')
                PUSH_INT(9)
                SET_REG(2)
                LOAD_STACK(-4)
                POP_JMP_ZERO('first_end')
                LOAD_STACK(-4)
                PUSH_INT(1)
                SUB()
                POP_TO(-4)
                JMP('first')
                label('first_end')
                label('second')
                PUSH_INT(9)
                SET_REG(2)
                LOAD_STACK(-8)
                POP_JMP_ZERO('second_end')
                LOAD_STACK(-8)
                PUSH_INT(1)
                SUB()
                POP_TO(-8)
                JMP('second')
                label('second_end')
                label('third')
                LOAD_STACK(-4)
                POP_JMP_ZERO('third_end')
                PUSH_INT(1)
                SET_REG(3)
                PUSH_INT(0)
                POP_TO(-4)
                JMP('third')
                label('third_end')
                label('fourth')
                LOAD_STACK(-8)
                POP_JMP_ZERO('fourth_end')
                PUSH_INT(2)
                SET_REG(3)
                PUSH_INT(0)
                POP_TO(-8)
                JMP('fourth')
                label('fourth_end')
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(8)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_macro_values(self):
        """A macro's leaf value as Set's target, its statement first; a macro calling macros, one making a statement of
        another's value; a macro returning a list after a statement; a macro as a method; a macro first in an
        operation and in a call's arguments, its statement before the whole statement (Python's order: the later
        operand is read after it)"""
        def hlil(scena):
            @scena.HLILCode()
            def Values(arg1: Value32):
                Set(slot(7), 5)
                If(arg1, [two_notes(1, 2), NOTES.note(4), note_then_list(6), set_counted(arg1)])
                Set(REGS[4], set_then(REGS[3], REGS[5]) + REGS[3])
                Syscall(1, 2, set_then(REGS[3], REGS[5]), REGS[3])
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Values(arg1: Value32):
                PUSH_INT(7)
                SET_REG(1)
                PUSH_INT(5)
                SET_REG(7)
                LOAD_STACK(-4)
                POP_JMP_ZERO('if_end')
                PUSH_INT(1)
                SET_REG(3)
                PUSH_INT(2)
                SET_REG(3)
                PUSH_INT(4)
                SET_REG(3)
                PUSH_INT(6)
                SET_REG(1)
                PUSH_INT(6)
                SET_REG(2)
                PUSH_INT(9)
                SET_REG(2)
                LOAD_STACK(-4)
                SET_REG(6)
                label('if_end')
                PUSH_INT(9)
                SET_REG(3)
                GET_REG(5)
                GET_REG(3)
                ADD()
                SET_REG(4)
                PUSH_INT(9)
                SET_REG(3)
                GET_REG(3)
                GET_REG(5)
                SYSCALL(1, 2, 2)
                POP(8)
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_constant_operands_before_a_macro(self):
        """An operand read before a macro's is no read of the game when it is a constant or an operation on constants
        only, so the macro's statement runs before the whole statement"""
        def hlil(scena):
            @scena.HLILCode()
            def Constants(arg1: Value32):
                Syscall(1, 2, Int(8) | 16, counted(arg1))
                Syscall(1, 2, -Int(8), counted(arg1))
                Set(REGS[1], 5 - counted(arg1))
                Set(REGS[4], And(1, 2, counted(arg1)))
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Constants(arg1: Value32):
                PUSH_INT(9)
                SET_REG(2)
                LOAD_STACK(-4)
                PUSH_INT(8)
                PUSH_INT(16)
                BITWISE_OR()
                SYSCALL(1, 2, 2)
                POP(8)
                PUSH_INT(9)
                SET_REG(2)
                LOAD_STACK(-4)
                PUSH_INT(8)
                NEG()
                SYSCALL(1, 2, 2)
                POP(8)
                PUSH_INT(9)
                SET_REG(2)
                PUSH_INT(5)
                LOAD_STACK(-8)
                SUB()
                SET_REG(1)
                PUSH_INT(9)
                SET_REG(2)
                PUSH_INT(1)
                PUSH_INT(2)
                LOGICAL_AND()
                LOAD_STACK(-8)
                LOGICAL_AND()
                SET_REG(4)
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_macro_statement_orders(self):
        """A macro's statements in the order made: two for an operand in a block and for a While's condition, one
        after the If it returns, one after its list's element; a macro returning another's value; Let taking a macro's
        local; an unmarked function's value kept in a global or a closure's variable"""
        def hlil(scena):
            @scena.HLILCode()
            def Orders(arg1: Value32):
                t = Local('t')
                If(arg1, [Set(REGS[3], two_then(arg1))])
                While(two_then(arg1), [Set(arg1, arg1 - 1)])
                If(arg1, [if_then_note(REGS[5])])
                If(arg1, [list_then_note(6)])
                If(arg1, [Set(REGS[4], outer_counted(arg1))])
                keep_in_a_global()
                keep_in_a_closure()
                Let(fresh(t), 2)
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Orders(arg1: Value32):
                LOAD_STACK(-4)
                POP_JMP_ZERO('first_end')
                PUSH_INT(1)
                SET_REG(1)
                PUSH_INT(2)
                SET_REG(2)
                LOAD_STACK(-4)
                SET_REG(3)
                label('first_end')
                label('loop')
                PUSH_INT(1)
                SET_REG(1)
                PUSH_INT(2)
                SET_REG(2)
                LOAD_STACK(-4)
                POP_JMP_ZERO('loop_end')
                LOAD_STACK(-4)
                PUSH_INT(1)
                SUB()
                POP_TO(-4)
                JMP('loop')
                label('loop_end')
                LOAD_STACK(-4)
                POP_JMP_ZERO('third_end')
                GET_REG(5)
                POP_JMP_ZERO('inner_end')
                PUSH_INT(1)
                SET_REG(1)
                label('inner_end')
                PUSH_INT(2)
                SET_REG(2)
                label('third_end')
                LOAD_STACK(-4)
                POP_JMP_ZERO('fourth_end')
                PUSH_INT(6)
                SET_REG(1)
                PUSH_INT(6)
                SET_REG(2)
                label('fourth_end')
                LOAD_STACK(-4)
                POP_JMP_ZERO('fifth_end')
                PUSH_INT(9)
                SET_REG(2)
                LOAD_STACK(-4)
                SET_REG(4)
                label('fifth_end')
                PUSH_INT(1)
                SET_REG(3)
                PUSH_INT(2)
                SET_REG(3)
                PUSH_INT(1)
                SET_REG(1)
                PUSH_RAW(RawInt(0))
                PUSH_INT(2)
                POP_TO(-4)
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(8)
                RETURN()

        self.assert_twins(hlil, llil)

    def test_unmarked_functions_standing(self):
        """An unmarked function's statement stands where it is made at each boundary that keeps its call out of an
        expression: a line of its own in the body or in a function, a plain variable, a keyword or a starred call, one
        side of a ternary line, a returned call"""
        def hlil(scena):
            @scena.HLILCode()
            def Standing(arg1: Value32):
                plain_boundaries(True)
                plain_note(8)
                Return()

        def llil(scena):
            @scena.LLILCode()
            def Standing(arg1: Value32):
                PUSH_INT(1)
                SET_REG(3)
                PUSH_INT(2)
                SET_REG(3)
                PUSH_INT(3)
                SET_REG(3)
                PUSH_INT(4)
                SET_REG(3)
                PUSH_INT(5)
                SET_REG(3)
                PUSH_INT(7)
                SET_REG(3)
                PUSH_INT(8)
                SET_REG(3)
                PUSH_RAW(RawInt(0))
                SET_REG(0)
                POP(4)
                RETURN()

        self.assert_twins(hlil, llil)


if __name__ == '__main__':
    unittest.main()
