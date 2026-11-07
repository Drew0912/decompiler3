#!/usr/bin/env python3
"""Assembled functions and helpers that two or more of the logic check's test files read
(tests/tools_tests/test_logic_check_*.py): the bytecode, its LLIL facts and MLIL, its MLIL and HLIL, each pair's
categories; it imports logic_check from tools/, which the importing test puts on sys.path"""

from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil_stack
from ir.llil.llil import WORD_SIZE
from tests.shared.llil_utils import lift_asm
from tests.shared.scp_asm import CALLEE_ID, CALLER_ID, Asm, returning_callee
import logic_check

GLOBAL_A, GLOBAL_B, GLOBAL_C, GLOBAL_D = 1, 2, 3, 4
MESSAGE = 'this'
LOOP_LIMIT = 3
STORED = 3
OUT_INITIAL = 1
UNRELATED_ARG = 9
DEBUG_VALUE = -5
REG_INDEX = 5
NESTED_TESTS = 17               # conditions one guard runs under: past formulas.ROW_CAP's 2 ** 16 rows


# === Assembled functions ===

def call(asm: Asm, label: str, *args: int):
    """A local call of the callee with int arguments, returning at label"""
    asm.push_raw(CALLER_ID); asm.push_raw(label)
    for arg in args:
        asm.push_int(arg)
    asm.call(CALLEE_ID); asm.label(label)


def return_nothing(asm: Asm):
    asm.push_raw(0); asm.set_reg(0); asm.ret()


def calls_function() -> tuple[Asm, int]:
    """callee(8, 7); GLOBAL_A = its result; callee(10, 9); a POPN and a DEBUG_INT; returned"""
    asm = Asm()
    call(asm, 'first', 7, 8); asm.get_reg(0); asm.set_global(GLOBAL_A)
    call(asm, 'second', 9, 10)
    asm.push_str(MESSAGE); asm.push_int(5); asm.popn(2); asm.debug_int(DEBUG_VALUE)
    return_nothing(asm)
    return asm, 2


def branch_function() -> tuple[Asm, int]:
    """callee(4); if GLOBAL[0]: callee(1) else GLOBAL_B = 3"""
    asm = Asm()
    call(asm, 'before', 4)
    asm.load_global(0); asm.jz('else')
    call(asm, 'then', 1); asm.jmp('end')
    asm.label('else'); asm.push_int(3); asm.set_global(GLOBAL_B)
    asm.label('end'); return_nothing(asm)
    return asm, 1


def initialised_out_parameter_function() -> tuple[Asm, int]:
    """v = OUT_INITIAL; callee(&v); GLOBAL[0] = v: the callee may read v before it writes it"""
    asm = Asm()
    asm.push_int(OUT_INITIAL)
    asm.push_raw(CALLER_ID); asm.push_raw('after'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('after'); asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def loop_call_function() -> tuple[Asm, int]:
    """i = 0; while i < LOOP_LIMIT: callee(i); i = i + 1"""
    asm = Asm()
    asm.push_int(0)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.load_stack(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('back'); asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('head')
    asm.label('done'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def optional_call_result_function() -> tuple[Asm, int]:
    """if GLOBAL[0]: callee(); GLOBAL_A = REG[0]: the call's result read after the join"""
    asm = Asm()
    asm.load_global(0); asm.jz('join')
    call(asm, 'after')
    asm.label('join'); asm.get_reg(0); asm.set_global(GLOBAL_A)
    return_nothing(asm)
    return asm, 0


def reference_and_mlil(build, argc: int = 0) -> tuple:
    """The function's LLIL facts (taken before the conversion) and its MLIL as the decompiler makes it; argc its
    parameters"""
    asm, callee_argc = build()
    _, llil = lift_asm(asm, argc=argc, others=(returning_callee(callee_argc),))
    reference = logic_check.analyze(logic_check.LLILLayer(llil))
    return reference, convert_falcom_llil_to_mlil_stack(llil)


def categories(reference, mlil) -> set[str]:
    return {difference.category for difference in
            logic_check.compare_facts(reference, logic_check.analyze(logic_check.MLILLayer(mlil)))}


# === Mutations of the MLIL ===

def statements(mlil) -> list[tuple]:
    """(block, index, statement) for every statement, in block order"""
    return [(block, index, inst) for block in mlil.basic_blocks for index, inst in enumerate(block.instructions)]


def first(mlil, predicate) -> tuple:
    found = [entry for entry in statements(mlil) if predicate(entry[2])]
    if not found:
        raise AssertionError('the mutation found nothing to change: the MLIL shape changed')
    return found[0]


# === Mutations of the HLIL ===

def mlil_and_hlil(build, argc: int = 0) -> tuple:
    """The function's MLIL as the decompiler makes it and the HLIL made from it"""
    _, mlil = reference_and_mlil(build, argc)
    return mlil, convert_falcom_mlil_to_hlil(mlil)


def hlil_categories(mlil, hlil) -> set[str]:
    return {difference.category for difference in logic_check.compare_mlil_hlil(mlil, hlil)}
