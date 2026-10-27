#!/usr/bin/env python3
"""The logic check (tools/logic_check/): a bug planted in the MLIL or the HLIL of a small assembled function shows up
as its category, and the unchanged layer compares clean; structures HLIL builds otherwise than MLIL compare clean; the
condition normal form and formula keys; post-dominators and control dependence; a real script compares clean"""

from pathlib import Path
from typing import Callable
from unittest import mock
import copy
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.mlil.mlil_translator import DEBUG_LOG_CALL_TARGET
from ir.core.il_literals import SourceFloat
from ir.hlil.hlil import (
    BinaryOp, HLILAssign, HLILBinaryOp, HLILBlock, HLILBreak, HLILCall, HLILConst, HLILContinue, HLILIf, HLILReturn,
    HLILSwitch, HLILUnstructured, HLILVar, HLILVariable, HLILWhile, VariableKind, iter_tree,
)
from ir.llil.llil import WORD_SIZE
from ir.mlil.mlil import (
    MediumLevelILCall, MLILAdd, MLILCall, MLILConst, MLILGe, MLILIf, MLILLoadGlobal, MLILLogicalNot, MLILLt,
    MLILRet, MLILSetVar, MLILStoreDeref, MLILStoreGlobal, MLILStoreReg, MLILVar, map_operands, walk,
)
from tests.shared.corpus import SORA2_SCRIPTS, require
from tests.shared.llil_utils import lift_asm
from tests.shared.scp_asm import CALLEE_ID, CALLER_ID, Asm, returning_callee
import logic_check
from logic_check import compare, formulas
from logic_check.compare import Namer
from logic_check.evaluation import FUNCTION_ENTRY, RETURN_KEY, Branch, Effect, Facts
from logic_check.post_dominators import EXIT, control_dependence, exit_blocks, immediate_post_dominators
from logic_check.state import PHI_DEPTH, Fingerprints
from logic_check.trees import const, constant_truth, op, truth

GLOBAL_A, GLOBAL_B, GLOBAL_C = 1, 2, 3
MESSAGE = 'this'
LOOP_LIMIT = 3
OUT_INITIAL = 1
UNRELATED_ARG = 9
REG_INDEX = 5
REG_OUT = 7
DEEP_INITIAL = 1
ENDLESS_TAIL_PARAMETERS = 2
EARLY_ARG = 9
SKIPPED = 1
CHAIN_CASES = 3                 # HLIL's if-to-switch takes a chain of at least SWITCH_MIN_CASES tests
NESTED_TESTS = 17               # conditions one guard runs under: past formulas.ROW_CAP's 2 ** 16 rows
DIAGRAM_NODES_TOO_FEW = 2       # a formulas.DIAGRAM_NODE_CAP no decision diagram fits in (its two terminals)


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
    """callee(8, 7); GLOBAL_A = its result; callee(10, 9); a DEBUG_LOG; returned"""
    asm = Asm()
    call(asm, 'first', 7, 8); asm.get_reg(0); asm.set_global(GLOBAL_A)
    call(asm, 'second', 9, 10)
    asm.push_str(MESSAGE); asm.push_int(5); asm.debug_log(2)
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


def two_results_function() -> tuple[Asm, int]:
    """x = callee(); y = callee(); GLOBAL[0] = callee() + (x - y): two results held across later calls"""
    asm = Asm()
    asm.push_raw(0); asm.push_raw(0)
    call(asm, 'x'); asm.get_reg(0); asm.pop_to(-2 * WORD_SIZE)
    call(asm, 'y'); asm.get_reg(0); asm.pop_to(-WORD_SIZE)
    call(asm, 'z'); asm.get_reg(0)
    asm.load_stack(-3 * WORD_SIZE); asm.load_stack(-3 * WORD_SIZE); asm.sub(); asm.add(); asm.set_global(0)
    asm.pop(2 * WORD_SIZE); return_nothing(asm)
    return asm, 0


def out_parameter_function() -> tuple[Asm, int]:
    """v; callee(&v); GLOBAL[0] = v"""
    asm = Asm()
    asm.push_raw(0)
    asm.push_raw(CALLER_ID); asm.push_raw('after'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('after'); asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def unrelated_call_function() -> tuple[Asm, int]:
    """v = OUT_INITIAL; callee(UNRELATED_ARG); GLOBAL[0] = v; callee(&v): the first call is given no pointer to v, so
    v holds its value across it"""
    asm = Asm()
    asm.push_int(OUT_INITIAL)
    call(asm, 'first', UNRELATED_ARG)
    asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.push_raw(CALLER_ID); asm.push_raw('second'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('second'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def escaped_address_function() -> tuple[Asm, int]:
    """v = OUT_INITIAL; GLOBAL_A = &v; callee(); GLOBAL_B = v: the callee is given no pointer, but can reach v through
    the global"""
    asm = Asm()
    asm.push_int(OUT_INITIAL); asm.push_stack_offset(-WORD_SIZE); asm.set_global(GLOBAL_A)
    call(asm, 'back')
    asm.load_stack(-WORD_SIZE); asm.set_global(GLOBAL_B)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def pointer_to_pointer_function() -> tuple[Asm, int]:
    """v = OUT_INITIAL; q = &v; callee(&q): the callee is given q's address, and reaches v through q"""
    asm = Asm()
    asm.push_int(OUT_INITIAL); asm.push_stack_offset(-WORD_SIZE)
    asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('back'); asm.pop(2 * WORD_SIZE); return_nothing(asm)
    return asm, 1


def one_arm_register_function() -> tuple[Asm, int]:
    """if GLOBAL_A: REG = REG_OUT; returned: the other arm leaves the register's incoming value for the caller"""
    asm = Asm()
    asm.load_global(GLOBAL_A); asm.jz('end')
    asm.push_int(REG_OUT); asm.set_reg(REG_INDEX)
    asm.label('end'); return_nothing(asm)
    return asm, 0


def loop_function() -> tuple[Asm, int]:
    """i = 0; while i < LOOP_LIMIT: i = i + 1; GLOBAL[0] = i"""
    asm = Asm()
    asm.push_int(0)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE); asm.jmp('head')
    asm.label('done'); asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def initialised_out_parameter_function() -> tuple[Asm, int]:
    """v = OUT_INITIAL; callee(&v); GLOBAL[0] = v: the callee may read v before it writes it"""
    asm = Asm()
    asm.push_int(OUT_INITIAL)
    asm.push_raw(CALLER_ID); asm.push_raw('after'); asm.push_stack_offset(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('after'); asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def deep_join_function() -> tuple[Asm, int]:
    """v = DEEP_INITIAL; then PHI_DEPTH + 1 times: if GLOBAL[i]: v = DEEP_INITIAL + i + 1; GLOBAL[0] = v: the value
    stored merges more joins deep than a phi is spelled out"""
    asm = Asm()
    asm.push_int(DEEP_INITIAL)
    for index in range(PHI_DEPTH + 1):
        asm.load_global(index); asm.jz(f'skip{index}')
        asm.push_int(DEEP_INITIAL + index + 1); asm.pop_to(-WORD_SIZE)
        asm.label(f'skip{index}')
    asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def endless_tail_function() -> tuple[Asm, int]:
    """f(a, b): if b: { if a: REG = 1 else REG = 2; callee() } then loop forever: the call runs on the outer arm only,
    in a block the endless loop post-dominates. The branches read parameters, which a call does not change, and only
    the call is an effect, so a moved call differs in its guard alone"""
    asm = Asm()
    asm.load_stack(-WORD_SIZE); asm.jz('forever')
    asm.load_stack(-2 * WORD_SIZE); asm.jz('else')
    asm.push_int(1); asm.set_reg(REG_INDEX); asm.jmp('join')
    asm.label('else'); asm.push_int(2); asm.set_reg(REG_INDEX)
    asm.label('join'); call(asm, 'outer')
    asm.label('forever'); asm.jmp('forever')
    return asm, 0


def and_condition_function() -> tuple[Asm, int]:
    """x = callee(1); if GLOBAL_A && x: GLOBAL_B = 1: the call runs whatever GLOBAL_A holds"""
    asm = Asm()
    asm.push_raw(0)
    call(asm, 'first', 1); asm.get_reg(0); asm.pop_to(-WORD_SIZE)
    asm.load_global(GLOBAL_A); asm.load_stack(-2 * WORD_SIZE); asm.logical_and(); asm.jz('end')
    asm.push_int(1); asm.set_global(GLOBAL_B)
    asm.label('end'); asm.pop(WORD_SIZE); return_nothing(asm)
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


def case_chain_function() -> tuple[Asm, int]:
    """if GLOBAL_A == 1: callee(1) elif == 2: callee(2) elif == 3: callee(3) else callee(4): HLIL makes it a switch"""
    asm = Asm()
    for case in range(1, CHAIN_CASES + 1):
        asm.load_global(GLOBAL_A); asm.push_int(case); asm.eq(); asm.jz(f'not{case}')
        call(asm, f'call{case}', case); asm.jmp('end')
        asm.label(f'not{case}')
    call(asm, 'default', CHAIN_CASES + 1)
    asm.label('end'); return_nothing(asm)
    return asm, 1


def nested_tests_function() -> tuple[Asm, int]:
    """if GLOBAL[1] && ... && GLOBAL[NESTED_TESTS - 1]: (if GLOBAL[NESTED_TESTS]: callee(1) else callee(2)): each
    call's guard over more conditions than a truth table holds"""
    asm = Asm()
    for index in range(1, NESTED_TESTS):
        asm.load_global(index); asm.jz('end')
    asm.load_global(NESTED_TESTS); asm.jz('other')
    call(asm, 'one', 1); asm.jmp('end')
    asm.label('other'); call(asm, 'two', 2)
    asm.label('end'); return_nothing(asm)
    return asm, 1


def arms_joined_in_a_loop_function() -> tuple[Asm, int]:
    """i = 0; while i < LOOP_LIMIT: (if GLOBAL_A: i = i + 1 else i = i + 2); GLOBAL_B = i: MLIL joins the arms in a
    block of their own before the back edge, HLIL takes one from each arm"""
    asm = Asm()
    asm.push_int(0)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.load_global(GLOBAL_A); asm.jz('else')
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE); asm.jmp('join')
    asm.label('else'); asm.load_stack(-WORD_SIZE); asm.push_int(2); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.label('join'); asm.jmp('head')
    asm.label('done'); asm.load_stack(-WORD_SIZE); asm.set_global(GLOBAL_B); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def constant_loop_test_function() -> tuple[Asm, int]:
    """while 1: callee(1); if GLOBAL_A: (callee(2); break): MLIL keeps the constant test's exit edge, HLIL makes a
    while (1)"""
    asm = Asm()
    asm.label('head'); asm.push_int(1); asm.jz('done')
    call(asm, 'body', 1)
    asm.load_global(GLOBAL_A); asm.jz('head')
    call(asm, 'last', 2)
    asm.label('done'); return_nothing(asm)
    return asm, 1


def skipping_loop_function() -> tuple[Asm, int]:
    """i = 0; while 1: (if i == SKIPPED: (i = i + 1; continue)); callee(i); if i >= LOOP_LIMIT: return; i = i + 1:
    the loop's only way out is through the call's arm, so the call runs in some iteration whatever the test says"""
    asm = Asm()
    asm.push_int(0)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(SKIPPED); asm.eq(); asm.jz('work')
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE); asm.jmp('head')
    asm.label('work')
    asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.load_stack(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('back'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.ge(); asm.jz('next'); asm.jmp('done')
    asm.label('next'); asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE); asm.jmp('head')
    asm.label('done'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def nested_arms_function() -> tuple[Asm, int]:
    """if GLOBAL_A: x = 1 elif GLOBAL_B: x = 2 else x = 3; if x == 2: callee(2): MLIL joins the inner arms in a block
    that only jumps on, HLIL all three at once, and the merged x is in the call's guard"""
    asm = Asm()
    asm.push_int(0)
    asm.load_global(GLOBAL_A); asm.jz('else')
    asm.push_int(1); asm.pop_to(-WORD_SIZE); asm.jmp('end')
    asm.label('else'); asm.load_global(GLOBAL_B); asm.jz('last')
    asm.push_int(2); asm.pop_to(-WORD_SIZE); asm.jmp('inner_end')
    asm.label('last'); asm.push_int(3); asm.pop_to(-WORD_SIZE)
    asm.label('inner_end'); asm.jmp('end')
    asm.label('end'); asm.load_stack(-WORD_SIZE); asm.push_int(2); asm.eq(); asm.jz('skip')
    call(asm, 'two', 2)
    asm.label('skip'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def break_loop_function() -> tuple[Asm, int]:
    """while GLOBAL_A: (if GLOBAL_B == 0: (callee(1); continue) else break)"""
    asm = Asm()
    asm.label('head'); asm.load_global(GLOBAL_A); asm.jz('done')
    asm.load_global(GLOBAL_B); asm.jnz('done')
    call(asm, 'body', 1); asm.jmp('head')
    asm.label('done'); return_nothing(asm)
    return asm, 1


def wait_loop_function() -> tuple[Asm, int]:
    """callee(1); while GLOBAL_A: ; callee(2): a loop with no effect of its own"""
    asm = Asm()
    call(asm, 'before', 1)
    asm.label('head'); asm.load_global(GLOBAL_A); asm.jz('done'); asm.jmp('head')
    asm.label('done'); call(asm, 'after', 2); return_nothing(asm)
    return asm, 1


def nested_break_function() -> tuple[Asm, int]:
    """outer: while GLOBAL_A: (while GLOBAL_B: (callee(1); if GLOBAL_C: break outer)); callee(2)"""
    asm = Asm()
    asm.label('outer'); asm.load_global(GLOBAL_A); asm.jz('done')
    asm.label('inner'); asm.load_global(GLOBAL_B); asm.jz('outer')
    call(asm, 'body', 1)
    asm.load_global(GLOBAL_C); asm.jnz('done'); asm.jmp('inner')
    asm.label('done'); call(asm, 'after', 2); return_nothing(asm)
    return asm, 1


def bottom_test_function() -> tuple[Asm, int]:
    """do callee(1) while GLOBAL_A: the test after the loop's only effect, nothing after the loop"""
    asm = Asm()
    asm.label('head'); call(asm, 'body', 1)
    asm.load_global(GLOBAL_A); asm.jnz('head')
    return_nothing(asm)
    return asm, 1


def split_exit_function() -> tuple[Asm, int]:
    """while 1: (callee(2); while 1: (callee(1); if GLOBAL_A == 0 && GLOBAL_B == 0: break)): MLIL tests the inner
    loop's only way out at once, HLIL one test per operand"""
    asm = Asm()
    asm.label('outer'); call(asm, 'outer_body', 2)
    asm.label('inner'); call(asm, 'inner_body', 1)
    asm.load_global(GLOBAL_A); asm.ez(); asm.load_global(GLOBAL_B); asm.ez(); asm.logical_and(); asm.jz('inner')
    asm.jmp('outer')
    return asm, 1


def two_returns_function() -> tuple[Asm, int]:
    """if GLOBAL_A: (callee(1); return) else (callee(2); return)"""
    asm = Asm()
    asm.load_global(GLOBAL_A); asm.jz('else')
    call(asm, 'then', 1); return_nothing(asm)
    asm.label('else'); call(asm, 'other', 2); return_nothing(asm)
    return asm, 1


def return_after_a_loop_function() -> tuple[Asm, int]:
    """if GLOBAL_A: (i = 0; while i < LOOP_LIMIT: (callee(i); i = i + 1); return) else (callee(EARLY_ARG); return)"""
    asm = Asm()
    asm.load_global(GLOBAL_A); asm.jz('early')
    asm.push_int(0)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.load_stack(-3 * WORD_SIZE); asm.call(CALLEE_ID)
    asm.label('back'); asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('head')
    asm.label('done'); asm.pop(WORD_SIZE); return_nothing(asm)
    asm.label('early'); call(asm, 'early', EARLY_ARG); return_nothing(asm)
    return asm, 1


def branch_then_loop_function() -> tuple[Asm, int]:
    """x = 1 if GLOBAL_A else 2; while x < LOOP_LIMIT: x = x + 1; callee(x)"""
    asm = Asm()
    asm.load_global(GLOBAL_A); asm.jz('two')
    asm.push_int(1); asm.jmp('head')
    asm.label('two'); asm.push_int(2)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('head')
    asm.label('done'); asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.load_stack(-3 * WORD_SIZE)
    asm.call(CALLEE_ID)
    asm.label('back'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def calls_then_loop_function() -> tuple[Asm, int]:
    """x = 0; if GLOBAL_A: callee(1) else callee(2); while x < LOOP_LIMIT: x = x + 1; callee(x)"""
    asm = Asm()
    asm.push_int(0)
    asm.load_global(GLOBAL_A); asm.jz('other')
    call(asm, 'first', 1); asm.jmp('head')
    asm.label('other'); call(asm, 'second', 2)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('head')
    asm.label('done'); asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.load_stack(-3 * WORD_SIZE)
    asm.call(CALLEE_ID)
    asm.label('back'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def reference_and_mlil(build, argc: int = 0) -> tuple:
    """The function's LLIL facts (taken before the conversion) and its MLIL as the decompiler makes it; argc its
    parameters"""
    asm, callee_argc = build()
    _, llil = lift_asm(asm, argc=argc, others=(returning_callee(callee_argc),))
    reference = logic_check.analyze(logic_check.LLILLayer(llil))
    return reference, convert_falcom_llil_to_mlil(llil, optimize=True, infer_types=False)


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


def is_debug_log(inst) -> bool:
    return isinstance(inst, MLILCall) and inst.target == DEBUG_LOG_CALL_TARGET


def is_call(inst) -> bool:
    return isinstance(inst, MediumLevelILCall) and not is_debug_log(inst)


def rewrite(node, transform):
    """transform applied bottom-up to every expression under node"""
    return transform(map_operands(node, lambda operand: rewrite(operand, transform)))


def replace_reads(mlil, old, new, start: tuple):
    """Every read of variable old from the statement at start on (in its block) read as variable new instead"""
    block, index, _ = start
    for position in range(index, len(block.instructions)):
        block.instructions[position] = rewrite(
            block.instructions[position], lambda e: MLILVar(new) if isinstance(e, MLILVar) and e.var == old else e)


class TestPlantedBugs(unittest.TestCase):
    """Each bug class a translator or a pass could bring, planted in real MLIL: the comparator reports its category"""

    def check(self, build, mutate, expected: str, argc: int = 0):
        reference, mlil = reference_and_mlil(build, argc)
        self.assertEqual(categories(reference, mlil), set(), 'the unchanged MLIL compares clean')
        mutate(mlil)
        self.assertIn(expected, categories(reference, mlil))

    def test_swapped_arguments(self):
        def mutate(mlil):
            inst = first(mlil, is_call)[2]
            inst.args[0], inst.args[1] = inst.args[1], inst.args[0]
        self.check(calls_function, mutate, 'arg_differs')

    def test_changed_constant(self):
        def mutate(mlil):
            inst = first(mlil, is_call)[2]
            inst.args[0] = MLILConst(inst.args[0].value + 1)
        self.check(calls_function, mutate, 'arg_differs')

    def test_dropped_effect(self):
        def mutate(mlil):
            block, index, _ = first(mlil, lambda inst: isinstance(inst, MLILStoreGlobal))
            del block.instructions[index]
        self.check(calls_function, mutate, 'missing_effect')

    def test_duplicated_effect(self):
        def mutate(mlil):
            block, index, inst = first(mlil, is_call)
            block.instructions.insert(index, inst.rebuild(*inst.args))
        self.check(calls_function, mutate, 'added_effect')

    def test_two_calls_swapped(self):
        def mutate(mlil):
            calls = [entry for entry in statements(mlil) if is_call(entry[2])]
            (block, a, call_a), (_, b, call_b) = calls[0], calls[1]
            block.instructions[a], block.instructions[b] = call_b, call_a
        self.check(calls_function, mutate, 'order_differs')

    def test_debug_log_argument_changed(self):
        def mutate(mlil):
            inst = first(mlil, is_debug_log)[2]
            inst.args[1] = MLILConst(MESSAGE + '!')
        self.check(calls_function, mutate, 'arg_differs')

    def test_debug_log_dropped(self):
        def mutate(mlil):
            block, index, _ = first(mlil, is_debug_log)
            del block.instructions[index]
        self.check(calls_function, mutate, 'missing_effect')

    def test_debug_log_duplicated(self):
        def mutate(mlil):
            block, index, inst = first(mlil, is_debug_log)
            block.instructions.insert(index, inst.rebuild(*inst.args))
        self.check(calls_function, mutate, 'added_effect')

    def test_flipped_branch(self):
        def mutate(mlil):
            branch = first(mlil, lambda inst: isinstance(inst, MLILIf))[2]
            branch.true_target, branch.false_target = branch.false_target, branch.true_target
        self.check(branch_function, mutate, 'branch_targets_differ')

    def test_changed_condition(self):
        def mutate(mlil):
            block, index, branch = first(mlil, lambda inst: isinstance(inst, MLILIf))
            condition = rewrite(branch.condition,
                                lambda e: MLILLoadGlobal(GLOBAL_C) if isinstance(e, MLILLoadGlobal) else e)
            block.instructions[index] = MLILIf(condition, branch.true_target, branch.false_target) \
                .copy_metadata_from(branch)
        self.check(branch_function, mutate, 'condition_differs')

    def test_call_moved_under_a_branch(self):
        def mutate(mlil):
            block, index, inst = first(mlil, is_call)
            branch = block.instructions[-1]
            del block.instructions[index]
            branch.false_target.instructions.insert(0, inst)
        self.check(branch_function, mutate, 'guard_differs')

    def test_stale_register_read(self):
        """x = reg0; call; use(x) read as use(reg0): the copy before the call left out"""
        def mutate(mlil):
            start = first(mlil, lambda inst: isinstance(inst, MLILSetVar) and isinstance(inst.value, MLILVar))
            copy = start[2]
            later = (start[0], start[1] + 1, None)
            replace_reads(mlil, copy.var, copy.value.var, later)
        self.check(two_results_function, mutate, 'arg_differs')

    def test_reused_temporary(self):
        """The second held result given the first one's variable"""
        def mutate(mlil):
            copies = [entry for entry in statements(mlil)
                      if isinstance(entry[2], MLILSetVar) and isinstance(entry[2].value, MLILVar)]
            (_, _, x), (block, index, y) = copies[0], copies[1]
            block.instructions[index] = MLILSetVar(x.var, y.value).copy_metadata_from(y)
            replace_reads(mlil, y.var, x.var, (block, index + 1, None))
        self.check(two_results_function, mutate, 'arg_differs')

    def test_out_parameter_read_before_its_call(self):
        """GLOBAL[0] = v moved before callee(&v): the read no longer sees what the call wrote"""
        def mutate(mlil):
            block, index, store = first(mlil, lambda inst: isinstance(inst, MLILStoreGlobal))
            call_index = first(mlil, is_call)[1]
            del block.instructions[index]
            block.instructions.insert(call_index, store)
        self.check(out_parameter_function, mutate, 'arg_differs')

    def test_value_behind_a_pointer_changed(self):
        """v's initial value changed before callee(&v): only the callee can read it, and v after the call is the call's
        leaf"""
        def mutate(mlil):
            init = first(mlil, lambda inst: isinstance(inst, MLILStoreDeref)    # v's memory form, *&v = OUT_INITIAL
                         and isinstance(inst.value, MLILConst) and inst.value.value == OUT_INITIAL)[2]
            init.value = MLILConst(OUT_INITIAL + 1)
        self.check(initialised_out_parameter_function, mutate, 'arg_differs')

    def test_value_merged_past_the_phi_depth_changed(self):
        """v's initial value changed: it reaches the store only through more joins than a phi spells out"""
        def mutate(mlil):
            init = first(mlil, lambda inst: isinstance(inst, MLILSetVar) and isinstance(inst.value, MLILConst)
                         and inst.value.value == DEEP_INITIAL)[2]
            init.value = MLILConst(DEEP_INITIAL + PHI_DEPTH + 2)
        self.check(deep_join_function, mutate, 'arg_differs')

    def test_register_written_before_the_return(self):
        """A register the bytecode leaves alone written before the return: the caller can read it after the call"""
        def mutate(mlil):
            block, index, _ = first(mlil, lambda inst: isinstance(inst, MLILRet))
            block.instructions.insert(index, MLILStoreReg(REG_INDEX, MLILConst(1)))
        self.check(calls_function, mutate, 'return_differs')

    def test_value_held_across_an_unrelated_call_changed(self):
        """v's initial value changed: read after a call that is given no pointer to v, which a later call is"""
        def mutate(mlil):
            init = first(mlil, lambda inst: isinstance(inst, MLILStoreDeref)    # v's memory form, *&v = OUT_INITIAL
                         and isinstance(inst.value, MLILConst) and inst.value.value == OUT_INITIAL)[2]
            init.value = MLILConst(OUT_INITIAL + 1)
        self.check(unrelated_call_function, mutate, 'arg_differs')

    def test_read_after_a_call_that_reaches_it_through_a_global_made_stale(self):
        """GLOBAL_B = v after the call read as v's value before it: the call can write v through GLOBAL_A"""
        def mutate(mlil):
            store = first(mlil, lambda inst: isinstance(inst, MLILStoreGlobal) and inst.index == GLOBAL_B)[2]
            store.value = MLILConst(OUT_INITIAL)
        self.check(escaped_address_function, mutate, 'arg_differs')

    def test_value_behind_a_pointer_to_a_pointer_changed(self):
        """v's initial value changed before callee(&q), q = &v: the callee can read v through q"""
        def mutate(mlil):
            init = first(mlil, lambda inst: isinstance(inst, MLILStoreDeref)    # v's memory form, *&v = OUT_INITIAL
                         and isinstance(inst.value, MLILConst) and inst.value.value == OUT_INITIAL)[2]
            init.value = MLILConst(OUT_INITIAL + 1)
        self.check(pointer_to_pointer_function, mutate, 'arg_differs')

    def test_register_one_arm_leaves_changed(self):
        """The arm's write changed; the other arm's incoming value compares clean on both layers (MLIL copies it, LLIL
        leaves it)"""
        def mutate(mlil):
            write = first(mlil, lambda inst: isinstance(inst, MLILSetVar) and isinstance(inst.value, MLILConst)
                          and inst.value.value == REG_OUT)[2]
            write.value = MLILConst(REG_OUT + 1)
        self.check(one_arm_register_function, mutate, 'return_differs')

    def test_call_hoisted_out_of_an_endless_tail(self):
        """The outer arm's second call moved before the branch: it now runs on both arms"""
        def mutate(mlil):
            block, index, inst = [entry for entry in statements(mlil) if is_call(entry[2])][-1]
            del block.instructions[index]
            mlil.basic_blocks[0].instructions.insert(0, inst)
        self.check(endless_tail_function, mutate, 'guard_differs', ENDLESS_TAIL_PARAMETERS)

    def test_loop_update_changed(self):
        """i = i + 1 made i = i + 3: the value after the loop is the same leaf, the value carried round differs"""
        def mutate(mlil):
            block, index, update = first(mlil, lambda inst: isinstance(inst, MLILSetVar)
                                         and isinstance(inst.value, MLILAdd))
            block.instructions[index] = MLILSetVar(update.var, MLILAdd(update.value.lhs, MLILConst(3))) \
                .copy_metadata_from(update)
        self.check(loop_function, mutate, 'loop_value_differs')

    def test_ordering_inverted(self):
        """!(i < LIMIT) written i >= LIMIT: equal but for NaN, its own category"""
        def mutate(mlil):
            block, index, branch = first(mlil, lambda inst: isinstance(inst, MLILIf))
            negated = next(node for node in walk(branch.condition) if isinstance(node, MLILLogicalNot))
            ordering = negated.operand
            self.assertIsInstance(ordering, MLILLt)
            block.instructions[index] = MLILIf(MLILGe(ordering.lhs, ordering.rhs), branch.true_target,
                                               branch.false_target).copy_metadata_from(branch)
        reference, mlil = reference_and_mlil(loop_function)
        mutate(mlil)
        self.assertEqual(categories(reference, mlil), {'condition_ordering_inverted'})


# === Mutations of the HLIL ===

def mlil_and_hlil(build, argc: int = 0) -> tuple:
    """The function's MLIL as the decompiler makes it and the HLIL made from it"""
    _, mlil = reference_and_mlil(build, argc)
    return mlil, convert_falcom_mlil_to_hlil(mlil)


def hlil_categories(mlil, hlil) -> set[str]:
    return {difference.category for difference in logic_check.compare_mlil_hlil(mlil, hlil)}


def first_node(hlil, kind: type, predicate: Callable = lambda node: True):
    found = [node for node in iter_tree(hlil.body) if isinstance(node, kind) and predicate(node)]
    if not found:
        raise AssertionError('the mutation found nothing to change: the HLIL shape changed')
    return found[0]


def makes_a_call(block) -> bool:
    return any(isinstance(node, HLILCall) for node in iter_tree(block))


def arm_with_a_call(if_stmt: HLILIf) -> tuple:
    """(the arm of if_stmt that makes a call, the other arm)"""
    arms = (if_stmt.true_block, if_stmt.false_block)
    return arms if makes_a_call(arms[0]) else arms[::-1]


class TestPlantedHLILBugs(unittest.TestCase):
    """Each bug class HLIL structuring or a pass could bring, planted in real HLIL: the comparator reports its
    category against the MLIL it came from"""

    def check(self, build, mutate, expected: str, argc: int = 0):
        mlil, hlil = mlil_and_hlil(build, argc)
        self.assertEqual(hlil_categories(mlil, hlil), set(), 'the unchanged HLIL compares clean')
        mutate(hlil)
        self.assertIn(expected, hlil_categories(mlil, hlil))

    def test_arms_swapped_without_negating(self):
        def mutate(hlil):
            if_stmt = first_node(hlil, HLILIf)
            if_stmt.true_block, if_stmt.false_block = if_stmt.false_block, if_stmt.true_block
        self.check(branch_function, mutate, 'guard_differs')

    def test_loop_copy_carrying_a_wrong_value(self):
        """The loop rebuilt in both arms, both entered with 0, the first copy's step made 2: the second copy carries the
        right value, and is not taken for both"""
        def mutate(hlil):
            TestHLILStructures.rebuild_in_both_arms(hlil)
            loop = next(node for node in iter_tree(first_node(hlil, HLILIf).true_block) if isinstance(node, HLILWhile))
            step = next(node for node in iter_tree(loop.body) if isinstance(node, HLILConst) and node.value == 1)
            step.value = 2
        self.check(calls_then_loop_function, mutate, 'loop_value_differs')

    def test_loop_copy_leaving_at_once(self):
        """The loop rebuilt in both arms, the second copy's test made `test && c`, c the arms' condition, false in that
        arm: that copy never goes round, which the first copy going round must not hide"""
        def mutate(hlil):
            TestHLILStructures.rebuild_in_both_arms(hlil)
            if_stmt = first_node(hlil, HLILIf)
            loop = next(node for node in iter_tree(if_stmt.false_block) if isinstance(node, HLILWhile))
            loop.condition = HLILBinaryOp(BinaryOp.AND, loop.condition, copy.deepcopy(if_stmt.condition))
        self.check(calls_then_loop_function, mutate, 'guard_differs')

    def test_arms_swapped_in_a_loop(self):
        """The call's arm swapped with the skip's: it runs in other iterations, a guard within one iteration differs"""
        def mutate(hlil):
            if_stmt = first_node(hlil, HLILIf)
            if_stmt.true_block, if_stmt.false_block = if_stmt.false_block or HLILBlock(), if_stmt.true_block
        self.check(skipping_loop_function, mutate, 'guard_differs')

    def test_call_hoisted_from_the_only_way_out(self):
        """The call moved from the arm every way out of the loop passes to the top of the body: it runs once every
        iteration, not only in those that skip nothing - a guard within one iteration differs, not over the graph"""
        def mutate(hlil):
            loop = first_node(hlil, HLILWhile)
            calling = arm_with_a_call(first_node(hlil, HLILIf))[0]
            statement = next(stmt for stmt in calling.statements if makes_a_call(stmt))
            calling.statements.remove(statement)
            loop.body.statements.insert(0, statement)
        self.check(skipping_loop_function, mutate, 'guard_differs')

    def test_arm_dropped(self):
        def mutate(hlil):
            arm_with_a_call(first_node(hlil, HLILIf))[0].statements.clear()
        self.check(branch_function, mutate, 'missing_effect')

    def test_region_cloned_under_a_wrong_guard(self):
        """The arm's call repeated in the other arm: an occurrence count is no finding, the joined guard is"""
        def mutate(hlil):
            calling, other = arm_with_a_call(first_node(hlil, HLILIf))
            other.statements.extend(calling.statements)
        self.check(branch_function, mutate, 'guard_differs')

    def test_call_moved_into_a_short_circuit_right_operand(self):
        """x = callee(1); if (GLOBAL_A && x) made if (GLOBAL_A && callee(1)): the call no longer runs on every path"""
        def mutate(hlil):
            assignment = first_node(hlil, HLILAssign, lambda node: isinstance(node.src, HLILCall))
            hlil.body.statements.remove(assignment)
            test = first_node(hlil, HLILIf).condition.rhs
            self.assertIsInstance(test.lhs, HLILVar)
            test.lhs = assignment.src
        self.check(and_condition_function, mutate, 'guard_differs')

    def test_loop_test_polarity_flipped(self):
        def mutate(hlil):
            loop = first_node(hlil, HLILWhile)
            loop.condition = HLILBinaryOp(BinaryOp.EQ, loop.condition, HLILConst(0))
        self.check(loop_call_function, mutate, 'guard_differs')

    def test_ordering_inverted(self):
        """while (i < LIMIT) written while (!(i >= LIMIT)): equal but for NaN, its own category"""
        def mutate(hlil):
            loop = first_node(hlil, HLILWhile)
            ordering = first_node(hlil, HLILBinaryOp, lambda node: node.op == BinaryOp.LT)
            loop.condition = HLILBinaryOp(BinaryOp.EQ, HLILBinaryOp(BinaryOp.GE, ordering.lhs, ordering.rhs),
                                          HLILConst(0))
        mlil, hlil = mlil_and_hlil(loop_call_function)
        mutate(hlil)
        self.assertEqual(hlil_categories(mlil, hlil), {'condition_ordering_inverted'})

    def test_case_body_moved(self):
        def mutate(hlil):
            cases = first_node(hlil, HLILSwitch).cases
            cases[0].body, cases[1].body = cases[1].body, cases[0].body
        self.check(case_chain_function, mutate, 'guard_differs')

    def test_effect_moved_past_the_row_cap(self):
        """The inner arms swapped under NESTED_TESTS conditions, more than a truth table holds: a decision diagram
        compares the guards exactly, and past its node cap they are guard_unchecked, a difference too"""
        def mutate(hlil):
            inner = first_node(hlil, HLILIf, lambda node: node.false_block is not None)
            inner.true_block, inner.false_block = inner.false_block, inner.true_block
        self.check(nested_tests_function, mutate, 'guard_differs')

        mlil, hlil = mlil_and_hlil(nested_tests_function)
        mutate(hlil)
        with mock.patch.object(formulas, 'DIAGRAM_NODE_CAP', DIAGRAM_NODES_TOO_FEW):
            self.assertIn('guard_unchecked', hlil_categories(mlil, hlil))

    def test_unstructured_jump(self):
        def mutate(hlil):
            arm_with_a_call(first_node(hlil, HLILIf))[0].statements.insert(0, HLILUnstructured('end', 'planted'))
        self.check(branch_function, mutate, 'unstructured_jump')

    @classmethod
    def replace_break(cls, hlil, replacement):
        """The first break's place in its block taken by replacement's statements"""
        for block in (node for node in iter_tree(hlil.body) if isinstance(node, HLILBlock)):
            for index, stmt in enumerate(block.statements):
                if isinstance(stmt, HLILBreak):
                    block.statements[index:index + 1] = replacement(stmt)
                    return
        raise AssertionError('the mutation found nothing to change: the HLIL shape changed')

    def test_break_made_continue(self):
        """The loop no longer ends on the test: it goes round again where it left"""
        self.check(break_loop_function, lambda hlil: self.replace_break(hlil, lambda stmt: [HLILContinue()]),
                   'guard_differs')

    def test_break_dropped(self):
        """The arm falls off the loop body's end, which goes round again"""
        self.check(break_loop_function, lambda hlil: self.replace_break(hlil, lambda stmt: []), 'guard_differs')

    def test_labeled_break_made_plain(self):
        """break loop_1 made break: the outer loop goes round again where both ended"""
        def plain(stmt):
            self.assertIsNotNone(stmt.label)
            return [HLILBreak()]
        self.check(nested_break_function, lambda hlil: self.replace_break(hlil, plain), 'guard_differs')

    def test_effect_free_loop_test_flipped(self):
        def mutate(hlil):
            loop = first_node(hlil, HLILWhile)
            loop.condition = HLILBinaryOp(BinaryOp.EQ, loop.condition, HLILConst(0))
        self.check(wait_loop_function, mutate, 'guard_differs')

    def test_bottom_test_flipped(self):
        """The test after the loop's only effect: every iteration still makes the call, it goes round otherwise"""
        def mutate(hlil):
            test = first_node(hlil, HLILIf)
            test.condition = HLILBinaryOp(BinaryOp.EQ, test.condition, HLILConst(0))
        self.check(bottom_test_function, mutate, 'guard_differs')

    def test_effect_free_loop_moved_under_a_condition(self):
        """The wait made conditional: it runs no more whenever GLOBAL_B is 0"""
        def mutate(hlil):
            body = hlil.body.statements
            index = body.index(first_node(hlil, HLILWhile))
            gate = HLILVar(HLILVariable(kind=VariableKind.GLOBAL, index=GLOBAL_B))
            body[index] = HLILIf(gate, HLILBlock([body[index]]))
        self.check(wait_loop_function, mutate, 'guard_differs')

    def test_unchecked_value_formulas(self):
        """A value whose formulas are past the diagram cap fails the gate, as a guard's do: the common return's arm test
        c written c && (c || GLOBAL_B), one function in another formula, which under the lowered caps neither a table
        nor a diagram holds"""
        mlil, hlil = mlil_and_hlil(two_returns_function)
        TestHLILStructures.extract_common_return(hlil)
        test = first_node(hlil, HLILIf)
        other = HLILVar(HLILVariable(kind=VariableKind.GLOBAL, index=GLOBAL_B))
        test.condition = HLILBinaryOp(BinaryOp.AND, test.condition,
                                      HLILBinaryOp(BinaryOp.OR, copy.deepcopy(test.condition), other))
        self.assertEqual(hlil_categories(mlil, hlil), set())
        with mock.patch.multiple(formulas, ROW_CAP=1, DIAGRAM_NODE_CAP=DIAGRAM_NODES_TOO_FEW):
            found = logic_check.compare_mlil_hlil(mlil, hlil)
        # The returned values' difference (its detail their components), not the return's guard's (its two formulas)
        values = [difference.category for difference in found
                  if difference.key == RETURN_KEY and isinstance(difference.detail, list)]
        self.assertEqual(values, ['guard_unchecked'])


class TestHLILStructures(unittest.TestCase):
    """Structures HLIL builds otherwise than MLIL writes them, compared clean: the same logic"""

    def test_arms_joined_before_the_back_edge(self):
        self.assertEqual(hlil_categories(*mlil_and_hlil(arms_joined_in_a_loop_function)), set())

    def test_inner_arms_joined_first(self):
        self.assertEqual(hlil_categories(*mlil_and_hlil(nested_arms_function)), set())

    def test_constant_loop_test(self):
        self.assertEqual(hlil_categories(*mlil_and_hlil(constant_loop_test_function)), set())

    def test_chain_made_a_switch(self):
        mlil, hlil = mlil_and_hlil(case_chain_function)
        first_node(hlil, HLILSwitch)
        self.assertEqual(hlil_categories(mlil, hlil), set())

    def test_condition_split_at_its_short_circuit(self):
        self.assertEqual(hlil_categories(*mlil_and_hlil(and_condition_function)), set())

    @classmethod
    def extract_common_return(cls, hlil):
        """if (c) {A; return x} B; return x made if (c) {A} else {B}; return x, as CommonReturnExtractionPass does: two
        returns one, its registers merged after the if"""
        body = hlil.body.statements
        index = next(index for index, stmt in enumerate(body) if isinstance(stmt, HLILIf))
        if_stmt, rest = body[index], body[index + 1:]
        if not (isinstance(if_stmt.true_block.statements[-1], HLILReturn) and isinstance(rest[-1], HLILReturn)):
            raise AssertionError('the rewrite found no two returns: the HLIL shape changed')
        if_stmt.true_block.statements.pop()
        if_stmt.false_block = HLILBlock(rest[:-1])
        hlil.body.statements = [*body[:index + 1], rest[-1]]

    @classmethod
    def rebuild_in_both_arms(cls, hlil):
        """if (c) {A} else {B}; rest made if (c) {A; rest} else {B; rest}, the loop in rest and its stamp in each arm,
        as the converter rebuilds a self-contained loop on each path into a region (_clone_region_blocks)"""
        body = hlil.body.statements
        index = next(index for index, stmt in enumerate(body) if isinstance(stmt, HLILIf))
        if_stmt, rest = body[index], body[index + 1:]
        if if_stmt.false_block is None or not any(isinstance(stmt, HLILWhile) for stmt in rest):
            raise AssertionError('the rewrite found no two arms and a loop after them: the HLIL shape changed')
        if_stmt.true_block.statements.extend(rest)
        if_stmt.false_block.statements.extend(copy.deepcopy(rest))
        hlil.body.statements = body[:index + 1]

    def test_loop_rebuilt_in_both_arms(self):
        """Each copy carries in its arm's value: lifted into their formulas, the one MLIL loop's entry choice"""
        mlil, hlil = mlil_and_hlil(branch_then_loop_function)
        self.rebuild_in_both_arms(hlil)
        self.assertEqual(hlil_categories(mlil, hlil), set())

    def test_common_return(self):
        mlil, hlil = mlil_and_hlil(two_returns_function)
        self.extract_common_return(hlil)
        self.assertEqual(hlil_categories(mlil, hlil), set())

    def test_choices_past_the_lifting_cap(self):
        """A merged choice left whole past LIFTED_CHOICES, a common return's value or a loop's entry choice its copies
        carry in one value each: unchecked, not a difference"""
        mlil, hlil = mlil_and_hlil(two_returns_function)
        self.extract_common_return(hlil)
        loop_mlil, loop_hlil = mlil_and_hlil(branch_then_loop_function)
        self.rebuild_in_both_arms(loop_hlil)
        with mock.patch.object(compare, 'LIFTED_CHOICES', 1):
            self.assertEqual(hlil_categories(mlil, hlil), {'guard_unchecked'})
            self.assertEqual(hlil_categories(loop_mlil, loop_hlil), {'guard_unchecked'})

    def test_common_return_after_a_loop(self):
        """One arm reaches the return through the loop's exit, the only way out of its test"""
        mlil, hlil = mlil_and_hlil(return_after_a_loop_function)
        self.extract_common_return(hlil)
        self.assertEqual(hlil_categories(mlil, hlil), set())

    def test_loop_exit_split_at_its_short_circuit(self):
        """The inner loop's only way out tested at once by MLIL, one operand at a time by HLIL"""
        self.assertEqual(hlil_categories(*mlil_and_hlil(split_exit_function)), set())


class TestSplitLoopValues(unittest.TestCase):
    """Two de-SSA splits of one stack slot carried round one loop: each must carry the reference's value, so a right
    one does not hide a wrong one"""

    HEADER, BACK_EDGE = (FUNCTION_ENTRY, 10), 10
    SLOT, SPLIT, OTHER_SPLIT = ('stack', 0), ('name', 'var_s0'), ('name', 'var_s0_v0')

    def facts(self, read_by_store: tuple, carried: dict, neutral_key=None) -> Facts:
        """A loop test reading the first key carried, a global store after the loop reading read_by_store"""
        first_key = next(iter(carried))
        loop_leaf = lambda key: ('loop', self.HEADER, key)
        condition = op('LT', [loop_leaf(first_key), const(LOOP_LIMIT)])
        facts = Facts(neutral_key=neutral_key)
        facts.effects[(20, 'store global')] = [Effect(20, 'store global', 0, (loop_leaf(read_by_store),))]
        facts.branches[5] = Branch(5, condition, 6, 20)
        for key, step in carried.items():
            facts.loop_values[(self.HEADER, key, FUNCTION_ENTRY)] = [(formulas.TRUE, const(0))]
            facts.loop_values[(self.HEADER, key, self.BACK_EDGE)] = [(formulas.TRUE,
                                                                      op('ADD', [loop_leaf(key), const(step)]))]
        return facts

    def compare(self, other_split_step: int) -> set[str]:
        reference = self.facts(self.SLOT, {self.SLOT: 1})
        checked = self.facts(self.OTHER_SPLIT, {self.SPLIT: 1, self.OTHER_SPLIT: other_split_step},
                             neutral_key=lambda key: self.SLOT if key in (self.SPLIT, self.OTHER_SPLIT) else key)
        return {difference.category for difference in logic_check.compare_facts(reference, checked)}

    def test_both_splits_right(self):
        self.assertEqual(self.compare(1), set())

    def test_wrong_split_beside_a_right_one(self):
        self.assertEqual(self.compare(3), {'loop_value_differs'})


class TestConditionNormalForm(unittest.TestCase):
    """Conditions compare in a normal form: the truth-test spellings equated, negation pushed through && and ||, ==
    and != commutative; an ordering is never inverted"""

    A, B = ('param', 1), ('param', 2)
    ZERO = const(0)

    def test_a_constant_condition_negated(self):
        """`!c` of a constant c is decided, as ir/hlil's constant_truth decides it: HLIL folds its branch"""
        self.assertIs(constant_truth(op('LOGICAL_NOT', [op('LT', [const(1), const(2)])])), False)

    def test_truth_test_spellings(self):
        condition = op('EQ', [self.A, self.B])
        negated = truth(condition)
        for spelling in (op('NE', [self.A, self.B]), op('EQ', [condition, self.ZERO]), op('TEST_ZERO', [condition]),
                         op('LOGICAL_NOT', [condition])):
            self.assertEqual(truth(spelling), (negated[0], not negated[1]), spelling)
        self.assertEqual(truth(op('NE', [condition, self.ZERO])), negated)

    def test_constant_condition(self):
        self.assertEqual(truth(op('EQ', [self.ZERO, self.ZERO])), truth(op('LOGICAL_NOT', [self.ZERO])))

    def test_negation_through_logic(self):
        both = op('LOGICAL_AND', [self.A, self.B])
        either_not = op('LOGICAL_OR', [op('TEST_ZERO', [self.A]), op('TEST_ZERO', [self.B])])
        self.assertEqual(truth(op('TEST_ZERO', [both])), truth(either_not))

    def test_truth_test_values_are_one_tree(self):
        self.assertEqual(op('LOGICAL_NOT', [self.A]), op('TEST_ZERO', [self.A]))
        self.assertEqual(op('TEST_ZERO', [self.A]), op('EQ', [self.A, self.ZERO]))

    def test_equality_is_commutative(self):
        namer = Namer(Facts())
        self.assertEqual(namer(op('EQ', [self.A, self.B])), namer(op('EQ', [self.B, self.A])))
        self.assertNotEqual(namer(op('LT', [self.A, self.B])), namer(op('LT', [self.B, self.A])))

    def test_orderings_are_not_inverted(self):
        less, at_least = op('LT', [self.A, self.B]), op('GE', [self.A, self.B])
        self.assertNotEqual(truth(op('TEST_ZERO', [less]))[0], at_least)
        self.assertEqual(truth(at_least, representative=True), (less, True))
        self.assertEqual(truth(op('TEST_ZERO', [at_least]), representative=True), (less, False))

    @classmethod
    def branch_categories(cls, reference: tuple, checked: tuple) -> set[str]:
        """The categories of one branch's (condition, true target, false target) on two layers"""
        sides = []
        for condition, true_target, false_target in (reference, checked):
            facts = Facts()
            facts.branches[cls.BRANCH] = Branch(cls.BRANCH, condition, true_target, false_target)
            sides.append(facts)
        return {difference.category for difference in logic_check.compare_facts(*sides)}

    BRANCH, THEN, ELSE = 5, 6, 7

    def test_negation_dropped_by_swapping_targets(self):
        """!(a < b) to THEN against a < b to ELSE: exact, no difference"""
        less = op('LT', [self.A, self.B])
        self.assertEqual(self.branch_categories((op('TEST_ZERO', [less]), self.THEN, self.ELSE),
                                                (less, self.ELSE, self.THEN)), set())

    def test_inversion_with_swapped_arms(self):
        """a < b to THEN against a >= b to ELSE: equal but for NaN, counted once"""
        self.assertEqual(self.branch_categories((op('LT', [self.A, self.B]), self.THEN, self.ELSE),
                                                (op('GE', [self.A, self.B]), self.ELSE, self.THEN)),
                         {'condition_ordering_inverted'})


class TestFormulaKeys(unittest.TestCase):
    """Formulas compare as functions of their conditions: the equality tests of one value exclude each other, but
    for float constants; a condition nothing depends on is left out; past the truth table's rows, by decision
    diagram"""

    X, Y = ('param', 1), ('param', 2)

    def setUp(self):
        self.keys = formulas.FormulaKeys(Fingerprints(lambda key: key))

    @classmethod
    def equals(cls, value: tuple, constant: int | float, polarity: bool = True) -> tuple:
        return formulas.literal(op('EQ', [value, const(constant)]), polarity)

    def test_a_case_of_a_chain_and_of_its_switch(self):
        chain = formulas.conjunction(self.equals(self.X, 1, False), self.equals(self.X, 2))
        self.assertEqual(self.keys(chain), self.keys(self.equals(self.X, 2)))

    def test_a_truth_test_among_its_equalities(self):
        both = formulas.conjunction(formulas.literal(self.X, True), self.equals(self.X, 3))
        self.assertEqual(self.keys(both), self.keys(self.equals(self.X, 3)))

    def test_float_constants_that_compare_equal(self):
        """0.0 and -0.0 are two constants equal under float ==, as are 1 and 1.0: tests of one value against them may
        both hold, and a test of two of them is not decided. Floats as scripts decode them, SourceFloat, as well"""
        zero, negative_zero, one = SourceFloat(0.0, '0.0'), SourceFloat(-0.0, '-0.0'), SourceFloat(1.0, '1.0')
        for first, second in ((0.0, -0.0), (1, 1.0), (zero, negative_zero), (1, one)):
            both = formulas.conjunction(self.equals(self.X, first), self.equals(self.X, second, False))
            self.assertNotEqual(self.keys(both), self.keys(self.equals(self.X, first)), (first, second))
        constants = formulas.literal(op('EQ', [const(zero), const(negative_zero)]), True)
        self.assertNotEqual(self.keys(constants), formulas.FALSE_KEY)
        self.assertEqual(const(SourceFloat(0.2999999523162842, '0.3')), const(0.2999999523162842))

    def test_a_condition_nothing_depends_on_left_out(self):
        less = formulas.literal(op('LT', [self.X, self.Y]), True)
        either = formulas.disjunction([formulas.conjunction(formulas.literal(self.Y, polarity), less)
                                       for polarity in (True, False)])
        self.assertEqual(self.keys(either), self.keys(less))

    def test_orderings_by_their_representatives(self):
        at_least = formulas.literal(op('GE', [self.X, self.Y]), True)
        not_less = formulas.literal(op('LT', [self.X, self.Y]), False)
        self.assertNotEqual(self.keys(at_least), self.keys(not_less))
        representative = formulas.FormulaKeys(Fingerprints(lambda key: key), representative=True)
        self.assertEqual(representative(at_least), representative(not_less))

    def test_past_the_row_cap(self):
        """any of NESTED_TESTS values, written flat and as an || chain one test at a time"""
        values = [('param', index) for index in range(NESTED_TESTS)]
        flat = formulas.disjunction(formulas.literal(value, True) for value in values)
        chained = formulas.literal(values[-1], True)
        for value in reversed(values[:-1]):
            chained = formulas.disjunction([formulas.literal(value, True),
                                            formulas.conjunction(formulas.literal(value, False), chained)])
        self.assertIsNone(self.keys.table_key(flat))
        self.assertEqual(self.keys(flat), self.keys(chained))
        self.assertTrue(formulas.Diagrams().same(self.keys.structure(flat, {}), self.keys.structure(chained, {})))

        flipped = formulas.disjunction(formulas.literal(value, index != 0) for index, value in enumerate(values))
        self.assertNotEqual(self.keys(flipped), self.keys(flat))
        self.assertFalse(formulas.Diagrams().same(self.keys.structure(flat, {}), self.keys.structure(flipped, {})))


class TestPostDominators(unittest.TestCase):
    """Cooper-Harvey-Kennedy on the reversed graph, and control dependence read off its tree"""

    @classmethod
    def graph(cls, edges: dict) -> tuple[list, Callable]:
        return list(edges), lambda block: edges[block]

    def test_diamond(self):
        blocks, successors = self.graph({'a': ['b', 'c'], 'b': ['d'], 'c': ['d'], 'd': []})
        ipdom = immediate_post_dominators(blocks, successors)
        self.assertEqual({block: ipdom[block] for block in blocks}, {'a': 'd', 'b': 'd', 'c': 'd', 'd': EXIT})

        branches = lambda block: (1, 'b', 'c') if block == 'a' else None
        dependence = control_dependence(blocks, successors, branches)
        self.assertEqual(dependence, {'a': frozenset(), 'b': {(1, 't')}, 'c': {(1, 'f')}, 'd': frozenset()})

    def test_loop_test_controls_the_body_and_itself(self):
        blocks, successors = self.graph({'entry': ['head'], 'head': ['body', 'exit'], 'body': ['head'], 'exit': []})
        branches = lambda block: (2, 'body', 'exit') if block == 'head' else None
        dependence = control_dependence(blocks, successors, branches)
        self.assertEqual(dependence['body'], {(2, 't')})
        self.assertEqual(dependence['head'], {(2, 't')})
        self.assertEqual(dependence['exit'], frozenset())

    def test_endless_loop_still_has_a_post_dominator(self):
        blocks, successors = self.graph({'a': ['b', 'c'], 'b': ['b'], 'c': []})
        ipdom = immediate_post_dominators(blocks, successors)
        self.assertEqual(ipdom['b'], EXIT)
        self.assertEqual(ipdom['a'], EXIT)

    def test_endless_region_exit_by_start_address(self):
        """A region entered at two blocks: the block with the lowest start gets the EXIT edge, whatever the order"""
        blocks, successors = self.graph({'e': ['c', 'b'], 'c': ['b'], 'b': ['c']})
        start = {'e': 0, 'b': 1, 'c': 2}.get
        self.assertEqual(exit_blocks(blocks, successors, start), {'b'})
        self.assertEqual(exit_blocks(blocks, successors), {'c'})

    def test_block_before_an_endless_loop_keeps_its_guard(self):
        """d runs only on a's true arm, and every path ends in the endless loop e"""
        blocks, successors = self.graph({'a': ['b', 'c'], 'b': ['d'], 'c': ['e'], 'd': ['e'], 'e': ['e']})
        self.assertEqual(immediate_post_dominators(blocks, successors)['d'], 'e')
        branches = lambda block: (1, 'b', 'c') if block == 'a' else None
        dependence = control_dependence(blocks, successors, branches)
        self.assertEqual(dependence['d'], {(1, 't')})
        self.assertEqual(dependence['e'], frozenset())


class TestRealScript(unittest.TestCase):
    """A real script with loops and branches: its LLIL and MLIL, and its MLIL and HLIL, compare clean in every
    function"""

    def test_btlsys(self):
        path = require(SORA2_SCRIPTS / 'battle' / 'btlsys.dat')
        results = logic_check.check_script(path, 'sora2')
        self.assertTrue(results)
        for result in results:
            with self.subTest(function=result.name):
                self.assertIsNone(result.internal_error)
                self.assertIsNone(result.decompile_error)
                self.assertEqual(result.mlil_differences, [])
                self.assertEqual(result.hlil_differences, [])


if __name__ == '__main__':
    unittest.main()
