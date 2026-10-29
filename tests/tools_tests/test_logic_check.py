#!/usr/bin/env python3
"""The logic check (tools/logic_check/): a bug planted in the MLIL or the HLIL of a small assembled function shows up
as its category, and the unchanged layer compares clean; structures HLIL builds otherwise than MLIL compare clean; the
condition normal form and formula keys; post-dominators and control dependence; a real script compares clean"""

from pathlib import Path
from typing import Callable
from unittest import mock
import contextlib
import copy
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / 'tools'))

from dc3.utils import raise_recursion_limit
from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from falcom.ed9.ir.mlil.mlil_converter import convert_falcom_llil_to_mlil
from falcom.ed9.ir.mlil.mlil_translator import DEBUG_LOG_CALL_TARGET
from ir.core.il_literals import SourceFloat
from ir.hlil.hlil import (
    BinaryOp, HighLevelILFunction, HLILAssign, HLILBinaryOp, HLILBlock, HLILBreak, HLILCall, HLILConst, HLILContinue,
    HLILDoWhile, HLILExprStmt, HLILIf, HLILReturn, HLILSwitch, HLILUnaryOp, HLILUnstructured, HLILVar, HLILVariable,
    HLILWhile, UnaryOp, VariableKind, iter_tree,
)
from ir.llil.llil import WORD_SIZE
from ir.mlil.mlil import (
    MediumLevelILCall, MediumLevelILFunction, MLILAdd, MLILCall, MLILConst, MLILEq, MLILGe, MLILGoto, MLILIf,
    MLILLoadGlobal, MLILLogicalNot, MLILLt, MLILNe, MLILRet, MLILSetVar, MLILStoreDeref, MLILStoreGlobal, MLILStoreReg,
    MLILVar, map_operands, walk,
)
from tests.shared.corpus import SORA2_SCRIPTS, require
from tests.shared.hlil_cfg_utils import EARLY_EXIT, SHARED_LOOP, build_function, structure, to_hlil
from tests.shared.ir_utils import connect
from tests.shared.llil_utils import lift_asm
from tests.shared.scp_asm import CALLEE_ID, CALLER_ID, Asm, returning_callee
import logic_check
from logic_check import compare, decision_diagrams, formulas, gated_comparison
from logic_check.evaluation import widen_loop_headers
from logic_check.facts import RETURN_KEY, Branch, Effect, Facts
from logic_check.naming import FUNCTION_ENTRY, GatedNaming
from logic_check.neutral_names import Fingerprints
from logic_check.post_dominators import EXIT, ControlFlow, control_dependence, exit_blocks, immediate_post_dominators
from logic_check.state import ESCAPED, GLOBAL_EPOCH, MEMORY_EPOCH, PHI_DEPTH, State, merged_value
from logic_check.trees import ENTRY, const, constant_truth, equal_trees, op, truth
from logic_check.vm_effects import VMEffects

GLOBAL_A, GLOBAL_B, GLOBAL_C, GLOBAL_D = 1, 2, 3, 4
STARTED = 5
MESSAGE = 'this'
LOOP_LIMIT = 3
STORED = 3
OUT_INITIAL = 1
UNRELATED_ARG = 9
REG_INDEX = 5
REG_OUT = 7
REPEATED_REG, EQUAL_REG, LARGER_REG = 1, 2, 3   # repeated_register_arms_function's registers
DEEP_INITIAL = 1
ENDLESS_TAIL_PARAMETERS = 2
EARLY_ARG = 9
TAIL_CALL_ARG = 6
SKIPPED = 1
CHAIN_CASES = 3                 # HLIL's if-to-switch takes a chain of at least SWITCH_MIN_CASES tests
NESTED_TESTS = 17               # conditions one guard runs under: past formulas.ROW_CAP's 2 ** 16 rows
DIAGRAM_NODES_TOO_FEW = 2       # a decision_diagrams.DIAGRAM_NODE_CAP no decision diagram fits in (its two terminals)
CHAIN_GLOBAL = 10               # the first global a chain of register writes tests (register_chain)
CHAIN_LENGTH = 3                # a chain's writes in the HLIL structure tests: merges nested in merges
DEEP_MERGES = 1_500             # TestDeepValues' chains: a call through __call__ fails from 1,200, Python frames 2,000
LIFTED_FLAG_DIAGRAM_NODES = 11  # a DIAGRAM_NODE_CAP the planted flag test's guards fit in (9, 10), not lifted (13, 16)
ORDERING_ROWS = 4               # a ROW_CAP an ordering's formulas fit in, not those with two more tests (2 to 6 do)
TWO_TESTS_ROWS = 2              # a ROW_CAP one test's formulas fit in, not two tests' (2 and 3 do)
PAIRS = 9                       # pairs of tests in TestFormulaKeys.pairs_formulas: 18 variables, past ROW_CAP's rows
PAIRS_KEY_NODES = 500           # a DIAGRAM_KEY_NODE_CAP: pair by pair 103-137 nodes fit, firsts first 1,537+ do not
ARM_VALUE, OTHER_ARM_VALUE = 100, 200
LIFTING_CAP = 8                 # compare.LIFTED_CHOICES in the tests past it, so their chains stay short
LONG_CHAIN = LIFTING_CAP + 1    # writes whose merges are more alternatives than are lifted


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


def pointer_store_function() -> tuple[Asm, int]:
    """f(p): *p = STORED: a store through the caller's pointer"""
    asm = Asm()
    asm.push_int(STORED); asm.pop_to_deref(-WORD_SIZE)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


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


def dead_arm_function() -> tuple[Asm, int]:
    """x = callee(1); if x && 0: callee(3) else callee(2): the game's eager &&, one MLIL branch whose arm never runs"""
    asm = Asm()
    call(asm, 'first', 1); asm.get_reg(0); asm.push_int(0); asm.logical_and(); asm.jz('else')
    call(asm, 'dead', 3); asm.jmp('done')
    asm.label('else'); call(asm, 'live', 2)
    asm.label('done'); return_nothing(asm)
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


def ordered_arms_function() -> tuple[Asm, int]:
    """if GLOBAL_A < LOOP_LIMIT: x = 1 elif GLOBAL_B: x = 2 else x = 3; callee(x): a choice passed, its first arm under
    an ordering"""
    asm = Asm()
    asm.push_int(0)
    asm.load_global(GLOBAL_A); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('else')
    asm.push_int(1); asm.pop_to(-WORD_SIZE); asm.jmp('end')
    asm.label('else'); asm.load_global(GLOBAL_B); asm.jz('last')
    asm.push_int(2); asm.pop_to(-WORD_SIZE); asm.jmp('end')
    asm.label('last'); asm.push_int(3); asm.pop_to(-WORD_SIZE)
    asm.label('end'); asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.load_stack(-3 * WORD_SIZE)
    asm.call(CALLEE_ID)
    asm.label('back'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def two_choices_function() -> tuple[Asm, int]:
    """x = 1 if GLOBAL_A < LOOP_LIMIT else 2; y = 1 if GLOBAL_B < LOOP_LIMIT else 2; callee(x, y): two choices
    passed, each under an ordering"""
    asm = Asm()
    asm.push_int(0); asm.push_int(0)
    asm.load_global(GLOBAL_A); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('x_other')
    asm.push_int(1); asm.pop_to(-2 * WORD_SIZE); asm.jmp('y_test')
    asm.label('x_other'); asm.push_int(2); asm.pop_to(-2 * WORD_SIZE)
    asm.label('y_test'); asm.load_global(GLOBAL_B); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('y_other')
    asm.push_int(1); asm.pop_to(-WORD_SIZE); asm.jmp('pass')
    asm.label('y_other'); asm.push_int(2); asm.pop_to(-WORD_SIZE)
    asm.label('pass'); asm.push_raw(CALLER_ID); asm.push_raw('back')
    asm.load_stack(-3 * WORD_SIZE); asm.load_stack(-5 * WORD_SIZE)    # y, then x: the last pushed is the first
    asm.call(CALLEE_ID)
    asm.label('back'); asm.pop(2 * WORD_SIZE); return_nothing(asm)
    return asm, 2


def choice_then_loop_function() -> tuple[Asm, int]:
    """x = 1 if GLOBAL_A < LOOP_LIMIT else 2; while GLOBAL_B: x = x + 1; callee(x): a choice the loop carries in"""
    asm = Asm()
    asm.load_global(GLOBAL_A); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('two')
    asm.push_int(1); asm.jmp('head')
    asm.label('two'); asm.push_int(2)
    asm.label('head'); asm.load_global(GLOBAL_B); asm.jz('done')
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE); asm.jmp('head')
    asm.label('done'); asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.load_stack(-3 * WORD_SIZE)
    asm.call(CALLEE_ID)
    asm.label('back'); asm.pop(WORD_SIZE); return_nothing(asm)
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


def store_then_wait_loop_function() -> tuple[Asm, int]:
    """GLOBAL_B = STORED; while GLOBAL_A: ; callee(2): a store, then a loop with no effect of its own"""
    asm = Asm()
    asm.push_int(STORED); asm.set_global(GLOBAL_B)
    asm.label('head'); asm.load_global(GLOBAL_A); asm.jz('done'); asm.jmp('head')
    asm.label('done'); call(asm, 'after', 2); return_nothing(asm)
    return asm, 1


def split_exit_value_function() -> tuple[Asm, int]:
    """x = 0; if GLOBAL_A: (x = STARTED; while GLOBAL_B && x < LOOP_LIMIT: callee(1)); callee(x): the && exit HLIL
    splits in two tests, x merged after the loop from both exits and from the skip"""
    asm = Asm()
    asm.push_int(0)
    asm.load_global(GLOBAL_A); asm.jz('join')
    asm.push_int(STARTED); asm.pop_to(-WORD_SIZE)
    asm.label('head'); asm.load_global(GLOBAL_B); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt()
    asm.logical_and(); asm.jz('join')
    call(asm, 'body', 1); asm.jmp('head')
    asm.label('join'); asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.load_stack(-3 * WORD_SIZE)
    asm.call(CALLEE_ID)
    asm.label('back'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def two_exits_two_targets_function() -> tuple[Asm, int]:
    """while 1: (callee(1); if GLOBAL_A: break; callee(2); if GLOBAL_B: return); callee(3): the code after the loop
    and the return are reached by different exits"""
    asm = Asm()
    asm.label('head'); call(asm, 'one', 1)
    asm.load_global(GLOBAL_A); asm.jnz('out')
    call(asm, 'two', 2)
    asm.load_global(GLOBAL_B); asm.jnz('ret')
    asm.jmp('head')
    asm.label('out'); call(asm, 'three', 3)
    asm.label('ret'); return_nothing(asm)
    return asm, 1


def split_inner_in_outer_function() -> tuple[Asm, int]:
    """while GLOBAL_A: (while GLOBAL_B && GLOBAL_C: callee(1)): the outer loop goes round when the inner one ends"""
    asm = Asm()
    asm.label('outer'); asm.load_global(GLOBAL_A); asm.jz('done')
    asm.label('inner'); asm.load_global(GLOBAL_B); asm.load_global(GLOBAL_C); asm.logical_and(); asm.jz('outer')
    call(asm, 'body', 1); asm.jmp('inner')
    asm.label('done'); return_nothing(asm)
    return asm, 1


def guarded_store_before_wait_function() -> tuple[Asm, int]:
    """while GLOBAL_A: (callee(1); if GLOBAL_D: GLOBAL_C = 1; while GLOBAL_B: ;): a store before an effect-free inner
    loop, in an outer loop"""
    asm = Asm()
    asm.label('outer'); asm.load_global(GLOBAL_A); asm.jz('done')
    call(asm, 'body', 1)
    asm.load_global(GLOBAL_D); asm.jz('inner')
    asm.push_int(1); asm.set_global(GLOBAL_C)
    asm.label('inner'); asm.load_global(GLOBAL_B); asm.jz('outer'); asm.jmp('inner')
    asm.label('done'); return_nothing(asm)
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


def tail_call_function() -> tuple[Asm, int]:
    """callee(1); then a tail call (CALL_SCRIPT_NO_RETURN) of another script's function, which MLIL writes as the
    script call and the return of its result"""
    asm = Asm()
    call(asm, 'first', 1)
    asm.push_int(TAIL_CALL_ARG); asm.call_script_no_return(1)
    return asm, 1


def register_chain(asm: Asm, depth: int):
    """depth times: if GLOBAL[CHAIN_GLOBAL + i]: REG = i + 1"""
    for index in range(depth):
        asm.load_global(CHAIN_GLOBAL + index); asm.jz(f'skip{index}')
        asm.push_int(index + 1); asm.set_reg(REG_INDEX)
        asm.label(f'skip{index}')


def chain_then_early_return_function(depth: int = CHAIN_LENGTH) -> tuple[Asm, int]:
    """if GLOBAL_A: (register_chain; return) else return: a common return merges the chain's value once more"""
    asm = Asm()
    asm.load_global(GLOBAL_A); asm.jz('early')
    register_chain(asm, depth); return_nothing(asm)
    asm.label('early'); return_nothing(asm)
    return asm, 0


def arms_then_chain_function() -> tuple[Asm, int]:
    """REG = ARM_VALUE if GLOBAL_A else OTHER_ARM_VALUE; register_chain; return: the arms' merge is one more under the
    chain's, which HLIL repeating the chain and the return in each arm does without"""
    asm = Asm()
    asm.load_global(GLOBAL_A); asm.jz('other')
    asm.push_int(ARM_VALUE); asm.set_reg(REG_INDEX); asm.jmp('join')
    asm.label('other'); asm.push_int(OTHER_ARM_VALUE); asm.set_reg(REG_INDEX)
    asm.label('join'); register_chain(asm, CHAIN_LENGTH); return_nothing(asm)
    return asm, 0


def chain_arm_then_loop_function(depth: int = CHAIN_LENGTH + 1) -> tuple[Asm, int]:
    """x = 0; if GLOBAL_A: (depth times: if GLOBAL[CHAIN_GLOBAL + i]: x = i + 1) else x = OTHER_ARM_VALUE;
    while x < LOOP_LIMIT: x = x + 1; callee(x): the loop entered with the arms' merge, one more than the chain's"""
    asm = Asm()
    asm.push_int(0)
    asm.load_global(GLOBAL_A); asm.jz('other')
    for index in range(depth):
        asm.load_global(CHAIN_GLOBAL + index); asm.jz(f'skip{index}')
        asm.push_int(index + 1); asm.pop_to(-WORD_SIZE)
        asm.label(f'skip{index}')
    asm.jmp('head')
    asm.label('other'); asm.push_int(OTHER_ARM_VALUE); asm.pop_to(-WORD_SIZE)
    asm.label('head'); asm.load_stack(-WORD_SIZE); asm.push_int(LOOP_LIMIT); asm.lt(); asm.jz('done')
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('head')
    asm.label('done'); asm.push_raw(CALLER_ID); asm.push_raw('back'); asm.load_stack(-3 * WORD_SIZE)
    asm.call(CALLEE_ID)
    asm.label('back'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def calls_then_chain_function() -> tuple[Asm, int]:
    """if GLOBAL_A: callee(1) else callee(2); register_chain; return: each chain test reads a global after the arms'
    calls, a choice of the two calls' epochs, which HLIL repeating the chain in each arm reads after its arm's call"""
    asm = Asm()
    asm.load_global(GLOBAL_A); asm.jz('other')
    call(asm, 'first', 1); asm.jmp('join')
    asm.label('other'); call(asm, 'second', 2)
    asm.label('join'); register_chain(asm, CHAIN_LENGTH); return_nothing(asm)
    return asm, 1


def arms_then_slot_chain_function(depth: int = CHAIN_LENGTH) -> tuple[Asm, int]:
    """v = ARM_VALUE if GLOBAL_A else OTHER_ARM_VALUE; depth times: if GLOBAL[CHAIN_GLOBAL + i]: v = i + 1;
    REG = v + 1; return: the merge inside an operation"""
    asm = Asm()
    asm.push_int(0)
    asm.load_global(GLOBAL_A); asm.jz('other')
    asm.push_int(ARM_VALUE); asm.pop_to(-WORD_SIZE); asm.jmp('join')
    asm.label('other'); asm.push_int(OTHER_ARM_VALUE); asm.pop_to(-WORD_SIZE)
    asm.label('join')
    for index in range(depth):
        asm.load_global(CHAIN_GLOBAL + index); asm.jz(f'skip{index}')
        asm.push_int(index + 1); asm.pop_to(-WORD_SIZE)
        asm.label(f'skip{index}')
    asm.load_stack(-WORD_SIZE); asm.push_int(1); asm.add(); asm.set_reg(REG_INDEX)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


def flag_then_test_function() -> tuple[Asm, int]:
    """x = 0; if GLOBAL_A && GLOBAL_B: x = 1; if x == 0: callee(1): the call's guard tests a choice"""
    asm = Asm()
    asm.push_int(0)
    asm.load_global(GLOBAL_A); asm.load_global(GLOBAL_B); asm.logical_and(); asm.jz('test')
    asm.push_int(1); asm.pop_to(-WORD_SIZE)
    asm.label('test'); asm.load_stack(-WORD_SIZE); asm.jnz('skip')
    call(asm, 'called', 1)
    asm.label('skip'); asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 1


def flag_from_flag_function() -> tuple[Asm, int]:
    """x = 0; if GLOBAL_A && GLOBAL_B: x = 1; y = 0; if x == 0: y = 1; if y == 0: callee(1): the choice x only in the
    formulas of the choice y"""
    asm = Asm()
    asm.push_int(0)                 # x
    asm.load_global(GLOBAL_A); asm.load_global(GLOBAL_B); asm.logical_and(); asm.jz('y')
    asm.push_int(1); asm.pop_to(-WORD_SIZE)
    asm.label('y'); asm.push_int(0)     # y
    asm.load_stack(-2 * WORD_SIZE); asm.jnz('test')
    asm.push_int(1); asm.pop_to(-WORD_SIZE)
    asm.label('test'); asm.load_stack(-WORD_SIZE); asm.jnz('skip')
    call(asm, 'called', 1)
    asm.label('skip'); asm.pop(2 * WORD_SIZE); return_nothing(asm)
    return asm, 1


def flag_copied_function() -> tuple[Asm, int]:
    """x = 0; if GLOBAL_A: x = 1; y = 0; if x: y = 1; if y: callee(1)"""
    asm = Asm()
    asm.push_int(0); asm.push_int(0)    # x, y
    asm.load_global(GLOBAL_A); asm.jz('x_set')
    asm.push_int(1); asm.pop_to(-2 * WORD_SIZE)
    asm.label('x_set'); asm.load_stack(-2 * WORD_SIZE); asm.jz('y_set')
    asm.push_int(1); asm.pop_to(-WORD_SIZE)
    asm.label('y_set'); asm.load_stack(-WORD_SIZE); asm.jz('end')
    call(asm, 'called', 1)
    asm.label('end'); asm.pop(2 * WORD_SIZE); return_nothing(asm)
    return asm, 1


def store_then_inner_wait_function() -> tuple[Asm, int]:
    """while 1: (GLOBAL_C = 1; if !GLOBAL_A: return; while GLOBAL_B: ;): a store in the outer loop's header, which
    runs before the inner loop in its iteration"""
    asm = Asm()
    asm.label('outer'); asm.push_int(1); asm.set_global(GLOBAL_C)
    asm.load_global(GLOBAL_A); asm.jz('done')
    asm.label('inner'); asm.load_global(GLOBAL_B); asm.jz('outer'); asm.jmp('inner')
    asm.label('done'); return_nothing(asm)
    return asm, 0


def repeated_register_arms_function() -> tuple[Asm, int]:
    """r1 = r2 = 1, r3 = 2; REG = r3 + r2 if GLOBAL_A else r1 + r1; GLOBAL[0] = REG: one arm's sum reads one value
    twice, the other's an equal value and an unequal one"""
    asm = Asm()
    for register, value in ((REPEATED_REG, 1), (EQUAL_REG, 1), (LARGER_REG, 2)):
        asm.push_int(value); asm.set_reg(register)
    asm.load_global(GLOBAL_A); asm.jz('other')
    asm.get_reg(LARGER_REG); asm.get_reg(EQUAL_REG); asm.add(); asm.set_reg(REG_INDEX); asm.jmp('join')
    asm.label('other'); asm.get_reg(REPEATED_REG); asm.get_reg(REPEATED_REG); asm.add(); asm.set_reg(REG_INDEX)
    asm.label('join'); asm.get_reg(REG_INDEX); asm.set_global(0)
    return_nothing(asm)
    return asm, 0


def uneven_inner_choices_function() -> tuple[Asm, int]:
    """v = 0; if GLOBAL_A: (if GLOBAL_B: v = 1 elif GLOBAL_C: v = 2 else return) else (if GLOBAL_B: v = 1 elif GLOBAL_C:
    v = 2 else v = 3); each arm then v = v + 0; GLOBAL[0] = v: the arms' choices of two and three values, the first two
    alike"""
    asm = Asm()
    asm.push_int(0)
    asm.load_global(GLOBAL_A); asm.jz('long')
    asm.load_global(GLOBAL_B); asm.jz('short_c')
    asm.push_int(1); asm.pop_to(-WORD_SIZE); asm.jmp('short_join')
    asm.label('short_c'); asm.load_global(GLOBAL_C); asm.jz('early')
    asm.push_int(2); asm.pop_to(-WORD_SIZE); asm.jmp('short_join')
    asm.label('early'); asm.pop(WORD_SIZE); return_nothing(asm)
    asm.label('short_join'); asm.load_stack(-WORD_SIZE); asm.push_int(0); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.jmp('outer')
    asm.label('long'); asm.load_global(GLOBAL_B); asm.jz('long_c')
    asm.push_int(1); asm.pop_to(-WORD_SIZE); asm.jmp('long_join')
    asm.label('long_c'); asm.load_global(GLOBAL_C); asm.jz('long_last')
    asm.push_int(2); asm.pop_to(-WORD_SIZE); asm.jmp('long_join')
    asm.label('long_last'); asm.push_int(3); asm.pop_to(-WORD_SIZE)
    asm.label('long_join'); asm.load_stack(-WORD_SIZE); asm.push_int(0); asm.add(); asm.pop_to(-WORD_SIZE)
    asm.label('outer'); asm.load_stack(-WORD_SIZE); asm.set_global(0)
    asm.pop(WORD_SIZE); return_nothing(asm)
    return asm, 0


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


# === Hand-built MLIL and HLIL ===

def calls_then_test() -> MediumLevelILFunction:
    """if (first()) body(); else if (second()) body(): both results tested as they come back"""
    func = MediumLevelILFunction('f', 0)
    reg0 = func.get_or_create_local('reg0')
    test1, test2, body, other = (func.create_block(label=label) for label in ('T1', 'T2', 'BODY', 'OTHER'))
    test1.instructions = [MLILCall('first', [], output=reg0), MLILIf(MLILVar(reg0), body, test2)]
    test2.instructions = [MLILCall('second', [], output=reg0), MLILIf(MLILVar(reg0), body, other)]
    body.instructions = [MLILCall('body', []), MLILRet(MLILConst(1))]
    other.instructions = [MLILRet(MLILConst(0))]
    return connect(func)


def returns_parameter() -> MediumLevelILFunction:
    """observable(); return p, beside a second parameter q"""
    func = MediumLevelILFunction('f', 0)
    p = func.get_or_create_parameter(1, 'p')
    func.get_or_create_parameter(2, 'q')
    block = func.create_block(label='B')
    block.instructions = [MLILCall('observable', []), MLILRet(MLILVar(p))]
    return connect(func)


def returns_call_result() -> MediumLevelILFunction:
    """reg0 = value(); return reg0: the call folds into the return"""
    func = MediumLevelILFunction('f', 0)
    reg0 = func.get_or_create_local('reg0')
    block = func.create_block(label='B')
    block.instructions = [MLILCall('value', [], output=reg0), MLILRet(MLILVar(reg0))]
    return connect(func)


def temporary_condition() -> MediumLevelILFunction:
    """tmp = p == 0; if (tmp != 0) ...: ControlFlowOptimizationPass folds tmp into the if"""
    func = MediumLevelILFunction('f', 0)
    p = func.get_or_create_parameter(1, 'p')
    tmp = func.get_or_create_local('tmp')
    test, yes, no = (func.create_block(label=label) for label in ('T', 'Y', 'N'))
    test.instructions = [MLILSetVar(tmp, MLILEq(MLILVar(p), MLILConst(0))),
                         MLILIf(MLILNe(MLILVar(tmp), MLILConst(0)), yes, no)]
    yes.instructions = [MLILCall('yes', []), MLILRet(MLILConst(1))]
    no.instructions = [MLILCall('no', []), MLILRet(MLILConst(0))]
    return connect(func)


def equality_chain() -> MediumLevelILFunction:
    """if (x == 1) one(); else if (x == 2) two(); else if (x == 3) three(); else other(); done()"""
    func = MediumLevelILFunction('f', 0)
    x = func.get_or_create_parameter(1, 'x')
    labels = ('T1', 'T2', 'T3', 'ONE', 'TWO', 'THREE', 'OTHER', 'DONE')
    t1, t2, t3, one, two, three, other, done = (func.create_block(label=label) for label in labels)
    for test, value, case, following in ((t1, 1, one, t2), (t2, 2, two, t3), (t3, 3, three, other)):
        test.instructions = [MLILIf(MLILEq(MLILVar(x), MLILConst(value)), case, following)]
    for case, name in ((one, 'one'), (two, 'two'), (three, 'three'), (other, 'other')):
        case.instructions = [MLILCall(name, []), MLILGoto(done)]
    done.instructions = [MLILCall('done', []), MLILRet(MLILConst(0))]
    return connect(func)


def either_call_hlil(func: MediumLevelILFunction, op: BinaryOp) -> HighLevelILFunction:
    """if (first() != 0 <op> second() != 0) { body(); return 1; } return 0: calls_then_test's HLIL written by hand, each
    call with the provenance and the address of the MLIL call it stands for (the logic check keys effects by address)"""
    calls = {inst.target: inst for inst in func.iter_instructions() if isinstance(inst, MLILCall)}

    def anchored(node, name: str):
        node.mlil_index, node.address = calls[name].inst_index, calls[name].address
        return node

    body = anchored(HLILExprStmt(anchored(HLILCall('body', []), 'body')), 'body')
    condition = HLILBinaryOp(op, *(HLILBinaryOp(BinaryOp.NE, anchored(HLILCall(name, []), name), HLILConst(0))
                                   for name in ('first', 'second')))
    hlil = HighLevelILFunction('f')
    hlil.body = HLILBlock([HLILIf(condition, HLILBlock([body, HLILReturn(HLILConst(1))])), HLILReturn(HLILConst(0))])
    return hlil


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
    """Each bug class a translator or a pass could bring, planted in real MLIL: the logic check reports its category"""

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

    def test_tail_call(self):
        """The tail call compares clean with MLIL's script call and return; the call's result not returned differs"""
        def mutate(mlil):
            block, index, ret = first(mlil, lambda inst: isinstance(inst, MLILRet))
            block.instructions[index] = MLILRet(MLILConst(0)).copy_metadata_from(ret)
        self.check(tail_call_function, mutate, 'return_differs')

    def test_ordering_inverted(self):
        """!(i < LIMIT) written i >= LIMIT: equal but for NaN, its own category; a call inside the loop runs under the
        inverted branch, its arm read against the condition's representative core, so it is no guard difference"""
        def mutate(mlil):
            block, index, branch = first(mlil, lambda inst: isinstance(inst, MLILIf))
            negated = next(node for node in walk(branch.condition) if isinstance(node, MLILLogicalNot))
            ordering = negated.operand
            self.assertIsInstance(ordering, MLILLt)
            block.instructions[index] = MLILIf(MLILGe(ordering.lhs, ordering.rhs), branch.true_target,
                                               branch.false_target).copy_metadata_from(branch)
        for build in (loop_function, loop_call_function):
            with self.subTest(function=build.__name__):
                reference, mlil = reference_and_mlil(build)
                mutate(mlil)
                self.assertEqual(categories(reference, mlil), {'condition_ordering_inverted'})


# === Mutations of the HLIL ===

def mlil_and_hlil(build, argc: int = 0) -> tuple:
    """The function's MLIL as the decompiler makes it and the HLIL made from it"""
    _, mlil = reference_and_mlil(build, argc)
    return mlil, convert_falcom_mlil_to_hlil(mlil)


def hlil_categories(mlil, hlil) -> set[str]:
    return {difference.category for difference in logic_check.compare_mlil_hlil(mlil, hlil)}


def with_hlil(func) -> tuple:
    """(a hand-built MLIL, the HLIL the pipeline makes from it)"""
    return func, to_hlil(func)


@contextlib.contextmanager
def formula_keys_past_their_caps():
    """No formula has a key, so a gated choice is told apart by its own digest, as one past the caps is (K4)"""
    with (mock.patch.object(formulas, 'ROW_CAP', 1),
          mock.patch.object(decision_diagrams, 'DIAGRAM_KEY_NODE_CAP', DIAGRAM_NODES_TOO_FEW)):
        yield


def flag_set_to(hlil, value: int, new: int):
    """The first write of the constant value made new"""
    write = first_node(hlil, HLILAssign, lambda node: isinstance(node.src, HLILConst) and node.src.value == value)
    write.src.value = new


def first_node(hlil, kind: type, predicate: Callable = lambda node: True):
    found = [node for node in iter_tree(hlil.body) if isinstance(node, kind) and predicate(node)]
    if not found:
        raise AssertionError('the mutation found nothing to change: the HLIL shape changed')
    return found[0]


def reads_global(node, index: int) -> bool:
    return any(isinstance(item, HLILVar) and item.var.kind == VariableKind.GLOBAL and item.var.index == index
               for item in iter_tree(node))


def replace_expression(hlil, old, new):
    """new in place of old, wherever the HLIL holds it"""
    for node in iter_tree(hlil.body):
        for field in ('lhs', 'rhs', 'operand', 'condition'):
            if getattr(node, field, None) is old:
                setattr(node, field, new)


def makes_a_call(block) -> bool:
    return any(isinstance(node, HLILCall) for node in iter_tree(block))


def arm_with_a_call(if_stmt: HLILIf) -> tuple:
    """(the arm of if_stmt that makes a call, the other arm)"""
    arms = (if_stmt.true_block, if_stmt.false_block)
    return arms if makes_a_call(arms[0]) else arms[::-1]


class TestPlantedHLILBugs(unittest.TestCase):
    """Each bug class HLIL structuring or a pass could bring, planted in real HLIL: the logic check reports its
    category against the MLIL it came from"""

    def check(self, build, mutate, expected: str, argc: int = 0):
        self.check_built(*mlil_and_hlil(build, argc), mutate, expected)

    def check_built(self, mlil, hlil, mutate, expected: str):
        """check for an MLIL and its HLIL built already"""
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

    def test_global_assigned_a_call_kept_as_the_bare_call(self):
        """GLOBALS[1] = callee(8, 7) made callee(8, 7): the call kept, the global's write gone"""
        def mutate(hlil):
            assignment = first_node(hlil, HLILAssign, lambda node: isinstance(node.src, HLILCall))
            statements = hlil.body.statements
            statements[statements.index(assignment)] = HLILExprStmt(assignment.src)
        self.check(calls_function, mutate, 'missing_effect')

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
        """while (i < LIMIT) written while (!(i >= LIMIT)): equal but for NaN, its own category; with the call's
        argument changed too, the call's guard (a slot of its own) still reads inverted, beside the argument's
        difference"""
        def mutate(hlil):
            loop = first_node(hlil, HLILWhile)
            ordering = first_node(hlil, HLILBinaryOp, lambda node: node.op == BinaryOp.LT)
            loop.condition = HLILBinaryOp(BinaryOp.EQ, HLILBinaryOp(BinaryOp.GE, ordering.lhs, ordering.rhs),
                                          HLILConst(0))
        mlil, hlil = mlil_and_hlil(loop_call_function)
        mutate(hlil)
        self.assertEqual(hlil_categories(mlil, hlil), {'condition_ordering_inverted'})
        self.change_argument(hlil, 0)
        # At the call's key: the loop's own pseudo-effects read inverted too
        self.assertEqual({difference.category for difference in logic_check.compare_mlil_hlil(mlil, hlil)
                          if difference.key[1] == 'call'}, {'condition_ordering_inverted', 'arg_differs'})

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
        with mock.patch.object(decision_diagrams, 'DIAGRAM_NODE_CAP', DIAGRAM_NODES_TOO_FEW):
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
        """The do-while's test, after the loop's only effect: every iteration still makes the call, it goes round
        otherwise"""
        def mutate(hlil):
            loop = first_node(hlil, HLILDoWhile)
            loop.condition = HLILBinaryOp(BinaryOp.EQ, loop.condition, HLILConst(0))
        self.check(bottom_test_function, mutate, 'guard_differs')

    def test_do_while_made_while(self):
        """The test moved before the body, the loop's stamp kept: the first call runs only when the test holds"""
        def mutate(hlil):
            loop = first_node(hlil, HLILDoWhile)
            tested_first = HLILWhile(loop.condition, loop.body)
            tested_first.address, tested_first.mlil_index = loop.address, loop.mlil_index
            statements = hlil.body.statements
            statements[statements.index(loop)] = tested_first
        self.check(bottom_test_function, mutate, 'order_differs')

    def test_store_moved_past_an_effect_free_loop(self):
        """Nothing the loop reads changes, so the loop's place in the order is the only witness"""
        def mutate(hlil):
            statements = hlil.body.statements
            index = statements.index(first_node(hlil, HLILWhile))
            statements[index - 1], statements[index] = statements[index], statements[index - 1]
        self.check(store_then_wait_loop_function, mutate, 'order_differs')

    def test_arm_of_a_live_eager_and_dropped(self):
        """The fold of a decided condition leaves the arm of `GLOBAL_A && x` to the comparison"""
        def mutate(hlil):
            first_node(hlil, HLILIf).true_block.statements.clear()
        self.check(and_condition_function, mutate, 'missing_effect')

    def test_store_before_an_inner_wait_made_depend_on_it(self):
        """The loop after the store ends in no iteration this check models, but only the wait's end orders them: the
        premise that a loop ends is for what comes after the loop's exits, not for what runs before it in an
        enclosing iteration"""
        def mutate(hlil):
            is_store_test = lambda node: node.false_block is None and not makes_a_call(node.true_block)
            store = first_node(hlil, HLILIf, is_store_test)
            wait = HLILUnaryOp(UnaryOp.NOT, HLILVar(HLILVariable(kind=VariableKind.GLOBAL, index=GLOBAL_B)))
            store.condition = HLILBinaryOp(BinaryOp.AND, store.condition, wait)
        self.check(guarded_store_before_wait_function, mutate, 'guard_differs')

    def test_call_after_a_split_exit_loop_made_depend_on_it(self):
        """A test of the loop, GLOBAL_B, made the guard of the call after it: not the same function even once a loop
        that runs ends"""
        def mutate(hlil):
            statements = hlil.body.statements
            index = next(index for index, stmt in enumerate(statements) if isinstance(stmt, HLILExprStmt))
            gate = HLILVar(HLILVariable(kind=VariableKind.GLOBAL, index=GLOBAL_B))
            statements[index] = HLILIf(gate, HLILBlock([statements[index]]))
        self.check(split_exit_value_function, mutate, 'guard_differs')

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
        with (mock.patch.object(formulas, 'ROW_CAP', 1),
              mock.patch.object(decision_diagrams, 'DIAGRAM_NODE_CAP', DIAGRAM_NODES_TOO_FEW)):
            found = logic_check.compare_mlil_hlil(mlil, hlil)
        # The returned values' difference (its detail their components), not the return's guard's (its two formulas)
        values = [difference.category for difference in found
                  if difference.key == RETURN_KEY and isinstance(difference.detail, list)]
        self.assertEqual(values, ['guard_unchecked'])

    def test_inverted_value_beside_unchecked_ones(self):
        """x's ordering test written inverted and its other test c written c && (c || GLOBAL_C): one value's formulas
        compare inverted and, under the lowered caps, the other two values' unchecked, which is no difference found"""
        mlil, hlil = mlil_and_hlil(ordered_arms_function)
        self.assertEqual(hlil_categories(mlil, hlil), set(), 'the unchanged HLIL compares clean')
        ordering = first_node(hlil, HLILBinaryOp, lambda node: node.op == BinaryOp.LT)
        inverted = HLILBinaryOp(BinaryOp.EQ, HLILBinaryOp(BinaryOp.GE, ordering.lhs, ordering.rhs), HLILConst(0))
        replace_expression(hlil, ordering, inverted)
        test = first_node(hlil, HLILIf, lambda node: node.condition is not inverted)
        other = HLILVar(HLILVariable(kind=VariableKind.GLOBAL, index=GLOBAL_C))
        test.condition = HLILBinaryOp(BinaryOp.AND, test.condition,
                                      HLILBinaryOp(BinaryOp.OR, copy.deepcopy(test.condition), other))
        self.assertEqual(hlil_categories(mlil, hlil), {'condition_ordering_inverted'})
        with (mock.patch.object(formulas, 'ROW_CAP', ORDERING_ROWS),
              mock.patch.object(decision_diagrams, 'DIAGRAM_NODE_CAP', DIAGRAM_NODES_TOO_FEW)):
            self.assertEqual(hlil_categories(mlil, hlil), {'guard_unchecked'})

    def test_inverted_value_beside_other_components(self):
        """callee(x, y), each a choice under an ordering: each argument compared on its own, then the strongest
        outcome taken, a difference before unchecked before an inversion. Unchecked: a test c written
        c && (c || GLOBAL_C), past TWO_TESTS_ROWS"""
        invert, widen, change = self.invert_ordering, self.widen_test, self.change_argument
        cases = [   # (name, the plants and their arguments, under the caps, the categories)
            ('x inverted, y changed', ((invert, GLOBAL_A), (change, 1)), False, {'arg_differs'}),
            ('x inverted, y unchecked', ((invert, GLOBAL_A), (widen, GLOBAL_B)), True, {'guard_unchecked'}),
            ('x unchecked, y changed', ((widen, GLOBAL_A), (change, 1)), True, {'arg_differs'}),
            ('both inverted', ((invert, GLOBAL_A), (invert, GLOBAL_B)), False, {'condition_ordering_inverted'}),
        ]
        self.assertEqual(hlil_categories(*mlil_and_hlil(two_choices_function)), set(),
                         'the unchanged HLIL compares clean')
        for name, plants, capped, expected in cases:
            with self.subTest(name):
                mlil, hlil = mlil_and_hlil(two_choices_function)
                for plant, argument in plants:
                    plant(hlil, argument)
                with contextlib.ExitStack() as caps:
                    if capped:
                        caps.enter_context(mock.patch.object(formulas, 'ROW_CAP', TWO_TESTS_ROWS))
                        caps.enter_context(mock.patch.object(decision_diagrams, 'DIAGRAM_NODE_CAP',
                                                             DIAGRAM_NODES_TOO_FEW))
                    found = logic_check.compare_mlil_hlil(mlil, hlil)
                self.assertEqual({difference.category for difference in found}, expected)
        # The last case's, both inverted: one difference, naming both arguments
        self.assertEqual([difference.detail for difference in found], [[0, 1]])

    def test_formulas_past_the_cap_as_written(self):
        """The branch's test g written (GLOBAL_B < LOOP_LIMIT && g) || (GLOBAL_B >= LOOP_LIMIT && g): three variables
        as written, past ORDERING_ROWS, two once orderings are read as one representative, which then decides: g, an
        inversion; with !g in the second arm, not g, a difference (the arms' guards, and the registers the return
        passes, the call's result on one arm only)"""
        for negated, expected in ((False, {'condition_ordering_inverted'}),
                                  (True, {'guard_differs', 'return_differs'})):
            with self.subTest(negated=negated):
                mlil, hlil = mlil_and_hlil(branch_function)
                test = first_node(hlil, HLILIf)
                g = test.condition
                tested = HLILVar(HLILVariable(kind=VariableKind.GLOBAL, index=GLOBAL_B))
                below = HLILBinaryOp(BinaryOp.LT, tested, HLILConst(LOOP_LIMIT))
                at_least = HLILBinaryOp(BinaryOp.GE, copy.deepcopy(tested), HLILConst(LOOP_LIMIT))
                second = HLILUnaryOp(UnaryOp.NOT, copy.deepcopy(g)) if negated else copy.deepcopy(g)
                test.condition = HLILBinaryOp(BinaryOp.OR, HLILBinaryOp(BinaryOp.AND, below, copy.deepcopy(g)),
                                              HLILBinaryOp(BinaryOp.AND, at_least, second))
                with (mock.patch.object(formulas, 'ROW_CAP', ORDERING_ROWS),
                      mock.patch.object(decision_diagrams, 'DIAGRAM_NODE_CAP', DIAGRAM_NODES_TOO_FEW)):
                    self.assertEqual(hlil_categories(mlil, hlil), expected)

    def test_ordering_inverted_in_a_loop_value(self):
        """x's ordering written inverted: the value the loop carries in differs by an inversion only; with the other
        arm's value changed too, it differs"""
        mlil, hlil = mlil_and_hlil(choice_then_loop_function)
        self.assertEqual(hlil_categories(mlil, hlil), set(), 'the unchanged HLIL compares clean')
        self.invert_ordering(hlil, GLOBAL_A)
        self.assertEqual(hlil_categories(mlil, hlil), {'condition_ordering_inverted'})
        flag_set_to(hlil, 2, 3)
        self.assertEqual(hlil_categories(mlil, hlil), {'loop_value_differs'})

    @classmethod
    def invert_ordering(cls, hlil, index: int):
        """The ordering on GLOBAL[index], a < b, written !(a >= b)"""
        ordering = first_node(hlil, HLILBinaryOp, lambda node: node.op == BinaryOp.LT and reads_global(node, index))
        inverted = HLILBinaryOp(BinaryOp.EQ, HLILBinaryOp(BinaryOp.GE, ordering.lhs, ordering.rhs), HLILConst(0))
        replace_expression(hlil, ordering, inverted)

    @classmethod
    def widen_test(cls, hlil, index: int):
        """The test on GLOBAL[index], c, written c && (c || GLOBAL_C): one function, in two tests"""
        test = first_node(hlil, HLILIf, lambda node: reads_global(node.condition, index))
        other = HLILVar(HLILVariable(kind=VariableKind.GLOBAL, index=GLOBAL_C))
        test.condition = HLILBinaryOp(BinaryOp.AND, test.condition,
                                      HLILBinaryOp(BinaryOp.OR, copy.deepcopy(test.condition), other))

    @classmethod
    def change_argument(cls, hlil, position: int):
        first_node(hlil, HLILCall).args[position] = HLILConst(UNRELATED_ARG)

    @classmethod
    def change_write(cls, hlil, value: int):
        """The first write of the constant value made value + 1, which nothing else writes"""
        write = first_node(hlil, HLILAssign, lambda node: isinstance(node.src, HLILConst) and node.src.value == value)
        write.src.value += 1

    def test_register_wrong_under_a_common_return(self):
        """The chain's last write changed, its return made one with the other arm's: the merge, compared alternative by
        alternative, still differs in one"""
        def mutate(hlil):
            TestHLILStructures.extract_common_return(hlil)
            self.change_write(hlil, CHAIN_LENGTH)
        self.check(chain_then_early_return_function, mutate, 'return_differs')

    def test_register_wrong_in_one_repeated_arm(self):
        """The chain and the return repeated in each arm, the first copy's last write changed"""
        def mutate(hlil):
            TestHLILStructures.repeat_tail_in_arms(hlil)
            self.change_write(hlil, CHAIN_LENGTH)
        self.check(arms_then_chain_function, mutate, 'return_differs')

    @mock.patch.object(compare, 'LIFTED_CHOICES', LIFTING_CAP)
    def test_register_wrong_past_the_lifting_cap(self):
        """The long chain's last write changed, its merge inside an operation: the choices inside it are more
        alternatives than are lifted, so the difference found with the value whole stands, not an unchecked one"""
        mlil, hlil = mlil_and_hlil(lambda: arms_then_slot_chain_function(LONG_CHAIN))
        self.change_write(hlil, LONG_CHAIN)
        self.assertEqual(hlil_categories(mlil, hlil), {'return_differs'})

    def test_loop_entered_with_a_wrong_value_after_a_chain(self):
        """The loop rebuilt in both arms, the chain's last write in the first arm changed: that copy carries it in"""
        def mutate(hlil):
            TestHLILStructures.rebuild_in_both_arms(hlil)
            self.change_write(hlil, CHAIN_LENGTH + 1)
        self.check(chain_arm_then_loop_function, mutate, 'loop_value_differs')

    def test_register_wrong_in_one_chain_after_a_call(self):
        """The chain repeated after each arm's call, the first copy's last write changed"""
        def mutate(hlil):
            TestHLILStructures.repeat_tail_in_arms(hlil)
            self.change_write(hlil, CHAIN_LENGTH)
        self.check(calls_then_chain_function, mutate, 'return_differs')

    def test_value_wrong_inside_an_operation_in_one_arm(self):
        """v + 1 repeated in each arm, the first copy's chain's last write changed"""
        def mutate(hlil):
            TestHLILStructures.repeat_tail_in_arms(hlil)
            self.change_write(hlil, CHAIN_LENGTH)
        self.check(arms_then_slot_chain_function, mutate, 'return_differs')

    def test_flag_test_made_depend_on_another_global(self):
        """if (x == 0) made if (x == 0 && GLOBAL_C), the flag's formulas past their caps: lifted, still a difference"""
        with formula_keys_past_their_caps():
            def mutate(hlil):
                test = first_node(hlil, HLILIf, lambda node: makes_a_call(node.true_block)
                                  or (node.false_block is not None and makes_a_call(node.false_block)))
                gate = HLILVar(HLILVariable(kind=VariableKind.GLOBAL, index=GLOBAL_C))
                test.condition = HLILBinaryOp(BinaryOp.AND, test.condition, gate)
            self.check(flag_then_test_function, mutate, 'guard_differs')

    def test_flag_test_changed_past_the_diagram_cap_once_lifted(self):
        """The same change, the decision diagrams capped where the plain guards fit and the lifted ones do not: the
        lifted look is unchecked, and the difference found first stands"""
        with (formula_keys_past_their_caps(),
              mock.patch.object(decision_diagrams, 'DIAGRAM_NODE_CAP', LIFTED_FLAG_DIAGRAM_NODES)):
            mlil, hlil = mlil_and_hlil(flag_then_test_function)
            test = first_node(hlil, HLILIf, lambda node: makes_a_call(node.true_block)
                              or (node.false_block is not None and makes_a_call(node.false_block)))
            gate = HLILVar(HLILVariable(kind=VariableKind.GLOBAL, index=GLOBAL_C))
            test.condition = HLILBinaryOp(BinaryOp.AND, test.condition, gate)
            self.assertIn('guard_differs', hlil_categories(mlil, hlil))

    def test_flag_set_from_a_flag_never_set(self):
        """x = 1 made x = 0, the formulas past their caps: y is then always 1, and the call never runs"""
        with formula_keys_past_their_caps():
            self.check(flag_from_flag_function, lambda hlil: flag_set_to(hlil, 1, 0), 'guard_differs')

    def test_store_in_an_outer_header_made_depend_on_an_inner_wait(self):
        """GLOBAL_C = 1 made if (!GLOBAL_A || !GLOBAL_B) GLOBAL_C = 1: the store runs before the wait in its iteration,
        so the premise that the wait ends is not its to use"""
        def mutate(hlil):
            store = first_node(hlil, HLILAssign, lambda node: isinstance(node.dest, HLILVar)
                               and node.dest.var.kind == VariableKind.GLOBAL)
            glob = lambda index: HLILVar(HLILVariable(kind=VariableKind.GLOBAL, index=index))
            gate = HLILBinaryOp(BinaryOp.OR, HLILUnaryOp(UnaryOp.NOT, glob(GLOBAL_A)),
                                HLILUnaryOp(UnaryOp.NOT, glob(GLOBAL_B)))
            block = next(node for node in iter_tree(hlil.body) if isinstance(node, HLILBlock)
                         and store in node.statements)
            block.statements[block.statements.index(store)] = HLILIf(gate, HLILBlock([store]))
        self.check(store_then_inner_wait_function, mutate, 'guard_differs')

    def test_deleted_call(self):
        """The early exit's rest() deleted"""
        def mutate(hlil):
            for block in [node for node in iter_tree(hlil.body) if isinstance(node, HLILBlock)]:
                block.statements = [statement for statement in block.statements
                                    if not (isinstance(statement, HLILExprStmt) and statement.expr.func_name == 'rest')]
        self.check_built(*with_hlil(build_function('f', EARLY_EXIT)), mutate, 'missing_effect')

    def test_call_replaced_but_provenance_kept(self):
        """observable() made the constant 0, its statement still naming the call it came from"""
        def mutate(hlil):
            statement = first_node(hlil, HLILExprStmt)
            statement.expr = HLILConst(0)
            statement.expr.mlil_index = statement.mlil_index
        self.check_built(*with_hlil(returns_parameter()), mutate, 'missing_effect')

    def test_call_target_changed_but_provenance_kept(self):
        """observable() made other()"""
        def mutate(hlil):
            first_node(hlil, HLILCall).func_name = 'other'
        self.check_built(*with_hlil(returns_parameter()), mutate, 'target_differs')

    def test_returned_variable_changed(self):
        """return p made return q"""
        def mutate(hlil):
            first_node(hlil, HLILReturn).value = HLILVar(HLILVariable('q'))
        self.check_built(*with_hlil(returns_parameter()), mutate, 'return_differs')

    def test_short_circuit_made_eager(self):
        """second() runs only when first() returned 0: || keeps that, | runs both whatever first() returned"""
        func = calls_then_test()
        self.assertEqual(hlil_categories(func, either_call_hlil(func, BinaryOp.OR)), set())
        self.assertIn('guard_differs', hlil_categories(func, either_call_hlil(func, BinaryOp.BIT_OR)))

    def test_one_wrong_copy_of_a_repeated_region(self):
        """continue made break in the second of the loop's two copies only: that copy no longer repeats"""
        def mutate(hlil):
            loops = [node for node in iter_tree(hlil.body) if isinstance(node, HLILWhile)]
            self.assertEqual(len(loops), 2)
            for block in [node for node in iter_tree(loops[1].body) if isinstance(node, HLILBlock)]:
                block.statements = [HLILBreak() if isinstance(statement, HLILContinue) else statement
                                    for statement in block.statements]
        self.check_built(*structure(SHARED_LOOP), mutate, 'guard_differs')

    def test_falling_off_the_end(self):
        """The early exit's top-level returns deleted: the function falls off its end"""
        def mutate(hlil):
            hlil.body.statements = [statement for statement in hlil.body.statements
                                    if not isinstance(statement, HLILReturn)]
        self.check_built(*with_hlil(build_function('f', EARLY_EXIT)), mutate, 'guard_differs')


class TestHLILStructures(unittest.TestCase):
    """Structures HLIL builds otherwise than MLIL writes them, compared clean: the same logic"""

    def test_arms_joined_before_the_back_edge(self):
        self.assertEqual(hlil_categories(*mlil_and_hlil(arms_joined_in_a_loop_function)), set())

    def test_inner_arms_joined_first(self):
        self.assertEqual(hlil_categories(*mlil_and_hlil(nested_arms_function)), set())

    def test_value_after_a_split_exit_loop(self):
        """The value merged after the loop from the two tests HLIL splits its exit into, each taken in one iteration:
        a loop that runs ends through one of them"""
        self.assertEqual(hlil_categories(*mlil_and_hlil(split_exit_value_function)), set())

    def test_split_exit_with_an_ordering_inverted(self):
        """The same, with HLIL's own inversion of an ordering: counted as that, not as a difference of the value"""
        mlil, hlil = mlil_and_hlil(split_exit_value_function)
        ordering = first_node(hlil, HLILBinaryOp, lambda node: node.op == BinaryOp.LT)
        inverted = HLILBinaryOp(BinaryOp.EQ, HLILBinaryOp(BinaryOp.GE, ordering.lhs, ordering.rhs), HLILConst(0))
        replace_expression(hlil, ordering, inverted)
        self.assertEqual(hlil_categories(mlil, hlil), {'condition_ordering_inverted'})

    def test_loop_with_two_exits_to_two_targets(self):
        self.assertEqual(hlil_categories(*mlil_and_hlil(two_exits_two_targets_function)), set())

    def test_inner_loop_split_in_an_outer_one(self):
        self.assertEqual(hlil_categories(*mlil_and_hlil(split_inner_in_outer_function)), set())

    def test_constant_loop_test(self):
        self.assertEqual(hlil_categories(*mlil_and_hlil(constant_loop_test_function)), set())

    def test_chain_made_a_switch(self):
        mlil, hlil = mlil_and_hlil(case_chain_function)
        first_node(hlil, HLILSwitch)
        self.assertEqual(hlil_categories(mlil, hlil), set())

    def test_condition_split_at_its_short_circuit(self):
        self.assertEqual(hlil_categories(*mlil_and_hlil(and_condition_function)), set())

    def test_hand_built_instructions_have_addresses(self):
        """tests.shared.ir_utils.connect gives each its own: the check keys effects and branches by address"""
        func = build_function('f', {'E': (['first', 'second'], ('if', 'p', 'T', 'F')), 'T': ([], ('ret', 1)),
                                    'F': ([], ('ret', 2))})
        addresses = [inst.address for inst in func.iter_instructions()]
        self.assertEqual(len(set(addresses)), len(addresses))
        self.assertNotIn(0, addresses)

    def test_arm_a_decided_condition_never_reaches(self):
        """HLIL splits `x && 0` and folds the 0, so its arm has no predecessor; the MLIL branch is decided alike"""
        mlil, hlil = mlil_and_hlil(dead_arm_function)
        self.assertEqual(sum(isinstance(inst, MLILIf) for inst in mlil.iter_instructions()), 1)  # the && stays whole
        self.assertEqual(hlil_categories(mlil, hlil), set())

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

    @classmethod
    def repeat_tail_in_arms(cls, hlil):
        """if (c) {A} else {B}; rest; return made if (c) {A; rest; return} else {B; rest; return}, as the converter
        repeats a region on each path into it (_clone_region_blocks)"""
        body = hlil.body.statements
        index = next(index for index, stmt in enumerate(body) if isinstance(stmt, HLILIf))
        if_stmt, rest = body[index], body[index + 1:]
        if if_stmt.false_block is None or not isinstance(rest[-1], HLILReturn):
            raise AssertionError('the rewrite found no two arms and a return after them: the HLIL shape changed')
        if_stmt.true_block.statements.extend(rest)
        if_stmt.false_block.statements.extend(copy.deepcopy(rest))
        hlil.body.statements = body[:index + 1]

    def test_common_return_merging_a_chain_once_more(self):
        """The chain's value merged once more at the common return, on HLIL only: compared with MLIL's two returns
        alternative by alternative"""
        mlil, hlil = mlil_and_hlil(chain_then_early_return_function)
        self.extract_common_return(hlil)
        self.assertEqual(hlil_categories(mlil, hlil), set())

    def test_chain_after_arms_repeated_in_arms(self):
        """MLIL merges the arms under the chain; HLIL's copies of the chain do not"""
        mlil, hlil = mlil_and_hlil(arms_then_chain_function)
        self.repeat_tail_in_arms(hlil)
        self.assertEqual(hlil_categories(mlil, hlil), set())

    def test_loop_rebuilt_in_arms_entered_after_a_chain(self):
        """MLIL's loop entered with the arms' merge, one more than the chain's; each copy with its arm's value"""
        mlil, hlil = mlil_and_hlil(chain_arm_then_loop_function)
        self.rebuild_in_both_arms(hlil)
        self.assertEqual(hlil_categories(mlil, hlil), set())

    def test_chain_after_calls_repeated_in_arms(self):
        """Each copy's tests read globals after its arm's call; MLIL's one chain reads them after either call, a choice
        inside each test's leaf, lifted"""
        mlil, hlil = mlil_and_hlil(calls_then_chain_function)
        self.repeat_tail_in_arms(hlil)
        self.assertEqual(hlil_categories(mlil, hlil), set())

    def test_merge_inside_an_operation_repeated_in_arms(self):
        """MLIL's REG = v + 1 holds the merge of the arms and the chain; each HLIL copy's holds its arm's chain"""
        mlil, hlil = mlil_and_hlil(arms_then_slot_chain_function)
        self.repeat_tail_in_arms(hlil)
        self.assertEqual(hlil_categories(mlil, hlil), set())

    def test_flag_tested_with_formulas_past_their_caps(self):
        """The flag's choice, keyed by its digest, is built over HLIL's split && otherwise than over MLIL's: lifted in
        the guard, the two are one function"""
        with formula_keys_past_their_caps():
            self.assertEqual(hlil_categories(*mlil_and_hlil(flag_then_test_function)), set())

    def test_flag_set_from_a_flag_with_formulas_past_their_caps(self):
        """The flag x only in the formulas of the flag y: lifted in turn (lifted_atom)"""
        with formula_keys_past_their_caps():
            self.assertEqual(hlil_categories(*mlil_and_hlil(flag_from_flag_function)), set())

    def test_flag_test_written_as_its_condition(self):
        """if (x) written if (GLOBAL_A), x's value under it: y's choice then holds x only in its formulas"""
        mlil, hlil = mlil_and_hlil(flag_copied_function)
        test = [node for node in iter_tree(hlil.body) if isinstance(node, HLILIf)][1]
        test.condition = HLILVar(HLILVariable(kind=VariableKind.GLOBAL, index=GLOBAL_A))
        self.assertEqual(hlil_categories(mlil, hlil), set())

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

    def test_early_exit(self):
        self.assertEqual(hlil_categories(*with_hlil(build_function('f', EARLY_EXIT))), set())

    def test_calls_folded_into_conditions(self):
        self.assertEqual(hlil_categories(*with_hlil(calls_then_test())), set())

    def test_constant_comparison_decided_alike_on_both_levels(self):
        """if (1 == 1): the dead arm's call on neither level"""
        blocks = {'C': ([], ('if', ('==', 1, 1), 'L', 'D')), 'L': (['live'], ('ret', 1)), 'D': (['dead'], ('ret', 0))}
        self.assertEqual(hlil_categories(*with_hlil(build_function('f', blocks))), set())

    def test_temporary_an_hlil_pass_folds_away(self):
        self.assertEqual(hlil_categories(*with_hlil(temporary_condition())), set())

    def test_call_folded_into_a_return(self):
        self.assertEqual(hlil_categories(*with_hlil(returns_call_result())), set())

    def test_switch_from_an_equality_chain(self):
        func, hlil = with_hlil(equality_chain())
        self.assertTrue(any(isinstance(node, HLILSwitch) for node in iter_tree(hlil.body)))
        self.assertEqual(hlil_categories(func, hlil), set())

    def test_region_repeated(self):
        self.assertEqual(hlil_categories(*structure(SHARED_LOOP)), set())


class WriteBlock:
    def __init__(self, *writes: tuple):
        self.instructions = list(writes)


class LoopOfWrites:
    """A layer adapter (evaluation.py) as far as widen_loop_headers reads one: entry -> header -> body -> header,
    header -> exit; each instruction a (key, tree) write"""

    OWN_STORAGE_NAMES = True
    BRANCH_ADDRESS, HEADER_NAME = 5, (FUNCTION_ENTRY, 10)

    def __init__(self, entry_write: tuple, body_write: tuple, neutral_key):
        self.entry, self.body = WriteBlock(entry_write), WriteBlock(body_write)
        self.header, self.exit = WriteBlock(), WriteBlock()
        self.edges = {self.entry: [self.header], self.header: [self.body, self.exit], self.body: [self.header],
                      self.exit: []}
        self.neutral_key = neutral_key

    def successors(self, block) -> list:
        return self.edges[block]

    def predecessors(self, block) -> list:
        return [other for other, targets in self.edges.items() if block in targets]

    def branch(self, block) -> tuple | None:
        return (self.BRANCH_ADDRESS, self.body, self.exit) if block is self.header else None

    def header_name(self, block):
        return self.HEADER_NAME if block is self.header else None

    @classmethod
    def step(cls, inst: tuple, state: State, facts: Facts) -> list[Effect]:
        key, tree = inst
        state.items[key] = tree
        return []


class TestSplitLoopValues(unittest.TestCase):
    """Two de-SSA splits of one stack slot: carried round one loop, each must carry the reference's value, so a right
    one does not hide a wrong one; met at a join or round a loop, they stay two values, not one under neutral names"""

    HEADER, BACK_EDGE, OUTER_HEADER = (FUNCTION_ENTRY, 10), 10, (FUNCTION_ENTRY, 20)
    SLOT, SPLIT, OTHER_SPLIT = ('stack', 0), ('name', 'var_s0'), ('name', 'var_s0_v0')
    KEY = ('reg', REG_INDEX)

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

    def neutral_key(self, key):
        return self.SLOT if key in (self.SPLIT, self.OTHER_SPLIT) else key

    def test_splits_kept_apart_at_a_join(self):
        """Each arm writes a register from another split's loop leaf: one name under neutral names, two values"""
        leaves = [('loop', self.HEADER, split) for split in (self.SPLIT, self.OTHER_SPLIT)]
        states = [(formulas.literal(('param', 0), polarity), State({self.KEY: leaf}))
                  for polarity, leaf in zip((True, False), leaves)]
        value = merged_value(None, self.KEY, states, Fingerprints(self.neutral_key))
        self.assertEqual(value[0], 'gamma')
        self.assertEqual([leaf for _, leaf in value[1]], leaves)

    def test_splits_kept_apart_round_a_loop(self):
        """A register enters a loop with one split's leaf of an outer loop and goes round with the other's: the loop
        changes it, so its header widens it"""
        entered, carried = (('loop', self.OUTER_HEADER, split) for split in (self.SPLIT, self.OTHER_SPLIT))
        layer = LoopOfWrites((self.KEY, entered), (self.KEY, carried), self.neutral_key)
        flow = ControlFlow(layer.entry, layer.successors, layer.predecessors, layer.branch, GatedNaming.exit_rank)
        _, _, widened = widen_loop_headers(layer, flow, GatedNaming(layer, flow), Fingerprints(self.neutral_key))
        self.assertEqual(widened[layer.header], {self.KEY})


class TestDeepValues(unittest.TestCase):
    """Chains of DEEP_MERGES gated merges, never cut, built as trees (a function so deep takes seconds to decompile):
    digested and compared at the decompiler's recursion limit, through Python frames, each shared part once"""

    def setUp(self):
        self.addCleanup(sys.setrecursionlimit, sys.getrecursionlimit())
        raise_recursion_limit()

    @classmethod
    def increments(cls, initial: int = 0) -> tuple:
        """v = initial; DEEP_MERGES times: if p_i: v = v + 1: both arms of each merge hold the one before"""
        value = const(initial)
        for index in range(DEEP_MERGES):
            condition = ('param', index)
            value = ('gamma', ((formulas.literal(condition, True), op('ADD', [value, const(1)])),
                               (formulas.literal(condition, False), value)))
        return value

    @classmethod
    def retested_value(cls) -> tuple:
        """v = 0; DEEP_MERGES times: v = 1 if v == i else 0: each merge's formulas test the one before"""
        value = const(0)
        for index in range(1, DEEP_MERGES + 1):
            core = op('EQ', [value, const(index)])
            value = ('gamma', ((formulas.literal(core, True), const(1)), (formulas.literal(core, False), const(0))))
        return value

    def test_increments_digested(self):
        digest = Fingerprints(lambda key: key)
        self.assertNotEqual(digest(self.increments()), digest(self.increments(initial=1)))

    def test_increments_compared(self):
        self.assertTrue(equal_trees(self.increments(), self.increments()))
        self.assertFalse(equal_trees(self.increments(), self.increments(initial=1)))

    def test_retested_value_digested(self):
        """Each formula's key digests the merge before it"""
        self.assertEqual(Fingerprints(lambda key: key)(self.retested_value()),
                         Fingerprints(lambda key: key)(self.retested_value()))


class TestLiftedChoices(unittest.TestCase):
    """Gated choices inside a value or a condition lifted into the formulas their values arrive under
    (compare.choice_alternatives, gated_comparison.lifted_formula)"""

    EDGES = 7                       # incoming edges of each choice below, over two values

    def setUp(self):
        self.fingerprints = Fingerprints.of(Facts())

    def choice(self, first: int) -> tuple:
        """A choice over EDGES edges, each under a literal of its own, of the values 0 and 1"""
        return ('gamma', tuple((formulas.literal(('param', first + index), True), const(index % 2))
                               for index in range(self.EDGES)))

    def test_choice_in_a_leaf_found(self):
        choice = self.choice(0)
        read = ('global', GLOBAL_A, choice)         # a global read after the calls of either arm
        self.assertIs(compare.inner_choice(op('EQ', [read, const(0)]), set()), choice)

    def test_substitution_keeps_untouched_parts(self):
        choice, untouched = self.choice(0), op('ADD', [('param', 1), const(1)])
        tree = op('ADD', [untouched, choice])
        lifted = compare.substitute(tree, choice, const(1), {})
        self.assertIs(lifted[2][0], untouched)
        self.assertEqual(lifted[2][1], const(1))

    @mock.patch.object(compare, 'LIFTED_CHOICES', EDGES ** 3 - 1)
    def test_choices_counted_by_value(self):
        """Three choices in one operation: EDGES ** 3 alternatives by edge, past LIFTED_CHOICES; 2 ** 3 by value"""
        tree = op('EQ', [op('ADD', [self.choice(0), op('ADD', [self.choice(10), self.choice(20)])]), const(0)])
        alternatives, capped = compare.choice_alternatives(self.fingerprints, formulas.TRUE, tree, inner=True)
        self.assertFalse(capped)
        self.assertEqual(len(alternatives), 2 ** 3)

    def test_condition_split_before_its_choices_are_lifted(self):
        """a == 0 && b == 0 && c == 0 with room for two values only: lifted part by part, as FormulaKeys splits it"""
        parts = [op('EQ', [self.choice(first), const(0)]) for first in (0, 10, 20)]
        condition = op('LOGICAL_AND', [parts[0], op('LOGICAL_AND', parts[1:])])
        with mock.patch.object(compare, 'LIFTED_CHOICES', 2):
            lifted = gated_comparison.lifted_formula(self.fingerprints, formulas.literal(condition, True), {})
        self.assertIsNone(compare.inner_choice(lifted, set()))


class TestRenderedFormula(unittest.TestCase):
    """A gated detail's formula as text (gated_comparison.render), cut at RENDERED_FORMULA_CHARACTERS"""

    FORMULA = ('or', (formulas.TRUE, formulas.TRUE))   # (true || true)

    def test_cut_exactly_at_the_cap(self):
        """Text that reaches the cap with parts left is cut, and shown cut; text that ends there is whole"""
        with mock.patch.object(gated_comparison, 'RENDERED_FORMULA_CHARACTERS', len('(true || ')):
            self.assertEqual(gated_comparison.render(self.FORMULA), '(true || ...')
        with mock.patch.object(gated_comparison, 'RENDERED_FORMULA_CHARACTERS', len('(true || true)')):
            self.assertEqual(gated_comparison.render(self.FORMULA), '(true || true)')


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
        fingerprints = Fingerprints.of(Facts())
        self.assertEqual(fingerprints(op('EQ', [self.A, self.B])), fingerprints(op('EQ', [self.B, self.A])))
        self.assertNotEqual(fingerprints(op('LT', [self.A, self.B])), fingerprints(op('LT', [self.B, self.A])))

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


class TestEffectValues(unittest.TestCase):
    """An effect's values compared LLIL against MLIL (compare.value_differences): a difference for each argument or
    storage key that differs, the arguments left out where the two pass different counts"""

    ADDRESS = 0x10
    KEY     = (ADDRESS, 'call')

    @classmethod
    def differences(cls, expected: tuple, found: tuple) -> list:
        """The differences of one call passing expected on the reference and found on the checked side"""
        sides = [Facts(effects={cls.KEY: [Effect(cls.ADDRESS, 'call', CALLEE_ID, args)]}) for args in (expected, found)]
        return logic_check.compare_facts(*sides)

    def test_unequal_argument_counts(self):
        """The first argument dropped: the count differs, and the arguments left are not compared by index"""
        self.assertEqual(self.differences((const(1), const(2)), (const(2),)),
                         [logic_check.Difference('argc_differs', self.KEY, (2, 1))])

    def test_two_arguments_differing(self):
        self.assertEqual([(difference.category, difference.detail[0])
                          for difference in self.differences((const(1), const(2)), (const(3), const(4)))],
                         [('arg_differs', 0), ('arg_differs', 1)])


class TestFormulaKeys(unittest.TestCase):
    """Formulas compare as functions of their conditions: the equality tests of one value exclude each other, but
    for float constants; a condition nothing depends on is left out; past the truth table's rows, by decision
    diagram, over the variables a formula depends on"""

    X, Y = ('param', 1), ('param', 2)

    def setUp(self):
        self.keys = formulas.FormulaKeys(Fingerprints(lambda key: key))

    @classmethod
    def equals(cls, value: tuple, constant: int | float, polarity: bool = True) -> tuple:
        return formulas.literal(op('EQ', [value, const(constant)]), polarity)

    @classmethod
    def named_digest(cls, tree) -> str:
        """A digest naming a parameter ('param', name) by its name, and / or items sorted, so a test sets the variable
        orders by the names; a literal sorts before an and / or"""
        if not isinstance(tree, tuple):
            return repr(tree)
        if tree[0] == 'param':
            return tree[1]
        if tree[0] in ('and', 'or'):
            return f'({tree[0]} {" ".join(sorted(cls.named_digest(item) for item in tree[1]))})'
        return '(' + ' '.join(cls.named_digest(item) for item in tree) + ')'

    @classmethod
    def named(cls, name: str) -> tuple:
        return formulas.literal(op('EQ', [('param', name), const(1)]), True)

    @classmethod
    def pairs_formulas(cls, together: bool) -> tuple[tuple, tuple]:
        """(any of PAIRS pairs of tests both holding, any pair's first holding), the names in sorted order each pair
        together or every pair's first before every second"""
        names = ([(f'p{index:02d}a', f'p{index:02d}b') for index in range(PAIRS)] if together else
                 [(f'x{index:02d}', f'y{index:02d}') for index in range(PAIRS)])
        pairs = formulas.disjunction([formulas.conjunction(cls.named(first), cls.named(second))
                                      for first, second in names])
        return pairs, formulas.disjunction([cls.named(first) for first, _ in names])

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
        structure = self.keys.structure
        self.assertTrue(decision_diagrams.Diagrams().same(structure(flat), structure(chained)))

        flipped = formulas.disjunction(formulas.literal(value, index != 0) for index, value in enumerate(values))
        self.assertNotEqual(self.keys(flipped), self.keys(flat))
        self.assertFalse(decision_diagrams.Diagrams().same(structure(flat), structure(flipped)))

    def test_relevant_variables(self):
        """(x == 1 && y == 2) || (x == 1 && y != 2) || x == 3 || (x == 4 && x == 1) depends on x alone, told from any
        other value at 1 and 3"""
        formula = formulas.disjunction([
            *(formulas.conjunction(self.equals(self.X, 1), self.equals(self.Y, 2, polarity))
              for polarity in (True, False)),
            self.equals(self.X, 3), formulas.conjunction(self.equals(self.X, 4), self.equals(self.X, 1))])
        _, expected = self.keys.structure_and_variables(formulas.disjunction([self.equals(self.X, 1),
                                                                              self.equals(self.X, 3)]))
        self.assertEqual(decision_diagrams.Diagrams.relevant(*self.keys.structure_and_variables(formula)), expected)

    @mock.patch.object(decision_diagrams, 'DIAGRAM_KEY_NODE_CAP', PAIRS_KEY_NODES)
    def test_key_past_the_sorted_orders_cap(self):
        """a || (a && pairs), past ROW_CAP rows, its diagram in sorted order (every pair's first before every second)
        past the key's cap: a's key, the variables found in the order a digest walk meets them, each pair together"""
        keys = formulas.FormulaKeys(self.named_digest)
        a = self.named('a')
        formula = formulas.disjunction([a, formulas.conjunction(a, self.pairs_formulas(together=False)[0])])
        with self.assertRaises(decision_diagrams.DiagramOverflow):
            decision_diagrams.Diagrams.key(*keys.structure_and_variables(formula))
        self.assertEqual(keys(formula), keys(a))

    @mock.patch.object(decision_diagrams, 'DIAGRAM_KEY_NODE_CAP', PAIRS_KEY_NODES)
    def test_variables_found_in_sorted_order_past_the_walks_cap(self):
        """pairs && any first, whose digest walk meets every pair's first before the pairs (a literal sorts before an
        and), past the key's cap that way: the variables found in sorted order, each pair together, as Diagrams.key
        finds them"""
        keys = formulas.FormulaKeys(self.named_digest)
        formula = formulas.conjunction(*self.pairs_formulas(together=True))
        structure, variables = keys.structure_and_variables(formula)
        with self.assertRaises(decision_diagrams.DiagramOverflow):
            decision_diagrams.Diagrams.relevant(structure, keys.canonical_variables(formula))
        self.assertEqual(keys(formula), decision_diagrams.Diagrams.key(structure, variables)[1])

    @mock.patch.object(decision_diagrams, 'DIAGRAM_KEY_NODE_CAP', PAIRS_KEY_NODES)
    def test_one_outcome_for_formulas_of_one_digest(self):
        """a || (a && (pairs && any first)) and the same with the inner and's items swapped, one digest: in the order
        each meets its variables one fits the key's cap and the other not; two layers key them alike"""
        a = self.named('a')
        pairs, any_first = self.pairs_formulas(together=False)
        written = [formulas.disjunction([a, formulas.conjunction(a, formulas.conjunction(*items))])
                   for items in ((pairs, any_first), (any_first, pairs))]
        self.assertEqual(self.named_digest(written[0]), self.named_digest(written[1]))
        keyed = [formulas.FormulaKeys(self.named_digest)(formula) for formula in written]
        self.assertEqual(keyed[0], keyed[1])

    def test_comparisons_remembered_by_both_sides(self):
        """x == 1 && y == 1 against the condition x == 1 && y == 1 (one function, written otherwise), then against
        x == 1 && y == 2: the second comparison, its first side's formula the same, still differs"""
        reading = gated_comparison.GatedReading((Fingerprints.of(Facts()), Fingerprints.of(Facts())), {})
        both = formulas.conjunction(self.equals(self.X, 1), self.equals(self.Y, 1))
        condition = formulas.literal(op('LOGICAL_AND', [op('EQ', [value, const(1)]) for value in (self.X, self.Y)]),
                                     True)
        other = formulas.conjunction(self.equals(self.X, 1), self.equals(self.Y, 2))
        self.assertIsNone(gated_comparison.compare_formulas(reading, (both, condition)))
        self.assertEqual(gated_comparison.compare_formulas(reading, (both, other)), 'guard_differs')


class TestVMEffects(unittest.TestCase):
    """The VM's effects on a layer's storage (VMEffects), one definition for the three layers, so a slip in one makes
    every layer wrong alike: each operation's whole effect and the state it leaves"""

    ADDRESS       = 0x100
    PASSED        = ('stack', 1)                        # its address an argument; it holds POINTEE's
    POINTEE       = ('stack', 2)                        # reached through PASSED, never written
    ESCAPED_LOCAL = ('stack', 3)
    PARAMETER     = ('param', 1)                        # its address an argument, never written
    UNREACHED     = ('stack', 4)
    SPLIT         = ('name', f'reg{REG_INDEX}_v1')      # a de-SSA split of register REG_INDEX

    def setUp(self):
        neutral = {self.SPLIT: ('reg', REG_INDEX)}
        self.vm = VMEffects({self.PASSED, self.POINTEE, self.ESCAPED_LOCAL, self.PARAMETER, self.UNREACHED},
                            lambda key: neutral.get(key, key))

    @classmethod
    def escaped(cls, key: tuple) -> dict:
        return {(ESCAPED, key): (ESCAPED,)}

    def test_store_global(self):
        state = State()
        value = ('address', self.PASSED)
        self.assertEqual(self.vm.store_global(state, self.ADDRESS, GLOBAL_A, value),
                         Effect(self.ADDRESS, 'store global', GLOBAL_A, (value,)))
        self.assertEqual(state.items, {('global', GLOBAL_A): value, **self.escaped(self.PASSED)})

        state = State()
        self.vm.store_global(state, self.ADDRESS, GLOBAL_A, const(STORED))
        self.assertEqual(state.items, {('global', GLOBAL_A): const(STORED)})

    def test_store_deref(self):
        """The pointer first, then the value; memory behind pointers changes, no local"""
        state = State({self.UNREACHED: const(STORED)})
        pointer, value = self.PARAMETER, ('address', self.POINTEE)
        self.assertEqual(self.vm.store_deref(state, self.ADDRESS, pointer, value),
                         Effect(self.ADDRESS, 'store deref', None, (pointer, value)))
        self.assertEqual(state.items, {self.UNREACHED: const(STORED), MEMORY_EPOCH: self.ADDRESS,
                                       **self.escaped(self.POINTEE)})

    def test_return(self):
        """The value given, or for none the result register's; every other register passed on, the state unchanged"""
        result = ('reg', VMEffects.RESULT_REGISTER)
        state = State({('reg', REG_INDEX): const(STORED), result: const(OUT_INITIAL)})
        before = dict(state.items)
        registers = tuple((('reg', index), const(STORED) if index == REG_INDEX else ('reg', index, ENTRY))
                          for index in range(VMEffects.REGISTER_COUNT) if index != VMEffects.RESULT_REGISTER)
        self.assertEqual(self.vm.ret(state, self.ADDRESS, const(UNRELATED_ARG)),
                         Effect(self.ADDRESS, 'return', None, (const(UNRELATED_ARG),), storage=registers))
        self.assertEqual(self.vm.ret(state, self.ADDRESS),
                         Effect(self.ADDRESS, 'return', None, (const(OUT_INITIAL),), storage=registers))
        self.assertEqual(state.items, before)

    def test_call_passes_and_changes(self):
        """Passed: the locals an argument holds the address of, one whose address escaped before, one a passed local
        points to; a never-written parameter as itself, a never-written stack slot as undefined. Then every register
        but the result is the call's, the result its value, no global is left, memory behind pointers changes, and so
        does every passed local"""
        state = State({self.PASSED: ('address', self.POINTEE), self.ESCAPED_LOCAL: const(STORED),
                       **self.escaped(self.ESCAPED_LOCAL), self.UNREACHED: const(UNRELATED_ARG),
                       ('global', GLOBAL_A): const(OUT_INITIAL), ('reg', REG_INDEX): const(OUT_INITIAL)})
        args = (('address', self.PASSED), ('address', self.PARAMETER))
        passed = ((self.PARAMETER, self.PARAMETER), (self.PASSED, ('address', self.POINTEE)),
                  (self.POINTEE, ('undef', self.POINTEE)), (self.ESCAPED_LOCAL, const(STORED)))
        self.assertEqual(self.vm.call(state, self.ADDRESS, 'script call', MESSAGE, args),
                         Effect(self.ADDRESS, 'script call', MESSAGE, args, storage=passed))

        self.assertEqual(state.items, {
            **{('reg', index): ('reg', index, ('after', self.ADDRESS)) for index in range(VMEffects.REGISTER_COUNT)},
            ('reg', VMEffects.RESULT_REGISTER): ('call', self.ADDRESS),
            GLOBAL_EPOCH: self.ADDRESS, MEMORY_EPOCH: self.ADDRESS,
            **{key: ('slot_after', key, self.ADDRESS) for key, _ in passed},
            **self.escaped(self.ESCAPED_LOCAL), self.UNREACHED: const(UNRELATED_ARG)})

    def test_call_kinds(self):
        for kind, target in (('call', MESSAGE), ('script call', MESSAGE), ('syscall', (GLOBAL_A, GLOBAL_B))):
            with self.subTest(kind=kind):
                self.assertEqual(self.vm.call(State(), self.ADDRESS, kind, target, ()),
                                 Effect(self.ADDRESS, kind, target, ()))

    def test_call_that_does_not_clobber(self):
        state = State({self.PASSED: const(STORED), ('reg', REG_INDEX): const(OUT_INITIAL)})
        before = dict(state.items)
        args = (('address', self.PASSED),)
        self.assertEqual(self.vm.call(state, self.ADDRESS, 'call', DEBUG_LOG_CALL_TARGET, args, clobbers=False),
                         Effect(self.ADDRESS, 'call', DEBUG_LOG_CALL_TARGET, args))
        self.assertEqual(state.items, before)

    def test_write(self):
        """An address written to a register, or to a de-SSA split of one, escapes; to a stack slot not"""
        value = ('address', self.PASSED)
        for key, escapes in ((('reg', REG_INDEX), True), (self.SPLIT, True), (self.UNREACHED, False)):
            with self.subTest(key=key):
                state = State()
                self.vm.write(state, key, value)
                self.assertEqual(state.items, {key: value, **(self.escaped(self.PASSED) if escapes else {})})

    def test_address_written_to_a_register_reaches_the_next_call(self):
        state = State()
        self.vm.write(state, ('reg', REG_INDEX), ('address', self.PASSED))
        self.vm.call(state, self.ADDRESS, 'call', MESSAGE, ())
        self.assertEqual(state.get(self.PASSED, None), ('slot_after', self.PASSED, self.ADDRESS))


class TestLayerOperands(unittest.TestCase):
    """Each layer hands the shared VM effects its own operands: a function making the effect compares clean on both
    pairs, so a layer handing them otherwise differs from the next"""

    def test_store_through_a_pointer(self):
        self.assertEqual(categories(*reference_and_mlil(pointer_store_function, 1)), set())
        self.assertEqual(hlil_categories(*mlil_and_hlil(pointer_store_function, 1)), set())

    def test_local_written_in_its_memory_form(self):
        """v = OUT_INITIAL before callee(&v): HLIL writes v as *(&v), the local, not memory behind a pointer"""
        self.assertEqual(hlil_categories(*mlil_and_hlil(initialised_out_parameter_function)), set())


class TestJoinedValues(unittest.TestCase):
    """Values met at a join compared exactly (trees.equal_trees): arms that write alike merge to one value, any others
    stay a choice on every layer, so a function compares clean"""

    def test_register_added_to_itself_in_one_arm(self):
        """One arm's sum reads one value twice, the other's an equal value and an unequal one: two values"""
        self.assertEqual(categories(*reference_and_mlil(repeated_register_arms_function)), set())

    def test_choices_of_two_and_three_values(self):
        """The arms' choices agree in their first two values: one with a third is not equal to one without"""
        self.assertEqual(hlil_categories(*mlil_and_hlil(uneven_inner_choices_function)), set())


class TestPostDominators(unittest.TestCase):
    """Cooper-Harvey-Kennedy on the reversed graph, control dependence read off its tree, and a control flow's loops
    and dependence within one iteration"""

    @classmethod
    def graph(cls, edges: dict) -> tuple[list, Callable]:
        return list(edges), lambda block: edges[block]

    @classmethod
    def flow(cls, edges: dict, branches: dict) -> ControlFlow:
        """The control flow from edges' first block; branches: block -> (address, true target, false target)"""
        return ControlFlow(next(iter(edges)), edges.__getitem__,
                           lambda block: [other for other in edges if block in edges[other]], branches.get)

    def assert_iteration(self, edges: dict, branches: dict, dependence: dict, innermost_header: dict) -> ControlFlow:
        flow = self.flow(edges, branches)
        self.assertEqual(flow.iteration_dependence, dependence)
        self.assertEqual(flow.innermost_header, innermost_header)
        return flow

    def test_diamond(self):
        blocks, successors = self.graph({'a': ['b', 'c'], 'b': ['d'], 'c': ['d'], 'd': []})
        ipdom = immediate_post_dominators(blocks, successors)
        self.assertEqual({block: ipdom[block] for block in blocks}, {'a': 'd', 'b': 'd', 'c': 'd', 'd': EXIT})

        branches = lambda block: (1, 'b', 'c') if block == 'a' else None
        dependence = control_dependence(blocks, branches, ipdom)
        self.assertEqual(dependence, {'a': frozenset(), 'b': {(1, 't')}, 'c': {(1, 'f')}, 'd': frozenset()})

    def test_loop_bodies_are_natural_loops(self):
        self.assertEqual(self.flow({'e': ['h'], 'h': ['b', 'x'], 'b': ['h'], 'x': []}, {}).loop_bodies,
                         {'h': {'h', 'b'}})
        # Two entries into a cycle: the edge back to `a` is no loop's, neither of its ends dominates the other
        self.assertEqual(self.flow({'e': ['a', 'b'], 'a': ['b'], 'b': ['a', 'x'], 'x': []}, {}).loop_bodies, {})

    def test_iteration_of_a_loop(self):
        """do (if head: then) while test: test runs in every iteration, over the whole graph again only under its own
        true arm"""
        flow = self.assert_iteration(
            {'entry': ['head'], 'head': ['then', 'test'], 'then': ['test'], 'test': ['head', 'done'], 'done': []},
            {'head': (1, 'then', 'test'), 'test': (2, 'head', 'done')},
            {'entry': set(), 'head': {(2, 't')}, 'then': {(1, 't')}, 'test': set(), 'done': set()},
            {'then': 'head', 'test': 'head'})
        self.assertEqual(flow.dependence['test'], {(2, 't')})

    def test_iteration_of_nested_loops(self):
        """while outer: (do (if inner: then) while test): the inner loop's blocks within its own iteration, its header
        within the outer loop's"""
        flow = self.assert_iteration(
            {'entry': ['outer'], 'outer': ['inner', 'done'], 'inner': ['then', 'test'], 'then': ['test'],
             'test': ['inner', 'latch'], 'latch': ['outer'], 'done': []},
            {'outer': (1, 'inner', 'done'), 'inner': (2, 'then', 'test'), 'test': (3, 'inner', 'latch')},
            {'entry': set(), 'outer': {(1, 't')}, 'inner': {(1, 't'), (3, 't')}, 'then': {(2, 't')}, 'test': set(),
             'latch': {(1, 't')}, 'done': set()},
            {'inner': 'outer', 'then': 'inner', 'test': 'inner', 'latch': 'outer'})
        self.assertEqual(flow.dependence['test'], {(1, 't'), (3, 't')})

    def test_iteration_of_a_loop_with_one_way_out(self):
        """while 1: (if head: continue); work; if work: break: work runs in an iteration only under head's false arm,
        though over the whole graph every way out of the loop passes it (skipping_loop_function)"""
        flow = self.assert_iteration(
            {'entry': ['head'], 'head': ['skip', 'work'], 'skip': ['head'], 'work': ['done', 'next'],
             'next': ['head'], 'done': []},
            {'head': (1, 'skip', 'work'), 'work': (2, 'done', 'next')},
            {'entry': set(), 'head': {(1, 't'), (2, 'f')}, 'skip': {(1, 't')}, 'work': {(1, 'f')},
             'next': {(2, 'f')}, 'done': set()},
            {'skip': 'head', 'work': 'head', 'next': 'head'})
        self.assertEqual(flow.dependence['work'], {(2, 'f')})

    def test_iteration_of_an_endless_loop(self):
        """if entry: (while 1: (if head: then else other)): both back edges end the iteration, no edge leaves it"""
        self.assert_iteration(
            {'entry': ['head', 'done'], 'head': ['then', 'other'], 'then': ['head'], 'other': ['head'], 'done': []},
            {'entry': (1, 'head', 'done'), 'head': (2, 'then', 'other')},
            {'entry': set(), 'head': {(1, 't'), (2, 't'), (2, 'f')}, 'then': {(2, 't')}, 'other': {(2, 'f')},
             'done': {(1, 'f')}},
            {'then': 'head', 'other': 'head'})

    def test_iteration_in_an_irreducible_region(self):
        """A cycle entered at a and at b is no natural loop: its blocks keep their whole-graph dependence"""
        flow = self.assert_iteration(
            {'entry': ['a', 'b'], 'a': ['b'], 'b': ['a', 'done'], 'done': []},
            {'entry': (1, 'a', 'b'), 'b': (2, 'a', 'done')},
            {'entry': set(), 'a': {(1, 't'), (2, 't')}, 'b': {(2, 't')}, 'done': set()},
            {})
        self.assertEqual(flow.iteration_dependence, flow.dependence)

    def test_loop_test_controls_the_body_and_itself(self):
        blocks, successors = self.graph({'entry': ['head'], 'head': ['body', 'exit'], 'body': ['head'], 'exit': []})
        branches = lambda block: (2, 'body', 'exit') if block == 'head' else None
        dependence = control_dependence(blocks, branches, immediate_post_dominators(blocks, successors))
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
        ipdom = immediate_post_dominators(blocks, successors)
        self.assertEqual(ipdom['d'], 'e')
        branches = lambda block: (1, 'b', 'c') if block == 'a' else None
        dependence = control_dependence(blocks, branches, ipdom)
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
