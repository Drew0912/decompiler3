#!/usr/bin/env python3
"""The logic check (tools/logic_check/), MLIL against HLIL: a bug planted in the HLIL of a small assembled function
shows up as its category against the MLIL it came from; structures HLIL builds otherwise than MLIL writes them compare
clean"""

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

from ir.hlil.hlil import (
    BinaryOp, HighLevelILFunction, HLILAssign, HLILBinaryOp, HLILBlock, HLILBreak, HLILCall, HLILConst, HLILContinue,
    HLILDoWhile, HLILExprStmt, HLILIf, HLILReturn, HLILSwitch, HLILUnaryOp, HLILUnstructured, HLILVar, HLILVariable,
    HLILWhile, UnaryOp, VariableKind, iter_tree,
)
from ir.llil.llil import WORD_SIZE
from ir.mlil.mlil import (
    MediumLevelILFunction, MLILCall, MLILConst, MLILEq, MLILGoto, MLILIf, MLILNe, MLILRet, MLILSetVar, MLILVar,
)
from tests.shared.hlil_cfg_utils import EARLY_EXIT, SHARED_LOOP, build_function, structure, to_hlil
from tests.shared.ir_utils import connect
from tests.shared.logic_check_functions import (
    GLOBAL_A, GLOBAL_B, GLOBAL_C, GLOBAL_D, LOOP_LIMIT, NESTED_TESTS, REG_INDEX, STORED, UNRELATED_ARG, branch_function,
    call, calls_function, hlil_categories, loop_call_function, mlil_and_hlil, return_nothing, statements,
)
from tests.shared.scp_asm import CALLEE_ID, CALLER_ID, Asm
import logic_check
from logic_check import choice_lifting, decision_diagrams, formulas
from logic_check.facts import RETURN_KEY
from logic_check.trees import op

STARTED = 5
EARLY_ARG = 9
SKIPPED = 1
CHAIN_CASES = 3                 # HLIL's if-to-switch takes a chain of at least SWITCH_MIN_CASES tests
DIAGRAM_NODES_TOO_FEW = 2       # a decision_diagrams.DIAGRAM_NODE_CAP no decision diagram fits in (its two terminals)
CHAIN_GLOBAL = 10               # the first global a chain of register writes tests (register_chain)
CHAIN_LENGTH = 3                # a chain's writes in the HLIL structure tests: merges nested in merges
LIFTED_FLAG_DIAGRAM_NODES = 11  # a DIAGRAM_NODE_CAP the planted flag test's guards fit in (9, 10), not lifted (13, 16)
ORDERING_ROWS = 4               # a ROW_CAP an ordering's formulas fit in, not those with two more tests (2 to 6 do)
TWO_TESTS_ROWS = 2              # a ROW_CAP one test's formulas fit in, not two tests' (2 and 3 do)
ARM_VALUE, OTHER_ARM_VALUE = 100, 200
LIFTING_CAP = 8                 # choice_lifting.LIFTED_CHOICES in the tests past it, so their chains stay short
LONG_CHAIN = LIFTING_CAP + 1    # writes whose merges are more alternatives than are lifted


# === Assembled functions ===

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


def calls_in_two_of_three_arms_function() -> tuple[Asm, int]:
    """if GLOBAL_A: callee(); if GLOBAL_B: callee() elif GLOBAL_C: GLOBAL_D = STORED else GLOBAL_D = UNRELATED_ARG;
    GLOBAL_A = REG: the register read after the three arms' join, whose choice of call epochs holds the first join's
    choice in two arms"""
    asm = Asm()
    asm.load_global(GLOBAL_A); asm.jz('first_join')
    call(asm, 'first')
    asm.label('first_join'); asm.load_global(GLOBAL_B); asm.jz('third_test')
    call(asm, 'second'); asm.jmp('final')
    asm.label('third_test'); asm.load_global(GLOBAL_C); asm.jz('third_else')
    asm.push_int(STORED); asm.set_global(GLOBAL_D); asm.jmp('final')
    asm.label('third_else'); asm.push_int(UNRELATED_ARG); asm.set_global(GLOBAL_D)
    asm.label('final'); asm.get_reg(REG_INDEX); asm.set_global(GLOBAL_A)
    return_nothing(asm)
    return asm, 0


def region_two_conditions_share_function(pointer: bool = False) -> tuple[Asm, int]:
    """if GLOBAL_A: (callee(); if GLOBAL_C: shared) else shared, shared: GLOBAL_D = GLOBAL_B (pointer: *arg): the region
    two conditions share, which HLIL repeats, one copy after the call and one with none on the way in, and MLIL reads
    after their join"""
    asm = Asm()
    asm.load_global(GLOBAL_A); asm.jz('shared')
    call(asm, 'called')
    asm.load_global(GLOBAL_C); asm.jz('end')
    asm.label('shared')
    if pointer:
        asm.load_stack_deref(-WORD_SIZE)
    else:
        asm.load_global(GLOBAL_B)
    asm.set_global(GLOBAL_D)
    asm.label('end')
    if pointer:
        asm.pop(WORD_SIZE)
    return_nothing(asm)
    return asm, 0


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


# === Mutations of the HLIL ===

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

    @mock.patch.object(choice_lifting, 'LIFTED_CHOICES', LIFTING_CAP)
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

    def test_register_read_after_a_choice_of_calls_shared_by_two_arms(self):
        """The register a read takes after either call or none, its choice of epochs made of the first join's twice"""
        self.assertEqual(hlil_categories(*mlil_and_hlil(calls_in_two_of_three_arms_function)), set())

    def test_global_read_in_a_region_repeated_after_a_call_on_one_way(self):
        """Each copy reads the global after its own way in, the call or none; MLIL after the join, whose global epoch
        the way with none comes in with as a read takes it"""
        self.assert_repeated_region_clean(*mlil_and_hlil(region_two_conditions_share_function))

    def test_pointer_read_in_a_region_repeated_after_a_call_on_one_way(self):
        """The same for memory behind a pointer (the memory epoch)"""
        self.assert_repeated_region_clean(*mlil_and_hlil(lambda: region_two_conditions_share_function(pointer=True),
                                                         argc=1))

    def assert_repeated_region_clean(self, mlil, hlil):
        stores = [node for node in iter_tree(hlil.body)
                  if isinstance(node, HLILAssign) and reads_global(node.dest, GLOBAL_D)]
        self.assertEqual(len(stores), 2)        # the shape the test needs: the shared region in each arm
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
        with mock.patch.object(choice_lifting, 'LIFTED_CHOICES', 1):
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


if __name__ == '__main__':
    unittest.main()
