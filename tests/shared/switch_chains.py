#!/usr/bin/env python3
"""Dispatch chains as the compiler writes them, assembled, and the checks both LLIL -> MLIL paths' switch tests share;
it imports logic_check from tools/, which the importing test puts on sys.path"""

from falcom.ed9.ir.hlil.hlil_converter import convert_falcom_mlil_to_hlil
from ir.hlil import HLILSwitch, iter_tree
from ir.llil.llil import WORD_SIZE
from tests.shared.llil_utils import lift_asm
from tests.shared.logic_check_functions import GLOBAL_A, hlil_categories, return_nothing
from tests.shared.scp_asm import Asm, returning_callee

SELECTOR_GLOBAL = 2             # the global a register selector is loaded from
VALUES = (1, 2, 3)
FUNNEL_LABEL = 4                # a second label sharing the first case's body


class Selector:
    """Where the chain's tests read the value they dispatch on: REG[0], set once from a global, as the compiler does,
    or the function's parameter, read again by each test"""

    def __init__(self, argc: int, scrutinee: str):
        self.argc = argc
        self.scrutinee = scrutinee      # the decompile path's switch scrutinee

    def setup(self, asm: Asm):
        if not self.argc:
            asm.load_global(SELECTOR_GLOBAL); asm.set_reg(0)

    def read(self, asm: Asm):
        if self.argc:
            asm.load_stack(-WORD_SIZE)
        else:
            asm.get_reg(0)

    def finish(self, asm: Asm):
        if self.argc:
            asm.pop(WORD_SIZE)          # the parameter, before the return
        return_nothing(asm)


IN_REGISTER = Selector(0, 'REGS[0]')
PARAMETER = Selector(1, 'arg1')


def case_body(asm: Asm, value: int):
    asm.push_int(value); asm.set_global(GLOBAL_A)


def if_else_chain(test, values=VALUES, selector=IN_REGISTER) -> Asm:
    """if / else if: each test(asm, value) jumps over its case body to the next test when it fails"""
    asm = Asm()
    selector.setup(asm)
    for value in values:
        selector.read(asm); test(asm, value); asm.jz(f'next_{value}')
        case_body(asm, value); asm.jmp('end')
        asm.label(f'next_{value}')
    asm.label('end')
    selector.finish(asm)
    return asm


def jump_chain(links, test_jump, selector=IN_REGISTER) -> Asm:
    """Every test first, each (value, case) jumping to its case's body when it holds (test_jump(asm, value, label)),
    the bodies after"""
    asm = Asm()
    selector.setup(asm)
    for value, case in links:
        selector.read(asm); test_jump(asm, value, f'case_{case}')
    asm.jmp('end')
    for case in dict.fromkeys(case for _, case in links):
        asm.label(f'case_{case}'); case_body(asm, case); asm.jmp('end')
    asm.label('end')
    selector.finish(asm)
    return asm


def equals(asm: Asm, value: int):
    asm.push_int(value); asm.eq()


def jump_if_equal(asm: Asm, value: int, label: str):
    equals(asm, value); asm.jnz(label)


def jump_if_equal_through_ez(asm: Asm, value: int, label: str):
    """EQ; EZ; JZ: two truth tests over the equality"""
    equals(asm, value); asm.ez(); asm.jz(label)


def zero_or_equals(asm: Asm, value: int):
    """The value 0 tested by EZ, as the compiler writes `x == 0`; any other by EQ"""
    if value:
        equals(asm, value)
    else:
        asm.ez()


def less_than(asm: Asm, value: int):
    asm.push_int(value); asm.lt()


# chain -> (its function, the selector, the labels per case)
SWITCH_SHAPES = {
    'EQ; JZ next': (lambda: if_else_chain(equals), IN_REGISTER, [[value] for value in VALUES]),
    'EQ; JNZ case': (lambda: jump_chain([(value, value) for value in VALUES], jump_if_equal), IN_REGISTER,
                     [[value] for value in VALUES]),
    'EQ; EZ; JZ case': (lambda: jump_chain([(value, value) for value in VALUES], jump_if_equal_through_ez),
                        IN_REGISTER, [[value] for value in VALUES]),
    'two tests to one case': (
        lambda: jump_chain([(VALUES[0], VALUES[0]), (FUNNEL_LABEL, VALUES[0])]
                           + [(value, value) for value in VALUES[1:]], jump_if_equal),
        IN_REGISTER, [[VALUES[0], FUNNEL_LABEL]] + [[value] for value in VALUES[1:]]),
    'EZ for 0': (lambda: if_else_chain(zero_or_equals, (0, *VALUES[:2])), IN_REGISTER,
                 [[0]] + [[value] for value in VALUES[:2]]),
    'a parameter read by each test': (lambda: if_else_chain(equals, selector=PARAMETER), PARAMETER,
                                      [[value] for value in VALUES]),
}

# chain -> its function
IF_SHAPES = {
    'two tests': lambda: if_else_chain(equals, VALUES[:2]),
    'orderings': lambda: if_else_chain(less_than),
}


def hlil_and_differences(build, argc: int, convert) -> tuple:
    """build()'s HLIL through convert, and the logic check's MLIL -> HLIL categories on it"""
    _, llil = lift_asm(build(), argc=argc, others=(returning_callee(),))
    mlil = convert(llil)
    hlil = convert_falcom_mlil_to_hlil(mlil)
    return hlil, hlil_categories(mlil, hlil)


def switches(hlil) -> list[HLILSwitch]:
    return [node for node in iter_tree(hlil.body) if isinstance(node, HLILSwitch)]


def case_labels(switch: HLILSwitch) -> list[list]:
    """Each case's labels, the default left out"""
    return [[value.value for value in case.values] for case in switch.cases if not case.is_default()]
