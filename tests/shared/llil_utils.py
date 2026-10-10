#!/usr/bin/env python3
'''A Falcom LLIL builder ready for a hand-built test function, and the lift of hand-written bytecode'''

from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder
from tests.shared import scp_asm


FUNC_START = 0x1000
BLOCK_STRIDE = 0x10
SECOND_BLOCK_START = FUNC_START + BLOCK_STRIDE
THIRD_BLOCK_START = FUNC_START + 2 * BLOCK_STRIDE
FOURTH_BLOCK_START = FUNC_START + 3 * BLOCK_STRIDE
FUNC_NAME = 'test_func'


def make_builder(num_params: int = 0) -> FalcomVMBuilder:
    '''A builder with one function and its entry block current'''
    builder = FalcomVMBuilder()
    builder.create_function(FUNC_NAME, FUNC_START, num_params = num_params)
    builder.set_current_block(builder.create_basic_block(FUNC_START, FUNC_NAME))
    return builder


def lift_asm(asm: scp_asm.Asm, *, argc: int = 0, others: tuple = ()) -> tuple:
    '''asm disassembled as scp_asm's main function (others beside it) and lifted: (parser, its LLIL)'''
    parser, functions = scp_asm.Program(scp_asm.Func(scp_asm.FUNC_NAME, argc, asm), *others).disassemble()
    main = next(func for func in functions if func.name == scp_asm.FUNC_NAME)
    return parser, ED9VMLifter(parser = parser).lift_function(main)


def instructions_of(func, kind: type) -> list:
    '''func's instructions of type kind, in block order'''
    return [inst for block in func.basic_blocks for inst in block.instructions if isinstance(inst, kind)]
