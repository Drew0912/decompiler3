#!/usr/bin/env python3
'''A Falcom LLIL builder ready for a hand-built test function'''

from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder


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
