#!/usr/bin/env python3
'''A Falcom LLIL builder ready for a hand-built test function'''

from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder


FUNC_START = 0x1000
FUNC_NAME = 'test_func'


def make_builder(num_params: int = 0) -> FalcomVMBuilder:
    '''A builder with one function and its entry block current'''
    builder = FalcomVMBuilder()
    builder.create_function(FUNC_NAME, FUNC_START, num_params = num_params)
    builder.set_current_block(builder.create_basic_block(FUNC_START, FUNC_NAME))
    return builder
