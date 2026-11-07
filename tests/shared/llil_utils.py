#!/usr/bin/env python3
"""A Falcom LLIL builder ready for a hand-built test function, the lift of hand-written bytecode, and the small
functions and checks two test files share"""

import unittest

from falcom.ed9.ir.llil import ED9VMLifter
from falcom.ed9.ir.llil.llil_builder import FalcomVMBuilder
from ir.core import IRParameter
from ir.llil.llil import WORD_SIZE, LowLevelILFunction
from ir.mlil.mlil import MediumLevelILFunction
from tests.shared import scp_asm


FUNC_START = 0x1000
BLOCK_STRIDE = 0x10
SECOND_BLOCK_START = FUNC_START + BLOCK_STRIDE
THIRD_BLOCK_START = FUNC_START + 2 * BLOCK_STRIDE
FOURTH_BLOCK_START = FUNC_START + 3 * BLOCK_STRIDE
FUNC_NAME = 'test_func'
ARG_VALUE = 7
ONE_ARG = 1


def make_builder(num_params: int = 0) -> FalcomVMBuilder:
    """A builder with one function and its entry block current"""
    builder = FalcomVMBuilder()
    builder.create_function(FUNC_NAME, FUNC_START, [IRParameter(f'arg{i + 1}') for i in range(num_params)])
    builder.set_current_block(builder.create_basic_block(FUNC_START, FUNC_NAME))
    return builder


def lift_asm(asm: scp_asm.Asm, *, argc: int = 0, others: tuple = ()) -> tuple:
    """asm disassembled as scp_asm's main function (others beside it) and lifted: (parser, its LLIL)"""
    parser, functions = scp_asm.Program(scp_asm.Func(scp_asm.FUNC_NAME, argc, asm), *others).disassemble()
    main = next(func for func in functions if func.name == scp_asm.FUNC_NAME)
    return parser, ED9VMLifter(parser=parser).lift_function(main)


def instructions_of(func, kind: type) -> list:
    """func's instructions of type kind, in block order"""
    return [inst for block in func.basic_blocks for inst in block.instructions if isinstance(inst, kind)]


def build_function_with_deref(num_params: int, offset: int, *, deref_write: bool, with_ret: bool = False):
    """1-param function: load_stack_deref(offset) if not deref_write, else push a marker then
    pop_to_deref(offset). with_ret also pops the stack and returns, which MLIL translation needs (every block
    ends in a terminal); without it only the LLIL shape is checked."""
    builder = make_builder(num_params)
    entry = builder.current_block

    if deref_write:
        builder.push_int(99)
        builder.pop_to_deref(offset)
    else:
        builder.load_stack_deref(offset)

    if with_ret:
        if not deref_write:
            builder.pop_bytes(WORD_SIZE)   # load_stack_deref leaves its loaded value pushed
        builder.pop_bytes(num_params * WORD_SIZE)   # a real function cleans up its own params too
        builder.ret()

    return builder.function, entry


def build_call_function() -> LowLevelILFunction:
    """A call, then a return, one address per LLIL instruction - the call ends its LLIL block, so translation
    leaves a goto to the return block that block merge removes"""
    builder = FalcomVMBuilder()
    builder.create_function('provenance_test', FUNC_START)
    builder.set_current_block(builder.create_basic_block(FUNC_START, 'entry'))
    ret_block = builder.create_basic_block(FUNC_START + BLOCK_STRIDE, 'ret')
    emits = (builder.push_func_id, lambda: builder.push_ret_addr(ret_block), lambda: builder.push_int(ARG_VALUE),
             lambda: builder.call_local('f', ONE_ARG))
    for offset, emit in enumerate(emits):
        builder.set_current_address(FUNC_START + offset)
        emit()

    builder.begin_block(ret_block)
    builder.set_current_address(FUNC_START + BLOCK_STRIDE)
    builder.ret()
    return builder.finalize()


def llil_instructions(llil: LowLevelILFunction) -> dict:
    return {inst.inst_index: inst for block in llil.basic_blocks for inst in block.instructions}


class ProvenanceTestCase(unittest.TestCase):
    def check_contract(self, mlil: MediumLevelILFunction, llil: LowLevelILFunction):
        """Each statement names an LLIL instruction at its own address, and inst_index runs 0..N-1 in block order"""
        sources = llil_instructions(llil)
        mlil_statements = list(mlil.iter_instructions())
        for inst in mlil_statements:
            with self.subTest(inst=str(inst)):
                self.assertIn(inst.llil_index, sources)
                self.assertEqual(inst.address, sources[inst.llil_index].address)

        self.assertEqual([inst.inst_index for inst in mlil_statements], list(range(len(mlil_statements))))
