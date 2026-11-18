#!/usr/bin/env python3
"""Shared helpers for the HLIL DSL's compile-side tests: a script compiled by each kind of game writer, an HLIL body
against its LLIL twin, and a small library of real function names with their parameter counts"""

import functools
from typing import Callable

from falcom.ed9.games.kuro1.writer.scp_writer import Kuro1ScpWriter
from falcom.ed9.games.sora2.writer.scp_writer import Sora2ScpWriter
from falcom.ed9.writer.scp_writer import ScpWriter
from falcom.ed9.writer.scp_writer_helper import *
from tests.shared.scp_writer_test_utils import WriterTestCase, fresh_writer

# The base writer's rules (sora1, sora2) and kuro1's (kuro2, kai1): records on common functions, strings pooled apart
WRITER_CLASSES = (Sora2ScpWriter, Kuro1ScpWriter)


@library_function
def chr_wait_animeclip(arg1: Value32, arg2: Value32):
    POP(2 * WORD_SIZE)
    RETURN()


@library_function
def chr_change_skin(arg1: Value32, arg2: NullableStr, arg3: Value32):
    POP(3 * WORD_SIZE)
    RETURN()


@library_function
def chr_set_animeclip_speed(arg1: Value32, arg2: Nullable32, arg3: Value32 = 0):
    POP(3 * WORD_SIZE)
    RETURN()


@library_function
def chr_play_animeclip(arg1: Value32, arg2: NullableStr, arg3: Nullable32, arg4: Value32, arg5: Value32 = 0):
    POP(5 * WORD_SIZE)
    RETURN()


@library_function
def chr_allow_controll(arg1: Value32, arg2: Value32):
    POP(2 * WORD_SIZE)
    RETURN()


@library_function
def map_obj_play_animeclip(arg1: NullableStr, arg2: NullableStr, arg3: Nullable32, arg4: Value32, arg5: Value32):
    POP(5 * WORD_SIZE)
    RETURN()


@library_function
def map_obj_set_animeclip_frame(arg1: NullableStr, arg2: Nullable32, arg3: Value32):
    POP(3 * WORD_SIZE)
    RETURN()


@library_function
def map_obj_get_animeclip_frame_length(arg1: NullableStr, arg2: Value32):
    """Returns its first argument"""
    LOAD_STACK(-WORD_SIZE)
    SET_REG(0)
    POP(2 * WORD_SIZE)
    RETURN()


@library_function
def AdjustSpeed(arg1: Nullable32):
    """Returns its argument"""
    LOAD_STACK(-WORD_SIZE)
    SET_REG(0)
    POP(WORD_SIZE)
    RETURN()


@library_function
def AdjustBlend(arg1: Nullable32, arg2: Nullable32):
    """Returns its first argument"""
    LOAD_STACK(-WORD_SIZE)
    SET_REG(0)
    POP(2 * WORD_SIZE)
    RETURN()


LIBRARY = [chr_wait_animeclip, chr_change_skin, chr_set_animeclip_speed, chr_play_animeclip, chr_allow_controll,
           map_obj_play_animeclip, map_obj_set_animeclip_frame, map_obj_get_animeclip_frame_length, AdjustSpeed,
           AdjustBlend]


def passthrough(func: Callable) -> Callable:
    """An ordinary decorator, a functools.wraps wrapper taking *args"""
    @functools.wraps(func)
    def wrapper(*args):
        func(*args)

    return wrapper


def use_library(scena: ScpWriter):
    """The script imports LIBRARY"""
    @scena.CommonImports()
    def commonImports():
        return LIBRARY


class HLILTestCase(WriterTestCase):
    """Scripts compiled to test.dat in a temp dir, each by a fresh writer"""

    def compiled(self, register: Callable[[ScpWriter], None], writer_class: type[ScpWriter] = Sora2ScpWriter,
                 check: bool = True) -> bytes:
        """The bytes of the script register(scena) declares, compiled by a fresh writer_class, the compile check on or
        off; the writer is the one every DSL statement and hook reaches meanwhile"""
        writer = fresh_writer(self.dat, writer_class)
        writer.check_compiled = check
        register(writer)
        return writer.build({})

    def assert_twins(self, hlil: Callable[[ScpWriter], None], llil: Callable[[ScpWriter], None]):
        """The two scripts compile to the same bytes, by each kind of writer"""
        for writer_class in WRITER_CLASSES:
            with self.subTest(writer=writer_class.__name__):
                self.assertEqual(self.compiled(hlil, writer_class), self.compiled(llil, writer_class))
