#!/usr/bin/env python3
"""Disassembler Demo - hand-coded ED9 bytecode disassembled to LLIL DSL and checked against expected output"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import difflib
from ml import *
from falcom.ed9.disasm import *
from falcom.ed9.disasm.ed9_optable import ed9_create_fallthrough_jump
from falcom.ed9.parser import *

HEX_DUMP_WIDTH = 16

# Bytecode below is hand-coded on purpose, with the DSL equivalent of each instruction in a comment.
# PUSH is 6 bytes: opcode, size byte (always 4), 4-byte ScpValue (top 2 bits = type, 01 = Integer).


def format_hex_dump(bytecode: bytes) -> list[str]:
    lines = []
    for offset in range(0, len(bytecode), HEX_DUMP_WIDTH):
        chunk = bytecode[offset:offset + HEX_DUMP_WIDTH]
        lines.append(f'  {offset:08X}: {chunk.hex(" ").upper()}')

    return lines


def disasm_to_dsl(name: str, bytecode: bytes) -> list[str]:
    context = DisassemblerContext(create_fallthrough_jump = ed9_create_fallthrough_jump)
    disasm = Disassembler(ED9_INSTRUCTION_TABLE, context)

    func = Function()
    func.name = name
    func.offset = 0
    func.is_common_func = False
    func.entry_block = disasm.disasm_function(bytecode, offset = 0, name = name)

    return Formatter(FormatterContext()).format_function(func)


def run_case(title: str, name: str, bytecode: bytes, expected: str) -> bool:
    print(f'=== {title} ===\n')

    print(f'Bytecode ({len(bytecode)} bytes):')
    print('\n'.join(format_hex_dump(bytecode)))
    print()

    try:
        actual = [line.rstrip() for line in disasm_to_dsl(name, bytecode)]

    except Exception as e:
        print(f'FAIL: {name}: {type(e).__name__}: {e}\n')
        return False

    print('LLIL DSL:')
    print('\n'.join(actual))
    print()

    expected_lines = expected.strip('\n').splitlines()
    if actual == expected_lines:
        print(f'PASS: {name}\n')
        return True

    print(f'FAIL: {name}')
    print('\n'.join(difflib.unified_diff(expected_lines, actual, 'expected', 'actual', lineterm = '')))
    print()
    return False


def test_simple_function() -> bool:
    bytecode = bytes([
        0x00, 0x04, 0x01, 0x00, 0x00, 0x40,  # 0x00: PUSH_INT(1)
        0x00, 0x04, 0x02, 0x00, 0x00, 0x40,  # 0x06: PUSH_INT(2)
        0x10,                                # 0x0C: ADD()
        0x0A, 0x00,                          # 0x0D: SET_REG(0)
        0x0D,                                # 0x0F: RETURN()
    ])

    expected = '''
@scena.LLILCode()
def test_add():
    PUSH_INT(1)
    PUSH_INT(2)
    ADD()
    SET_REG(0)
    RETURN()
'''

    return run_case('Simple Function', 'test_add', bytecode, expected)


def test_conditional() -> bool:
    bytecode = bytes([
        0x09, 0x00,                          # 0x00: GET_REG(0)
        0x0F, 0x12, 0x00, 0x00, 0x00,        # 0x02: POP_JMP_ZERO('loc_12')
                                             #       label('loc_7')
        0x00, 0x04, 0x01, 0x00, 0x00, 0x40,  # 0x07: PUSH_INT(1)
        0x0B, 0x18, 0x00, 0x00, 0x00,        # 0x0D: JMP('loc_18')
                                             #       label('loc_12')
        0x00, 0x04, 0x00, 0x00, 0x00, 0x40,  # 0x12: PUSH_INT(0)
                                             #       label('loc_18')
        0x0A, 0x00,                          # 0x18: SET_REG(0)
        0x0D,                                # 0x1A: RETURN()
    ])

    expected = '''
@scena.LLILCode()
def test_cond():
    GET_REG(0)
    POP_JMP_ZERO('loc_12')

    label('loc_7')

    PUSH_INT(1)
    JMP('loc_18')

    label('loc_12')

    PUSH_INT(0)

    label('loc_18')

    SET_REG(0)
    RETURN()
'''

    return run_case('Conditional Branch', 'test_cond', bytecode, expected)


def test_caller_frame() -> bool:
    bytecode = bytes([
        0x25, 0x12, 0x00, 0x00, 0x00,        # 0x00: PUSH_CALLER_FRAME('loc_12')
        0x00, 0x04, 0x01, 0x00, 0x00, 0x40,  # 0x05: PUSH_INT(1)
        0x0A, 0x00,                          # 0x0B: SET_REG(0)
        0x0B, 0x12, 0x00, 0x00, 0x00,        # 0x0D: JMP('loc_12')
                                             #       label('loc_12')
        0x00, 0x04, 0x00, 0x00, 0x00, 0x40,  # 0x12: PUSH_INT(0)
        0x0A, 0x00,                          # 0x18: SET_REG(0)
        0x0D,                                # 0x1A: RETURN()
    ])

    expected = '''
@scena.LLILCode()
def test_frame():
    PUSH_CALLER_FRAME('loc_12')
    PUSH_INT(1)
    SET_REG(0)
    JMP('loc_12')

    label('loc_12')

    PUSH_INT(0)
    SET_REG(0)
    RETURN()
'''

    return run_case('PUSH_CALLER_FRAME', 'test_frame', bytecode, expected)


def test_loop() -> bool:
    bytecode = bytes([
        0x00, 0x04, 0x00, 0x00, 0x00, 0x40,  # 0x00: PUSH_INT(0)
        0x0A, 0x00,                          # 0x06: SET_REG(0)
                                             #       label('loc_8')
        0x09, 0x00,                          # 0x08: GET_REG(0)
        0x00, 0x04, 0x0A, 0x00, 0x00, 0x40,  # 0x0A: PUSH_INT(10)
        0x19,                                # 0x10: LT()
        0x0F, 0x26, 0x00, 0x00, 0x00,        # 0x11: POP_JMP_ZERO('loc_26')
                                             #       label('loc_16')
        0x09, 0x00,                          # 0x16: GET_REG(0)
        0x00, 0x04, 0x01, 0x00, 0x00, 0x40,  # 0x18: PUSH_INT(1)
        0x10,                                # 0x1E: ADD()
        0x0A, 0x00,                          # 0x1F: SET_REG(0)
        0x0B, 0x08, 0x00, 0x00, 0x00,        # 0x21: JMP('loc_8')
                                             #       label('loc_26')
        0x00, 0x04, 0x00, 0x00, 0x00, 0x40,  # 0x26: PUSH_INT(0)
        0x0A, 0x00,                          # 0x2C: SET_REG(0)
        0x0D,                                # 0x2E: RETURN()
    ])

    expected = '''
@scena.LLILCode()
def test_loop():
    PUSH_INT(0)
    SET_REG(0)

    label('loc_8')

    GET_REG(0)
    PUSH_INT(10)
    LT()
    POP_JMP_ZERO('loc_26')

    label('loc_16')

    GET_REG(0)
    PUSH_INT(1)
    ADD()
    SET_REG(0)
    JMP('loc_8')

    label('loc_26')

    PUSH_INT(0)
    SET_REG(0)
    RETURN()
'''

    return run_case('Loop (Backward Jump)', 'test_loop', bytecode, expected)


def test_jump_into_middle() -> bool:
    # JMP('loc_10') targets the middle of the already disassembled entry block, which must be split there
    bytecode = bytes([
        0x00, 0x04, 0x00, 0x00, 0x00, 0x40,  # 0x00: PUSH_INT(0)
        0x0A, 0x00,                          # 0x06: SET_REG(0)
        0x00, 0x04, 0x01, 0x00, 0x00, 0x40,  # 0x08: PUSH_INT(1)
        0x0A, 0x01,                          # 0x0E: SET_REG(1)
                                             #       label('loc_10')
        0x09, 0x01,                          # 0x10: GET_REG(1)
        0x00, 0x04, 0x0A, 0x00, 0x00, 0x40,  # 0x12: PUSH_INT(10)
        0x19,                                # 0x18: LT()
        0x0F, 0x2E, 0x00, 0x00, 0x00,        # 0x19: POP_JMP_ZERO('loc_2E')
                                             #       label('loc_1E')
        0x09, 0x01,                          # 0x1E: GET_REG(1)
        0x00, 0x04, 0x01, 0x00, 0x00, 0x40,  # 0x20: PUSH_INT(1)
        0x10,                                # 0x26: ADD()
        0x0A, 0x01,                          # 0x27: SET_REG(1)
        0x0B, 0x10, 0x00, 0x00, 0x00,        # 0x29: JMP('loc_10')
                                             #       label('loc_2E')
        0x00, 0x04, 0x00, 0x00, 0x00, 0x40,  # 0x2E: PUSH_INT(0)
        0x0A, 0x00,                          # 0x34: SET_REG(0)
        0x0D,                                # 0x36: RETURN()
    ])

    expected = '''
@scena.LLILCode()
def test_split():
    PUSH_INT(0)
    SET_REG(0)
    PUSH_INT(1)
    SET_REG(1)

    label('loc_10')

    GET_REG(1)
    PUSH_INT(10)
    LT()
    POP_JMP_ZERO('loc_2E')

    label('loc_1E')

    GET_REG(1)
    PUSH_INT(1)
    ADD()
    SET_REG(1)
    JMP('loc_10')

    label('loc_2E')

    PUSH_INT(0)
    SET_REG(0)
    RETURN()
'''

    return run_case('Jump Into Middle of Block', 'test_split', bytecode, expected)


def main() -> int:
    tests = [
        test_simple_function,
        test_conditional,
        test_caller_frame,
        test_loop,
        test_jump_into_middle,
    ]

    failed = [test.__name__ for test in tests if not test()]

    print(f'{len(tests) - len(failed)}/{len(tests)} passed')
    if failed:
        print(f'Failed: {", ".join(failed)}')
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
