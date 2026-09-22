"""Position-independent fingerprint of a disassembled function.

Two copies of the same function in different scripts differ in bytes, because branch targets are
absolute offsets and CALL operands are per-script table ids. The fingerprint normalizes those away:
same fingerprint means the same function in every way that affects game logic. Shared by the
common-function library generator and the DSL emitter, so both sides always agree.
"""

import hashlib
from typing import TYPE_CHECKING, Callable

from ...disasm.instruction import Instruction, Operand
from ...disasm.instruction_table import OperandType
from ...disasm.ed9_optable import ED9OperandType

if TYPE_CHECKING:
    from ...parser.scp import ScpParser
    from ...parser.types_parser import Function

BRANCH_TAG              = 'L'   # branch target, as the destination's ordinal among the reachable instructions
UNRESOLVED_BRANCH_TAG   = 'L?'  # branch target that isn't a reachable instruction start, relative to the function
FUNC_TAG                = 'F'   # CALL target, by name
GLOBAL_TAG              = 'G'   # global variable, by name
GLOBAL_INDEX_TAG        = 'G#'  # global variable index with no name in the table
VALUE_TAG               = 'V'   # any other operand, by content

DIGEST_ENCODING = 'utf-8'


def operand_key(op: Operand, func_offset: int, ordinals: dict[int, int], get_func_name: Callable[[int], str], get_global_name: Callable[[int], str | None]) -> tuple:
    match op.descriptor.type:
        case OperandType.Offset:
            if op.value in ordinals:
                return (BRANCH_TAG, ordinals[op.value])

            return (UNRESOLVED_BRANCH_TAG, op.value - func_offset)

        case ED9OperandType.Func:
            return (FUNC_TAG, get_func_name(op.value))

        case ED9OperandType.GlobalVar:
            name = get_global_name(op.value)
            return (GLOBAL_TAG, name) if name is not None else (GLOBAL_INDEX_TAG, op.value)

        case _:
            # repr, never ==: ScpValue has no __eq__, and 1 == 1.0 while their encodings differ
            return (VALUE_TAG, repr(op.value))


def body_fingerprint(instructions: list[Instruction], func_offset: int, get_func_name: Callable[[int], str], get_global_name: Callable[[int], str | None]) -> tuple:
    """instructions: the function's reachable instructions in offset order (ScpParser.get_instructions)"""
    ordinals = {inst.offset: ordinal for ordinal, inst in enumerate(instructions)}

    return tuple(
        (int(inst.opcode), *(operand_key(op, func_offset, ordinals, get_func_name, get_global_name) for op in inst.operands))
        for inst in instructions
    )


def signature_fingerprint(func: 'Function') -> tuple:
    """Parameter flags and defaults - stored outside the code, so the body alone can't see them"""
    return tuple((int(param.type.flags), repr(param.default_value)) for param in func.params)


def function_fingerprint(parser: 'ScpParser', func: 'Function') -> tuple:
    body = body_fingerprint(parser.get_instructions(func), func.offset, parser.get_func_name_from_func_id, parser.get_global_name_from_index)
    return (body, signature_fingerprint(func))


def fingerprint_digest(fingerprint: tuple) -> str:
    return hashlib.sha256(repr(fingerprint).encode(DIGEST_ENCODING)).hexdigest()
