"""HLIL's operators (re-exported by ir/hlil/hlil.py, which holds what they mean), in a module of their own so the HLIL
DSL's nodes can key on them without loading HLIL's passes"""

from enum import auto, IntEnum


class BinaryOp(IntEnum):
    """Binary operators"""

    # Arithmetic
    ADD     = auto()
    SUB     = auto()
    MUL     = auto()
    DIV     = auto()
    MOD     = auto()

    # Comparison
    EQ      = auto()
    NE      = auto()
    LT      = auto()
    LE      = auto()
    GT      = auto()
    GE      = auto()

    # Logical: the VM's eager ops, both operands always run
    AND     = auto()
    OR      = auto()

    # Logical, recovered from jumps: the right operand runs only when the left leaves the answer open
    AND_THEN = auto()
    OR_ELSE  = auto()

    # Bitwise
    BIT_AND = auto()
    BIT_OR  = auto()
    BIT_XOR = auto()
    SHL     = auto()
    SHR     = auto()


class UnaryOp(IntEnum):
    """Unary operators"""

    NEG     = auto()
    NOT     = auto()
    BIT_NOT = auto()
