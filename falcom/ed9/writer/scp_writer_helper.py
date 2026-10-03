"""DSL statements that emit no instruction (label, GLOBAL_VAR) and genLabel(), layered over the per-opcode primitives"""

import uuid

from .scp_writer_opcode_handler import *


def genLabel() -> str:
    """A fresh label name for a DSL function body, hand-written or generated. Real decompiled
    labels are always 'loc_' + hex offset, so a UUID can never collide with one; label names are
    resolved to offsets before any bytes are written, so they never appear in compiled output."""
    return str(uuid.uuid4())


def label(name: str):
    """Marks the current position in the function body as a jump target (emits no instruction)"""
    assert isinstance(name, str)
    get_scp_writer().add_label(name)


def GLOBAL_VAR(name: str, type: sint32):
    """Declares one entry of the script's global variable table (see @scena.GlobalVars())"""
    assert isinstance(name, str)
    assert isinstance(type, sint32) and not isinstance(type, bool), f'GLOBAL_VAR type must be an int, not {type!r}'
    return get_scp_writer().add_global_var(name, type)
