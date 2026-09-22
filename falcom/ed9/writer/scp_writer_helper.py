"""User-facing utility helpers for the scp_writer DSL, layered over the per-opcode primitives"""

import uuid

from .scp_writer_opcode_handler import *

# utils

def genLabel() -> str:
    """A fresh label name for a DSL function body, hand-written or generated. Real decompiled
    labels are always 'loc_' + hex offset, so a UUID can never collide with one; label names are
    resolved to offsets before any bytes are written, so they never appear in compiled output."""
    return str(uuid.uuid4())
