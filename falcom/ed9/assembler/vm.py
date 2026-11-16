"""The ED9 VM's facts every layer reads: the slot size, a call's setup slots, the registers and the argument order
(docs/falcom/ed9/ED9_VM.md)"""

__all__ = (
    'WORD_SIZE',
    'LOCAL_SETUP_SLOTS',
    'CALLER_FRAME_SLOTS',
    'RESULT_REGISTER',
    'REGISTER_COUNT',
    'parameter_position',
)

WORD_SIZE               = 4     # bytes per stack slot: every VM value is one 32-bit word
LOCAL_SETUP_SLOTS       = 2     # CALL: func_id, ret_addr
CALLER_FRAME_SLOTS      = 5     # PUSH_CALLER_FRAME: func_id, ret_addr, script pointer (2 slots), frame marker
RESULT_REGISTER         = 0     # where a returning call leaves its result
REGISTER_COUNT          = 16    # the VM's registers (GET_REG / SET_REG)


def parameter_position(num_params: int, frame_slot: int) -> int:
    """The 1-based parameter in frame slot frame_slot (0 at the frame base): a call pushes its arguments right to left,
    so the first parameter is in the highest slot and slot 0 holds the last"""
    return num_params - frame_slot
