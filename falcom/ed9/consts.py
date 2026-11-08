"""ED9 values the decompiler prints by name"""

from dc3 import IntEnum2

CHR_ID_KIND = 'ChrId'   # the ID kind of a character-ID argument (HLILConst.id_kind, HLILVariable.id_kind)


class PseudoChrId(IntEnum2):
    """Character IDs the VM resolves itself: in no table"""

    Self    = 0xFFFE    # the thread's owner
    Nothing = 0xFFFF    # no character
