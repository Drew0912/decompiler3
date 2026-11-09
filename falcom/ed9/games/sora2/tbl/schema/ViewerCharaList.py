from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerCharaList(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'W'),
        ('pad02',      'P6'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('name',       'S'),
        ('saveBit',    'I'),
        ('saveBit2',   'I'),
        # flags, a bit per letter:
        #   C 0x1, H 0x2, W 0x80: each adds two ViewerCharaEquipList rows to the list: C those with id 2 and 3,
        #     H those with 9 and 10, W those with 0 and 1
        #   G 0x4, 1 0x8, 2 0x10, 3 0x20, 4 0x100, 5 0x200: each one set adds 1 to a count. Rows with id 4 are
        #     then added if the count isn't 0; rows with id 5 to 8, 0xB and 0xC are each added while the count is
        #     above 0 and an unknown check passes, and each takes 1 from the count
        #   F 0x40: viewer menu items of kinds 2 to 5 and 0xA are apparently greyed out without F, and with F when
        #     an unknown per-slot byte is 0; kind 8 follows the same rule, with any of C, H, G, 1 to 5 in place of F
        ('flags',      'S'),
        # flags2, a bit per letter:
        #   (one letter set, shared with ViewerMotionList flags2 and the flags of ViewerCostumeList and ViewerFaceList)
        #   H 0x1, M 0x2, F 0x4, A 0x8, C 0x10, B 0x20, E 0x40, N 0x80: a motion whose flags2 has one of these is
        #     listed only for a character whose flags2 has it too; a character with H can also play the attach and
        #     detach clips
        #   P 0x100: hides motions that have P when no costume is chosen
        #   J 0x800, S 0x1000: a character with J hides the motions with J; one with S hides the faces with S
        #   L 0x200: read by code, purpose not known
        ('flags2',     'S'),
        ('float32_38', 'f'),
        ('float32_3c', 'f'),
    )
