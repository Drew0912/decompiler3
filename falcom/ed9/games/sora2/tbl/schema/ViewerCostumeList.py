from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerCostumeList(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',     'W'),   # 0xFFFF: any
        ('pad02',     'P2'),
        ('id',        'I'),
        ('name',      'S'),
        ('saveBit',   'I'),
        ('uint32_14', 'I'),
        # flags, a bit per letter:
        #   (one letter set, shared with ViewerCharaList flags2)
        #   P 0x100: motions that have P in their flags2 are hidden while this costume is chosen
        #   H 0x1, M 0x2, F 0x4, A 0x8, C 0x10, B 0x20, E 0x40, N 0x80, L 0x200, J 0x800, S 0x1000:
        #     nothing found reading it
        ('flags',     'S'),
    )
