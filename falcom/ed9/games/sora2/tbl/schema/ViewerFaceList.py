from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerFaceList(TableDataEntry):
    DESCRIPTOR = (
        ('id',       'I'),
        ('pad04',    'P4'),
        ('name',     'S'),
        ('commands', 'S'),   # #-codes such as #E_0#M_0#B_0; nothing is read unless it starts with #
        ('str18',    'S'),
        ('uint8_20', 'B'),
        ('pad21',    'P7'),
        # flags, a bit per letter:
        #   (one letter set, shared with ViewerCharaList flags2)
        #   S 0x1000: a face with S is hidden from the list for a character whose flags2 has S
        #   H 0x1, M 0x2, F 0x4, A 0x8, C 0x10, B 0x20, E 0x40, N 0x80, P 0x100, L 0x200, J 0x800:
        #     nothing found reading it
        ('flags',    'S'),
    )
