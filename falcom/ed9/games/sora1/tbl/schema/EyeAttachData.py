from falcom.ed9.parser.tbl import TableDataEntry


# t_face_anime.tbl
class EyeAttachData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
        ('str18',     'S'),
    )
