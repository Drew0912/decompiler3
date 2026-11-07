from falcom.ed9.parser.tbl import TableDataEntry


# t_face_anime.tbl
class EyeModifyAttachData(TableDataEntry):
    DESCRIPTOR = (
        ('pattern',   'B'),
        ('selector',  'B'),
        ('int16_02',  'w'),
        ('pad04',     'P4'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
        ('str18',     'S'),
    )
