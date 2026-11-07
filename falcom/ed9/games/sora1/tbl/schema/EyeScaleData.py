from falcom.ed9.parser.tbl import TableDataEntry


# t_face_anime.tbl
class EyeScaleData(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',      'W'),
        ('pattern',    'B'),
        ('pad03',      'P1'),
        ('float32_04', 'f'),
    )
