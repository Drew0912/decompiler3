from falcom.ed9.parser.tbl import TableDataEntry


# t_face_anime.tbl
class EyePresetData(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',    'W'),  # 0xFFFF: any
        ('pattern',  'B'),
        ('uint8_03', 'B'),
        ('uint8_04', 'B'),
        ('uint8_05', 'B'),
    )
