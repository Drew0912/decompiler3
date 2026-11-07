from falcom.ed9.parser.tbl import TableDataEntry


# t_face_anime.tbl
class EyePresetData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint16_04', 'W'),
    )
