from falcom.ed9.parser.tbl import TableDataEntry


# t_face_anime.tbl
class EyeScaleData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('float32_04', 'f'),
    )
