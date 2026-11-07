from falcom.ed9.parser.tbl import TableDataEntry


# t_face_anime.tbl
class EyeBallSizePatternNameData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )
