from falcom.ed9.parser.tbl import TableDataEntry


# t_face_anime.tbl
class FaceAnimeData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
    )
