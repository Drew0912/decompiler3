from falcom.ed9.parser.tbl import TableDataEntry


# t_face_anime.tbl
class FaceAnimeData(TableDataEntry):
    DESCRIPTOR = (
        ('chrId', 'W'),
        ('pad02', 'P6'),
        ('name',  'S'),
        ('text',  'S'),
    )
