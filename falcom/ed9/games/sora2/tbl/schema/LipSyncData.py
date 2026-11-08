from falcom.ed9.parser.tbl import TableDataEntry


# t_face_anime.tbl
class LipSyncData(TableDataEntry):
    DESCRIPTOR = (
        ('chrId', 'W'),   # 0xFFFF: any
        ('pad02', 'P6'),
        ('name',  'S'),
        ('str10', 'S'),
        ('str18', 'S'),
    )
