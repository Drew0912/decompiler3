from falcom.ed9.parser.tbl import TableDataEntry


# t_face_anime.tbl
class MouthPatternMap(TableDataEntry):
    DESCRIPTOR = (
        # (value + 150) / 30.0 is stored twice in the clip Mouse_<row number> (a clip, by a reading); only
        # the first 36 rows get a slot
        ('uint16_00', 'W'),
    )
