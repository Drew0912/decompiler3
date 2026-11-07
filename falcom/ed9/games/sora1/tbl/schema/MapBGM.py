from falcom.ed9.parser.tbl import TableDataEntry


# t_bgmset.tbl
class MapBGM(TableDataEntry):
    DESCRIPTOR = (
        ('placeId',    'I'),
        ('pad04',      'P4'),
        ('flagsSet',   'A2'),
        ('uint32_14',  'I'),
        ('flagsClear', 'A2'),
        ('bgmId',      'I'),
        ('float32_28', 'f'),
        ('uint32_2c',  'I'),
    )
