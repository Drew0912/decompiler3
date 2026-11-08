from falcom.ed9.parser.tbl import TableDataEntry


# t_bgmset.tbl
class MapBGM(TableDataEntry):
    DESCRIPTOR = (
        ('placeId',    'I'),
        ('pad04',      'P4'),
        ('flagsSet',   'A2'),  # scenario flags that must all be set
        ('uint32_14',  'I'),
        ('flagsClear', 'A2'),  # scenario flags none of which may be set
        ('bgmId',      'I'),
        ('float32_28', 'f'),
        ('uint32_2c',  'I'),
    )
