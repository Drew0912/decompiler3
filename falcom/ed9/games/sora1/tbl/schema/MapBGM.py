from falcom.ed9.parser.tbl import TableDataEntry


# t_bgmset.tbl
class MapBGM(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('arr16_08',   'A2'),
        ('uint32_14',  'I'),
        ('arr16_18',   'A2'),
        ('uint32_24',  'I'),
        ('float32_28', 'f'),
        ('uint32_2c',  'I'),
    )
