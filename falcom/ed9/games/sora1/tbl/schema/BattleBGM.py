from falcom.ed9.parser.tbl import TableDataEntry


# t_bgmset.tbl
class BattleBGM(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
        ('arr16_18',  'A2'),
        ('uint32_24', 'I'),
        ('uint32_28', 'I'),
        ('uint32_2c', 'I'),
        ('uint64_30', 'Q'),
    )
