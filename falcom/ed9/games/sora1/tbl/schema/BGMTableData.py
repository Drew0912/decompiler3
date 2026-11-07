from falcom.ed9.parser.tbl import TableDataEntry


# t_bgm.tbl
class BGMTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('float32_10', 'f'),
        ('uint32_14',  'I'),
    )
