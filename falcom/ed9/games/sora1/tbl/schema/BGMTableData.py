from falcom.ed9.parser.tbl import TableDataEntry


# t_bgm.tbl
class BGMTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'I'),
        ('pad04',      'P4'),
        ('name',       'S'),
        ('float32_10', 'f'),
        ('uint8_14',   'B'),
        ('pad15',      'P3'),
    )
