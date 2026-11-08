from falcom.ed9.parser.tbl import TableDataEntry


# t_se.tbl
class SETableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'I'),   # 0: none; rows sorted by it at load
        ('pad04',      'P4'),
        ('name',       'S'),
        ('uint8_10',   'B'),
        ('pad11',      'P3'),
        ('float32_14', 'f'),
        ('uint16_18',  'W'),
        ('uint8_1a',   'B'),
        ('uint8_1b',   'B'),
        ('distance',   'f'),
    )
