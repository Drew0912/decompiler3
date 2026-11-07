from falcom.ed9.parser.tbl import TableDataEntry


# t_title.tbl
class TitleTableData(TableDataEntry):
    DESCRIPTOR = (
        ('groupKey',   'W'),
        ('pad02',      'P6'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('str18',      'S'),
        ('bgmId',      'I'),
        ('float32_24', 'f'),
        ('str28',      'S'),
        ('float32_30', 'f'),
        ('uint32_34',  'I'),
    )
