from falcom.ed9.parser.tbl import TableDataEntry


# t_title.tbl
class TitleTableData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('str18',      'S'),
        ('uint32_20',  'I'),
        ('float32_24', 'f'),
        ('str28',      'S'),
        ('float32_30', 'f'),
        ('uint32_34',  'I'),
    )
