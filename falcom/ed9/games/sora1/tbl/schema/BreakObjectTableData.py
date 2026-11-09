from falcom.ed9.parser.tbl import TableDataEntry


# t_break_object.tbl
class BreakObjectTableData(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',    'S'),
        ('name',      'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('uint16_20', 'W'),
        ('itemGroup', 'W'),
        ('uint32_24', 'I'),
        ('str28',     'S'),
        ('str30',     'S'),
    )
