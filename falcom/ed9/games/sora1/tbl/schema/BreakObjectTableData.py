from falcom.ed9.parser.tbl import TableDataEntry


# t_break_object.tbl
class BreakObjectTableData(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('uint32_20', 'I'),
        ('uint32_24', 'I'),
        ('str28',     'S'),
        ('str30',     'S'),
    )
