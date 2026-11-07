from falcom.ed9.parser.tbl import TableDataEntry


# t_break_object.tbl
class BreakObjectTableData(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',    'S'),
        ('name',      'S'),
        ('statusKey', 'S'),
        ('function',  'S'),
        ('flag',      'W'),
        ('itemGroup', 'W'),
        ('countA',    'W'),
        ('countB',    'W'),
        ('str28',     'S'),
        ('flags',     'S'),
        ('uint64_38', 'Q'),
    )
