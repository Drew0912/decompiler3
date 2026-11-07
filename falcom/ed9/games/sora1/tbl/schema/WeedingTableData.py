from falcom.ed9.parser.tbl import TableDataEntry


# t_break_object.tbl
class WeedingTableData(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',    'S'),
        ('name',      'S'),
        ('function',  'S'),
        ('chance',    'W'),
        ('itemGroup', 'W'),
        ('countA',    'W'),
        ('countB',    'W'),
    )
