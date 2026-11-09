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
        # flags, a bit per letter:
        #   E 0x1, e 0x2, S 0x4, D 0x8: read by code, purpose not known
        ('flags',     'S'),
        ('uint64_38', 'Q'),
    )
