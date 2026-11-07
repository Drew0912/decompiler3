from falcom.ed9.parser.tbl import TableDataEntry


# t_costume.tbl
class CostumeParam(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',   'W'),
        ('kind',    'B'),
        ('pad03',   'P1'),
        ('variant', 'W'),
        ('flag',    'W'),
        ('flags',   'S'),
        ('name',    'S'),
        ('partId',  'I'),
        ('pad1c',   'P4'),
        ('str20',   'S'),
        ('str28',   'S'),
        ('str30',   'S'),
    )
