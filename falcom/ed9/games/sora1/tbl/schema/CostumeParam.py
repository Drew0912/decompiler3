from falcom.ed9.parser.tbl import TableDataEntry


# t_costume.tbl
class CostumeParam(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',   'W'),   # 0xFFFF: any, in the lookups for kind 1 and 2
        ('kind',    'B'),
        ('pad03',   'P1'),
        ('variant', 'W'),
        ('flag',    'W'),   # 0: none
        ('flags',   'S'),
        ('name',    'S'),
        ('partId',  'I'),
        ('pad1c',   'P4'),
        ('str20',   'S'),
        ('str28',   'S'),
        ('str30',   'S'),
    )
