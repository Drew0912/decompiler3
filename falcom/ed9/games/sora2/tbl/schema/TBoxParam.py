from falcom.ed9.parser.tbl import TableDataEntry


# t_tbox.tbl
class TBoxParam(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',     'S'),
        ('name',       'S'),
        ('uint64_10',  'Q'),
        ('flags',      'S'),
        ('function',   'S'),
        ('flag1',      'W'),
        ('flag2',      'W'),
        ('pad2c',      'P4'),
        ('items',      'A2'),
        ('uint32_3c',  'I'),
        ('altFlag',    'W'),   # scenario flag; once set, altItems and uint32_54 replace items and uint32_3c; 0: none
        ('pad42',      'P6'),
        ('altItems',   'A2'),
        ('uint32_54',  'I'),
        ('flagsSet',   'A2'),  # scenario flags that must all be set
        ('uint32_64',  'I'),
        ('flagsClear', 'A2'),  # scenario flags none of which may be set
        ('uint32_74',  'I'),
    )
