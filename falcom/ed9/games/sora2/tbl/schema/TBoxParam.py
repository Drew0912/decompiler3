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
        ('altFlag',    'W'),
        ('pad42',      'P6'),
        ('altItems',   'A2'),
        ('uint32_54',  'I'),
        ('flagsSet',   'A2'),
        ('uint32_64',  'I'),
        ('flagsClear', 'A2'),
        ('uint32_74',  'I'),
    )
