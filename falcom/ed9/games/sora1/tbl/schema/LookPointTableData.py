from falcom.ed9.parser.tbl import TableDataEntry


# t_lookpoint.tbl
class LookPointTableData(TableDataEntry):
    DESCRIPTOR = (
        ('mapKey',     'S'),
        ('name',       'S'),
        ('str10',      'S'),
        ('function',   'S'),
        ('flagsSet',   'A2'),
        ('uint32_2c',  'I'),
        ('flagsClear', 'A2'),
        ('uint32_3c',  'I'),
    )
