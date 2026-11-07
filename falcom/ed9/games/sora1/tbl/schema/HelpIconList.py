from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class HelpIconList(TableDataEntry):
    DESCRIPTOR = (
        ('titleId',    'W'),
        ('page',       'B'),
        ('pad03',      'P1'),
        ('uint32_04',  'I'),
        ('text1',      'S'),
        ('float32_10', 'f'),
        ('uint32_14',  'I'),
        ('text2',      'S'),
        ('float32_20', 'f'),
        ('uint32_24',  'I'),
        ('text3',      'S'),
        ('flags',      'S'),
    )
