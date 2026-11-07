from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class HelpIconList(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00',  'I'),
        ('uint32_04',  'I'),
        ('str08',      'S'),
        ('float32_10', 'f'),
        ('uint32_14',  'I'),
        ('str18',      'S'),
        ('float32_20', 'f'),
        ('uint32_24',  'I'),
        ('str28',      'S'),
        ('str30',      'S'),
    )
