from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class HelpIconList(TableDataEntry):
    DESCRIPTOR = (
        ('titleId',    'W'),
        ('page',       'B'),
        ('pad03',      'P1'),
        ('cellIndex',  'I'),
        ('text1',      'S'),
        ('float32_10', 'f'),
        ('uint32_14',  'I'),
        ('text2',      'S'),
        ('float32_20', 'f'),
        ('uint32_24',  'I'),
        ('text3',      'S'),
        # flags, 1 when it holds A, else 0 (not a mask):
        #   A: the at_icon widget, filled from the t_btlsys row whose first byte equals cellIndex, is used in place
        #     of the icon widget
        ('flags',      'S'),
    )
