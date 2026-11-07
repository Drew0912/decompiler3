from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class HelpOverlayIcon(TableDataEntry):
    DESCRIPTOR = (
        ('titleId',    'W'),
        ('page',       'B'),
        ('pad03',      'P5'),
        ('text',       'S'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
        ('uint8_18',   'B'),
        ('pad19',      'P3'),
        ('float32_1c', 'f'),
        ('kind',       'B'),
        ('pad21',      'P7'),
    )
