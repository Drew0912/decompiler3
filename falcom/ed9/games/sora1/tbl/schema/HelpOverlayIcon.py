from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class HelpOverlayIcon(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('float32_10', 'f'),
        ('float32_14', 'f'),
        ('uint32_18',  'I'),
        ('float32_1c', 'f'),
        ('uint64_20',  'Q'),
    )
