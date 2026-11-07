from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class HelpController(TableDataEntry):
    DESCRIPTOR = (
        ('titleId',     'W'),
        ('page',        'B'),
        ('holderIndex', 'B'),
        ('pad04',       'P4'),
        ('str08',       'S'),
    )
