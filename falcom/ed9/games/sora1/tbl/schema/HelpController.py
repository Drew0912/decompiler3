from falcom.ed9.parser.tbl import TableDataEntry


# t_help.tbl
class HelpController(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
    )
