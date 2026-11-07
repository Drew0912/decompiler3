from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteCookCategory(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
    )
