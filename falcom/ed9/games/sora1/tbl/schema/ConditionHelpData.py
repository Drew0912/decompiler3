from falcom.ed9.parser.tbl import TableDataEntry


# t_itemhelp.tbl
class ConditionHelpData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('str18',     'S'),
        ('str20',     'S'),
    )
