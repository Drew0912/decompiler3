from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteMonsRecordData(TableDataEntry):
    DESCRIPTOR = (
        ('statusKey', 'S'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('uint64_10', 'Q'),
        ('str18',     'S'),
        ('str20',     'S'),
    )
