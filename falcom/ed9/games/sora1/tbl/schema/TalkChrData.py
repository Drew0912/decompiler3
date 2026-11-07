from falcom.ed9.parser.tbl import TableDataEntry


# t_chrdata.tbl
class TalkChrData(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
    )
