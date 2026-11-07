from falcom.ed9.parser.tbl import TableDataEntry


# t_chrdata.tbl
class TalkChrData(TableDataEntry):
    DESCRIPTOR = (
        ('index',     'W'),
        ('uint16_02', 'W'),
        ('key',       'I'),
    )
