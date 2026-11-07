from falcom.ed9.parser.tbl import TableDataEntry


# t_text.tbl
class TextTableData(TableDataEntry):
    DESCRIPTOR = (
        ('key',  'S'),
        ('text', 'S'),
    )
