from falcom.ed9.parser.tbl import TableDataEntry


# t_text.tbl
class TextTableData(TableDataEntry):
    DESCRIPTOR = (
        ('str00', 'S'),
        ('str08', 'S'),
    )
