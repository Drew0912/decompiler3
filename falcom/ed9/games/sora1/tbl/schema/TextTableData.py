from falcom.ed9.parser.tbl import TableDataEntry


# t_text.tbl
class TextTableData(TableDataEntry):
    DESCRIPTOR = (
        ('key',  'S'),  # hashed at load; rows are found by the hash
        ('text', 'S'),
    )
