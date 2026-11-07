from falcom.ed9.parser.tbl import TableDataEntry


# t_books.tbl
class BooksCategory(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'W'),
        ('pad02', 'P6'),
        ('text',  'S'),
        ('ruby',  'S'),
    )
