from falcom.ed9.parser.tbl import TableDataEntry


# t_books.tbl
class BooksText(TableDataEntry):
    DESCRIPTOR = (
        ('bookId', 'W'),
        ('page',   'H'),
        ('pad04',  'P4'),
        ('text',   'S'),
        ('image',  'S'),
    )
