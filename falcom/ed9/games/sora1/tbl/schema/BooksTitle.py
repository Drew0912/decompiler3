from falcom.ed9.parser.tbl import TableDataEntry


# t_books.tbl
class BooksTitle(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'W'),
        ('categoryId', 'W'),
        ('pad04',      'P4'),
        ('title',      'S'),
        ('itemId',     'W'),
        ('uint16_12',  'W'),
        ('uint8_14',   'B'),
        ('pad15',      'P3'),
    )
