from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteCookCategory(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'B'),
        ('pad01', 'P7'),
        ('name',  'S'),
        ('text',  'S'),
        ('ruby',  'S'),
    )
