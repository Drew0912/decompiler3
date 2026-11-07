from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteBattleCategory(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'B'),
        ('pad01', 'P7'),
        ('text',  'S'),
        ('ruby',  'S'),
    )
