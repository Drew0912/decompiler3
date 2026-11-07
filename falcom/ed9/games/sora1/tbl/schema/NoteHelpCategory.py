from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteHelpCategory(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'B'),
        ('pad01', 'P7'),
        ('text',  'S'),
        ('ruby',  'S'),
        ('str18', 'S'),
    )
