from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl, t_quest_fc.tbl
class NoteMainCategory(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'B'),
        ('pad01', 'P7'),
        ('text',  'S'),
        ('ruby',  'S'),
    )
