from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl, t_quest_fc.tbl
class NoteMainAffiliation(TableDataEntry):
    DESCRIPTOR = (
        ('text',  'S'),
        ('flag',  'W'),
        ('pad0a', 'P6'),
    )
