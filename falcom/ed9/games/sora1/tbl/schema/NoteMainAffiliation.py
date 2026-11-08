from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl, t_quest_fc.tbl
class NoteMainAffiliation(TableDataEntry):
    DESCRIPTOR = (
        ('text',  'S'),
        ('flag',  'W'),   # of the rows with it set, the last is taken; else row 0
        ('pad0a', 'P6'),
    )
