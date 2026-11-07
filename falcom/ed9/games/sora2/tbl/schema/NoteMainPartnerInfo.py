from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteMainPartnerInfo(TableDataEntry):
    DESCRIPTOR = (
        ('text',  'S'),
        ('str08', 'S'),
        ('flag',  'W'),
        ('pad12', 'P6'),
    )
