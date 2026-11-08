from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteMainPartnerInfo(TableDataEntry):
    DESCRIPTOR = (
        ('text',  'S'),
        ('str08', 'S'),
        ('flag',  'W'),   # scenario flag that must be set; 0: none
        ('pad12', 'P6'),
    )
