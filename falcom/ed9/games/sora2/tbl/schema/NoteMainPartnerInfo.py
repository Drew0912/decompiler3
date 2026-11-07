from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteMainPartnerInfo(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('str08',     'S'),
        ('uint64_10', 'Q'),
    )
