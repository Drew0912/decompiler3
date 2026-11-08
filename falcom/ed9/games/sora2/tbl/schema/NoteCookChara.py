from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteCookChara(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',     'W'),
        ('pad02',     'P6'),
        ('flagsAny',  'A2'),  # listed if any one is set; a 0 is skipped
        ('workIndex', 'I'),
    )
