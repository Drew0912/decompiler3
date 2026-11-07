from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteCookChara(TableDataEntry):
    DESCRIPTOR = (
        ('chrId',     'W'),
        ('pad02',     'P6'),
        ('flagsAny',  'A2'),
        ('workIndex', 'I'),
    )
