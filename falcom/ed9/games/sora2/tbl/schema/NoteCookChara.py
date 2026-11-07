from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteCookChara(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('arr16_08',  'A2'),
        ('uint32_14', 'I'),
    )
