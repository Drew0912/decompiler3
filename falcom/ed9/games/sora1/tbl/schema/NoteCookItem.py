from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteCookItem(TableDataEntry):
    DESCRIPTOR = (
        ('uint32_00', 'I'),
        ('uint32_04', 'I'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('str10',     'S'),
        ('uint32_18', 'I'),
        ('uint32_1c', 'I'),
        ('str20',     'S'),
        ('arr8_28',   'A1'),
        ('uint32_34', 'I'),
    )
