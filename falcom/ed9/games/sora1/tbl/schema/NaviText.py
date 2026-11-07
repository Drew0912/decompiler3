from falcom.ed9.parser.tbl import TableDataEntry


# t_quest.tbl
class NaviText(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00', 'Q'),
        ('str08',     'S'),
        ('str10',     'S'),
        ('arr32_18',  'A4'),
        ('uint32_24', 'I'),
        ('arr32_28',  'A4'),
        ('uint32_34', 'I'),
    )
