from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteMonsRecordData(TableDataEntry):
    DESCRIPTOR = (
        ('str00',     'S'),
        ('uint32_08', 'I'),
        ('uint32_0c', 'I'),
        ('arr16_10',  'A2'),
        ('uint32_1c', 'I'),
        ('str20',     'S'),
        ('str28',     'S'),
    )
