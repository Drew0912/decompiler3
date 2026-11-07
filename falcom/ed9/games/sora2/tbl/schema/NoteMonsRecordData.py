from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteMonsRecordData(TableDataEntry):
    DESCRIPTOR = (
        ('statusKey', 'S'),
        ('uint32_08', 'I'),
        ('saveIndex', 'I'),
        ('arr16_10',  'A2'),
        ('category',  'W'),
        ('pad1e',     'P2'),
        ('flags',     'S'),
        ('name',      'S'),
    )
