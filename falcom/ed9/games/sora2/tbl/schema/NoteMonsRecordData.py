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
        # flags, 1 when it holds A, else 0 (not a mask):
        #   A: not counted in the total of monster records (a count scripts can read)
        ('flags',     'S'),
        ('name',      'S'),
    )
