from falcom.ed9.parser.tbl import TableDataEntry


# t_notemenu.tbl
class NoteMonsRecordData(TableDataEntry):
    DESCRIPTOR = (
        ('statusKey', 'S'),
        ('sortKey',   'i'),   # the battle notes list order, ascending
        ('saveIndex', 'I'),
        ('flagsAny',  'A2'),  # scenario flags: listed only once one is set; empty: always listed
        ('category',  'W'),
        ('pad1e',     'P2'),
        # flags, 1 when it holds A, else 0 (not a mask):
        #   A: not counted in the total of monster records (a count scripts can read)
        ('flags',     'S'),
        ('name',      'S'),
    )
