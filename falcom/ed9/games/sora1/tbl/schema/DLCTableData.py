from falcom.ed9.parser.tbl import TableDataEntry


# t_dlc.tbl
class DLCTableData(TableDataEntry):
    DESCRIPTOR = (
        ('id',          'I'),
        ('sortKey',     'i'),   # the DLC list order, ascending
        ('itemIds',     'A4'),
        ('uint32_14',   'I'),
        ('itemCounts',  'A4'),  # one per itemIds entry: how many are given
        ('uint32_24',   'I'),
        ('name',        'S'),
        ('description', 'S'),
        ('str38',       'S'),
    )
