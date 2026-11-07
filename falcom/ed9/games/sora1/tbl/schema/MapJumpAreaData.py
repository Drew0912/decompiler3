from falcom.ed9.parser.tbl import TableDataEntry


# t_mapjump.tbl
class MapJumpAreaData(TableDataEntry):
    DESCRIPTOR = (
        ('id',        'I'),
        ('uint32_04', 'I'),
        ('name',      'S'),
        ('mapKey',    'S'),
        ('x',         'f'),
        ('y',         'f'),
        ('z',         'f'),
        ('uint32_24', 'I'),
        ('flags',     'S'),
        ('str30',     'S'),
    )
