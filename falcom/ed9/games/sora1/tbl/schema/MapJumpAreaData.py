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
        # flags, a bit per letter:
        #   N 0x1, F 0x2, T 0x4, R 0x8: read by code, purpose not known
        ('flags',     'S'),
        ('str30',     'S'),
    )
