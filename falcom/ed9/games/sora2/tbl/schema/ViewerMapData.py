from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerMapData(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'W'),
        ('pad02',      'P6'),
        ('str08',      'S'),
        ('name',       'S'),
        ('envIds',     'A2'),
        ('uint32_24',  'I'),
        ('str28',      'S'),
        ('saveBit',    'I'),
        ('uint8_34',   'B'),
        ('pad35',      'P3'),
        # flags, a bit per letter:
        #   D 0x2: x, y, z are used in place of a vector the code works out
        #   L 0x1, A 0x4, K 0x8, O 0x10, P 0x20, S 0x40: read by code, purpose not known
        ('flags',      'S'),
        ('x',          'f'),   # x, y, z: a position, by its use; only rows with D in flags set them
        ('y',          'f'),
        ('z',          'f'),
        ('uint32_4c',  'I'),
    )
