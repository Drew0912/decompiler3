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
        #   L 0x1: read by code, purpose not known
        #   D 0x2, A 0x4, K 0x8, O 0x10, P 0x20, S 0x40: nothing found reading it
        ('flags',      'S'),
        ('float32_40', 'f'),
        ('float32_44', 'f'),
        ('float32_48', 'f'),
        ('uint32_4c',  'I'),
    )
