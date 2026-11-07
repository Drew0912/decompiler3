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
        ('flags',      'S'),
        ('float32_40', 'f'),
        ('float32_44', 'f'),
        ('float32_48', 'f'),
        ('uint32_4c',  'I'),
    )
