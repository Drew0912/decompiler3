from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerMapData(TableDataEntry):
    DESCRIPTOR = (
        ('uint64_00',  'Q'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('arr16_18',   'A2'),
        ('uint32_24',  'I'),
        ('str28',      'S'),
        ('uint32_30',  'I'),
        ('uint32_34',  'I'),
        ('str38',      'S'),
        ('float32_40', 'f'),
        ('float32_44', 'f'),
        ('float32_48', 'f'),
        ('uint32_4c',  'I'),
    )
