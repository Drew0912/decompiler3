from falcom.ed9.parser.tbl import TableDataEntry


# t_viewer.tbl
class ViewerCharaList(TableDataEntry):
    DESCRIPTOR = (
        ('id',         'W'),
        ('pad02',      'P6'),
        ('str08',      'S'),
        ('str10',      'S'),
        ('name',       'S'),
        ('saveBit',    'I'),
        ('saveBit2',   'I'),
        ('flags',      'S'),
        ('flags2',     'S'),
        ('float32_38', 'f'),
        ('float32_3c', 'f'),
    )
